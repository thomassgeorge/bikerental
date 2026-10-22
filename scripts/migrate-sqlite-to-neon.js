#!/usr/bin/env node
/**
 * scripts/migrate-sqlite-to-neon.js
 *
 * One-shot migration: reads every row from the local database.db SQLite file
 * and upserts it into the Neon PostgreSQL database.
 *
 * Usage:
 *   node scripts/migrate-sqlite-to-neon.js
 *   npm run migrate:sqlite
 *
 * Safe to rerun — uses INSERT … ON CONFLICT DO UPDATE so no data is duplicated.
 * NEVER drops tables or destroys existing Neon data.
 */
"use strict";

const path = require("path");
const fs = require("fs");
require("dotenv").config({ path: path.join(__dirname, "../.env") });
const { neon } = require("@neondatabase/serverless");

const SQLITE_PATH = path.join(__dirname, "../database.db");

const connStr =
    process.env.DATABASE_URL_UNPOOLED ||   // prefer unpooled for schema work
    process.env.POSTGRES_URL_NON_POOLING ||
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL;

if (!connStr) {
    console.error("ERROR: No PostgreSQL connection string found. Check your .env file.");
    process.exit(1);
}

if (!fs.existsSync(SQLITE_PATH)) {
    console.error("ERROR: database.db not found at", SQLITE_PATH);
    console.error("       Nothing to migrate — Neon database is the primary store.");
    process.exit(1);
}

const sql = neon(connStr);

// Ordered to satisfy foreign-key constraints
const TABLES = ["users", "vendor_applications", "vendors", "vehicles", "bookings"];

async function getPkColumn(sqlite, table) {
    const info = sqlite.prepare(`PRAGMA table_info(${table})`).all();
    const pk = info.find(c => c.pk === 1);
    return pk ? pk.name : null;
}

async function migrateTable(sqlite, table) {
    const rows = sqlite.prepare(`SELECT * FROM ${table} ORDER BY 1`).all();
    if (rows.length === 0) {
        console.log(`  ${table}: 0 rows — skipped`);
        return;
    }

    const cols = sqlite.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name);
    const pkCol = await getPkColumn(sqlite, table);

    let inserted = 0;
    let updated = 0;

    for (const row of rows) {
        const values = cols.map(c => {
            const v = row[c];
            // Convert SQLite integers (0/1) for boolean-like fields if needed
            return v === undefined ? null : v;
        });
        const placeholders = cols.map((_, i) => `$${i + 1}`).join(", ");
        const updateCols = cols.filter(c => c !== pkCol);
        const updateClause = updateCols.map(c => `${c} = EXCLUDED.${c}`).join(", ");

        const query = pkCol && updateClause
            ? `INSERT INTO ${table} (${cols.join(", ")})
               VALUES (${placeholders})
               ON CONFLICT (${pkCol}) DO UPDATE SET ${updateClause}`
            : `INSERT INTO ${table} (${cols.join(", ")})
               VALUES (${placeholders})
               ON CONFLICT DO NOTHING`;

        try {
            const result = await sql.query(query, values);
            // neon returns rows array; rowCount is tricky with tagged template
            // Just count rows for reporting
            if (Array.isArray(result) && result.length === 0) updated++;
            else inserted++;
        } catch (err) {
            console.warn(`  WARNING: skipped row in ${table} (${pkCol}=${row[pkCol]}): ${err.message}`);
        }
    }

    console.log(`  ${table}: ${rows.length} row(s) processed`);

    // After explicit inserts, reset the SERIAL sequence so auto-increment works
    if (pkCol) {
        try {
            await sql.query(
                `SELECT setval(pg_get_serial_sequence($1, $2),
                    COALESCE((SELECT MAX(${pkCol}) FROM ${table}), 0) + 1, false)`,
                [table, pkCol]
            );
        } catch (e) {
            // ignore if sequence doesn't exist
        }
    }
}

async function main() {
    console.log("=".repeat(60));
    console.log("MOTORENT — SQLite → Neon PostgreSQL Migration");
    console.log("=".repeat(60));
    console.log("Source :", SQLITE_PATH);
    console.log("Target :", connStr.split("@")[1]?.split("?")[0] ?? "(connection string)");
    console.log();

    // Verify Neon connection
    try {
        const rows = await sql.query("SELECT current_database() AS db");
        console.log("✅ Connected to Neon database:", Array.isArray(rows) ? rows[0].db : rows.rows[0].db);
    } catch (e) {
        console.error("❌ Cannot connect to Neon:", e.message);
        process.exit(1);
    }

    // Ensure schema exists first
    console.log("\nInitialising schema...");
    const db = require("../database.js");
    await db.initializeDatabase();
    console.log("✅ Schema ready\n");

    // Load SQLite
    let Database;
    try {
        Database = require("better-sqlite3");
    } catch (e) {
        console.error("ERROR: better-sqlite3 not installed. Run: npm install better-sqlite3");
        process.exit(1);
    }
    const sqlite = new Database(SQLITE_PATH, { readonly: true });

    try {
        for (const table of TABLES) {
            await migrateTable(sqlite, table);
        }
        console.log("\n✅ Migration complete!");
        console.log("   Tip: verify row counts with: node scripts/test-db.js");
    } finally {
        sqlite.close();
    }
}

main().catch(e => {
    console.error("\nFATAL:", e.message);
    process.exit(1);
});
