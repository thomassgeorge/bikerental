#!/usr/bin/env node
"use strict";
/**
 * scripts/test-db.js
 * Quick verification of Neon database connectivity and table row counts.
 * Uses @neondatabase/serverless (HTTP) — same driver as the app.
 *
 * Usage:  node scripts/test-db.js
 *         npm run test:db
 */
const path = require("path");
require("dotenv").config({ path: path.join(__dirname, "../.env") });
const { neon } = require("@neondatabase/serverless");

const connStr =
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL ||
    process.env.DATABASE_URL_UNPOOLED ||
    process.env.POSTGRES_URL_NON_POOLING;

if (!connStr) {
    console.error("ERROR: No DATABASE_URL found in environment. Check your .env file.");
    process.exit(1);
}

const sql = neon(connStr);

async function main() {
    try {
        const rows = await sql.query("SELECT current_database() AS db, version() AS v");
        const info = Array.isArray(rows) ? rows[0] : rows.rows[0];
        console.log("✅ Connected to Neon database:", info.db);
        console.log("   PostgreSQL:", info.v.split(" ").slice(0, 2).join(" "));
    } catch (e) {
        console.error("❌ Connection failed:", e.message);
        process.exit(1);
    }

    const { rows: tables } = await sql.query(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name"
    ).then(r => Array.isArray(r) ? { rows: r } : r);

    const tableNames = tables.map(r => r.table_name);
    console.log("\nExisting tables:", tableNames.join(", ") || "(none yet)");

    const expected = ["bookings", "users", "vendor_applications", "vendors", "vehicles"];
    const missing = expected.filter(t => !tableNames.includes(t));
    if (missing.length) {
        console.log("⚠️  Missing tables:", missing.join(", "));
        console.log("   Run the server once to auto-create them.");
    }

    for (const t of ["users", "vendor_applications", "vendors", "vehicles", "bookings"]) {
        try {
            const countRows = await sql.query(`SELECT COUNT(*) AS n FROM ${t}`);
            const count = Array.isArray(countRows) ? countRows[0].n : countRows.rows[0].n;
            console.log(`  ${t}: ${count} row(s)`);
        } catch (e) {
            console.log(`  ${t}: MISSING — ${e.message.split("\n")[0]}`);
        }
    }

    console.log("\n✅ Test complete.");
}

main().catch(e => { console.error("FATAL:", e.message); process.exit(1); });
