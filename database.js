"use strict";
/**
 * database.js — PostgreSQL adapter for MOTORENT
 *
 * Uses @neondatabase/serverless for HTTP-based Postgres access.
 * This driver works correctly in Vercel serverless functions AND
 * in long-lived Node.js processes (local dev).
 *
 * Connection string priority:
 *   DATABASE_URL  →  POSTGRES_URL  →  DATABASE_URL_UNPOOLED  →  POSTGRES_URL_NON_POOLING
 */

require("dotenv").config();
const { neon, neonConfig } = require("@neondatabase/serverless");

// Optional: use WebSocket pooling in non-edge environments for better performance
// neonConfig.webSocketConstructor = require("ws");   // uncomment if you install ws

const connectionString =
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL ||
    process.env.DATABASE_URL_UNPOOLED ||
    process.env.POSTGRES_URL_NON_POOLING ||
    process.env.POSTGRES_URL_NO_SSL;

if (!connectionString) {
    throw new Error(
        "Missing PostgreSQL connection string. " +
        "Set DATABASE_URL (or POSTGRES_URL) in Vercel or your local .env file."
    );
}

// sql is a tagged-template query function; sql.query() accepts ($1, $2) placeholders
const sql = neon(connectionString);

/**
 * Run a parameterised query and return all rows.
 * @param {string} text   SQL with $1/$2/… placeholders
 * @param {any[]}  params Parameter values
 * @returns {Promise<any[]>}
 */
async function query(text, params = []) {
    const rows = await sql.query(text, params);
    // @neondatabase/serverless returns the rows array directly via sql.query()
    return Array.isArray(rows) ? rows : (rows.rows ?? []);
}

/**
 * Run a query and return the first row, or null.
 */
async function get(text, params = []) {
    const rows = await query(text, params);
    return rows[0] ?? null;
}

/**
 * Run a DML statement (INSERT/UPDATE/DELETE) and return the pg result object.
 * The result object has a `rowCount` property.
 */
async function run(text, params = []) {
    // sql.query returns rows array for neon; wrap it to expose rowCount
    // We need the raw result for rowCount — use a transaction client trick
    const rows = await sql.query(text, params);
    // For compatibility with rowCount checks, return a pg-like result
    if (Array.isArray(rows)) {
        return { rows, rowCount: rows.length };
    }
    return rows;
}

/**
 * Execute multiple statements inside a single transaction.
 * The callback receives a `client` object with `.query(text, params)`.
 *
 * With @neondatabase/serverless the transaction API uses neon's transaction() helper.
 * @param {(client: { query: Function }) => Promise<any>} callback
 */
async function withTransaction(callback) {
    // Build a transaction-compatible client wrapper
    return sql.transaction(async (txClient) => {
        // txClient from neon is already a tagged-template; wrap it so existing
        // code that calls client.query(text, params) continues to work.
        const client = {
            async query(text, params = []) {
                const rows = await txClient.query(text, params);
                return Array.isArray(rows)
                    ? { rows, rowCount: rows.length }
                    : rows;
            },
        };
        return callback(client);
    });
}

/**
 * Idempotent schema initialisation.
 * Safe to run on every cold-start — all DDL uses IF NOT EXISTS / IF EXISTS.
 */
async function initializeDatabase() {
    // --- Core tables ---
    await query(`
        CREATE TABLE IF NOT EXISTS users (
            user_id      SERIAL PRIMARY KEY,
            name         TEXT NOT NULL,
            email        TEXT NOT NULL UNIQUE,
            phone        TEXT,
            password_hash TEXT NOT NULL,
            role         TEXT NOT NULL DEFAULT 'CUSTOMER'
                CHECK (role IN ('ADMIN', 'VENDOR', 'CUSTOMER')),
            created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await query(`
        CREATE TABLE IF NOT EXISTS vendor_applications (
            application_id SERIAL PRIMARY KEY,
            user_id        INTEGER REFERENCES users(user_id),
            name           TEXT NOT NULL,
            email          TEXT NOT NULL,
            phone          TEXT,
            status         TEXT NOT NULL DEFAULT 'PENDING'
                CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
            submitted_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            reviewed_at    TIMESTAMPTZ
        )
    `);

    await query(`
        CREATE TABLE IF NOT EXISTS vendors (
            vendor_id     SERIAL PRIMARY KEY,
            user_id       INTEGER NOT NULL UNIQUE REFERENCES users(user_id),
            business_name TEXT NOT NULL,
            location      TEXT NOT NULL,
            status        TEXT NOT NULL DEFAULT 'ACTIVE'
                CHECK (status IN ('ACTIVE', 'SUSPENDED'))
        )
    `);

    await query(`
        CREATE TABLE IF NOT EXISTS vehicles (
            vehicle_id    SERIAL PRIMARY KEY,
            vendor_id     INTEGER NOT NULL REFERENCES vendors(vendor_id),
            vehicle_type  TEXT NOT NULL CHECK (vehicle_type IN ('MOTORCYCLE', 'CAR')),
            brand         TEXT NOT NULL,
            model         TEXT NOT NULL,
            segment       TEXT NOT NULL,
            price_per_day DOUBLE PRECISION NOT NULL CHECK (price_per_day >= 0),
            location      TEXT NOT NULL,
            image_path    TEXT NOT NULL DEFAULT 'images/default-vehicle.jpg',
            status        TEXT NOT NULL DEFAULT 'ACTIVE'
                CHECK (status IN ('ACTIVE', 'INACTIVE')),
            created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await query(`
        CREATE TABLE IF NOT EXISTS bookings (
            booking_id      SERIAL PRIMARY KEY,
            customer_id     INTEGER NOT NULL REFERENCES users(user_id),
            vehicle_id      INTEGER NOT NULL REFERENCES vehicles(vehicle_id),
            pickup_datetime  TIMESTAMPTZ NOT NULL,
            return_datetime  TIMESTAMPTZ NOT NULL,
            total_price     DOUBLE PRECISION NOT NULL CHECK (total_price >= 0),
            status          TEXT NOT NULL DEFAULT 'PENDING'
                CHECK (status IN (
                    'PENDING', 'CONFIRMED', 'REJECTED',
                    'EXPIRED', 'CANCELLED', 'ACTIVE', 'COMPLETED', 'ACCEPTED'
                )),
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CHECK (return_datetime > pickup_datetime)
        )
    `);

    // --- Indexes (idempotent) ---
    await query(`CREATE INDEX IF NOT EXISTS idx_vehicles_vendor  ON vehicles(vendor_id)`);
    await query(`CREATE INDEX IF NOT EXISTS idx_vehicles_status  ON vehicles(status)`);
    await query(`CREATE INDEX IF NOT EXISTS idx_bookings_customer ON bookings(customer_id)`);
    await query(`CREATE INDEX IF NOT EXISTS idx_bookings_vehicle  ON bookings(vehicle_id)`);
    await query(`CREATE INDEX IF NOT EXISTS idx_bookings_status   ON bookings(status)`);
    await query(`CREATE INDEX IF NOT EXISTS idx_bookings_dates    ON bookings(vehicle_id, pickup_datetime, return_datetime)`);
    await query(`CREATE INDEX IF NOT EXISTS idx_vendors_user      ON vendors(user_id)`);
}

module.exports = {
    query,
    get,
    run,
    withTransaction,
    initializeDatabase,
    /** Expose raw sql for ad-hoc use */
    sql,
};
