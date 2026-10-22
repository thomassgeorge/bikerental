
const Database = require("better-sqlite3");

const db = new Database("database.db");

db.pragma("foreign_keys = ON");

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        phone TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'CUSTOMER'
            CHECK (role IN ('ADMIN', 'VENDOR', 'CUSTOMER')),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS vendor_applications (
        application_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'PENDING'
            CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
        submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(user_id)
    );

    CREATE TABLE IF NOT EXISTS vendors (
        vendor_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL UNIQUE,
        business_name TEXT NOT NULL,
        location TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'ACTIVE'
            CHECK (status IN ('ACTIVE', 'SUSPENDED')),
        FOREIGN KEY (user_id) REFERENCES users(user_id)
    );

    CREATE TABLE IF NOT EXISTS vehicles (
        vehicle_id INTEGER PRIMARY KEY AUTOINCREMENT,
        vendor_id INTEGER NOT NULL,
        vehicle_type TEXT NOT NULL
            CHECK (vehicle_type IN ('MOTORCYCLE', 'CAR')),
        brand TEXT NOT NULL,
        model TEXT NOT NULL,
        segment TEXT NOT NULL,
        price_per_day REAL NOT NULL CHECK (price_per_day >= 0),
        location TEXT NOT NULL,
        image_path TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'ACTIVE'
            CHECK (status IN ('ACTIVE', 'INACTIVE')),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (vendor_id) REFERENCES vendors(vendor_id)
    );

    CREATE TABLE IF NOT EXISTS bookings (
        booking_id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER NOT NULL,
        vehicle_id INTEGER NOT NULL,
        pickup_datetime TEXT NOT NULL,
        return_datetime TEXT NOT NULL,
        total_price REAL NOT NULL CHECK (total_price >= 0),
        status TEXT NOT NULL DEFAULT 'PENDING'
            CHECK (status IN (
                'PENDING', 'CONFIRMED', 'REJECTED',
                'EXPIRED', 'CANCELLED', 'ACTIVE', 'COMPLETED'
            )),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (customer_id) REFERENCES users(user_id),
        FOREIGN KEY (vehicle_id) REFERENCES vehicles(vehicle_id),
        CHECK (return_datetime > pickup_datetime)
    );
`);

// Safely add user_id to existing databases.
const applicationColumns = db
    .prepare("PRAGMA table_info(vendor_applications)")
    .all()
    .map(column => column.name);

if (!applicationColumns.includes("user_id")) {
    db.exec(`
        ALTER TABLE vendor_applications
        ADD COLUMN user_id INTEGER REFERENCES users(user_id)
    `);
}

module.exports = db;
