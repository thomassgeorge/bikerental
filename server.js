const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const db = require("./database.js");

const app = express();
const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, "public");
const IMAGE_DIR = path.join(PUBLIC_DIR, "images");

if (!fs.existsSync(IMAGE_DIR)) {
    fs.mkdirSync(IMAGE_DIR, { recursive: true });
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));

app.use(
    session({
        name: "bikerental.sid",
        secret: process.env.SESSION_SECRET || "local-development-secret-change-before-deploying",
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            sameSite: "lax",
            secure: process.env.NODE_ENV === "production",
            maxAge: 1000 * 60 * 60 * 8
        }
    })
);

// --------------------------------------------------
// DATABASE INDEXES
// --------------------------------------------------

try {
    db.exec(`
        CREATE INDEX IF NOT EXISTS idx_vehicles_vendor
        ON vehicles(vendor_id);

        CREATE INDEX IF NOT EXISTS idx_vehicles_status
        ON vehicles(status);

        CREATE INDEX IF NOT EXISTS idx_bookings_customer
        ON bookings(customer_id);

        CREATE INDEX IF NOT EXISTS idx_bookings_vehicle
        ON bookings(vehicle_id);
    `);
} catch (error) {
    console.error("Database index setup warning:", error.message);
}

// --------------------------------------------------
// DEVELOPMENT ADMIN ACCOUNT
// --------------------------------------------------

try {
    const adminEmail = "admin@bikerental.local";
    const existingAdmin = db.prepare(
        "SELECT user_id FROM users WHERE email = ?"
    ).get(adminEmail);

    if (!existingAdmin) {
        const hash = bcrypt.hashSync("ChangeMe123!", 10);

        db.prepare(`
            INSERT INTO users (name, email, password_hash, role)
            VALUES (?, ?, ?, ?)
        `).run("Development Admin", adminEmail, hash, "ADMIN");

        console.log("Development admin created:");
        console.log("Email: admin@bikerental.local");
        console.log("Password: ChangeMe123!");
    }
} catch (error) {
    console.error("Admin initialization warning:", error.message);
}

// --------------------------------------------------
// AUTHENTICATION HELPERS
// --------------------------------------------------

function requireAuth(req, res, next) {
    if (!req.session || !req.session.user) {
        return res.status(401).json({
            error: "Please sign in to continue."
        });
    }

    next();
}

function requireAdmin(req, res, next) {
    if (!req.session || !req.session.user) {
        return res.status(401).json({
            error: "Please sign in to continue."
        });
    }

    if (String(req.session.user.role).toUpperCase() !== "ADMIN") {
        return res.status(403).json({
            error: "Administrator access required."
        });
    }

    next();
}

function requireVendor(req, res, next) {
    if (!req.session || !req.session.user) {
        return res.status(401).json({
            error: "Please sign in to continue."
        });
    }

    const role = String(req.session.user.role || "").toUpperCase();

    if (role !== "VENDOR") {
        return res.status(403).json({
            error: "Vendor access required."
        });
    }

    const vendor = db.prepare(`
        SELECT vendor_id, user_id, business_name, location, status
        FROM vendors
        WHERE user_id = ?
    `).get(req.session.user.user_id);

    if (!vendor) {
        return res.status(403).json({
            error: "No vendor profile is linked to this account."
        });
    }

    if (vendor.status && String(vendor.status).toUpperCase() !== "ACTIVE") {
        return res.status(403).json({
            error: "Your vendor account is not active."
        });
    }

    req.vendor = vendor;
    req.vendorId = vendor.vendor_id;

    next();
}

function requireCustomer(req, res, next) {
    if (!req.session || !req.session.user) {
        return res.status(401).json({
            error: "Please sign in to continue."
        });
    }

    if (String(req.session.user.role).toUpperCase() !== "CUSTOMER") {
        return res.status(403).json({
            error: "Customer access required."
        });
    }

    next();
}

function getPublicUser(user) {
    if (!user) return null;

    return {
        user_id: user.user_id,
        name: user.name,
        email: user.email,
        phone: user.phone || null,
        role: user.role
    };
}

function normalizeDate(value) {
    if (!value) return null;

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) return null;

    return date.toISOString();
}

function isValidDateRange(start, end) {
    const startDate = new Date(start);
    const endDate = new Date(end);

    return (
        !Number.isNaN(startDate.getTime()) &&
        !Number.isNaN(endDate.getTime()) &&
        endDate > startDate
    );
}

function generateReference() {
    return crypto.randomBytes(6).toString("hex").toUpperCase();
}

// --------------------------------------------------
// HEALTH CHECK
// --------------------------------------------------

app.get("/api/health", (req, res) => {
    res.json({
        status: "ok",
        message: "MOTORENT server is running."
    });
});

// --------------------------------------------------
// AUTH: CURRENT SESSION
// --------------------------------------------------

app.get("/api/auth/me", (req, res) => {
    if (!req.session || !req.session.user) {
        return res.json({
            user: null
        });
    }

    const user = db.prepare(`
        SELECT user_id, name, email, phone, role
        FROM users
        WHERE user_id = ?
    `).get(req.session.user.user_id);

    if (!user) {
        req.session.destroy(() => {});
        return res.json({
            user: null
        });
    }

    const role = String(user.role || "").toUpperCase();

    if (role === "VENDOR") {
        const vendor = db.prepare(`
            SELECT vendor_id, business_name, location, status
            FROM vendors
            WHERE user_id = ?
        `).get(user.user_id);

        if (!vendor || (vendor.status && String(vendor.status).toUpperCase() !== "ACTIVE")) {
            user.role = "CUSTOMER";
            db.prepare(`
                UPDATE users SET role = 'CUSTOMER'
                WHERE user_id = ?
            `).run(user.user_id);

            req.session.user.role = "CUSTOMER";
        }
    }

    req.session.user = getPublicUser(user);

    res.json({
        user: req.session.user
    });
});

// --------------------------------------------------
// AUTH: REGISTER
// --------------------------------------------------

app.post("/api/auth/register", (req, res) => {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const phone = String(req.body.phone || "").trim();

    if (!name || !email || !password) {
        return res.status(400).json({
            error: "Name, email and password are required."
        });
    }

    if (password.length < 8) {
        return res.status(400).json({
            error: "Password must contain at least 8 characters."
        });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({
            error: "Please enter a valid email address."
        });
    }

    const existing = db.prepare(`
        SELECT user_id FROM users WHERE email = ?
    `).get(email);

    if (existing) {
        return res.status(409).json({
            error: "An account with this email already exists."
        });
    }

    const passwordHash = bcrypt.hashSync(password, 10);

    try {
        const result = db.prepare(`
            INSERT INTO users (name, email, password_hash, phone, role)
            VALUES (?, ?, ?, ?, 'CUSTOMER')
        `).run(name, email, passwordHash, phone || null);

        const user = db.prepare(`
            SELECT user_id, name, email, phone, role
            FROM users
            WHERE user_id = ?
        `).get(result.lastInsertRowid);

        req.session.user = getPublicUser(user);

        res.status(201).json({
            message: "Account created successfully.",
            user: req.session.user
        });
    } catch (error) {
        console.error("Registration error:", error);

        res.status(500).json({
            error: "Unable to create the account."
        });
    }
});

// --------------------------------------------------
// AUTH: LOGIN
// --------------------------------------------------

app.post("/api/auth/login", (req, res) => {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!email || !password) {
        return res.status(400).json({
            error: "Email and password are required."
        });
    }

    const user = db.prepare(`
        SELECT user_id, name, email, phone, password_hash, role
        FROM users
        WHERE email = ?
    `).get(email);

    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
        return res.status(401).json({
            error: "Incorrect email or password."
        });
    }

    const role = String(user.role || "").toUpperCase();

    if (role === "VENDOR") {
        const vendor = db.prepare(`
            SELECT vendor_id, status
            FROM vendors
            WHERE user_id = ?
        `).get(user.user_id);

        if (!vendor || (vendor.status && String(vendor.status).toUpperCase() !== "ACTIVE")) {
            return res.status(403).json({
                error: "Your vendor account is not active yet."
            });
        }
    }

    req.session.user = getPublicUser(user);

    res.json({
        message: "Login successful.",
        user: req.session.user
    });
});

// --------------------------------------------------
// AUTH: LOGOUT
// --------------------------------------------------

app.post("/api/auth/logout", (req, res) => {
    if (!req.session) {
        return res.json({
            message: "Signed out."
        });
    }

    req.session.destroy(error => {
        if (error) {
            return res.status(500).json({
                error: "Unable to sign out."
            });
        }

        res.clearCookie("bikerental.sid");

        res.json({
            message: "Signed out successfully."
        });
    });
});

// --------------------------------------------------
// VENDOR APPLICATION: SUBMIT
// --------------------------------------------------

app.post("/api/vendor-applications", requireAuth, (req, res) => {
    const userId = req.session.user.user_id;

    const user = db.prepare(`
        SELECT user_id, name, email, phone, role
        FROM users
        WHERE user_id = ?
    `).get(userId);

    if (!user) {
        return res.status(404).json({
            error: "User account not found."
        });
    }

    if (String(user.role).toUpperCase() === "ADMIN") {
        return res.status(403).json({
            error: "Administrator accounts cannot apply as vendors."
        });
    }

    const existingVendor = db.prepare(`
        SELECT vendor_id FROM vendors WHERE user_id = ?
    `).get(userId);

    if (existingVendor) {
        return res.status(409).json({
            error: "A vendor profile already exists for this account."
        });
    }

    const existingApplication = db.prepare(`
        SELECT application_id, status
        FROM vendor_applications
        WHERE user_id = ?
        ORDER BY application_id DESC
        LIMIT 1
    `).get(userId);

    if (existingApplication && String(existingApplication.status).toUpperCase() === "PENDING") {
        return res.status(409).json({
            error: "Your vendor application is already pending."
        });
    }

    if (existingApplication && String(existingApplication.status).toUpperCase() === "APPROVED") {
        return res.status(409).json({
            error: "Your vendor application has already been approved."
        });
    }

    try {
        const result = db.prepare(`
            INSERT INTO vendor_applications
                (user_id, name, email, phone, status, created_at)
            VALUES (?, ?, ?, ?, 'PENDING', CURRENT_TIMESTAMP)
        `).run(
            userId,
            user.name,
            user.email,
            user.phone || null
        );

        res.status(201).json({
            message: "Vendor application submitted.",
            application_id: result.lastInsertRowid,
            status: "PENDING"
        });
    } catch (error) {
        console.error("Vendor application error:", error);

        res.status(500).json({
            error: "Unable to submit your vendor application."
        });
    }
});

// --------------------------------------------------
// VENDOR APPLICATION: STATUS FOR CURRENT USER
// --------------------------------------------------

app.get("/api/vendor-application-status", requireAuth, (req, res) => {
    const userId = req.session.user.user_id;

    const vendor = db.prepare(`
        SELECT vendor_id, business_name, location, status
        FROM vendors
        WHERE user_id = ?
    `).get(userId);

    const application = db.prepare(`
        SELECT *
        FROM vendor_applications
        WHERE user_id = ?
        ORDER BY application_id DESC
        LIMIT 1
    `).get(userId);

    res.json({
        isVendor: Boolean(vendor),
        vendor: vendor || null,
        application: application || null
    });
});

// --------------------------------------------------
// ADMIN: LIST VENDOR APPLICATIONS
// --------------------------------------------------

app.get("/api/admin/vendor-applications", requireAdmin, (req, res) => {
    const applications = db.prepare(`
        SELECT
            va.*,
            u.name AS account_name,
            u.email AS account_email,
            u.phone AS account_phone
        FROM vendor_applications va
        LEFT JOIN users u ON u.user_id = va.user_id
        ORDER BY
            CASE WHEN UPPER(va.status) = 'PENDING' THEN 0 ELSE 1 END,
            va.application_id DESC
    `).all();

    res.json(applications);
});

// --------------------------------------------------
// ADMIN: APPROVE VENDOR APPLICATION
// --------------------------------------------------

app.post("/api/admin/vendor-applications/:id/approve", requireAdmin, (req, res) => {
    const applicationId = Number(req.params.id);
    const businessName = String(req.body.business_name || req.body.businessName || "").trim();
    const location = String(req.body.location || "").trim();

    if (!Number.isSafeInteger(applicationId) || applicationId < 1) {
        return res.status(400).json({
            error: "Invalid application ID."
        });
    }

    if (!businessName || !location) {
        return res.status(400).json({
            error: "Business name and location are required."
        });
    }

    const application = db.prepare(`
        SELECT * FROM vendor_applications
        WHERE application_id = ?
    `).get(applicationId);

    if (!application) {
        return res.status(404).json({
            error: "Vendor application not found."
        });
    }

    if (String(application.status).toUpperCase() !== "PENDING") {
        return res.status(409).json({
            error: "This application has already been reviewed."
        });
    }

    let userId = application.user_id;

    if (!userId) {
        const user = db.prepare(`
            SELECT user_id FROM users WHERE email = ?
        `).get(String(application.email || "").trim().toLowerCase());

        if (!user) {
            return res.status(400).json({
                error: "No account is linked to this application. The applicant must create an account first."
            });
        }

        userId = user.user_id;
    }

    const user = db.prepare(`
        SELECT user_id, role FROM users WHERE user_id = ?
    `).get(userId);

    if (!user) {
        return res.status(404).json({
            error: "Applicant account not found."
        });
    }

    try {
        const approve = db.transaction(() => {
            const existingVendor = db.prepare(`
                SELECT vendor_id FROM vendors WHERE user_id = ?
            `).get(userId);

            if (existingVendor) {
                db.prepare(`
                    UPDATE users SET role = 'VENDOR'
                    WHERE user_id = ?
                `).run(userId);

                db.prepare(`
                    UPDATE vendor_applications
                    SET status = 'APPROVED',
                        reviewed_at = CURRENT_TIMESTAMP
                    WHERE application_id = ?
                `).run(applicationId);

                return existingVendor.vendor_id;
            }

            const result = db.prepare(`
                INSERT INTO vendors
                    (user_id, business_name, location, status)
                VALUES (?, ?, ?, 'ACTIVE')
            `).run(userId, businessName, location);

            db.prepare(`
                UPDATE users SET role = 'VENDOR'
                WHERE user_id = ?
            `).run(userId);

            db.prepare(`
                UPDATE vendor_applications
                SET status = 'APPROVED',
                    reviewed_at = CURRENT_TIMESTAMP
                WHERE application_id = ?
            `).run(applicationId);

            return result.lastInsertRowid;
        });

        const vendorId = approve();

        res.json({
            message: "Vendor application approved.",
            vendor_id: vendorId
        });
    } catch (error) {
        console.error("Vendor approval error:", error);

        res.status(500).json({
            error: "Unable to approve the vendor application."
        });
    }
});

// --------------------------------------------------
// ADMIN: REJECT VENDOR APPLICATION
// --------------------------------------------------

app.post("/api/admin/vendor-applications/:id/reject", requireAdmin, (req, res) => {
    const applicationId = Number(req.params.id);

    if (!Number.isSafeInteger(applicationId) || applicationId < 1) {
        return res.status(400).json({
            error: "Invalid application ID."
        });
    }

    const application = db.prepare(`
        SELECT application_id, status
        FROM vendor_applications
        WHERE application_id = ?
    `).get(applicationId);

    if (!application) {
        return res.status(404).json({
            error: "Vendor application not found."
        });
    }

    if (String(application.status).toUpperCase() !== "PENDING") {
        return res.status(409).json({
            error: "This application has already been reviewed."
        });
    }

    db.prepare(`
        UPDATE vendor_applications
        SET status = 'REJECTED',
            reviewed_at = CURRENT_TIMESTAMP
        WHERE application_id = ?
    `).run(applicationId);

    res.json({
        message: "Vendor application rejected."
    });
});

// --------------------------------------------------
// PUBLIC: LIST ACTIVE VEHICLES
// --------------------------------------------------

app.get("/api/vehicles", (req, res) => {
    const vehicles = db.prepare(`
        SELECT
            v.*,
            ven.business_name,
            ven.location AS vendor_location
        FROM vehicles v
        LEFT JOIN vendors ven ON ven.vendor_id = v.vendor_id
        WHERE UPPER(COALESCE(v.status, 'ACTIVE')) = 'ACTIVE'
          AND (ven.status IS NULL OR UPPER(ven.status) = 'ACTIVE')
        ORDER BY v.vehicle_id DESC
    `).all();

    res.json(vehicles);
});

// --------------------------------------------------
// PUBLIC: VEHICLE DETAILS
// --------------------------------------------------

app.get("/api/vehicles/:id", (req, res) => {
    const id = Number(req.params.id);

    if (!Number.isSafeInteger(id) || id < 1) {
        return res.status(400).json({
            error: "Invalid vehicle ID."
        });
    }

    const vehicle = db.prepare(`
        SELECT
            v.*,
            ven.business_name,
            ven.location AS vendor_location
        FROM vehicles v
        LEFT JOIN vendors ven ON ven.vendor_id = v.vendor_id
        WHERE v.vehicle_id = ?
          AND UPPER(COALESCE(v.status, 'ACTIVE')) = 'ACTIVE'
    `).get(id);

    if (!vehicle) {
        return res.status(404).json({
            error: "Vehicle not found."
        });
    }

    res.json(vehicle);
});

// --------------------------------------------------
// VENDOR: LIST OWN VEHICLES
// --------------------------------------------------

app.get("/api/vendor/vehicles", requireAuth, requireVendor, (req, res) => {
    const vehicles = db.prepare(`
        SELECT *
        FROM vehicles
        WHERE vendor_id = ?
        ORDER BY vehicle_id DESC
    `).all(req.vendorId);

    res.json(vehicles);
});

// --------------------------------------------------
// VENDOR: ADD VEHICLE
// --------------------------------------------------

const storage = multer.diskStorage({
    destination: (req, file, callback) => {
        callback(null, IMAGE_DIR);
    },
    filename: (req, file, callback) => {
        const extension = path.extname(file.originalname).toLowerCase();
        const safeExtension = /^\.(jpg|jpeg|png|webp|gif)$/.test(extension)
            ? extension
            : ".jpg";

        callback(null, `${Date.now()}-${crypto.randomBytes(5).toString("hex")}${safeExtension}`);
    }
});

const upload = multer({
    storage,
    limits: {
        fileSize: 5 * 1024 * 1024
    },
    fileFilter: (req, file, callback) => {
        const allowed = ["image/jpeg", "image/png", "image/webp", "image/gif"];

        if (!allowed.includes(file.mimetype)) {
            return callback(new Error("Only JPG, PNG, WEBP or GIF images are allowed."));
        }

        callback(null, true);
    }
});

app.post(
    "/api/vendor/vehicles",
    requireAuth,
    requireVendor,
    upload.single("image"),
    (req, res) => {
        const brand = String(req.body.brand || "").trim();
        const model = String(req.body.model || "").trim();
        const vehicleType = String(req.body.vehicle_type || req.body.type || "").trim().toUpperCase();
        const segment = String(req.body.segment || "").trim();
        const price = Number(req.body.price_per_day || req.body.price);
        const location = String(req.body.location || req.vendor.location || "").trim();

        if (!brand || !model || !vehicleType || !segment || !location || !Number.isFinite(price) || price <= 0) {
            if (req.file) fs.unlink(req.file.path, () => {});

            return res.status(400).json({
                error: "Brand, model, type, category, price and location are required."
            });
        }

        if (!["CAR", "MOTORCYCLE"].includes(vehicleType)) {
            if (req.file) fs.unlink(req.file.path, () => {});

            return res.status(400).json({
                error: "Vehicle type must be CAR or MOTORCYCLE."
            });
        }

        const imagePath = req.file ? `images/${req.file.filename}` : null;

        try {
            const result = db.prepare(`
                INSERT INTO vehicles
                    (vendor_id, brand, model, vehicle_type, segment,
                     price_per_day, location, image_path, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE')
            `).run(
                req.vendorId,
                brand,
                model,
                vehicleType,
                segment,
                price,
                location,
                imagePath
            );

            res.status(201).json({
                message: "Vehicle listed successfully.",
                vehicle_id: result.lastInsertRowid
            });
        } catch (error) {
            if (req.file) fs.unlink(req.file.path, () => {});
            console.error("Add vehicle error:", error);

            res.status(500).json({
                error: "Unable to add the vehicle."
            });
        }
    }
);

// --------------------------------------------------
// VENDOR: EDIT VEHICLE
// --------------------------------------------------

app.put(
    "/api/vendor/vehicles/:id",
    requireAuth,
    requireVendor,
    upload.single("image"),
    (req, res) => {
        const id = Number(req.params.id);

        if (!Number.isSafeInteger(id) || id < 1) {
            if (req.file) fs.unlink(req.file.path, () => {});

            return res.status(400).json({
                error: "Invalid vehicle ID."
            });
        }

        const existing = db.prepare(`
            SELECT *
            FROM vehicles
            WHERE vehicle_id = ? AND vendor_id = ?
        `).get(id, req.vendorId);

        if (!existing) {
            if (req.file) fs.unlink(req.file.path, () => {});

            return res.status(404).json({
                error: "Vehicle not found."
            });
        }

        const brand = String(req.body.brand ?? existing.brand).trim();
        const model = String(req.body.model ?? existing.model).trim();
        const vehicleType = String(req.body.vehicle_type ?? req.body.type ?? existing.vehicle_type).trim().toUpperCase();
        const segment = String(req.body.segment ?? existing.segment).trim();
        const price = Number(req.body.price_per_day ?? req.body.price ?? existing.price_per_day);
        const location = String(req.body.location ?? existing.location).trim();

        if (!brand || !model || !segment || !location || !Number.isFinite(price) || price <= 0) {
            if (req.file) fs.unlink(req.file.path, () => {});

            return res.status(400).json({
                error: "Please provide valid vehicle details."
            });
        }

        if (!["CAR", "MOTORCYCLE"].includes(vehicleType)) {
            if (req.file) fs.unlink(req.file.path, () => {});

            return res.status(400).json({
                error: "Vehicle type must be CAR or MOTORCYCLE."
            });
        }

        const imagePath = req.file
            ? `images/${req.file.filename}`
            : existing.image_path;

        try {
            db.prepare(`
                UPDATE vehicles
                SET brand = ?,
                    model = ?,
                    vehicle_type = ?,
                    segment = ?,
                    price_per_day = ?,
                    location = ?,
                    image_path = ?
                WHERE vehicle_id = ?
                  AND vendor_id = ?
            `).run(
                brand,
                model,
                vehicleType,
                segment,
                price,
                location,
                imagePath,
                id,
                req.vendorId
            );

            res.json({
                message: "Vehicle updated successfully."
            });
        } catch (error) {
            if (req.file) fs.unlink(req.file.path, () => {});
            console.error("Edit vehicle error:", error);

            res.status(500).json({
                error: "Unable to update the vehicle."
            });
        }
    }
);

// --------------------------------------------------
// VENDOR: REACTIVATE INACTIVE VEHICLE
// --------------------------------------------------

app.patch(
    "/api/vendor/vehicles/:id/activate",
    requireAuth,
    requireVendor,
    (req, res) => {
        const id = Number(req.params.id);

        if (!Number.isSafeInteger(id) || id < 1) {
            return res.status(400).json({
                error: "Invalid vehicle ID."
            });
        }

        const result = db.prepare(`
            UPDATE vehicles
            SET status = 'ACTIVE'
            WHERE vehicle_id = ?
              AND vendor_id = ?
              AND status = 'INACTIVE'
        `).run(id, req.vendorId);

        if (!result.changes) {
            return res.status(404).json({
                error: "Inactive vehicle listing not found."
            });
        }

        res.json({
            message: "Vehicle listing reactivated."
        });
    }
);

// --------------------------------------------------
// VENDOR: DEACTIVATE VEHICLE
// --------------------------------------------------

app.delete(
    "/api/vendor/vehicles/:id",
    requireAuth,
    requireVendor,
    (req, res) => {
        const id = Number(req.params.id);

        if (!Number.isSafeInteger(id) || id < 1) {
            return res.status(400).json({
                error: "Invalid vehicle ID."
            });
        }

        const vehicle = db.prepare(`
            SELECT vehicle_id, status
            FROM vehicles
            WHERE vehicle_id = ? AND vendor_id = ?
        `).get(id, req.vendorId);

        if (!vehicle) {
            return res.status(404).json({
                error: "Vehicle not found."
            });
        }

        db.prepare(`
            UPDATE vehicles
            SET status = 'INACTIVE'
            WHERE vehicle_id = ? AND vendor_id = ?
        `).run(id, req.vendorId);

        res.json({
            message: "Vehicle listing deactivated."
        });
    }
);

// --------------------------------------------------
// CUSTOMER: CREATE BOOKING
// --------------------------------------------------

app.post("/api/bookings", requireAuth, requireCustomer, (req, res) => {
    const vehicleId = Number(req.body.vehicle_id);
    const pickup = normalizeDate(req.body.pickup_datetime || req.body.pickup_date);
    const returned = normalizeDate(req.body.return_datetime || req.body.return_date);

    if (!Number.isSafeInteger(vehicleId) || vehicleId < 1) {
        return res.status(400).json({
            error: "Invalid vehicle."
        });
    }

    if (!pickup || !returned || !isValidDateRange(pickup, returned)) {
        return res.status(400).json({
            error: "Please choose valid pickup and return dates."
        });
    }

    const vehicle = db.prepare(`
        SELECT vehicle_id, vendor_id, price_per_day, status
        FROM vehicles
        WHERE vehicle_id = ?
    `).get(vehicleId);

    if (!vehicle || String(vehicle.status || "ACTIVE").toUpperCase() !== "ACTIVE") {
        return res.status(404).json({
            error: "This vehicle is not available for booking."
        });
    }

    const vendor = db.prepare(`
        SELECT status FROM vendors WHERE vendor_id = ?
    `).get(vehicle.vendor_id);

    if (vendor && vendor.status && String(vendor.status).toUpperCase() !== "ACTIVE") {
        return res.status(404).json({
            error: "This vehicle is not available for booking."
        });
    }

    const overlapping = db.prepare(`
        SELECT booking_id
        FROM bookings
        WHERE vehicle_id = ?
          AND UPPER(status) IN ('PENDING', 'CONFIRMED', 'ACCEPTED')
          AND pickup_datetime < ?
          AND return_datetime > ?
    `).get(vehicleId, returned, pickup);

    if (overlapping) {
        return res.status(409).json({
            error: "This vehicle already has a booking request for those dates."
        });
    }

    const startTime = new Date(pickup).getTime();
    const endTime = new Date(returned).getTime();
    const days = Math.max(1, Math.ceil((endTime - startTime) / (1000 * 60 * 60 * 24)));
    const totalPrice = days * Number(vehicle.price_per_day);

    try {
        const result = db.prepare(`
            INSERT INTO bookings
                (customer_id, vehicle_id, pickup_datetime, return_datetime,
                 total_price, status, created_at)
            VALUES (?, ?, ?, ?, ?, 'PENDING', CURRENT_TIMESTAMP)
        `).run(
            req.session.user.user_id,
            vehicleId,
            pickup,
            returned,
            totalPrice
        );

        res.status(201).json({
            message: "Booking request submitted.",
            booking_id: result.lastInsertRowid,
            total_price: totalPrice,
            status: "PENDING"
        });
    } catch (error) {
        console.error("Booking creation error:", error);

        res.status(500).json({
            error: "Unable to create the booking request."
        });
    }
});

// --------------------------------------------------
// CUSTOMER: MY BOOKINGS
// --------------------------------------------------

app.get("/api/my-bookings", requireAuth, requireCustomer, (req, res) => {
    const bookings = db.prepare(`
        SELECT
            b.*,
            v.brand,
            v.model,
            v.vehicle_type,
            v.segment,
            v.image_path,
            v.location,
            v.price_per_day,
            ven.business_name
        FROM bookings b
        JOIN vehicles v ON v.vehicle_id = b.vehicle_id
        LEFT JOIN vendors ven ON ven.vendor_id = v.vendor_id
        WHERE b.customer_id = ?
        ORDER BY b.created_at DESC, b.booking_id DESC
    `).all(req.session.user.user_id);

    res.json(bookings);
});

// --------------------------------------------------
// CUSTOMER: CANCEL BOOKING
// --------------------------------------------------

app.post("/api/bookings/:id/cancel", requireAuth, requireCustomer, (req, res) => {
    const id = Number(req.params.id);

    if (!Number.isSafeInteger(id) || id < 1) {
        return res.status(400).json({
            error: "Invalid booking ID."
        });
    }

    const booking = db.prepare(`
        SELECT booking_id, status
        FROM bookings
        WHERE booking_id = ? AND customer_id = ?
    `).get(id, req.session.user.user_id);

    if (!booking) {
        return res.status(404).json({
            error: "Booking not found."
        });
    }

    if (!["PENDING", "CONFIRMED", "ACCEPTED"].includes(String(booking.status).toUpperCase())) {
        return res.status(409).json({
            error: "This booking cannot be cancelled."
        });
    }

    db.prepare(`
        UPDATE bookings
        SET status = 'CANCELLED'
        WHERE booking_id = ? AND customer_id = ?
    `).run(id, req.session.user.user_id);

    res.json({
        message: "Booking cancelled."
    });
});

// --------------------------------------------------
// VENDOR: VIEW BOOKINGS
// --------------------------------------------------

app.get("/api/vendor/bookings", requireAuth, requireVendor, (req, res) => {
    const bookings = db.prepare(`
        SELECT
            b.*,
            v.brand,
            v.model,
            v.vehicle_type,
            v.segment,
            v.image_path,
            u.name AS customer_name,
            u.email AS customer_email,
            u.phone AS customer_phone
        FROM bookings b
        JOIN vehicles v ON v.vehicle_id = b.vehicle_id
        JOIN users u ON u.user_id = b.customer_id
        WHERE v.vendor_id = ?
        ORDER BY b.created_at DESC, b.booking_id DESC
    `).all(req.vendorId);

    res.json(bookings);
});

// --------------------------------------------------
// VENDOR: ACCEPT OR REJECT BOOKING
// --------------------------------------------------

app.post("/api/vendor/bookings/:id/respond", requireAuth, requireVendor, (req, res) => {
    const id = Number(req.params.id);
    const decision = String(req.body.status || req.body.action || "").trim().toUpperCase();

    if (!Number.isSafeInteger(id) || id < 1) {
        return res.status(400).json({
            error: "Invalid booking ID."
        });
    }

    if (!["ACCEPTED", "CONFIRMED", "REJECTED"].includes(decision)) {
        return res.status(400).json({
            error: "Response must be ACCEPTED or REJECTED."
        });
    }

    const booking = db.prepare(`
        SELECT b.booking_id, b.status, b.vehicle_id
        FROM bookings b
        JOIN vehicles v ON v.vehicle_id = b.vehicle_id
        WHERE b.booking_id = ?
          AND v.vendor_id = ?
    `).get(id, req.vendorId);

    if (!booking) {
        return res.status(404).json({
            error: "Booking not found."
        });
    }

    if (String(booking.status).toUpperCase() !== "PENDING") {
        return res.status(409).json({
            error: "This booking has already been reviewed."
        });
    }

    if (decision !== "REJECTED") {
        const overlap = db.prepare(`
            SELECT booking_id
            FROM bookings
            WHERE vehicle_id = ?
              AND booking_id != ?
              AND UPPER(status) IN ('CONFIRMED', 'ACCEPTED')
              AND pickup_datetime < (
                  SELECT return_datetime FROM bookings WHERE booking_id = ?
              )
              AND return_datetime > (
                  SELECT pickup_datetime FROM bookings WHERE booking_id = ?
              )
        `).get(booking.vehicle_id, id, id, id);

        if (overlap) {
            return res.status(409).json({
                error: "This vehicle has another confirmed booking during those dates."
            });
        }
    }

    const newStatus = decision === "REJECTED" ? "REJECTED" : "CONFIRMED";

    db.prepare(`
        UPDATE bookings
        SET status = ?
        WHERE booking_id = ?
    `).run(newStatus, id);

    res.json({
        message: `Booking ${newStatus.toLowerCase()}.`,
        status: newStatus
    });
});

// --------------------------------------------------
// ADMIN: VIEW ALL VEHICLES
// --------------------------------------------------

app.get("/api/admin/vehicles", requireAdmin, (req, res) => {
    const vehicles = db.prepare(`
        SELECT
            v.*,
            ven.business_name,
            ven.location AS vendor_location,
            u.name AS vendor_name,
            u.email AS vendor_email
        FROM vehicles v
        LEFT JOIN vendors ven ON ven.vendor_id = v.vendor_id
        LEFT JOIN users u ON u.user_id = ven.user_id
        ORDER BY v.vehicle_id DESC
    `).all();

    res.json(vehicles);
});

// --------------------------------------------------
// ADMIN: VIEW ALL BOOKINGS
// --------------------------------------------------

app.get("/api/admin/bookings", requireAdmin, (req, res) => {
    const bookings = db.prepare(`
        SELECT
            b.*,
            v.brand,
            v.model,
            v.vehicle_type,
            u.name AS customer_name,
            u.email AS customer_email,
            ven.business_name
        FROM bookings b
        JOIN vehicles v ON v.vehicle_id = b.vehicle_id
        JOIN users u ON u.user_id = b.customer_id
        LEFT JOIN vendors ven ON ven.vendor_id = v.vendor_id
        ORDER BY b.created_at DESC, b.booking_id DESC
    `).all();

    res.json(bookings);
});

// --------------------------------------------------
// ERROR HANDLER
// --------------------------------------------------

app.use((err, req, res, next) => {
    console.error("Server error:", err);

    if (err instanceof multer.MulterError) {
        if (err.code === "LIMIT_FILE_SIZE") {
            return res.status(400).json({
                error: "Image must be smaller than 5 MB."
            });
        }

        return res.status(400).json({
            error: err.message
        });
    }

    if (err.code === "SQLITE_CONSTRAINT_UNIQUE") {
        return res.status(409).json({
            error: "That email or record already exists."
        });
    }

    res.status(500).json({
        error: err.message
    });
});

// --------------------------------------------------
// START SERVER
// --------------------------------------------------

app.listen(PORT, () => {
    console.log(`Bike rental server running at http://localhost:${PORT}`);
    console.log(`Admin page: http://localhost:${PORT}/admin.html`);
});