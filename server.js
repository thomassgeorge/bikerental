const express = require("express");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { put } = require("@vercel/blob");
const db = require("./database.js");

const app = express();
app.set("trust proxy", 1);

const PORT = Number(process.env.PORT) || 3000;
const PUBLIC_DIR = path.join(__dirname, "public");
const IMAGE_DIR = path.join(PUBLIC_DIR, "images");

if (!fs.existsSync(IMAGE_DIR)) {
    fs.mkdirSync(IMAGE_DIR, { recursive: true });
}

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(express.static(PUBLIC_DIR));

// ---------------------------------------------------------------------------
// Serverless-compatible signed-cookie session middleware.
// Works seamlessly across all Vercel function instances and cold-starts
// without requiring in-memory state or external session store plugins.
// ---------------------------------------------------------------------------
const SESSION_SECRET = process.env.SESSION_SECRET || "motorent-session-secret-key-production-neon";
const SESSION_COOKIE = "bikerental.sid";

function signSession(data) {
    const json = JSON.stringify(data);
    const b64 = Buffer.from(json, "utf8").toString("base64url");
    const sig = crypto.createHmac("sha256", SESSION_SECRET).update(b64).digest("base64url");
    return `${b64}.${sig}`;
}

function verifySession(token) {
    if (!token || typeof token !== "string") return null;
    const dot = token.indexOf(".");
    if (dot <= 0) return null;
    const b64 = token.slice(0, dot);
    const sig = token.slice(dot + 1);
    if (!b64 || !sig) return null;
    const expectedSig = crypto.createHmac("sha256", SESSION_SECRET).update(b64).digest("base64url");
    const sigBuf = Buffer.from(sig);
    const expBuf = Buffer.from(expectedSig);
    if (sigBuf.length !== expBuf.length) return null;
    if (!crypto.timingSafeEqual(sigBuf, expBuf)) return null;
    try {
        const data = JSON.parse(Buffer.from(b64, "base64url").toString("utf8"));
        if (data.exp && Date.now() > data.exp) return null;
        return data;
    } catch {
        return null;
    }
}

function parseCookies(header) {
    const map = {};
    if (!header || typeof header !== "string") return map;
    const pairs = header.split(";");
    for (let i = 0; i < pairs.length; i++) {
        const pair = pairs[i].trim();
        const eq = pair.indexOf("=");
        if (eq > 0) {
            const key = pair.slice(0, eq).trim();
            const val = pair.slice(eq + 1).trim();
            map[key] = decodeURIComponent(val);
        }
    }
    return map;
}

app.use((req, res, next) => {
    const cookies = parseCookies(req.headers.cookie);
    let token = cookies[SESSION_COOKIE];
    if (!token && req.headers.authorization && req.headers.authorization.startsWith("Bearer ")) {
        token = req.headers.authorization.slice(7).trim();
    }
    const sessionData = verifySession(token);

    let sessionUser = sessionData ? sessionData.user : null;
    let currentToken = sessionData ? token : null;

    req.session = {
        get user() {
            return sessionUser;
        },
        set user(val) {
            sessionUser = val;
            if (val) {
                currentToken = signSession({
                    user: val,
                    exp: Date.now() + 1000 * 60 * 60 * 24 * 7 // 7 days
                });
                res.cookie(SESSION_COOKIE, currentToken, {
                    httpOnly: true,
                    sameSite: "lax",
                    secure: process.env.NODE_ENV === "production",
                    path: "/",
                    maxAge: 1000 * 60 * 60 * 24 * 7
                });
            } else {
                currentToken = null;
                res.clearCookie(SESSION_COOKIE, { path: "/" });
            }
        },
        get token() {
            if (currentToken) return currentToken;
            if (sessionUser) {
                currentToken = signSession({
                    user: sessionUser,
                    exp: Date.now() + 1000 * 60 * 60 * 24 * 7
                });
                return currentToken;
            }
            return null;
        },
        destroy(callback) {
            sessionUser = null;
            currentToken = null;
            res.clearCookie(SESSION_COOKIE, { path: "/" });
            if (typeof callback === "function") callback(null);
        }
    };

    next();
});

// ---------------------------------------------------------------------------
// Database readiness — initialise schema once per process (lazy singleton).
// On Vercel each cold-start triggers this; subsequent requests reuse the
// already-resolved promise so there is zero overhead per request after init.
// ---------------------------------------------------------------------------
let _dbReady = null;
function ensureDatabase() {
    if (!_dbReady) {
        _dbReady = db.initializeDatabase().catch((err) => {
            _dbReady = null; // allow retry on next request
            throw err;
        });
    }
    return _dbReady;
}

// Run DB init before every API request (static files bypass this).
app.use("/api", async (req, res, next) => {
    try {
        await ensureDatabase();
        next();
    } catch (err) {
        console.error("Database initialisation failed:", err);
        res.status(503).json({ error: "Service temporarily unavailable. Please retry in a moment." });
    }
});

function requireAuth(req, res, next) {
    if (!req.session || !req.session.user) {
        return res.status(401).json({ error: "Please sign in to continue." });
    }
    next();
}

function requireAdmin(req, res, next) {
    if (!req.session || !req.session.user) {
        return res.status(401).json({ error: "Please sign in to continue." });
    }

    if (String(req.session.user.role).toUpperCase() !== "ADMIN") {
        return res.status(403).json({ error: "Administrator access required." });
    }

    next();
}

function requireVendor(req, res, next) {
    if (!req.session || !req.session.user) {
        return res.status(401).json({ error: "Please sign in to continue." });
    }

    if (String(req.session.user.role).toUpperCase() !== "VENDOR") {
        return res.status(403).json({ error: "Vendor access required." });
    }

    next();
}

function requireCustomer(req, res, next) {
    if (!req.session || !req.session.user) {
        return res.status(401).json({ error: "Please sign in to continue." });
    }

    if (String(req.session.user.role).toUpperCase() !== "CUSTOMER") {
        return res.status(403).json({ error: "Customer access required." });
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
    return !Number.isNaN(startDate.getTime()) && !Number.isNaN(endDate.getTime()) && endDate > startDate;
}

function deleteLocalImageIfNeeded(imagePath) {
    if (!imagePath || imagePath.startsWith("http://") || imagePath.startsWith("https://")) {
        return;
    }

    if (!imagePath.startsWith("images/")) {
        return;
    }

    const targetPath = path.join(PUBLIC_DIR, imagePath);
    if (fs.existsSync(targetPath)) {
        fs.unlinkSync(targetPath);
    }
}

const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, callback) => {
        const allowed = ["image/jpeg", "image/png", "image/webp", "image/gif"];
        if (!allowed.includes(file.mimetype)) {
            return callback(new Error("Only JPG, PNG, WEBP or GIF images are allowed."));
        }
        callback(null, true);
    }
});

async function saveUploadedImage(file) {
    if (!file) {
        return null;
    }

    const extension = path.extname(file.originalname || "image.jpg").toLowerCase() || ".jpg";
    const safeExtension = [".jpg", ".jpeg", ".png", ".webp", ".gif"].includes(extension) ? extension : ".jpg";

    if (process.env.BLOB_READ_WRITE_TOKEN) {
        const result = await put(`vehicles/${Date.now()}-${crypto.randomBytes(8).toString("hex")}${safeExtension}`, file.buffer, {
            access: "public",
            contentType: file.mimetype,
            addRandomSuffix: false
        });
        return result.url;
    }

    const fileName = `${Date.now()}-${crypto.randomBytes(5).toString("hex")}${safeExtension}`;
    const destination = path.join(IMAGE_DIR, fileName);
    fs.writeFileSync(destination, file.buffer);
    return `images/${fileName}`;
}

async function ensureVendorProfile(userId) {
    const vendor = await db.get(
        `SELECT vendor_id, user_id, business_name, location, status
         FROM vendors
         WHERE user_id = $1`,
        [userId]
    );

    if (!vendor) {
        return null;
    }

    if (vendor.status && String(vendor.status).toUpperCase() !== "ACTIVE") {
        return null;
    }

    return vendor;
}

app.get(["/api/health", "/health"], async (req, res) => {
    try {
        await db.get("SELECT 1 AS ok");
        res.json({ status: "ok", message: "MOTORENT server is running." });
    } catch (error) {
        console.error("Health check failed:", error);
        res.status(500).json({ status: "error", message: "Database check failed." });
    }
});

app.get("/", (req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

app.get("/api/auth/me", async (req, res) => {
    if (!req.session || !req.session.user) {
        return res.json({ user: null });
    }

    const user = await db.get(
        `SELECT user_id, name, email, phone, role FROM users WHERE user_id = $1`,
        [req.session.user.user_id]
    );

    if (!user) {
        req.session.destroy(() => {});
        return res.json({ user: null });
    }

    if (String(user.role).toUpperCase() === "VENDOR") {
        const vendor = await db.get(
            `SELECT vendor_id, business_name, location, status FROM vendors WHERE user_id = $1`,
            [user.user_id]
        );

        if (!vendor || (vendor.status && String(vendor.status).toUpperCase() !== "ACTIVE")) {
            await db.run(`UPDATE users SET role = 'CUSTOMER' WHERE user_id = $1`, [user.user_id]);
            user.role = "CUSTOMER";
            req.session.user.role = "CUSTOMER";
        }
    }

    req.session.user = getPublicUser(user);
    res.json({ user: req.session.user, token: req.session.token });
});

app.post("/api/auth/register", async (req, res) => {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const phone = String(req.body.phone || "").trim();

    if (!name || !email || !password) {
        return res.status(400).json({ error: "Name, email and password are required." });
    }

    if (password.length < 8) {
        return res.status(400).json({ error: "Password must contain at least 8 characters." });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ error: "Please enter a valid email address." });
    }

    const existing = await db.get(`SELECT user_id FROM users WHERE email = $1`, [email]);
    if (existing) {
        return res.status(409).json({ error: "An account with this email already exists." });
    }

    const passwordHash = bcrypt.hashSync(password, 10);

    try {
        const inserted = await db.get(
            `INSERT INTO users (name, email, password_hash, phone, role)
             VALUES ($1, $2, $3, $4, 'CUSTOMER')
             RETURNING user_id, name, email, phone, role`,
            [name, email, passwordHash, phone || null]
        );

        req.session.user = getPublicUser(inserted);
        res.status(201).json({ message: "Account created successfully.", user: req.session.user, token: req.session.token });
    } catch (error) {
        console.error("Registration error:", error);
        res.status(500).json({ error: "Unable to create the account." });
    }
});

app.post("/api/auth/login", async (req, res) => {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required." });
    }

    const user = await db.get(
        `SELECT user_id, name, email, phone, password_hash, role
         FROM users
         WHERE email = $1`,
        [email]
    );

    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
        return res.status(401).json({ error: "Incorrect email or password." });
    }

    if (String(user.role).toUpperCase() === "VENDOR") {
        const vendor = await db.get(
            `SELECT vendor_id, status FROM vendors WHERE user_id = $1`,
            [user.user_id]
        );

        if (!vendor || (vendor.status && String(vendor.status).toUpperCase() !== "ACTIVE")) {
            return res.status(403).json({ error: "Your vendor account is not active yet." });
        }
    }

    req.session.user = getPublicUser(user);
    res.json({ message: "Login successful.", user: req.session.user, token: req.session.token });
});

app.post("/api/auth/logout", (req, res) => {
    if (!req.session) {
        return res.json({ message: "Signed out." });
    }

    req.session.destroy((error) => {
        if (error) {
            return res.status(500).json({ error: "Unable to sign out." });
        }

        res.json({ message: "Signed out successfully." });
    });
});

app.post("/api/vendor-applications", requireAuth, async (req, res) => {
    const userId = req.session.user.user_id;
    const user = await db.get(
        `SELECT user_id, name, email, phone, role FROM users WHERE user_id = $1`,
        [userId]
    );

    if (!user) {
        return res.status(404).json({ error: "User account not found." });
    }

    if (String(user.role).toUpperCase() === "ADMIN") {
        return res.status(403).json({ error: "Administrator accounts cannot apply as vendors." });
    }

    const existingVendor = await db.get(`SELECT vendor_id FROM vendors WHERE user_id = $1`, [userId]);
    if (existingVendor) {
        return res.status(409).json({ error: "A vendor profile already exists for this account." });
    }

    const existingApplication = await db.get(
        `SELECT application_id, status FROM vendor_applications WHERE user_id = $1 ORDER BY application_id DESC LIMIT 1`,
        [userId]
    );

    if (existingApplication && String(existingApplication.status).toUpperCase() === "PENDING") {
        return res.status(409).json({ error: "Your vendor application is already pending." });
    }

    if (existingApplication && String(existingApplication.status).toUpperCase() === "APPROVED") {
        return res.status(409).json({ error: "Your vendor application has already been approved." });
    }

    try {
        const application = await db.get(
            `INSERT INTO vendor_applications (user_id, name, email, phone, status)
             VALUES ($1, $2, $3, $4, 'PENDING')
             RETURNING application_id, status`,
            [userId, user.name, user.email, user.phone || null]
        );

        res.status(201).json({
            message: "Vendor application submitted.",
            application_id: application.application_id,
            status: application.status
        });
    } catch (error) {
        console.error("Vendor application error:", error);
        res.status(500).json({ error: "Unable to submit your vendor application." });
    }
});

app.get("/api/vendor-application-status", requireAuth, async (req, res) => {
    const userId = req.session.user.user_id;
    const vendor = await db.get(
        `SELECT vendor_id, business_name, location, status FROM vendors WHERE user_id = $1`,
        [userId]
    );

    const application = await db.get(
        `SELECT * FROM vendor_applications WHERE user_id = $1 ORDER BY application_id DESC LIMIT 1`,
        [userId]
    );

    res.json({ isVendor: Boolean(vendor), vendor: vendor || null, application: application || null });
});

app.get("/api/admin/vendor-applications", requireAdmin, async (req, res) => {
    const applications = await db.query(
        `SELECT va.*, u.name AS account_name, u.email AS account_email, u.phone AS account_phone
         FROM vendor_applications va
         LEFT JOIN users u ON u.user_id = va.user_id
         ORDER BY CASE WHEN UPPER(va.status) = 'PENDING' THEN 0 ELSE 1 END, va.application_id DESC`
    );

    res.json(applications);
});

app.post("/api/admin/vendor-applications/:id/approve", requireAdmin, async (req, res) => {
    const applicationId = Number(req.params.id);
    const businessName = String(req.body.business_name || req.body.businessName || "").trim();
    const location = String(req.body.location || "").trim();

    if (!Number.isSafeInteger(applicationId) || applicationId < 1) {
        return res.status(400).json({ error: "Invalid application ID." });
    }

    if (!businessName || !location) {
        return res.status(400).json({ error: "Business name and location are required." });
    }

    const application = await db.get(`SELECT * FROM vendor_applications WHERE application_id = $1`, [applicationId]);
    if (!application) {
        return res.status(404).json({ error: "Vendor application not found." });
    }

    if (String(application.status).toUpperCase() !== "PENDING") {
        return res.status(409).json({ error: "This application has already been reviewed." });
    }

    let userId = application.user_id;
    if (!userId) {
        const user = await db.get(`SELECT user_id FROM users WHERE email = $1`, [String(application.email || "").trim().toLowerCase()]);
        if (!user) {
            return res.status(400).json({ error: "No account is linked to this application. The applicant must create an account first." });
        }
        userId = user.user_id;
    }

    const user = await db.get(`SELECT user_id, role FROM users WHERE user_id = $1`, [userId]);
    if (!user) {
        return res.status(404).json({ error: "Applicant account not found." });
    }

    try {
        const vendorId = await db.withTransaction(async (client) => {
            const existingVendorResult = await client.query(
                `SELECT vendor_id FROM vendors WHERE user_id = $1`,
                [userId]
            );

            if (existingVendorResult.rows[0]) {
                await client.query(`UPDATE users SET role = 'VENDOR' WHERE user_id = $1`, [userId]);
                await client.query(
                    `UPDATE vendor_applications SET status = 'APPROVED', reviewed_at = NOW() WHERE application_id = $1`,
                    [applicationId]
                );
                return existingVendorResult.rows[0].vendor_id;
            }

            const insertResult = await client.query(
                `INSERT INTO vendors (user_id, business_name, location, status)
                 VALUES ($1, $2, $3, 'ACTIVE')
                 RETURNING vendor_id`,
                [userId, businessName, location]
            );

            await client.query(`UPDATE users SET role = 'VENDOR' WHERE user_id = $1`, [userId]);
            if (req.body.password && String(req.body.password).trim().length >= 8) {
                const newHash = bcrypt.hashSync(String(req.body.password).trim(), 10);
                await client.query(`UPDATE users SET password_hash = $1 WHERE user_id = $2`, [newHash, userId]);
            }
            await client.query(
                `UPDATE vendor_applications SET status = 'APPROVED', reviewed_at = NOW() WHERE application_id = $1`,
                [applicationId]
            );

            return insertResult.rows[0].vendor_id;
        });

        res.json({ message: "Vendor application approved.", vendor_id: vendorId });
    } catch (error) {
        console.error("Vendor approval error:", error);
        res.status(500).json({ error: "Unable to approve the vendor application." });
    }
});

app.post("/api/admin/vendor-applications/:id/reject", requireAdmin, async (req, res) => {
    const applicationId = Number(req.params.id);

    if (!Number.isSafeInteger(applicationId) || applicationId < 1) {
        return res.status(400).json({ error: "Invalid application ID." });
    }

    const application = await db.get(
        `SELECT application_id, status FROM vendor_applications WHERE application_id = $1`,
        [applicationId]
    );

    if (!application) {
        return res.status(404).json({ error: "Vendor application not found." });
    }

    if (String(application.status).toUpperCase() !== "PENDING") {
        return res.status(409).json({ error: "This application has already been reviewed." });
    }

    await db.run(
        `UPDATE vendor_applications SET status = 'REJECTED', reviewed_at = NOW() WHERE application_id = $1`,
        [applicationId]
    );

    res.json({ message: "Vendor application rejected." });
});

app.get("/api/vehicles", async (req, res) => {
    const vehicles = await db.query(
        `SELECT v.*, ven.business_name, ven.location AS vendor_location
         FROM vehicles v
         LEFT JOIN vendors ven ON ven.vendor_id = v.vendor_id
         WHERE UPPER(COALESCE(v.status, 'ACTIVE')) = 'ACTIVE'
           AND (ven.status IS NULL OR UPPER(ven.status) = 'ACTIVE')
         ORDER BY v.vehicle_id DESC`
    );

    res.json(vehicles);
});

app.get("/api/vehicles/:id", async (req, res) => {
    const id = Number(req.params.id);

    if (!Number.isSafeInteger(id) || id < 1) {
        return res.status(400).json({ error: "Invalid vehicle ID." });
    }

    const vehicle = await db.get(
        `SELECT v.*, ven.business_name, ven.location AS vendor_location
         FROM vehicles v
         LEFT JOIN vendors ven ON ven.vendor_id = v.vendor_id
         WHERE v.vehicle_id = $1 AND UPPER(COALESCE(v.status, 'ACTIVE')) = 'ACTIVE'`,
        [id]
    );

    if (!vehicle) {
        return res.status(404).json({ error: "Vehicle not found." });
    }

    res.json(vehicle);
});

app.get("/api/vendor/vehicles", requireAuth, async (req, res) => {
    const vendor = await ensureVendorProfile(req.session.user.user_id);
    if (!vendor) {
        return res.status(403).json({ error: "No active vendor profile is linked to this account." });
    }

    const vehicles = await db.query(
        `SELECT * FROM vehicles WHERE vendor_id = $1 ORDER BY vehicle_id DESC`,
        [vendor.vendor_id]
    );

    res.json(vehicles);
});

app.post("/api/vendor/vehicles", requireAuth, upload.single("image"), async (req, res) => {
    const vendor = await ensureVendorProfile(req.session.user.user_id);
    if (!vendor) {
        return res.status(403).json({ error: "No active vendor profile is linked to this account." });
    }

    const brand = String(req.body.brand || "").trim();
    const model = String(req.body.model || "").trim();
    const vehicleType = String(req.body.vehicle_type || req.body.type || "").trim().toUpperCase();
    const segment = String(req.body.segment || "").trim();
    const price = Number(req.body.price_per_day || req.body.price);
    const location = String(req.body.location || vendor.location || "").trim();

    if (!brand || !model || !vehicleType || !segment || !location || !Number.isFinite(price) || price <= 0) {
        return res.status(400).json({ error: "Brand, model, type, category, price and location are required." });
    }

    if (!["CAR", "MOTORCYCLE"].includes(vehicleType)) {
        return res.status(400).json({ error: "Vehicle type must be CAR or MOTORCYCLE." });
    }

    try {
        const imageUrl = await saveUploadedImage(req.file || null);
        const result = await db.get(
            `INSERT INTO vehicles (vendor_id, brand, model, vehicle_type, segment, price_per_day, location, image_path, status)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'ACTIVE')
             RETURNING vehicle_id`,
            [vendor.vendor_id, brand, model, vehicleType, segment, price, location, imageUrl || "images/default-vehicle.jpg"]
        );

        res.status(201).json({ message: "Vehicle listed successfully.", vehicle_id: result.vehicle_id });
    } catch (error) {
        console.error("Add vehicle error:", error);
        res.status(500).json({ error: "Unable to add the vehicle." });
    }
});

app.put("/api/vendor/vehicles/:id", requireAuth, upload.single("image"), async (req, res) => {
    const vendor = await ensureVendorProfile(req.session.user.user_id);
    if (!vendor) {
        return res.status(403).json({ error: "No active vendor profile is linked to this account." });
    }

    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) {
        return res.status(400).json({ error: "Invalid vehicle ID." });
    }

    const existing = await db.get(
        `SELECT * FROM vehicles WHERE vehicle_id = $1 AND vendor_id = $2`,
        [id, vendor.vendor_id]
    );

    if (!existing) {
        return res.status(404).json({ error: "Vehicle not found." });
    }

    const brand = String(req.body.brand ?? existing.brand).trim();
    const model = String(req.body.model ?? existing.model).trim();
    const vehicleType = String(req.body.vehicle_type ?? req.body.type ?? existing.vehicle_type).trim().toUpperCase();
    const segment = String(req.body.segment ?? existing.segment).trim();
    const price = Number(req.body.price_per_day ?? req.body.price ?? existing.price_per_day);
    const location = String(req.body.location ?? existing.location).trim();

    if (!brand || !model || !segment || !location || !Number.isFinite(price) || price <= 0) {
        return res.status(400).json({ error: "Please provide valid vehicle details." });
    }

    if (!["CAR", "MOTORCYCLE"].includes(vehicleType)) {
        return res.status(400).json({ error: "Vehicle type must be CAR or MOTORCYCLE." });
    }

    try {
        const imageUrl = req.file ? await saveUploadedImage(req.file) : existing.image_path;
        if (req.file && existing.image_path && existing.image_path.startsWith("images/")) {
            deleteLocalImageIfNeeded(existing.image_path);
        }

        await db.run(
            `UPDATE vehicles
             SET brand = $1,
                 model = $2,
                 vehicle_type = $3,
                 segment = $4,
                 price_per_day = $5,
                 location = $6,
                 image_path = $7
             WHERE vehicle_id = $8 AND vendor_id = $9`,
            [brand, model, vehicleType, segment, price, location, imageUrl || existing.image_path, id, vendor.vendor_id]
        );

        res.json({ message: "Vehicle updated successfully." });
    } catch (error) {
        console.error("Edit vehicle error:", error);
        res.status(500).json({ error: "Unable to update the vehicle." });
    }
});

app.patch("/api/vendor/vehicles/:id/activate", requireAuth, async (req, res) => {
    const vendor = await ensureVendorProfile(req.session.user.user_id);
    if (!vendor) {
        return res.status(403).json({ error: "No active vendor profile is linked to this account." });
    }

    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) {
        return res.status(400).json({ error: "Invalid vehicle ID." });
    }

    const result = await db.run(
        `UPDATE vehicles SET status = 'ACTIVE'
         WHERE vehicle_id = $1 AND vendor_id = $2 AND status = 'INACTIVE'`,
        [id, vendor.vendor_id]
    );

    if (result.rowCount === 0) {
        return res.status(404).json({ error: "Inactive vehicle listing not found." });
    }

    res.json({ message: "Vehicle listing reactivated." });
});

app.delete("/api/vendor/vehicles/:id", requireAuth, async (req, res) => {
    const vendor = await ensureVendorProfile(req.session.user.user_id);
    if (!vendor) {
        return res.status(403).json({ error: "No active vendor profile is linked to this account." });
    }

    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) {
        return res.status(400).json({ error: "Invalid vehicle ID." });
    }

    const vehicle = await db.get(
        `SELECT vehicle_id, status FROM vehicles WHERE vehicle_id = $1 AND vendor_id = $2`,
        [id, vendor.vendor_id]
    );

    if (!vehicle) {
        return res.status(404).json({ error: "Vehicle not found." });
    }

    await db.run(`UPDATE vehicles SET status = 'INACTIVE' WHERE vehicle_id = $1 AND vendor_id = $2`, [id, vendor.vendor_id]);
    res.json({ message: "Vehicle listing deactivated." });
});

app.post("/api/bookings", requireAuth, async (req, res) => {
    if (String(req.session.user.role).toUpperCase() !== "CUSTOMER") {
        return res.status(403).json({ error: "Customer access required." });
    }

    const vehicleId = Number(req.body.vehicle_id);
    const pickup = normalizeDate(req.body.pickup_datetime || req.body.pickup_date);
    const returned = normalizeDate(req.body.return_datetime || req.body.return_date);

    if (!Number.isSafeInteger(vehicleId) || vehicleId < 1) {
        return res.status(400).json({ error: "Invalid vehicle." });
    }

    if (!pickup || !returned || !isValidDateRange(pickup, returned)) {
        return res.status(400).json({ error: "Please choose valid pickup and return dates." });
    }

    const vehicle = await db.get(
        `SELECT vehicle_id, vendor_id, price_per_day, status FROM vehicles WHERE vehicle_id = $1`,
        [vehicleId]
    );

    if (!vehicle || String(vehicle.status || "ACTIVE").toUpperCase() !== "ACTIVE") {
        return res.status(404).json({ error: "This vehicle is not available for booking." });
    }

    const vendor = await db.get(`SELECT status FROM vendors WHERE vendor_id = $1`, [vehicle.vendor_id]);
    if (vendor && vendor.status && String(vendor.status).toUpperCase() !== "ACTIVE") {
        return res.status(404).json({ error: "This vehicle is not available for booking." });
    }

    const overlapping = await db.get(
        `SELECT booking_id FROM bookings
         WHERE vehicle_id = $1
           AND UPPER(status) IN ('PENDING', 'CONFIRMED', 'ACCEPTED')
           AND pickup_datetime < $2
           AND return_datetime > $3`,
        [vehicleId, returned, pickup]
    );

    if (overlapping) {
        return res.status(409).json({ error: "This vehicle already has a booking request for those dates." });
    }

    const startTime = new Date(pickup).getTime();
    const endTime = new Date(returned).getTime();
    const days = Math.max(1, Math.ceil((endTime - startTime) / (1000 * 60 * 60 * 24)));
    const totalPrice = days * Number(vehicle.price_per_day);

    try {
        const result = await db.get(
            `INSERT INTO bookings (customer_id, vehicle_id, pickup_datetime, return_datetime, total_price, status)
             VALUES ($1, $2, $3, $4, $5, 'PENDING')
             RETURNING booking_id, total_price, status`,
            [req.session.user.user_id, vehicleId, pickup, returned, totalPrice]
        );

        res.status(201).json({
            message: "Booking request submitted.",
            booking_id: result.booking_id,
            total_price: result.total_price,
            status: result.status
        });
    } catch (error) {
        console.error("Booking creation error:", error);
        res.status(500).json({ error: "Unable to create the booking request." });
    }
});

app.get("/api/my-bookings", requireAuth, async (req, res) => {
    if (String(req.session.user.role).toUpperCase() !== "CUSTOMER") {
        return res.status(403).json({ error: "Customer access required." });
    }

    const bookings = await db.query(
        `SELECT b.*, v.brand, v.model, v.vehicle_type, v.segment, v.image_path, v.location, v.price_per_day, ven.business_name
         FROM bookings b
         JOIN vehicles v ON v.vehicle_id = b.vehicle_id
         LEFT JOIN vendors ven ON ven.vendor_id = v.vendor_id
         WHERE b.customer_id = $1
         ORDER BY b.created_at DESC, b.booking_id DESC`,
        [req.session.user.user_id]
    );

    res.json(bookings);
});

app.post("/api/bookings/:id/cancel", requireAuth, async (req, res) => {
    if (String(req.session.user.role).toUpperCase() !== "CUSTOMER") {
        return res.status(403).json({ error: "Customer access required." });
    }

    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) {
        return res.status(400).json({ error: "Invalid booking ID." });
    }

    const booking = await db.get(
        `SELECT booking_id, status FROM bookings WHERE booking_id = $1 AND customer_id = $2`,
        [id, req.session.user.user_id]
    );

    if (!booking) {
        return res.status(404).json({ error: "Booking not found." });
    }

    if (!["PENDING", "CONFIRMED", "ACCEPTED"].includes(String(booking.status).toUpperCase())) {
        return res.status(409).json({ error: "This booking cannot be cancelled." });
    }

    await db.run(
        `UPDATE bookings SET status = 'CANCELLED' WHERE booking_id = $1 AND customer_id = $2`,
        [id, req.session.user.user_id]
    );

    res.json({ message: "Booking cancelled." });
});

app.get("/api/vendor/bookings", requireAuth, async (req, res) => {
    const vendor = await ensureVendorProfile(req.session.user.user_id);
    if (!vendor) {
        return res.status(403).json({ error: "No active vendor profile is linked to this account." });
    }

    const bookings = await db.query(
        `SELECT b.*, v.brand, v.model, v.vehicle_type, v.segment, v.image_path, u.name AS customer_name, u.email AS customer_email, u.phone AS customer_phone
         FROM bookings b
         JOIN vehicles v ON v.vehicle_id = b.vehicle_id
         JOIN users u ON u.user_id = b.customer_id
         WHERE v.vendor_id = $1
         ORDER BY b.created_at DESC, b.booking_id DESC`,
        [vendor.vendor_id]
    );

    res.json(bookings);
});

app.post("/api/vendor/bookings/:id/respond", requireAuth, async (req, res) => {
    const vendor = await ensureVendorProfile(req.session.user.user_id);
    if (!vendor) {
        return res.status(403).json({ error: "No active vendor profile is linked to this account." });
    }

    const id = Number(req.params.id);
    const decision = String(req.body.status || req.body.action || "").trim().toUpperCase();

    if (!Number.isSafeInteger(id) || id < 1) {
        return res.status(400).json({ error: "Invalid booking ID." });
    }

    if (!["ACCEPTED", "CONFIRMED", "REJECTED"].includes(decision)) {
        return res.status(400).json({ error: "Response must be ACCEPTED or REJECTED." });
    }

    const booking = await db.get(
        `SELECT b.booking_id, b.status, b.vehicle_id
         FROM bookings b
         JOIN vehicles v ON v.vehicle_id = b.vehicle_id
         WHERE b.booking_id = $1 AND v.vendor_id = $2`,
        [id, vendor.vendor_id]
    );

    if (!booking) {
        return res.status(404).json({ error: "Booking not found." });
    }

    if (String(booking.status).toUpperCase() !== "PENDING") {
        return res.status(409).json({ error: "This booking has already been reviewed." });
    }

    if (decision !== "REJECTED") {
        const current = await db.get(`SELECT pickup_datetime, return_datetime FROM bookings WHERE booking_id = $1`, [id]);
        const overlap = await db.get(
            `SELECT booking_id
             FROM bookings
             WHERE vehicle_id = $1
               AND booking_id <> $2
               AND UPPER(status) IN ('CONFIRMED', 'ACCEPTED')
               AND pickup_datetime < $3
               AND return_datetime > $4`,
            [booking.vehicle_id, id, current.return_datetime, current.pickup_datetime]
        );

        if (overlap) {
            return res.status(409).json({ error: "This vehicle has another confirmed booking during those dates." });
        }
    }

    const newStatus = decision === "REJECTED" ? "REJECTED" : "CONFIRMED";
    await db.run(`UPDATE bookings SET status = $1 WHERE booking_id = $2`, [newStatus, id]);

    res.json({ message: `Booking ${newStatus.toLowerCase()}.`, status: newStatus });
});

app.get("/api/admin/vehicles", requireAdmin, async (req, res) => {
    const vehicles = await db.query(
        `SELECT v.*, ven.business_name, ven.location AS vendor_location, u.name AS vendor_name, u.email AS vendor_email
         FROM vehicles v
         LEFT JOIN vendors ven ON ven.vendor_id = v.vendor_id
         LEFT JOIN users u ON u.user_id = ven.user_id
         ORDER BY v.vehicle_id DESC`
    );

    res.json(vehicles);
});

app.get("/api/admin/bookings", requireAdmin, async (req, res) => {
    const bookings = await db.query(
        `SELECT b.*, v.brand, v.model, v.vehicle_type, u.name AS customer_name, u.email AS customer_email, ven.business_name
         FROM bookings b
         JOIN vehicles v ON v.vehicle_id = b.vehicle_id
         JOIN users u ON u.user_id = b.customer_id
         LEFT JOIN vendors ven ON ven.vendor_id = v.vendor_id
         ORDER BY b.created_at DESC, b.booking_id DESC`
    );

    res.json(bookings);
});

app.use((err, req, res, next) => {
    console.error("Server error:", err);

    if (err instanceof multer.MulterError) {
        if (err.code === "LIMIT_FILE_SIZE") {
            return res.status(400).json({ error: "Image must be smaller than 5 MB." });
        }
        return res.status(400).json({ error: err.message });
    }

    if (err.code === "23505") {
        return res.status(409).json({ error: "That email or record already exists." });
    }

    if (err.code === "23503") {
        return res.status(409).json({ error: "The referenced record could not be found." });
    }

    res.status(500).json({ error: "Unable to process the request." });
});

// Start the HTTP server only when this file is run directly (`node server.js`).
// On Vercel, the file is imported as a module and app.listen() must NOT be called.
if (require.main === module) {
    ensureDatabase()
        .then(() => {
            app.listen(PORT, () => {
                console.log(`MOTORENT server running on http://localhost:${PORT}`);
            });
        })
        .catch((err) => {
            console.error("Startup failed:", err);
            process.exit(1);
        });
}

module.exports = app;
