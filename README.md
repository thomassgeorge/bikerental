# MOTORENT

MOTORENT is a full-stack vehicle rental website that lets customers browse available vehicles, request bookings, and manage reservations while allowing vendors to manage their listings and admins to review applications and bookings.

The project is built with Node.js, Express, SQLite (with Neon/Postgres compatibility support), and static HTML/CSS/JavaScript pages served from the `public` directory.

## Overview

This platform is designed for a simple automobile rental marketplace:

- Customers can register, log in, browse cars and motorcycles, and submit rental bookings.
- Vendors can apply to become sellers, create listings for their vehicles, and manage availability.
- Admins can review vendor applications, approve or reject them, and oversee bookings.
- The website is served as a lightweight web app with a Node backend and static frontend pages.

## Main Features

### Customer features
- Account registration and sign-in
- Role-based user access control
- Browse available vehicles from active vendors
- View vehicle details and pricing
- Create booking requests with pickup and return dates
- View current bookings and cancel pending or active requests

### Vendor features
- Submit a vendor application
- View application status
- Manage vendor profile and active listing status
- Add, update, and deactivate vehicles
- Review customer booking requests
- Accept or reject bookings for their vehicles

### Admin features
- Review pending vendor applications
- Approve or reject vendor applications
- View all vehicles and bookings from a central admin dashboard
- Maintain marketplace oversight and operational control

### Security and auth
- Password hashing using `bcryptjs`
- Session-based authentication with signed cookies
- Role checks for customer, vendor, and admin actions
- File uploads are limited and validated for image types

## Tech Stack

- Node.js
- Express.js
- SQLite database (`better-sqlite3` for local/dev use)
- Neon/Postgres-compatible database layer for serverless deployment support
- Vercel Blob for uploaded vehicle images
- HTML, CSS, and vanilla JavaScript for the frontend

## Project Structure

```text
bikerental/
├── api/                     # API-related project files
├── public/                 # Frontend website pages and assets
│   ├── index.html          # Customer-facing home page
│   ├── admin.html          # Admin dashboard
│   ├── vendor.html         # Vendor application page
│   ├── vendor-status.html  # Vendor status and application tracking
│   ├── vendordash.html     # Vendor dashboard
│   ├── style.css          # Shared styling
│   └── images/            # Local uploaded images
├── scripts/                # Database and utility scripts
├── database.js             # Database access layer and setup
├── server.js               # Express app and API routes
├── package.json            # Dependencies and scripts
├── .env.example            # Environment template
├── vercel.json             # Vercel configuration
├── database.db            # Local SQLite database file
├── package-lock.json
├── .gitignore
└── README.md              # Project documentation
```

## Website Pages

### Home page (`public/index.html`)
The main storefront for customers. It showcases vehicle listings, booking flows, user sign-in/register forms, and customer account functions.

### Vendor pages (`public/vendor.html`, `public/vendor-status.html`, `public/vendordash.html`)
These pages help vendors submit applications, review their status, manage vehicle listings, and respond to customer rental requests.

### Admin page (`public/admin.html`)
This page provides administrators with tools to approve vendor applications and review the platform's vehicles and bookings.

## User Roles

### Customer
Customers can:
- create accounts
- find and book vehicles
- track bookings
- cancel bookings when allowed

### Vendor
Vendors can:
- apply for a business profile
- create and manage listings
- accept or reject customer bookings
- manage their active inventory

### Admin
Admins can:
- approve vendor accounts
- oversee bookings
- manage the marketplace from a single dashboard

## API Overview

The backend exposes REST-like routes for authentication, vendor management, vehicle listings, and bookings.

Examples include:
- `/api/auth/register`
- `/api/auth/login`
- `/api/auth/me`
- `/api/vehicles`
- `/api/vendor/vehicles`
- `/api/bookings`
- `/api/vendor/bookings`
- `/api/admin/vendor-applications`

The app also includes health-check endpoints like:
- `/api/health`
- `/health`

## Database

The application uses a database layer that initializes the schema and manages relational tables for:
- users
- vendors
- vendor_applications
- vehicles
- bookings

This is set up in `database.js`, and the app bootstraps the database during startup and API access.

## Environment Variables

A sample environment template is located in `.env.example`.

Typical values include:
- `PORT` for the app port
- `SESSION_SECRET` for signed session cookies
- `BLOB_READ_WRITE_TOKEN` to enable Vercel Blob uploads
- database connection values if using Neon/Postgres deployment

## Local Setup

1. Clone the repository.
2. Install dependencies:

```bash
npm install
```

3. Start the server:

```bash
npm start
```

4. Open the site in your browser at:

```text
http://localhost:3000
```

## Scripts

This project includes several useful scripts in `package.json`:

```bash
npm start
npm run dev
npm run migrate:sqlite
npm run test:db
npm run lint
```

## Deployment Notes

The app is designed to work in a serverless or hosted environment such as Vercel, while still supporting local development and SQLite-backed flows. Static pages are served from `public`, and the Express server handles API requests and business logic.

## Notes

This project is a complete rental marketplace prototype focused on real-world rental operations, including account security, vendor onboarding, vehicle management, and reservation workflows.

## License

This project is licensed under the ISC license as defined in `package.json`.

## Summary

MOTORENT is a vehicle rental website that combines customer booking functionality, vendor management tools, and admin controls in one full-stack app. It is a practical example of a rental marketplace built with Express and static frontend pages, suitable for learning, demoing, or extending into a production-ready platform.
