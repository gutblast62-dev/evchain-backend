# EVCHAIN Backend API

Production-ready backend for the EVCHAIN Evidence Management System.

## Features

- 🔐 **JWT Authentication** with bcrypt password hashing
- 🛡️ **Rate limiting** and account lockout protection
- 📊 **SQLite Database** with WAL mode for performance
- 🔗 **Immutable custody records** enforced at database level
- 📱 **QR token system** with expiry and revocation
- 📝 **Full audit logging** of all security events
- 👤 **Role-based access control** (Admin / Personnel)

## Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Initialize Database

```bash
npm run init-db
```

This creates `evchain.db` with all tables and a default admin user:
- **Username:** `admin`
- **Password:** `admin123` (change immediately!)

### 3. Configure Environment

```bash
cp .env.template .env
# Edit .env with your settings
```

### 4. Start Server

```bash
npm start
# or for development:
npm run dev
```

## Deployment Options

### Free Tier: Render.com

1. Push code to GitHub
2. Connect repo to [Render](https://render.com)
3. Set environment variables in Render dashboard
4. Deploy — free tier includes 512MB RAM

### Free Tier: Railway.app

1. Push code to GitHub
2. Import repo in [Railway](https://railway.app)
3. Add environment variables
4. Deploy automatically

### Free Tier: Fly.io

```bash
fly launch
fly deploy
```

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/login` | No | Login, returns JWT |
| GET | `/api/evidence` | Yes | List evidence (filtered by role) |
| GET | `/api/evidence/:id` | Yes | View single evidence |
| POST | `/api/evidence` | Admin | Log new evidence |
| DELETE | `/api/evidence/:id` | Admin | Delete evidence |
| GET | `/api/evidence/:id/custody` | Yes | Get custody timeline |
| POST | `/api/evidence/:id/custody` | Admin | Add custody event |
| GET | `/api/users` | Admin | List personnel |
| POST | `/api/users` | Admin | Create account |
| PUT | `/api/users/:id` | Admin | Update account |
| DELETE | `/api/users/:id` | Admin | Remove account |
| POST | `/api/evidence/:id/qr` | Yes | Generate QR token |
| GET | `/api/qr/:token` | No | Verify QR (returns evidence info) |
| GET | `/api/stats` | Yes | Dashboard statistics |
| GET | `/api/audit` | Admin | Security audit log |

## Security Features

- **Passwords:** bcrypt hashed (cost factor 12)
- **Account lockout:** 5 failed attempts = 15min lockout
- **Rate limiting:** 100 requests/15min general, 10/15min for auth
- **CORS:** Configurable origin restriction
- **Helmet:** Security headers
- **Immutable custody:** Database triggers prevent edit/delete
- **Audit trail:** Every action logged with IP address

## Connecting Frontend

Update `API_BASE` in your frontend JavaScript:

```javascript
const API_BASE = 'https://your-app.onrender.com/api';
```

## Database Schema

The SQLite schema includes:
- `users` — personnel accounts
- `evidence` — core evidence items
- `custody_events` — immutable chain of custody (append-only)
- `qr_tokens` — QR deep-link tokens
- `audit_log` — security event log

All tables are created automatically by `init-db.js`.
