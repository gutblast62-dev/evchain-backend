require('dotenv').config();
const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'evchain-secret-key-change-in-production';
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000;

// ============================================
// BULLETPROOF CORS - Works with any frontend
// ============================================
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, curl, Postman)
    if (!origin) return callback(null, true);

    // List of allowed origins
    const allowedOrigins = [
      process.env.FRONTEND_URL,
      'https://gutblast62-dev.github.io',
      'https://gutblast62-dev.github.io/Evchain',
      'http://localhost:3000',
      'http://localhost:8080',
      'http://127.0.0.1:3000',
      'http://127.0.0.1:5500'  // Live Server extension
    ].filter(Boolean);  // Remove undefined/null

    // Also allow any Railway or Render preview URL
    const isRailwayPreview = origin.includes('.up.railway.app');
    const isRenderPreview = origin.includes('.onrender.com');

    if (allowedOrigins.includes(origin) || isRailwayPreview || isRenderPreview) {
      callback(null, true);
    } else {
      console.log('CORS blocked origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  preflightContinue: false,
  optionsSuccessStatus: 204
};

// Apply CORS BEFORE all other middleware
app.use(cors(corsOptions));

// Handle preflight for ALL routes
app.options('*', cors(corsOptions));

// Now apply other middleware
app.use(helmet({
  contentSecurityPolicy: false,  // Allow frontend to load
  crossOriginEmbedderPolicy: false
}));

app.use(express.json({ limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests' }
});
app.use('/api/', limiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts' }
});

// Database
const dbPath = path.join(__dirname, 'evchain.db');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON'); // FIX #1 — enforce FK constraints

// Helper functions
function logAudit(eventType, username, evidenceId, details, ip) {
  db.prepare(`
    INSERT INTO audit_log (event_type, username, evidence_id, details, ip_address)
    VALUES (?, ?, ?, ?, ?)
  `).run(eventType, username || null, evidenceId || null, details || null, ip || null);
}

function generateEvId() {
  // FIX #2 — Use MAX-based sequence instead of COUNT to avoid
  // collision when records are deleted or concurrent inserts occur
  const now = new Date();
  const yy = String(now.getFullYear()).slice(-2);
  const mm = String(now.getMonth() + 1).padStart(2, '0');
  const prefix = `EV-${yy}${mm}-`;
  const row = db.prepare(
    "SELECT MAX(CAST(SUBSTR(id, 9) AS INTEGER)) as maxSeq FROM evidence WHERE id LIKE ?"
  ).get(prefix + '%');
  const seq = String((row.maxSeq || 0) + 1).padStart(4, '0');
  return `${prefix}${seq}`;
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(401).json({ error: 'Invalid or expired token' }); // FIX #3 — 401 = auth failure, 403 = authz failure
    req.user = user;
    next();
  });
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    logAudit('PERMISSION_DENIED', req.user.username, null, 'Admin access attempted', req.ip);
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// ============================================
// HEALTH CHECK - For testing if server is alive
// ============================================
app.get('/', (req, res) => {
  res.json({ 
    status: 'EVCHAIN API is running',
    timestamp: new Date().toISOString(),
    cors: 'enabled for gutblast62-dev.github.io'
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', database: 'connected' });
});

// ============================================
// AUTH ROUTES
// ============================================
app.post('/api/auth/login', authLimiter, (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  if (!user) {
    logAudit('LOGIN_FAILED', username, null, 'User not found', ip);
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  if (user.locked_until && new Date(user.locked_until) > new Date()) {
    logAudit('LOGIN_FAILED', username, null, 'Account locked', ip);
    return res.status(423).json({ error: 'Account locked. Try again later.' });
  }

  if (!user.is_active) {
    logAudit('LOGIN_FAILED', username, null, 'Account suspended', ip);
    return res.status(403).json({ error: 'Account suspended' });
  }

  const validPassword = bcrypt.compareSync(password, user.password_hash);

  if (!validPassword) {
    const newFailed = (user.failed_attempts || 0) + 1;
    let lockedUntil = null;
    if (newFailed >= MAX_FAILED_ATTEMPTS) {
      lockedUntil = new Date(Date.now() + LOCKOUT_DURATION).toISOString();
    }
    db.prepare('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?').run(newFailed, lockedUntil, user.id);
    logAudit('LOGIN_FAILED', username, null, `Failed attempt ${newFailed}`, ip);
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  db.prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP WHERE id = ?').run(user.id); // FIX #9

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role, name: user.name },
    JWT_SECRET,
    { expiresIn: '8h' }
  );

  logAudit('LOGIN_SUCCESS', username, null, 'Login successful', ip);

  res.json({
    token,
    user: {
      id: user.id,
      username: user.username,
      name: user.name,
      badge: user.badge,
      role: user.role
    }
  });
});

// ============================================
// EVIDENCE ROUTES
// ============================================
app.get('/api/evidence', authenticateToken, (req, res) => {
  const { search, type, status, caseNumber } = req.query;
  let query = 'SELECT * FROM v_evidence_summary WHERE 1=1';
  const params = [];

  if (req.user.role === 'personnel') {
    query += ' AND assigned_officer = ?';
    params.push(req.user.username);
  }

  if (search) {
    query += ' AND (id LIKE ? OR case_number LIKE ? OR description LIKE ?)';
    params.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }

  if (type) { query += ' AND type = ?'; params.push(type); }
  if (status) { query += ' AND status = ?'; params.push(status); }
  if (caseNumber) { query += ' AND case_number = ?'; params.push(caseNumber); }

  query += ' ORDER BY created_at DESC';

  res.json(db.prepare(query).all(...params));
});

app.get('/api/evidence/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const ev = db.prepare('SELECT * FROM v_evidence_summary WHERE id = ?').get(id);

  if (!ev) return res.status(404).json({ error: 'Evidence not found' });

  if (req.user.role === 'personnel' && ev.assigned_officer !== req.user.username) {
    logAudit('PERMISSION_DENIED', req.user.username, id, 'Attempted to view unauthorized evidence', req.ip);
    return res.status(403).json({ error: 'Access denied' });
  }

  logAudit('EVIDENCE_VIEWED', req.user.username, id, null, req.ip);
  res.json(ev);
});

app.post('/api/evidence', authenticateToken, requireAdmin, (req, res) => {
  const { caseNumber, description, type, status, assignedOfficer, collectedBy, dateCollected, location, notes } = req.body;

  if (!caseNumber || !description || !type || !assignedOfficer || !dateCollected) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const id = generateEvId();

  db.prepare(`
    INSERT INTO evidence (id, case_number, description, type, status, assigned_officer, collected_by, date_collected, location, notes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, caseNumber, description, type, status || 'Collected', assignedOfficer, collectedBy || assignedOfficer, dateCollected, location || null, notes || null);

  db.prepare(`
    INSERT INTO custody_events (evidence_id, case_number, action, handler, date, notes)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(id, caseNumber, 'Collected', collectedBy || assignedOfficer, dateCollected, notes || 'Initial collection');

  logAudit('EVIDENCE_CREATED', req.user.username, id, `Case: ${caseNumber}`, req.ip);
  res.status(201).json({ id, message: 'Evidence logged successfully' });
});

app.delete('/api/evidence/:id', authenticateToken, requireAdmin, (req, res) => {
  const { id } = req.params;
  // FIX #5 — explicitly check for custody events before deleting,
  // since older DBs may not have the FK constraint enforced
  const custodyCount = db.prepare(
    'SELECT COUNT(*) as cnt FROM custody_events WHERE evidence_id = ?'
  ).get(id).cnt;
  if (custodyCount > 0) {
    return res.status(409).json({ error: 'Cannot delete evidence with custody events. Archive it instead.' });
  }
  const ev = db.prepare('SELECT id FROM evidence WHERE id = ?').get(id);
  if (!ev) return res.status(404).json({ error: 'Evidence not found' });
  try {
    db.prepare('DELETE FROM evidence WHERE id = ?').run(id);
    logAudit('EVIDENCE_DELETED', req.user.username, id, null, req.ip);
    res.json({ message: 'Evidence deleted' });
  } catch (err) {
    throw err;
  }
});


// ============================================
// FIX #4 — BULK CUSTODY ROUTE
// Returns all custody events the requester can access
// (replaces the N+1 per-evidence calls from the frontend)
// ============================================
app.get('/api/custody', authenticateToken, (req, res) => {
  let query = `
    SELECT ce.* FROM custody_events ce
    JOIN evidence e ON ce.evidence_id = e.id
    WHERE 1=1
  `;
  const params = [];
  if (req.user.role === 'personnel') {
    query += ' AND e.assigned_officer = ?';
    params.push(req.user.username);
  }
  query += ' ORDER BY ce.date ASC';
  res.json(db.prepare(query).all(...params));
});

// ============================================
// CUSTODY ROUTES
// ============================================
app.get('/api/evidence/:id/custody', authenticateToken, (req, res) => {
  const { id } = req.params;
  const ev = db.prepare('SELECT assigned_officer FROM evidence WHERE id = ?').get(id);

  if (!ev) return res.status(404).json({ error: 'Evidence not found' });
  if (req.user.role === 'personnel' && ev.assigned_officer !== req.user.username) {
    return res.status(403).json({ error: 'Access denied' });
  }

  res.json(db.prepare('SELECT * FROM custody_events WHERE evidence_id = ? ORDER BY date ASC').all(id));
});

app.post('/api/evidence/:id/custody', authenticateToken, requireAdmin, (req, res) => {
  const { id } = req.params;
  const { action, handler, date, notes, newStatus } = req.body;

  if (!action || !handler || !date) {
    return res.status(400).json({ error: 'Action, handler, and date required' });
  }

  const ev = db.prepare('SELECT case_number, status FROM evidence WHERE id = ?').get(id);
  if (!ev) return res.status(404).json({ error: 'Evidence not found' });

  db.prepare(`
    INSERT INTO custody_events (evidence_id, case_number, action, handler, date, notes, new_status)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(id, ev.case_number, action, handler, date, notes || null, newStatus || null);

  if (newStatus) {
    db.prepare('UPDATE evidence SET status = ? WHERE id = ?').run(newStatus, id);
  }

  logAudit('CUSTODY_EVENT_ADDED', req.user.username, id, `Action: ${action}`, req.ip);
  res.status(201).json({ message: 'Custody event logged' });
});

// ============================================
// USER ROUTES
// ============================================
app.get('/api/users', authenticateToken, requireAdmin, (req, res) => {
  res.json(db.prepare(`
    SELECT id, username, name, badge, role, is_active, created_at,
      (SELECT COUNT(*) FROM evidence WHERE assigned_officer = users.username) as evidence_count
    FROM users ORDER BY created_at DESC
  `).all());
});

app.post('/api/users', authenticateToken, requireAdmin, (req, res) => {
  const { username, password, name, badge, role } = req.body;

  if (!username || !password || !name) {
    return res.status(400).json({ error: 'Username, password, and name required' });
  }

  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) return res.status(409).json({ error: 'Username already exists' });

  const id = uuidv4();
  const passwordHash = bcrypt.hashSync(password, 12);

  db.prepare(`
    INSERT INTO users (id, username, password_hash, name, badge, role)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(id, username.toLowerCase(), passwordHash, name, badge || null, role || 'personnel');

  logAudit('USER_CREATED', req.user.username, null, `Created: ${username}`, req.ip);
  res.status(201).json({ id, message: 'User created' });
});

app.put('/api/users/:id', authenticateToken, requireAdmin, (req, res) => {
  const { id } = req.params;
  const { name, badge, role, password, isActive } = req.body;

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  let updates = [];
  let params = [];

  if (name) { updates.push('name = ?'); params.push(name); }
  if (badge !== undefined) { updates.push('badge = ?'); params.push(badge); }
  if (role) {
    // FIX #6 — validate role value before accepting it
    if (!['admin', 'personnel'].includes(role)) {
      return res.status(400).json({ error: "Role must be 'admin' or 'personnel'" });
    }
    updates.push('role = ?'); params.push(role);
  }
  if (isActive !== undefined) { updates.push('is_active = ?'); params.push(isActive ? 1 : 0); }
  if (password) { updates.push('password_hash = ?'); params.push(bcrypt.hashSync(password, 12)); }

  if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });

  params.push(id);
  db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...params);

  logAudit('USER_UPDATED', req.user.username, null, `Updated: ${user.username}`, req.ip);
  res.json({ message: 'User updated' });
});

app.delete('/api/users/:id', authenticateToken, requireAdmin, (req, res) => {
  const { id } = req.params;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);

  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.username === 'admin') return res.status(403).json({ error: 'Cannot delete root admin' });

  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  logAudit('USER_DELETED', req.user.username, null, `Deleted: ${user.username}`, req.ip);
  res.json({ message: 'User deleted' });
});

// ============================================
// QR CODE ROUTES
// ============================================
app.post('/api/evidence/:id/qr', authenticateToken, (req, res) => {
  const { id } = req.params;
  const ev = db.prepare('SELECT * FROM evidence WHERE id = ?').get(id);

  if (!ev) return res.status(404).json({ error: 'Evidence not found' });
  if (req.user.role === 'personnel' && ev.assigned_officer !== req.user.username) {
    return res.status(403).json({ error: 'Access denied' });
  }

  const token = uuidv4();
  const tokenId = uuidv4();

  db.prepare(`INSERT INTO qr_tokens (id, evidence_id, token) VALUES (?, ?, ?)`).run(tokenId, id, token);

  const qrUrl = `${req.protocol}://${req.get('host')}/api/qr/${token}`;
  res.json({ token, url: qrUrl });
});

app.get('/api/qr/:token', (req, res) => {
  const { token } = req.params;

  const qr = db.prepare(`
    SELECT qr_tokens.*, evidence.case_number, evidence.description 
    FROM qr_tokens 
    JOIN evidence ON qr_tokens.evidence_id = evidence.id
    WHERE qr_tokens.token = ? AND qr_tokens.is_revoked = 0
    AND (qr_tokens.expires_at IS NULL OR qr_tokens.expires_at > CURRENT_TIMESTAMP)
  `).get(token);

  if (!qr) {
    logAudit('QR_ACCESS_DENIED', null, null, `Invalid token: ${token.substring(0,8)}…`, req.ip); // FIX #7 — never log full token
    return res.status(404).json({ error: 'Invalid or expired QR code' });
  }

  db.prepare('UPDATE qr_tokens SET scan_count = scan_count + 1, last_scanned = CURRENT_TIMESTAMP WHERE id = ?').run(qr.id);
  logAudit('QR_SCANNED', null, qr.evidence_id, `Token: ${token.substring(0,8)}…`, req.ip); // FIX #7 — never log full token
  res.json({ evidenceId: qr.evidence_id, caseNumber: qr.case_number });
});

// ============================================
// STATS & AUDIT
// ============================================
app.get('/api/stats', authenticateToken, (req, res) => {
  let evidenceQuery = 'SELECT COUNT(*) as total FROM evidence';
  let casesQuery = 'SELECT COUNT(DISTINCT case_number) as cases FROM evidence';
  let storedQuery = `SELECT COUNT(*) as stored FROM evidence WHERE status = 'Stored'`;
  let custodyQuery = 'SELECT COUNT(*) as events FROM custody_events';
  const params = [];

  if (req.user.role === 'personnel') {
    evidenceQuery += ' WHERE assigned_officer = ?';
    casesQuery += ' WHERE assigned_officer = ?';
    storedQuery += ' AND assigned_officer = ?';
    custodyQuery = `SELECT COUNT(*) as events FROM custody_events ce JOIN evidence e ON ce.evidence_id = e.id WHERE e.assigned_officer = ?`;
    params.push(req.user.username);
  }

  const total = db.prepare(evidenceQuery).get(...params).total;
  const cases = db.prepare(casesQuery).get(...params).cases;
  const stored = db.prepare(storedQuery).get(...params).stored;
  const events = db.prepare(custodyQuery).get(...params).events;

  res.json({ total, cases, stored, events });
});

app.get('/api/audit', authenticateToken, requireAdmin, (req, res) => {
  const { eventType, username, limit = 100 } = req.query;
  let query = 'SELECT * FROM audit_log WHERE 1=1';
  const params = [];

  if (eventType) { query += ' AND event_type = ?'; params.push(eventType); }
  if (username) { query += ' AND username = ?'; params.push(username); }
  query += ' ORDER BY created_at DESC LIMIT ?';
  params.push(parseInt(limit));

  res.json(db.prepare(query).all(...params));
});

// ============================================
// ERROR HANDLING
// ============================================
app.use((err, req, res, next) => {
  console.error('ERROR:', err.stack);
  res.status(500).json({ error: 'Internal server error', message: err.message });
});

app.listen(PORT, () => {
  console.log(`🚀 EVCHAIN API running on port ${PORT}`);
  console.log(`📁 Database: ${dbPath}`);
  console.log(`🔐 JWT Secret: ${JWT_SECRET === 'evchain-secret-key-change-in-production' ? 'DEFAULT (change in production!)' : 'Custom'}`);
  console.log(`🌐 CORS enabled for: gutblast62-dev.github.io`);
});
