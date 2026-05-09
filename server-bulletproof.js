const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
app.use(cors({
  origin: 'https://gutblast62-dev.github.io',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'evchain-secret-key-change-this';

// ============================================
// CORS - ALLOW EVERYTHING (for GitHub Pages)
// ============================================
// This MUST be the very first middleware
app.use(cors({
  origin: true,           // Reflects the request origin (allows any origin)
  credentials: true,      // Allow cookies/auth headers
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
  maxAge: 86400           // Cache preflight for 24 hours
}));

// Handle OPTIONS preflight for ALL routes manually
app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.sendStatus(204);
});

// Parse JSON bodies
app.use(express.json({ limit: '10mb' }));

// Request logger (so we can see what's happening)
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} | Origin: ${req.headers.origin || 'none'} | IP: ${req.ip}`);
  next();
});

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests' }
});
app.use('/api/', limiter);

// ============================================
// DATABASE SETUP (auto-creates if missing)
// ============================================
const dbPath = path.join(__dirname, 'evchain.db');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    badge TEXT,
    role TEXT CHECK(role IN ('admin', 'personnel')) DEFAULT 'personnel',
    is_active INTEGER DEFAULT 1,
    failed_attempts INTEGER DEFAULT 0,
    locked_until TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    case_number TEXT NOT NULL,
    description TEXT NOT NULL,
    type TEXT NOT NULL,
    status TEXT CHECK(status IN ('Collected', 'In Processing', 'Stored', 'Released', 'Destroyed')) DEFAULT 'Collected',
    assigned_officer TEXT NOT NULL,
    collected_by TEXT,
    date_collected TEXT NOT NULL,
    location TEXT,
    notes TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS custody_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT NOT NULL,
    case_number TEXT,
    action TEXT NOT NULL,
    handler TEXT NOT NULL,
    date TEXT NOT NULL,
    notes TEXT,
    new_status TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    username TEXT,
    evidence_id TEXT,
    details TEXT,
    ip_address TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_evidence_officer ON evidence(assigned_officer);
  CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_number);
  CREATE INDEX IF NOT EXISTS idx_custody_evidence ON custody_events(evidence_id);
`);

// Insert default admin
const adminPassword = bcrypt.hashSync('admin123', 12);
try {
  db.prepare(`INSERT INTO users (id, username, password_hash, name, badge, role, is_active)
    VALUES (?, ?, ?, ?, ?, ?, ?)`).run('user-admin-001', 'admin', adminPassword, 'System Administrator', '', 'admin', 1);
  console.log('Default admin created: admin / admin123');
} catch (e) {
  // Already exists
}

// Create view
db.exec(`
  CREATE VIEW IF NOT EXISTS v_evidence_summary AS
  SELECT e.*, u.name as officer_name, COUNT(ce.id) as custody_count
  FROM evidence e
  LEFT JOIN users u ON e.assigned_officer = u.username
  LEFT JOIN custody_events ce ON e.id = ce.evidence_id
  GROUP BY e.id;
`);

// ============================================
// HELPERS
// ============================================
function logAudit(eventType, username, evidenceId, details, ip) {
  db.prepare(`INSERT INTO audit_log (event_type, username, evidence_id, details, ip_address)
    VALUES (?, ?, ?, ?, ?)`).run(eventType, username || null, evidenceId || null, details || null, ip || null);
}

function generateEvId() {
  const now = new Date();
  const yy = String(now.getFullYear()).slice(-2);
  const mm = String(now.getMonth() + 1).padStart(2, '0');
  const count = db.prepare('SELECT COUNT(*) as count FROM evidence').get().count + 1;
  return `EV-${yy}${mm}-${String(count).padStart(4, '0')}`;
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// ============================================
// HEALTH CHECK
// ============================================
app.get('/', (req, res) => {
  res.json({ status: 'EVCHAIN API running', time: new Date().toISOString() });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', db: 'connected', cors: 'enabled' });
});

// ============================================
// AUTH
// ============================================
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  if (!user.is_active) return res.status(403).json({ error: 'Account suspended' });
  if (user.locked_until && new Date(user.locked_until) > new Date()) {
    return res.status(423).json({ error: 'Account locked' });
  }

  if (!bcrypt.compareSync(password, user.password_hash)) {
    const newFailed = (user.failed_attempts || 0) + 1;
    let lockedUntil = null;
    if (newFailed >= 5) lockedUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    db.prepare('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?').run(newFailed, lockedUntil, user.id);
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  db.prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?').run(user.id);
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '8h' });
  res.json({ token, user: { id: user.id, username: user.username, name: user.name, badge: user.badge, role: user.role } });
});

// ============================================
// EVIDENCE
// ============================================
app.get('/api/evidence', authenticateToken, (req, res) => {
  const { search, type, status } = req.query;
  let query = 'SELECT * FROM v_evidence_summary WHERE 1=1';
  const params = [];
  if (req.user.role === 'personnel') { query += ' AND assigned_officer = ?'; params.push(req.user.username); }
  if (search) { query += ' AND (id LIKE ? OR case_number LIKE ? OR description LIKE ?)'; params.push(`%${search}%`, `%${search}%`, `%${search}%`); }
  if (type) { query += ' AND type = ?'; params.push(type); }
  if (status) { query += ' AND status = ?'; params.push(status); }
  query += ' ORDER BY created_at DESC';
  res.json(db.prepare(query).all(...params));
});

app.get('/api/evidence/:id', authenticateToken, (req, res) => {
  const ev = db.prepare('SELECT * FROM v_evidence_summary WHERE id = ?').get(req.params.id);
  if (!ev) return res.status(404).json({ error: 'Evidence not found' });
  if (req.user.role === 'personnel' && ev.assigned_officer !== req.user.username) {
    return res.status(403).json({ error: 'Access denied' });
  }
  res.json(ev);
});

app.post('/api/evidence', authenticateToken, requireAdmin, (req, res) => {
  const { caseNumber, description, type, status, assignedOfficer, collectedBy, dateCollected, location, notes } = req.body;
  if (!caseNumber || !description || !type || !assignedOfficer || !dateCollected) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  const id = generateEvId();
  db.prepare(`INSERT INTO evidence (id, case_number, description, type, status, assigned_officer, collected_by, date_collected, location, notes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(id, caseNumber, description, type, status || 'Collected', assignedOfficer, collectedBy || assignedOfficer, dateCollected, location || null, notes || null);
  db.prepare(`INSERT INTO custody_events (evidence_id, case_number, action, handler, date, notes)
    VALUES (?, ?, ?, ?, ?, ?)`).run(id, caseNumber, 'Collected', collectedBy || assignedOfficer, dateCollected, notes || 'Initial collection');
  res.status(201).json({ id, message: 'Evidence logged' });
});

app.delete('/api/evidence/:id', authenticateToken, requireAdmin, (req, res) => {
  db.prepare('DELETE FROM evidence WHERE id = ?').run(req.params.id);
  res.json({ message: 'Evidence deleted' });
});

// ============================================
// CUSTODY
// ============================================
app.get('/api/evidence/:id/custody', authenticateToken, (req, res) => {
  const ev = db.prepare('SELECT assigned_officer FROM evidence WHERE id = ?').get(req.params.id);
  if (!ev) return res.status(404).json({ error: 'Evidence not found' });
  if (req.user.role === 'personnel' && ev.assigned_officer !== req.user.username) {
    return res.status(403).json({ error: 'Access denied' });
  }
  res.json(db.prepare('SELECT * FROM custody_events WHERE evidence_id = ? ORDER BY date ASC').all(req.params.id));
});

app.post('/api/evidence/:id/custody', authenticateToken, requireAdmin, (req, res) => {
  const { action, handler, date, notes, newStatus } = req.body;
  if (!action || !handler || !date) return res.status(400).json({ error: 'Action, handler, and date required' });
  const ev = db.prepare('SELECT case_number FROM evidence WHERE id = ?').get(req.params.id);
  if (!ev) return res.status(404).json({ error: 'Evidence not found' });
  db.prepare(`INSERT INTO custody_events (evidence_id, case_number, action, handler, date, notes, new_status)
    VALUES (?, ?, ?, ?, ?, ?, ?)`).run(req.params.id, ev.case_number, action, handler, date, notes || null, newStatus || null);
  if (newStatus) db.prepare('UPDATE evidence SET status = ? WHERE id = ?').run(newStatus, req.params.id);
  res.status(201).json({ message: 'Custody event logged' });
});

// ============================================
// USERS
// ============================================
app.get('/api/users', authenticateToken, requireAdmin, (req, res) => {
  res.json(db.prepare(`SELECT id, username, name, badge, role, is_active, created_at,
    (SELECT COUNT(*) FROM evidence WHERE assigned_officer = users.username) as evidence_count
    FROM users ORDER BY created_at DESC`).all());
});

app.post('/api/users', authenticateToken, requireAdmin, (req, res) => {
  const { username, password, name, badge, role } = req.body;
  if (!username || !password || !name) return res.status(400).json({ error: 'Username, password, and name required' });
  if (db.prepare('SELECT id FROM users WHERE username = ?').get(username)) {
    return res.status(409).json({ error: 'Username already exists' });
  }
  const id = uuidv4();
  db.prepare(`INSERT INTO users (id, username, password_hash, name, badge, role)
    VALUES (?, ?, ?, ?, ?, ?)`).run(id, username.toLowerCase(), bcrypt.hashSync(password, 12), name, badge || null, role || 'personnel');
  res.status(201).json({ id, message: 'User created' });
});

app.put('/api/users/:id', authenticateToken, requireAdmin, (req, res) => {
  const { name, badge, role, password, isActive } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  let updates = [];
  let params = [];
  if (name) { updates.push('name = ?'); params.push(name); }
  if (badge !== undefined) { updates.push('badge = ?'); params.push(badge); }
  if (role) { updates.push('role = ?'); params.push(role); }
  if (isActive !== undefined) { updates.push('is_active = ?'); params.push(isActive ? 1 : 0); }
  if (password) { updates.push('password_hash = ?'); params.push(bcrypt.hashSync(password, 12)); }
  if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });
  params.push(req.params.id);
  db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...params);
  res.json({ message: 'User updated' });
});

app.delete('/api/users/:id', authenticateToken, requireAdmin, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.username === 'admin') return res.status(403).json({ error: 'Cannot delete root admin' });
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ message: 'User deleted' });
});

// ============================================
// STATS
// ============================================
app.get('/api/stats', authenticateToken, (req, res) => {
  let eq = 'SELECT COUNT(*) as total FROM evidence';
  let cq = 'SELECT COUNT(DISTINCT case_number) as cases FROM evidence';
  let sq = `SELECT COUNT(*) as stored FROM evidence WHERE status = 'Stored'`;
  let cuq = 'SELECT COUNT(*) as events FROM custody_events';
  const params = [];
  if (req.user.role === 'personnel') {
    eq += ' WHERE assigned_officer = ?';
    cq += ' WHERE assigned_officer = ?';
    sq += ' AND assigned_officer = ?';
    cuq = 'SELECT COUNT(*) as events FROM custody_events ce JOIN evidence e ON ce.evidence_id = e.id WHERE e.assigned_officer = ?';
    params.push(req.user.username);
  }
  res.json({
    total: db.prepare(eq).get(...params).total,
    cases: db.prepare(cq).get(...params).cases,
    stored: db.prepare(sq).get(...params).stored,
    events: db.prepare(cuq).get(...params).events
  });
});

// ============================================
// ERROR HANDLER
// ============================================
app.use((err, req, res, next) => {
  console.error('ERROR:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`✅ EVCHAIN API running on port ${PORT}`);
  console.log(`📁 Database: ${dbPath}`);
  console.log(`🌐 CORS: enabled for ALL origins`);
});
