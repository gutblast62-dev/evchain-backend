require('dotenv').config();
const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'evchain-secret-key-change-in-production';
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000;

// ============================================================
// CORS — RUNS BEFORE EVERYTHING ELSE
// Writes headers directly — no cors() package, no middleware chain issues
// ============================================================
app.use((req, res, next) => {
  const origin = req.headers.origin;

  const allowed = [
    'https://github.com/gutblast62-dev/Evchain.github.io',
    'https://gutblast62-dev.github.io/Evchain.github.io/',
    'http://localhost:3000',
    'http://localhost:5500',
    'http://localhost:8080',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:5500',
  ];

  const originAllowed = !origin
    || allowed.includes(origin)
    || (process.env.FRONTEND_URL && origin === process.env.FRONTEND_URL)
    || (origin && origin.startsWith('https://gutblast62-dev.github.io'))
    || (origin && origin.endsWith('.up.railway.app'))
    || (origin && origin.endsWith('.onrender.com'))
    || (origin && origin.endsWith('.netlify.app'))
    || (origin && origin.endsWith('.vercel.app'));

  if (originAllowed) {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
    res.setHeader('Access-Control-Max-Age', '86400');
    res.setHeader('Vary', 'Origin');
  } else {
    console.warn(`[CORS] Blocked: ${origin}`);
  }

  // Respond to preflight immediately
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  next();
});

// ============================================================
// OTHER MIDDLEWARE
// ============================================================
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: false,
}));

app.use(express.json({ limit: '10mb' }));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, message: { error: 'Too many requests' } });
app.use('/api/', limiter);

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: 'Too many login attempts' } });

// ============================================================
// DATABASE
// ============================================================
const dbPath = path.join(__dirname, 'evchain.db');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ============================================================
// HELPERS
// ============================================================
function logAudit(eventType, username, evidenceId, details, ip) {
  try {
    db.prepare(`INSERT INTO audit_log (event_type, username, evidence_id, details, ip_address) VALUES (?, ?, ?, ?, ?)`)
      .run(eventType, username || null, evidenceId || null, details || null, ip || null);
  } catch (e) { console.error('[Audit]', e.message); }
}

function generateEvId() {
  const now = new Date();
  const yy = String(now.getFullYear()).slice(-2);
  const mm = String(now.getMonth() + 1).padStart(2, '0');
  const prefix = `EV-${yy}${mm}-`;
  const row = db.prepare("SELECT MAX(CAST(SUBSTR(id, 9) AS INTEGER)) as maxSeq FROM evidence WHERE id LIKE ?").get(prefix + '%');
  return `${prefix}${String((row.maxSeq || 0) + 1).padStart(4, '0')}`;
}

function authenticateToken(req, res, next) {
  const token = (req.headers['authorization'] || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(401).json({ error: 'Invalid or expired token' });
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

// ============================================================
// HEALTH CHECK
// ============================================================
app.get('/', (req, res) => res.json({ status: 'EVCHAIN API running', cors: 'active' }));
app.get('/health', (req, res) => res.json({ status: 'ok', database: 'connected', timestamp: new Date().toISOString() }));

// ============================================================
// AUTH
// ============================================================
app.post('/api/auth/login', authLimiter, (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) { logAudit('LOGIN_FAILED', username, null, 'Not found', req.ip); return res.status(401).json({ error: 'Invalid credentials' }); }
  if (user.locked_until && new Date(user.locked_until) > new Date()) return res.status(423).json({ error: 'Account locked. Try again later.' });
  if (!user.is_active) return res.status(403).json({ error: 'Account suspended' });

  if (!bcrypt.compareSync(password, user.password_hash)) {
    const fails = (user.failed_attempts || 0) + 1;
    const lock = fails >= MAX_FAILED_ATTEMPTS ? new Date(Date.now() + LOCKOUT_DURATION).toISOString() : null;
    db.prepare('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?').run(fails, lock, user.id);
    logAudit('LOGIN_FAILED', username, null, `Attempt ${fails}`, req.ip);
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  db.prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '8h' });
  logAudit('LOGIN_SUCCESS', username, null, null, req.ip);
  res.json({ token, user: { id: user.id, username: user.username, name: user.name, badge: user.badge, role: user.role } });
});

// ============================================================
// EVIDENCE
// ============================================================
app.get('/api/evidence', authenticateToken, (req, res) => {
  const { search, type, status, caseNumber } = req.query;
  let q = 'SELECT * FROM v_evidence_summary WHERE 1=1';
  const p = [];
  if (req.user.role === 'personnel') { q += ' AND assigned_officer = ?'; p.push(req.user.username); }
  if (search) { q += ' AND (id LIKE ? OR case_number LIKE ? OR description LIKE ?)'; p.push(`%${search}%`, `%${search}%`, `%${search}%`); }
  if (type)       { q += ' AND type = ?';        p.push(type); }
  if (status)     { q += ' AND status = ?';      p.push(status); }
  if (caseNumber) { q += ' AND case_number = ?'; p.push(caseNumber); }
  res.json(db.prepare(q + ' ORDER BY created_at DESC').all(...p));
});

app.get('/api/evidence/:id', authenticateToken, (req, res) => {
  const ev = db.prepare('SELECT * FROM v_evidence_summary WHERE id = ?').get(req.params.id);
  if (!ev) return res.status(404).json({ error: 'Evidence not found' });
  if (req.user.role === 'personnel' && ev.assigned_officer !== req.user.username) {
    logAudit('PERMISSION_DENIED', req.user.username, req.params.id, 'Unauthorized', req.ip);
    return res.status(403).json({ error: 'Access denied' });
  }
  logAudit('EVIDENCE_VIEWED', req.user.username, req.params.id, null, req.ip);
  res.json(ev);
});

app.post('/api/evidence', authenticateToken, requireAdmin, (req, res) => {
  const { caseNumber, description, type, status, assignedOfficer, collectedBy, dateCollected, location, notes } = req.body;
  if (!caseNumber || !description || !type || !assignedOfficer || !dateCollected)
    return res.status(400).json({ error: 'Missing required fields' });
  const id = generateEvId();
  db.prepare(`INSERT INTO evidence (id, case_number, description, type, status, assigned_officer, collected_by, date_collected, location, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(id, caseNumber, description, type, status || 'Collected', assignedOfficer, collectedBy || assignedOfficer, dateCollected, location || null, notes || null);
  db.prepare(`INSERT INTO custody_events (evidence_id, case_number, action, handler, date, notes) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(id, caseNumber, 'Collected', collectedBy || assignedOfficer, dateCollected, notes || 'Initial collection');
  logAudit('EVIDENCE_CREATED', req.user.username, id, `Case: ${caseNumber}`, req.ip);
  res.status(201).json({ id, message: 'Evidence logged' });
});

app.delete('/api/evidence/:id', authenticateToken, requireAdmin, (req, res) => {
  const { id } = req.params;
  if (db.prepare('SELECT COUNT(*) as c FROM custody_events WHERE evidence_id = ?').get(id).c > 0)
    return res.status(409).json({ error: 'Cannot delete evidence with custody events' });
  if (!db.prepare('SELECT id FROM evidence WHERE id = ?').get(id))
    return res.status(404).json({ error: 'Evidence not found' });
  db.prepare('DELETE FROM evidence WHERE id = ?').run(id);
  logAudit('EVIDENCE_DELETED', req.user.username, id, null, req.ip);
  res.json({ message: 'Deleted' });
});

// ============================================================
// CUSTODY
// ============================================================
app.get('/api/custody', authenticateToken, (req, res) => {
  let q = `SELECT ce.* FROM custody_events ce JOIN evidence e ON ce.evidence_id = e.id WHERE 1=1`;
  const p = [];
  if (req.user.role === 'personnel') { q += ' AND e.assigned_officer = ?'; p.push(req.user.username); }
  res.json(db.prepare(q + ' ORDER BY ce.date ASC').all(...p));
});

app.get('/api/evidence/:id/custody', authenticateToken, (req, res) => {
  const ev = db.prepare('SELECT assigned_officer FROM evidence WHERE id = ?').get(req.params.id);
  if (!ev) return res.status(404).json({ error: 'Not found' });
  if (req.user.role === 'personnel' && ev.assigned_officer !== req.user.username) return res.status(403).json({ error: 'Access denied' });
  res.json(db.prepare('SELECT * FROM custody_events WHERE evidence_id = ? ORDER BY date ASC').all(req.params.id));
});

app.post('/api/evidence/:id/custody', authenticateToken, requireAdmin, (req, res) => {
  const { action, handler, date, notes, newStatus } = req.body;
  if (!action || !handler || !date) return res.status(400).json({ error: 'Action, handler, and date required' });
  const ev = db.prepare('SELECT case_number FROM evidence WHERE id = ?').get(req.params.id);
  if (!ev) return res.status(404).json({ error: 'Not found' });
  db.prepare(`INSERT INTO custody_events (evidence_id, case_number, action, handler, date, notes, new_status) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(req.params.id, ev.case_number, action, handler, date, notes || null, newStatus || null);
  if (newStatus) db.prepare('UPDATE evidence SET status = ? WHERE id = ?').run(newStatus, req.params.id);
  logAudit('CUSTODY_EVENT_ADDED', req.user.username, req.params.id, action, req.ip);
  res.status(201).json({ message: 'Custody event logged' });
});

// ============================================================
// USERS
// ============================================================
app.get('/api/users', authenticateToken, requireAdmin, (req, res) => {
  res.json(db.prepare(`SELECT id, username, name, badge, role, is_active, created_at, last_login, (SELECT COUNT(*) FROM evidence WHERE assigned_officer = users.username) as evidence_count FROM users ORDER BY created_at DESC`).all());
});

app.post('/api/users', authenticateToken, requireAdmin, (req, res) => {
  const { username, password, name, badge, role } = req.body;
  if (!username || !password || !name) return res.status(400).json({ error: 'Username, password, name required' });
  if (db.prepare('SELECT id FROM users WHERE username = ?').get(username)) return res.status(409).json({ error: 'Username exists' });
  const id = uuidv4();
  db.prepare(`INSERT INTO users (id, username, password_hash, name, badge, role) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(id, username.toLowerCase(), bcrypt.hashSync(password, 12), name, badge || null, role || 'personnel');
  logAudit('USER_CREATED', req.user.username, null, `Created: ${username}`, req.ip);
  res.status(201).json({ id, message: 'User created' });
});

app.put('/api/users/:id', authenticateToken, requireAdmin, (req, res) => {
  const { name, badge, role, password, isActive } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const updates = [], params = [];
  if (name)             { updates.push('name = ?');          params.push(name); }
  if (badge !== undefined) { updates.push('badge = ?');      params.push(badge); }
  if (role) {
    if (!['admin', 'personnel'].includes(role)) return res.status(400).json({ error: "Role must be 'admin' or 'personnel'" });
    updates.push('role = ?'); params.push(role);
  }
  if (isActive !== undefined) { updates.push('is_active = ?'); params.push(isActive ? 1 : 0); }
  if (password) { updates.push('password_hash = ?'); params.push(bcrypt.hashSync(password, 12)); }
  if (!updates.length) return res.status(400).json({ error: 'Nothing to update' });
  params.push(req.params.id);
  db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...params);
  logAudit('USER_UPDATED', req.user.username, null, `Updated: ${user.username}`, req.ip);
  res.json({ message: 'User updated' });
});

app.delete('/api/users/:id', authenticateToken, requireAdmin, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.username === 'admin') return res.status(403).json({ error: 'Cannot delete root admin' });
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  logAudit('USER_DELETED', req.user.username, null, `Deleted: ${user.username}`, req.ip);
  res.json({ message: 'Deleted' });
});

// ============================================================
// QR
// ============================================================
app.post('/api/evidence/:id/qr', authenticateToken, (req, res) => {
  const ev = db.prepare('SELECT * FROM evidence WHERE id = ?').get(req.params.id);
  if (!ev) return res.status(404).json({ error: 'Not found' });
  if (req.user.role === 'personnel' && ev.assigned_officer !== req.user.username) return res.status(403).json({ error: 'Access denied' });
  const token = uuidv4();
  db.prepare(`INSERT INTO qr_tokens (id, evidence_id, token) VALUES (?, ?, ?)`).run(uuidv4(), req.params.id, token);
  res.json({ token, url: `${req.protocol}://${req.get('host')}/api/qr/${token}` });
});

app.get('/api/qr/:token', (req, res) => {
  const qr = db.prepare(`SELECT qr_tokens.*, evidence.case_number FROM qr_tokens JOIN evidence ON qr_tokens.evidence_id = evidence.id WHERE qr_tokens.token = ? AND qr_tokens.is_revoked = 0 AND (qr_tokens.expires_at IS NULL OR qr_tokens.expires_at > CURRENT_TIMESTAMP)`).get(req.params.token);
  if (!qr) { logAudit('QR_ACCESS_DENIED', null, null, `Token: ${req.params.token.substring(0,8)}…`, req.ip); return res.status(404).json({ error: 'Invalid or expired QR' }); }
  db.prepare('UPDATE qr_tokens SET scan_count = scan_count + 1, last_scanned = CURRENT_TIMESTAMP WHERE id = ?').run(qr.id);
  logAudit('QR_SCANNED', null, qr.evidence_id, `Token: ${req.params.token.substring(0,8)}…`, req.ip);
  res.json({ evidenceId: qr.evidence_id, caseNumber: qr.case_number });
});

// ============================================================
// STATS & AUDIT
// ============================================================
app.get('/api/stats', authenticateToken, (req, res) => {
  const p = [];
  let eQ = 'SELECT COUNT(*) as total FROM evidence';
  let cQ = 'SELECT COUNT(DISTINCT case_number) as cases FROM evidence';
  let sQ = `SELECT COUNT(*) as stored FROM evidence WHERE status = 'Stored'`;
  let cuQ = 'SELECT COUNT(*) as events FROM custody_events';
  if (req.user.role === 'personnel') {
    eQ += ' WHERE assigned_officer = ?'; cQ += ' WHERE assigned_officer = ?';
    sQ += ' AND assigned_officer = ?';
    cuQ = `SELECT COUNT(*) as events FROM custody_events ce JOIN evidence e ON ce.evidence_id = e.id WHERE e.assigned_officer = ?`;
    p.push(req.user.username);
  }
  res.json({ total: db.prepare(eQ).get(...p).total, cases: db.prepare(cQ).get(...p).cases, stored: db.prepare(sQ).get(...p).stored, events: db.prepare(cuQ).get(...p).events });
});

app.get('/api/audit', authenticateToken, requireAdmin, (req, res) => {
  const { eventType, username, limit = 100 } = req.query;
  let q = 'SELECT * FROM audit_log WHERE 1=1'; const p = [];
  if (eventType) { q += ' AND event_type = ?'; p.push(eventType); }
  if (username)  { q += ' AND username = ?';   p.push(username); }
  res.json(db.prepare(q + ' ORDER BY created_at DESC LIMIT ?').all(...p, parseInt(limit)));
});

// ============================================================
// ERROR HANDLER
// ============================================================
app.use((err, req, res, next) => {
  console.error('[Error]', err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// ============================================================
// START
// ============================================================
app.listen(PORT, () => {
  console.log(`🚀 EVCHAIN running on port ${PORT}`);
  console.log(`🌐 CORS: gutblast62-dev.github.io + railway/render/netlify/vercel`);
  console.log(`🔐 JWT: ${JWT_SECRET === 'evchain-secret-key-change-in-production' ? '⚠ DEFAULT KEY' : 'Custom ✓'}`);
});
