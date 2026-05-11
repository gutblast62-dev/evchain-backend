require('dotenv').config();
const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const crypto = require('crypto'); // ← ADDED for SHA-256 hash verification

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'evchain-secret-key-change-in-production';
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000;
const UNIT_CODE = process.env.UNIT_CODE || 'PNPRFUCAR'; // ← ADDED: configurable per deployment

// ============================================================
// CORS — RUNS BEFORE EVERYTHING ELSE
// ============================================================
const corsOptions = {
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
  exposedHeaders: ['Authorization'],
  maxAge: 86400
};

app.use(cors(corsOptions));

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

function requireAdminOrSelf(req, res, next) {
  if (req.user.role === 'admin' || req.user.id === req.params.id) {
    next();
  } else {
    logAudit('PERMISSION_DENIED', req.user.username, null, 'Unauthorized user update', req.ip);
    return res.status(403).json({ error: 'Access denied' });
  }
}

// ============================================================
// QR COMPOSITE ID VERIFICATION (Research Compliant)
// Composite ID: UNIT-CASE-EVSEQ-TIMESTAMP-HASH
// ============================================================
function verifyCompositeId(compositeIdString) {
  const parts = compositeIdString.split('-');
  if (parts.length < 5) return { valid: false, reason: 'Invalid format' };

  const unitCode = parts[0];
  const hashIdx = parts.length - 1;
  const timestamp = parts[hashIdx - 1];
  const evSeq = parts[hashIdx - 2];
  const caseRef = parts.slice(1, hashIdx - 2).join('-');
  const providedHash = parts[hashIdx];

  const baseString = `${unitCode}-${caseRef}-${evSeq}-${timestamp}`;
  const computedHash = crypto.createHash('sha256').update(baseString).digest('hex').substring(0, 12);

  return {
    valid: computedHash === providedHash,
    unitCode, caseRef, evSeq,
    timestamp: parseInt(timestamp),
    providedHash, computedHash
  };
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

  const normalizedUsername = username.toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(normalizedUsername);
  if (!user) { logAudit('LOGIN_FAILED', username, null, 'Not found', req.ip); return res.status(401).json({ error: 'Invalid credentials' }); }
  if (user.locked_until && new Date(user.locked_until) > new Date()) return res.status(423).json({ error: 'Account locked. Try again later.' });
  if (!user.is_active) return res.status(403).json({ error: 'Account pending admin approval' });

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

app.post('/api/auth/register', authLimiter, (req, res) => {
  const { username, password, name, badge } = req.body;
  if (!username || !password || !name) return res.status(400).json({ error: 'Username, password, name required' });
  const normalizedUsername = username.toLowerCase();
  if (db.prepare('SELECT id FROM users WHERE username = ?').get(normalizedUsername)) return res.status(409).json({ error: 'Username exists' });
  const id = uuidv4();
  db.prepare(`INSERT INTO users (id, username, password_hash, name, badge, role, is_active) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(id, normalizedUsername, bcrypt.hashSync(password, 12), name, badge || null, 'personnel', 0);
  logAudit('USER_REGISTERED', username, null, 'Pending admin approval', req.ip);
  res.status(201).json({ message: 'Registration submitted. Await admin approval.' });
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

app.put('/api/evidence/:id', authenticateToken, requireAdmin, (req, res) => {
  const { description, type, status, assignedOfficer, location, notes } = req.body;
  const ev = db.prepare('SELECT * FROM evidence WHERE id = ?').get(req.params.id);
  if (!ev) return res.status(404).json({ error: 'Evidence not found' });
  const updates = [], params = [];
  if (description) { updates.push('description = ?'); params.push(description); }
  if (type) { updates.push('type = ?'); params.push(type); }
  if (status) { updates.push('status = ?'); params.push(status); }
  if (assignedOfficer) { updates.push('assigned_officer = ?'); params.push(assignedOfficer); }
  if (location !== undefined) { updates.push('location = ?'); params.push(location); }
  if (notes !== undefined) { updates.push('notes = ?'); params.push(notes); }
  if (!updates.length) return res.status(400).json({ error: 'Nothing to update' });
  params.push(req.params.id);
  db.prepare(`UPDATE evidence SET ${updates.join(', ')} WHERE id = ?`).run(...params);
  logAudit('EVIDENCE_UPDATED', req.user.username, req.params.id, `Updated: ${updates.join(', ')}`, req.ip);
  res.json({ message: 'Evidence updated' });
});

app.get('/api/evidence/:id/timeline', authenticateToken, (req, res) => {
  const ev = db.prepare('SELECT assigned_officer FROM evidence WHERE id = ?').get(req.params.id);
  if (!ev) return res.status(404).json({ error: 'Not found' });
  if (req.user.role === 'personnel' && ev.assigned_officer !== req.user.username) return res.status(403).json({ error: 'Access denied' });
  const custody = db.prepare('SELECT ce.*, "custody" as event_type FROM custody_events ce WHERE ce.evidence_id = ? ORDER BY ce.date ASC').all(req.params.id);
  const audit = req.user.role === 'admin' ? db.prepare('SELECT al.*, "audit" as event_type FROM audit_log al WHERE al.evidence_id = ? ORDER BY al.created_at ASC').all(req.params.id) : [];
  const timeline = [...custody, ...audit].sort((a, b) => new Date(a.date || a.created_at) - new Date(b.date || a.created_at));
  res.json(timeline);
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

app.put('/api/users/:id', authenticateToken, requireAdminOrSelf, (req, res) => {
  const { name, badge, role, password, isActive } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  
  // Permission checks
  const isAdmin = req.user.role === 'admin';
  const isSelf = req.user.id === req.params.id;
  
  if (role && !isAdmin) return res.status(403).json({ error: 'Only admins can change roles' });
  if (isActive !== undefined && !isAdmin) return res.status(403).json({ error: 'Only admins can change activation status' });
  
  const updates = [], params = [];
  if (name)             { updates.push('name = ?');          params.push(name); }
  if (badge !== undefined) { updates.push('badge = ?');      params.push(badge); }
  if (role && isAdmin) {
    if (!['admin', 'personnel'].includes(role)) return res.status(400).json({ error: "Role must be 'admin' or 'personnel'" });
    updates.push('role = ?'); params.push(role);
  }
  if (isActive !== undefined && isAdmin) { updates.push('is_active = ?'); params.push(isActive ? 1 : 0); }
  if (password) { updates.push('password_hash = ?'); params.push(bcrypt.hashSync(password, 12)); }
  if (!updates.length) return res.status(400).json({ error: 'Nothing to update' });
  params.push(req.params.id);
  db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...params);
  logAudit('USER_UPDATED', req.user.username, null, `Updated: ${user.username}`, req.ip);
  res.json({ message: 'User updated' });
});

app.put('/api/users/:id/activate', authenticateToken, requireAdmin, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.is_active) return res.status(400).json({ error: 'User already active' });
  db.prepare('UPDATE users SET is_active = 1 WHERE id = ?').run(req.params.id);
  logAudit('USER_ACTIVATED', req.user.username, null, `Activated: ${user.username}`, req.ip);
  res.json({ message: 'User activated' });
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
// QR — ENHANCED WITH COMPOSITE ID (Research Compliant)
// ============================================================

// Generate QR with composite identifier
app.post('/api/evidence/:id/qr', authenticateToken, (req, res) => {
  const ev = db.prepare('SELECT * FROM evidence WHERE id = ?').get(req.params.id);
  if (!ev) return res.status(404).json({ error: 'Not found' });
  if (req.user.role === 'personnel' && ev.assigned_officer !== req.user.username) return res.status(403).json({ error: 'Access denied' });

  const timestamp = Date.now();
  const baseString = `${UNIT_CODE}-${ev.case_number}-${ev.id}-${timestamp}`;
  const hash = crypto.createHash('sha256').update(baseString).digest('hex').substring(0, 12);
  const compositeId = `${baseString}-${hash}`;

  const token = uuidv4();
  const tokenId = uuidv4();
  db.prepare(`INSERT INTO qr_tokens (id, evidence_id, token) VALUES (?, ?, ?)`).run(tokenId, req.params.id, token);

  const qrUrl = `${req.protocol}://${req.get('host')}/api/qr/verify?cid=${encodeURIComponent(compositeId)}&token=${token}`;

  res.json({ token, url: qrUrl, compositeId });
});

// Verify composite ID from scanned QR
app.get('/api/qr/verify', (req, res) => {
  const { cid, token } = req.query;
  if (!cid) return res.status(400).json({ error: 'Composite ID required' });

  const result = verifyCompositeId(cid);
  if (!result.valid) {
    logAudit('QR_VERIFY_FAILED', null, result.evSeq, `Invalid CID: ${cid}`, req.ip);
    return res.status(400).json({ error: 'Invalid or tampered QR code', details: result });
  }

  // Optional: also verify token if provided
  if (token) {
    const qr = db.prepare(`SELECT * FROM qr_tokens WHERE token = ? AND is_revoked = 0 AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`).get(token);
    if (!qr) {
      return res.status(404).json({ error: 'Invalid or expired token', details: result });
    }
    db.prepare('UPDATE qr_tokens SET scan_count = scan_count + 1, last_scanned = CURRENT_TIMESTAMP WHERE id = ?').run(qr.id);
  }

  const ev = db.prepare('SELECT id, case_number, status FROM evidence WHERE id = ?').get(result.evSeq);
  if (!ev) {
    return res.status(404).json({ error: 'Evidence not found', details: result });
  }

  logAudit('QR_VERIFY_SUCCESS', null, result.evSeq, `CID verified: ${cid}`, req.ip);
  res.json({ valid: true, evidenceId: ev.id, caseNumber: ev.case_number, status: ev.status, details: result });
});

// Legacy QR token lookup (kept for backward compatibility)
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
  console.log(`🏷️  QR Composite ID: ${UNIT_CODE} (SHA-256 verified)`);
});
