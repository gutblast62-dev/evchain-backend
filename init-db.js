const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');

const dbPath = path.join(__dirname, 'evchain.db');
const db = new Database(dbPath);

// Enable WAL mode for better concurrency
db.pragma('journal_mode = WAL');

// Create tables
db.exec(`
  -- Users table
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

  -- Evidence table
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
    hash_sha256 TEXT,
    is_biohazard INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (assigned_officer) REFERENCES users(username)
  );

  -- Custody events table (append-only)
  CREATE TABLE IF NOT EXISTS custody_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT NOT NULL,
    case_number TEXT,
    action TEXT NOT NULL,
    handler TEXT NOT NULL,
    date TEXT NOT NULL,
    notes TEXT,
    new_status TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,
    FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE RESTRICT
  );

  -- Audit log (append-only)
  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    username TEXT,
    evidence_id TEXT,
    details TEXT,
    ip_address TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  -- QR tokens table
  CREATE TABLE IF NOT EXISTS qr_tokens (
    id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at TEXT,
    is_revoked INTEGER DEFAULT 0,
    scan_count INTEGER DEFAULT 0,
    last_scanned TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE
  );

  -- Create indexes for performance
  CREATE INDEX IF NOT EXISTS idx_evidence_officer ON evidence(assigned_officer);
  CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_number);
  CREATE INDEX IF NOT EXISTS idx_evidence_status ON evidence(status);
  CREATE INDEX IF NOT EXISTS idx_custody_evidence ON custody_events(evidence_id);
  CREATE INDEX IF NOT EXISTS idx_custody_date ON custody_events(date);
  CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(username);
  CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_log(event_type);

  -- Trigger to prevent custody_events deletion
  CREATE TRIGGER IF NOT EXISTS prevent_custody_delete
  BEFORE DELETE ON custody_events
  BEGIN
    SELECT RAISE(ABORT, 'Custody events are immutable and cannot be deleted');
  END;

  -- Trigger to prevent custody_events update
  CREATE TRIGGER IF NOT EXISTS prevent_custody_update
  BEFORE UPDATE ON custody_events
  BEGIN
    SELECT RAISE(ABORT, 'Custody events are immutable and cannot be modified');
  END;

  -- Trigger to update evidence updated_at
  CREATE TRIGGER IF NOT EXISTS update_evidence_timestamp
  AFTER UPDATE ON evidence
  BEGIN
    UPDATE evidence SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
  END;
`);

// Insert default admin user
const adminPassword = bcrypt.hashSync('admin123', 12);
const adminExists = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');

if (!adminExists) {
  db.prepare(`
    INSERT INTO users (id, username, password_hash, name, badge, role, is_active)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    'user-admin-001',
    'admin',
    adminPassword,
    'System Administrator',
    '',
    'admin',
    1
  );
  console.log('✅ Default admin user created: admin / admin123');
}

// Create view for evidence summary
db.exec(`
  CREATE VIEW IF NOT EXISTS v_evidence_summary AS
  SELECT 
    e.*,
    u.name as officer_name,
    COUNT(ce.id) as custody_count
  FROM evidence e
  LEFT JOIN users u ON e.assigned_officer = u.username
  LEFT JOIN custody_events ce ON e.id = ce.evidence_id
  GROUP BY e.id;
`);

console.log('✅ Database initialized successfully at:', dbPath);
console.log('📊 Tables created: users, evidence, custody_events, audit_log, qr_tokens');

db.close();
