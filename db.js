const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const DB_PATH = path.join(__dirname, 'jartix.db');
const db = new Database(DB_PATH);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Initialize tables
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        hwid TEXT DEFAULT NULL,
        role TEXT DEFAULT 'user',
        created_at TEXT DEFAULT (datetime('now')),
        last_login TEXT
    );

    CREATE TABLE IF NOT EXISTS keys (
        id TEXT PRIMARY KEY,
        key_code TEXT UNIQUE NOT NULL,
        user_id TEXT DEFAULT NULL,
        key_type TEXT DEFAULT 'client',
        duration_days INTEGER DEFAULT 30,
        hwid TEXT DEFAULT NULL,
        hwid_limit INTEGER DEFAULT 1,
        active INTEGER DEFAULT 1,
        activated_at TEXT DEFAULT NULL,
        expires_at TEXT DEFAULT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        created_by TEXT DEFAULT 'admin',
        FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        hwid TEXT NOT NULL,
        ip TEXT,
        token TEXT UNIQUE NOT NULL,
        active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now')),
        last_active TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event TEXT NOT NULL,
        user_id TEXT,
        hwid TEXT,
        ip TEXT,
        details TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    );
`);

// Create default admin if not exists
const adminExists = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
if (!adminExists) {
    const hash = bcrypt.hashSync('admin123', 10);
    db.prepare('INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)').run(
        uuidv4(), 'admin', hash, 'admin'
    );
    console.log('[DB] Default admin created: admin / admin123');
}

// Helper: generate key
function generateKey() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const segments = [];
    segments.push('JX');
    for (let s = 0; s < 4; s++) {
        let seg = '';
        for (let i = 0; i < 5; i++) {
            seg += chars[Math.floor(Math.random() * chars.length)];
        }
        segments.push(seg);
    }
    return segments.join('-');
}

// Helper: generate HWID from system info
function hashHWID(rawHWID) {
    return crypto.createHash('sha256').update(rawHWID).digest('hex');
}

module.exports = {
    db,
    generateKey,
    hashHWID
};
