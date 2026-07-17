const { createClient } = require('@libsql/client');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const TURSO_URL = process.env.TURSO_URL;
const TURSO_TOKEN = process.env.TURSO_AUTH_TOKEN;

let client;

if (TURSO_URL && TURSO_TOKEN) {
    client = createClient({ url: TURSO_URL, authToken: TURSO_TOKEN });
    console.log('[DB] Connected to Turso');
} else {
    const Database = require('better-sqlite3');
    const path = require('path');
    const localDb = new Database(path.join(__dirname, 'jartix.db'));
    localDb.pragma('journal_mode = WAL');
    localDb.pragma('foreign_keys = ON');
    client = localDb;
    console.log('[DB] Using local SQLite');
}

// Wrapper that mimics better-sqlite3 API for compatibility
const db = {
    prepare(sql) {
        return {
            get(...args) {
                if (client.prepare) {
                    // Local SQLite (better-sqlite3)
                    return client.prepare(sql).get(...args);
                } else {
                    // Turso
                    const result = client.executeSync({ sql, args: args.length === 1 && Array.isArray(args[0]) ? args[0] : args });
                    return result.rows[0] || null;
                }
            },
            all(...args) {
                if (client.prepare) {
                    return client.prepare(sql).all(...args);
                } else {
                    const result = client.executeSync({ sql, args: args.length === 1 && Array.isArray(args[0]) ? args[0] : args });
                    return result.rows;
                }
            },
            run(...args) {
                if (client.prepare) {
                    return client.prepare(sql).run(...args);
                } else {
                    return client.executeSync({ sql, args: args.length === 1 && Array.isArray(args[0]) ? args[0] : args });
                }
            }
        };
    },
    exec(sql) {
        if (client.exec) {
            client.exec(sql);
        } else {
            // Turso: split by semicolons and execute each
            sql.split(';').filter(s => s.trim()).forEach(s => {
                try { client.executeSync(s.trim()); } catch (e) {}
            });
        }
    },
    pragma(str) {
        if (client.pragma) client.pragma(str);
    }
};

// Initialize
const initSQL = [
    `CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, hwid TEXT DEFAULT NULL, role TEXT DEFAULT 'user', created_at TEXT DEFAULT (datetime('now')), last_login TEXT)`,
    `CREATE TABLE IF NOT EXISTS keys (id TEXT PRIMARY KEY, key_code TEXT UNIQUE NOT NULL, user_id TEXT DEFAULT NULL, key_type TEXT DEFAULT 'client', duration_days INTEGER DEFAULT 30, hwid TEXT DEFAULT NULL, hwid_limit INTEGER DEFAULT 1, active INTEGER DEFAULT 1, activated_at TEXT DEFAULT NULL, expires_at TEXT DEFAULT NULL, created_at TEXT DEFAULT (datetime('now')), created_by TEXT DEFAULT 'admin')`,
    `CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, hwid TEXT NOT NULL, ip TEXT, token TEXT UNIQUE NOT NULL, active INTEGER DEFAULT 1, created_at TEXT DEFAULT (datetime('now')), last_active TEXT DEFAULT (datetime('now')))`,
    `CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, user_id TEXT, hwid TEXT, ip TEXT, details TEXT, created_at TEXT DEFAULT (datetime('now')))`,
    `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`
];

initSQL.forEach(sql => { try { db.exec(sql); } catch (e) {} });

// Default admin
try {
    const existing = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
    if (!existing) {
        const hash = bcrypt.hashSync('admin123', 10);
        db.prepare('INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)').run(uuidv4(), 'admin', hash, 'admin');
        console.log('[DB] Default admin: admin / admin123');
    }
} catch (e) { console.log('[DB] Admin init error:', e.message); }

function generateKey() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const segments = ['JX'];
    for (let s = 0; s < 4; s++) {
        let seg = '';
        for (let i = 0; i < 5; i++) seg += chars[Math.floor(Math.random() * chars.length)];
        segments.push(seg);
    }
    return segments.join('-');
}

function hashHWID(rawHWID) {
    return crypto.createHash('sha256').update(rawHWID).digest('hex');
}

module.exports = { db, generateKey, hashHWID };
