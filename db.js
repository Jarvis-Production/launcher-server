const { createClient } = require('@libsql/client');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const TURSO_URL = process.env.TURSO_URL;
const TURSO_TOKEN = process.env.TURSO_AUTH_TOKEN;

let client;
let isTurso = false;

if (TURSO_URL && TURSO_TOKEN) {
    client = createClient({ url: TURSO_URL, authToken: TURSO_TOKEN });
    isTurso = true;
    console.log('[DB] Connected to Turso');
} else {
    const Database = require('better-sqlite3');
    const path = require('path');
    client = new Database(path.join(__dirname, 'jartix.db'));
    client.pragma('journal_mode = WAL');
    client.pragma('foreign_keys = ON');
    console.log('[DB] Using local SQLite');
}

// Async wrapper for Turso
const db = {
    prepare(sql) {
        return {
            async get(...args) {
                if (!isTurso) {
                    return client.prepare(sql).get(...args);
                }
                const result = await client.execute({ sql, args: args.length === 1 && Array.isArray(args[0]) ? args[0] : args });
                return result.rows[0] || null;
            },
            async all(...args) {
                if (!isTurso) {
                    return client.prepare(sql).all(...args);
                }
                const result = await client.execute({ sql, args: args.length === 1 && Array.isArray(args[0]) ? args[0] : args });
                return result.rows;
            },
            async run(...args) {
                if (!isTurso) {
                    return client.prepare(sql).run(...args);
                }
                const result = await client.execute({ sql, args: args.length === 1 && Array.isArray(args[0]) ? args[0] : args });
                return { changes: result.rowsAffected || 0 };
            }
        };
    },
    async exec(sql) {
        if (!isTurso) {
            client.exec(sql);
        } else {
            const statements = sql.split(';').filter(s => s.trim());
            for (const s of statements) {
                try { await client.execute(s.trim()); } catch (e) {}
            }
        }
    },
    pragma(str) {
        if (!isTurso && client.pragma) client.pragma(str);
    }
};

// Initialize
const initSQL = [
    `CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, hwid TEXT DEFAULT NULL, role TEXT DEFAULT 'user', created_at TEXT DEFAULT (datetime('now')), last_login TEXT)`,
    `CREATE TABLE IF NOT EXISTS keys (id TEXT PRIMARY KEY, key_code TEXT UNIQUE NOT NULL, user_id TEXT DEFAULT NULL, key_type TEXT DEFAULT 'client', duration_days INTEGER DEFAULT 30, hwid TEXT DEFAULT NULL, hwid_limit INTEGER DEFAULT 1, active INTEGER DEFAULT 1, activated_at TEXT DEFAULT NULL, expires_at TEXT DEFAULT NULL, created_at TEXT DEFAULT (datetime('now')), created_by TEXT DEFAULT 'admin')`,
    `CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user_id TEXT, hwid TEXT NOT NULL, ip TEXT, token TEXT UNIQUE NOT NULL, active INTEGER DEFAULT 1, created_at TEXT DEFAULT (datetime('now')), last_active TEXT DEFAULT (datetime('now')))`,
    `CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, user_id TEXT, hwid TEXT, ip TEXT, details TEXT, created_at TEXT DEFAULT (datetime('now')))`,
    `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`,
    `CREATE TABLE IF NOT EXISTS telemetry (id INTEGER PRIMARY KEY AUTOINCREMENT, hwid TEXT NOT NULL, username TEXT, server TEXT, ip TEXT, brand TEXT, version TEXT, timestamp INTEGER NOT NULL, created_at TEXT DEFAULT (datetime('now')))`
];

(async () => {
    for (const sql of initSQL) {
        try { await db.exec(sql); } catch (e) {}
    }

    // Migration: make sessions.user_id nullable for client keys without user accounts
    try {
        await db.exec(`CREATE TABLE IF NOT EXISTS sessions_new (id TEXT PRIMARY KEY, user_id TEXT, hwid TEXT NOT NULL, ip TEXT, token TEXT UNIQUE NOT NULL, active INTEGER DEFAULT 1, created_at TEXT DEFAULT (datetime('now')), last_active TEXT DEFAULT (datetime('now')))`);
        await db.exec(`INSERT OR IGNORE INTO sessions_new SELECT * FROM sessions`);
        await db.exec(`DROP TABLE IF EXISTS sessions`);
        await db.exec(`ALTER TABLE sessions_new RENAME TO sessions`);
    } catch (e) {}

    // Default admin
    try {
        const existing = await db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
        if (!existing) {
            const hash = bcrypt.hashSync('admin123', 10);
            await db.prepare('INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)').run(uuidv4(), 'admin', hash, 'admin');
            console.log('[DB] Default admin: admin / admin123');
        }
    } catch (e) { console.log('[DB] Admin init error:', e.message); }

    // Store encryption key if not exists
    try {
        const keyRow = await db.prepare('SELECT value FROM settings WHERE key = ?').get('encryption_key');
        if (!keyRow) {
            const newKey = crypto.randomBytes(32).toString('hex');
            await db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)').run('encryption_key', newKey);
            console.log('[DB] Generated and stored encryption key');
        }
    } catch (e) { console.log('[DB] Encryption key init error:', e.message); }
})();

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
