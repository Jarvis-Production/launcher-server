const express = require('express');
const router = express.Router();
const path = require('path');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { db, generateKey, hashHWID } = require('./db');

const JWT_SECRET = process.env.JWT_SECRET || 'jartix-secret-change-in-production';
const upload = multer({ dest: path.join(__dirname, 'client') });

// ── Admin: Login ──────────────────────────────────────
router.post('/api/login', (req, res) => {
    try {
        const { username, password } = req.body;
        const user = db.prepare('SELECT * FROM users WHERE username = ? AND role = ?').get(username, 'admin');
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });
        if (!bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: 'Invalid credentials' });

        const token = jwt.sign({ id: user.id, role: 'admin' }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ ok: true, token });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ── Admin middleware ───────────────────────────────────
function adminAuth(req, res, next) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
        req.admin = decoded;
        next();
    } catch {
        res.status(401).json({ error: 'Invalid token' });
    }
}

// ── Admin: Dashboard stats ────────────────────────────
router.get('/api/stats', adminAuth, (req, res) => {
    try {
        const totalUsers = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
        const totalKeys = db.prepare('SELECT COUNT(*) as c FROM keys').get().c;
        const activeKeys = db.prepare('SELECT COUNT(*) as c FROM keys WHERE active = 1 AND expires_at > datetime(\'now\')').get().c;
        const activeSessions = db.prepare('SELECT COUNT(*) as c FROM sessions WHERE active = 1 AND last_active > datetime(\'now\', \'-5 minutes\')').get().c;
        const totalHWIDResets = db.prepare('SELECT COUNT(*) as c FROM logs WHERE event = ?').get('hwid_reset').c;

        res.json({ totalUsers, totalKeys, activeKeys, activeSessions, totalHWIDResets });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ── Admin: Keys CRUD ──────────────────────────────────
router.get('/api/keys', adminAuth, (req, res) => {
    try {
        const keys = db.prepare(`
            SELECT k.*, u.username FROM keys k
            LEFT JOIN users u ON k.user_id = u.id
            ORDER BY k.created_at DESC
        `).all();
        res.json(keys);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

router.post('/api/keys/generate', adminAuth, (req, res) => {
    try {
        const { count = 1, duration_days = 30, hwid_limit = 1, key_type = 'client' } = req.body;
        const validTypes = ['admin', 'client'];
        const type = validTypes.includes(key_type) ? key_type : 'client';
        const keys = [];
        const stmt = db.prepare('INSERT INTO keys (id, key_code, key_type, duration_days, hwid_limit, created_by) VALUES (?, ?, ?, ?, ?, ?)');
        for (let i = 0; i < Math.min(count, 100); i++) {
            const id = uuidv4();
            const keyCode = generateKey();
            stmt.run(id, keyCode, type, duration_days, hwid_limit, 'admin');
            keys.push(keyCode);
        }
        db.prepare('INSERT INTO logs (event, details) VALUES (?, ?)').run('keys_generated', `${count} ${type} keys`);
        res.json({ ok: true, keys, keyType: type });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

router.delete('/api/keys/:id', adminAuth, (req, res) => {
    try {
        db.prepare('UPDATE keys SET active = 0 WHERE id = ?').run(req.params.id);
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ── Admin: Users ──────────────────────────────────────
router.get('/api/users', adminAuth, (req, res) => {
    try {
        const users = db.prepare('SELECT id, username, role, hwid, created_at, last_login FROM users ORDER BY created_at DESC').all();
        res.json(users);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ── Admin: HWID Reset ─────────────────────────────────
router.post('/api/users/:id/reset-hwid', adminAuth, (req, res) => {
    try {
        db.prepare('UPDATE keys SET hwid = NULL, user_id = NULL, activated_at = NULL, expires_at = NULL WHERE user_id = ?').run(req.params.id);
        db.prepare('UPDATE users SET hwid = NULL WHERE id = ?').run(req.params.id);
        db.prepare('UPDATE sessions SET active = 0 WHERE user_id = ?').run(req.params.id);
        db.prepare('INSERT INTO logs (event, user_id, details) VALUES (?, ?, ?)').run('hwid_reset', req.params.id, 'admin reset');
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ── Admin: Logs ───────────────────────────────────────
router.get('/api/logs', adminAuth, (req, res) => {
    try {
        const limit = Math.min(parseInt(req.query.limit) || 50, 200);
        const logs = db.prepare('SELECT * FROM logs ORDER BY created_at DESC LIMIT ?').all(limit);
        res.json(logs);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ── Admin: Upload client JAR (stored in DB, not filesystem) ──
router.post('/api/client/upload', adminAuth, upload.single('client'), (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'No file' });
        const fs = require('fs');
        const jarData = fs.readFileSync(req.file.path);
        fs.unlinkSync(req.file.path); // cleanup temp
        db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').run('client_jar', jarData.toString('base64'));
        db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').run('client_version', req.body.version || '1.0.0');
        db.prepare('INSERT INTO logs (event, details) VALUES (?, ?)').run('client_upload', `version ${req.body.version || '1.0.0'}, size ${jarData.length} bytes`);
        res.json({ ok: true, message: 'Client uploaded', size: jarData.length });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ── Serve admin panel ─────────────────────────────────
router.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

module.exports = router;
