const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const { db, hashHWID } = require('./db');

const JWT_SECRET = process.env.JWT_SECRET || 'jartix-secret-change-in-production';

router.post('/auth/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
        if (username.length < 3 || username.length > 20) return res.status(400).json({ error: 'Username 3-20 chars' });
        if (password.length < 6) return res.status(400).json({ error: 'Password min 6 chars' });
        const exists = await db.prepare('SELECT id FROM users WHERE username = ?').get(username);
        if (exists) return res.status(409).json({ error: 'Username taken' });
        const id = uuidv4();
        const hash = bcrypt.hashSync(password, 10);
        await db.prepare('INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)').run(id, username, hash);
        await db.prepare('INSERT INTO logs (event, user_id, details) VALUES (?, ?, ?)').run('register', id, username);
        res.json({ ok: true, message: 'Account created' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await db.prepare('SELECT * FROM users WHERE username = ?').get(username);
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });
        if (!bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: 'Invalid credentials' });
        await db.prepare('UPDATE users SET last_login = datetime(\'now\') WHERE id = ?').run(user.id);
        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
        await db.prepare('INSERT INTO logs (event, user_id, details) VALUES (?, ?, ?)').run('login', user.id, user.username);
        res.json({ ok: true, token, username: user.username, role: user.role });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

function auth(req, res, next) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'No token' });
    try { req.user = jwt.verify(token, JWT_SECRET); next(); } catch { res.status(401).json({ error: 'Invalid token' }); }
}

router.post('/launcher/activate', auth, async (req, res) => {
    try {
        const { key, hwid } = req.body;
        if (!key || !hwid) return res.status(400).json({ error: 'Key and HWID required' });
        const keyRow = await db.prepare('SELECT * FROM keys WHERE key_code = ?').get(key);
        if (!keyRow) return res.status(404).json({ error: 'Key not found' });
        if (!keyRow.active) return res.status(403).json({ error: 'Key deactivated' });
        if (keyRow.user_id && keyRow.user_id !== req.user.id) return res.status(403).json({ error: 'Key already used by another account' });
        const hashedHWID = hashHWID(hwid);
        if (keyRow.user_id === req.user.id && keyRow.hwid && keyRow.hwid !== hashedHWID) return res.status(403).json({ error: 'HWID mismatch' });
        const expiresAt = new Date(); expiresAt.setDate(expiresAt.getDate() + keyRow.duration_days);
        const expiresStr = expiresAt.toISOString().replace('T', ' ').replace('Z', '');
        await db.prepare('UPDATE keys SET user_id = ?, hwid = ?, activated_at = datetime(\'now\'), expires_at = ? WHERE id = ?').run(req.user.id, hashedHWID, expiresStr, keyRow.id);
        await db.prepare('UPDATE users SET hwid = ? WHERE id = ?').run(hashedHWID, req.user.id);
        await db.prepare('INSERT INTO logs (event, user_id, hwid, details) VALUES (?, ?, ?, ?)').run('activate', req.user.id, hashedHWID, key);
        res.json({ ok: true, expires: expiresStr });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/launcher/validate', auth, async (req, res) => {
    try {
        const { hwid } = req.body;
        if (!hwid) return res.status(400).json({ error: 'HWID required' });
        const hashedHWID = hashHWID(hwid);
        const user = await db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const key = await db.prepare('SELECT * FROM keys WHERE user_id = ? AND active = 1 AND expires_at > datetime(\'now\') ORDER BY expires_at DESC LIMIT 1').get(req.user.id);
        if (!key) return res.status(403).json({ error: 'No active subscription' });
        if (key.hwid && key.hwid !== hashedHWID) return res.status(403).json({ error: 'HWID mismatch' });
        const sessionId = uuidv4();
        const sessionToken = crypto.randomBytes(32).toString('hex');
        await db.prepare('INSERT INTO sessions (id, user_id, hwid, ip, token) VALUES (?, ?, ?, ?, ?)').run(sessionId, req.user.id, hashedHWID, req.ip, sessionToken);
        await db.prepare('INSERT INTO logs (event, user_id, hwid, ip) VALUES (?, ?, ?, ?)').run('validate', req.user.id, hashedHWID, req.ip);
        let displayName = key.key_type === 'admin' ? 'J.P' : 'Player' + Math.floor(Math.random() * 9000 + 1000);
        res.json({ ok: true, session: sessionToken, expires: key.expires_at, keyType: key.key_type, displayName });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Public key check - no auth required
router.post('/launcher/check', async (req, res) => {
    try {
        const { key, hwid } = req.body;
        if (!key || !hwid) return res.status(400).json({ error: 'Key and HWID required' });
        const keyRow = await db.prepare('SELECT * FROM keys WHERE key_code = ?').get(key);
        if (!keyRow) return res.status(404).json({ error: 'Key not found' });
        if (!keyRow.active) return res.status(403).json({ error: 'Key deactivated' });
        const hashedHWID = hashHWID(hwid);
        const sessionId = uuidv4();
        const sessionToken = crypto.randomBytes(32).toString('hex');
        await db.prepare('INSERT INTO sessions (id, user_id, hwid, ip, token) VALUES (?, ?, ?, ?, ?)').run(sessionId, keyRow.user_id || null, hashedHWID, req.ip, sessionToken);
        await db.prepare('INSERT INTO logs (event, hwid, ip, details) VALUES (?, ?, ?, ?)').run('check', hashedHWID, req.ip, key);
        const displayName = keyRow.key_type === 'admin' ? 'J.P' : 'Player' + Math.floor(Math.random() * 9000 + 1000);
        res.json({ success: true, token: sessionToken, username: displayName, keyType: keyRow.key_type });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.get('/launcher/client', async (req, res) => {
    try {
        const sessionToken = req.headers['x-session'];
        if (!sessionToken) return res.status(401).json({ error: 'Session required' });
        const session = await db.prepare('SELECT * FROM sessions WHERE token = ? AND active = 1').get(sessionToken);
        if (!session) return res.status(401).json({ error: 'Invalid session' });
        await db.prepare('UPDATE sessions SET last_active = datetime(\'now\') WHERE id = ?').run(session.id);
        let data = null;
        const clientRow = await db.prepare('SELECT value FROM settings WHERE key = ?').get('client_jar');
        if (clientRow && clientRow.value) data = Buffer.from(clientRow.value, 'base64');
        else if (process.env.CLIENT_URL) {
            const http = process.env.CLIENT_URL.startsWith('https') ? require('https') : require('http');
            data = await new Promise((resolve, reject) => { http.get(process.env.CLIENT_URL, (r) => { const c = []; r.on('data', ch => c.push(ch)); r.on('end', () => resolve(Buffer.concat(c))); r.on('error', reject); }).on('error', reject); });
        }
        if (!data) return res.status(404).json({ error: 'Client not uploaded' });
        const encKey = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', encKey, iv);
        const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
        res.setHeader('Content-Type', 'application/octet-stream');
        res.send(Buffer.concat([iv, encrypted]));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.get('/launcher/version', async (req, res) => {
    const v = await db.prepare('SELECT value FROM settings WHERE key = ?').get('client_version');
    res.json({ version: v?.value || '1.0.0' });
});

module.exports = router;
