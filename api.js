const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const { db, hashHWID } = require('./db');
const { pool, one, clientIp } = require('./sbdb');

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
        // Calculate expiration (duration_days field now stores seconds)
        const expiresAt = new Date(Date.now() + keyRow.duration_days * 1000);
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

// Key check — used by TWO different callers:
//
//   launcher : {key, hwid}      -> full activation, binds the HWID
//   in-game  : {hwid[, username]} -> re-validates the licence while playing
//
// The in-game client (Jartix.validateKey) sends no key and treats any non-200
// as "invalid" — which disables every module — so the hwid/username-only form
// must be answered here. It scans the body for "valid":true / "active":true /
// "status":"ok", so those markers are part of the success payload.
router.post('/launcher/check', async (req, res) => {
    try {
        const { key, hwid, username } = req.body || {};
        if (!key && !hwid && !username)
            return res.status(400).json({ valid: false, error: 'Key or HWID required' });

        let p = null;
        if (key) {
            p = await one('SELECT * FROM profiles WHERE license_key = $1', [String(key).trim()]);
            if (!p) return res.status(404).json({ valid: false, error: 'Key not found' });
        } else {
            // in-game path: match by the launcher-provided login, else by HWID
            if (username)
                p = await one('SELECT * FROM profiles WHERE username = $1', [String(username).trim()]);
            if (!p && hwid)
                p = await one('SELECT * FROM profiles WHERE hwid = $1 OR hwid = $2 LIMIT 1',
                              [hashHWID(hwid), String(hwid)]);
            if (!p) return res.status(403).json({ valid: false, error: 'Not registered' });
        }

        if (p.banned)          return res.status(403).json({ valid: false, error: 'Account banned' });
        if (!p.active)         return res.status(403).json({ valid: false, error: 'Key deactivated' });
        if (!p.license_active) return res.status(403).json({ valid: false, error: 'No active license' });
        if (p.expires_at && new Date(p.expires_at) < new Date())
            return res.status(403).json({ valid: false, error: 'License expired' });

        const ip = clientIp(req);
        const hashedHWID = hwid ? hashHWID(hwid) : null;

        if (key) {
            // launcher: enforce and (first time) record the HWID binding
            if (p.hwid && hashedHWID && p.hwid !== hashedHWID)
                return res.status(403).json({ valid: false, error: 'HWID mismatch — reset it in the panel' });
            await pool.query(
                'UPDATE profiles SET hwid = COALESCE(hwid, $1), last_login = now(), last_ip = $2 WHERE id = $3',
                [hashedHWID, ip, p.id]
            );
            await pool.query(
                'INSERT INTO activity_logs (event, username, hwid, ip, details) VALUES ($1,$2,$3,$4,$5)',
                ['check', p.username, hashedHWID, ip, 'launcher login']
            );
        }

        const token = crypto.randomBytes(32).toString('hex');
        res.json({
            success: true, valid: true, active: true, status: 'ok',
            token, username: p.username, keyType: p.key_type, expires: p.expires_at
        });
    } catch (e) { console.error('[check]', e.message); res.status(500).json({ error: e.message }); }
});

// Telemetry ingest — the in-game cheat reports which server the player joined.
router.post('/telemetry', async (req, res) => {
    try {
        const { hwid, username, server, ip, brand, version, timestamp,
                motd, anarchy, dimension, gamemode, biome,
                x, y, z, health, maxHealth, ping, online } = req.body || {};
        if (!hwid) return res.sendStatus(400);
        // Use client-provided username, fallback to profile lookup
        let name = username || null;
        if (!name) {
            try {
                const m = await one('SELECT username FROM profiles WHERE hwid = $1 OR hwid = $2 LIMIT 1',
                    [hwid, hashHWID(hwid)]);
                name = m ? m.username : null;
            } catch {}
        }
        await pool.query(
            `INSERT INTO telemetry_logs
             (hwid, username, server, ip, brand, version, event, timestamp,
              motd, anarchy, dimension, gamemode, biome,
              pos_x, pos_y, pos_z, health, max_health, ping, online_count)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
            [hwid, name, server || '', ip || '', brand || '', version || '', 'server', timestamp || Date.now(),
             motd || '', anarchy || '', dimension || '', gamemode || '', biome || '',
             x || 0, y || 0, z || 0, health || 0, maxHealth || 0, ping || -1, online || 0]
        );
        res.sendStatus(200);
    } catch (e) { console.error('[telemetry]', e.message); res.sendStatus(500); }
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

router.get('/launcher/config', async (req, res) => {
    res.json({ encryptionKey: process.env.ENCRYPTION_KEY || '' });
});

module.exports = router;
