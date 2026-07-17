const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const { db, hashHWID } = require('./db');

const JWT_SECRET = process.env.JWT_SECRET || 'jartix-secret-change-in-production';

// ── Auth: Register ────────────────────────────────────
router.post('/auth/register', (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
        if (username.length < 3 || username.length > 20) return res.status(400).json({ error: 'Username 3-20 chars' });
        if (password.length < 6) return res.status(400).json({ error: 'Password min 6 chars' });

        const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
        if (exists) return res.status(409).json({ error: 'Username taken' });

        const id = uuidv4();
        const hash = bcrypt.hashSync(password, 10);
        db.prepare('INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)').run(id, username, hash);
        db.prepare('INSERT INTO logs (event, user_id, details) VALUES (?, ?, ?)').run('register', id, username);

        res.json({ ok: true, message: 'Account created' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ── Auth: Login ───────────────────────────────────────
router.post('/auth/login', (req, res) => {
    try {
        const { username, password } = req.body;
        const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });
        if (!bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: 'Invalid credentials' });

        db.prepare('UPDATE users SET last_login = datetime(\'now\') WHERE id = ?').run(user.id);
        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
        db.prepare('INSERT INTO logs (event, user_id, details) VALUES (?, ?, ?)').run('login', user.id, user.username);

        res.json({ ok: true, token, username: user.username, role: user.role });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ── Middleware: verify token ───────────────────────────
function auth(req, res, next) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        res.status(401).json({ error: 'Invalid token' });
    }
}

// ── Launcher: Activate key ────────────────────────────
router.post('/launcher/activate', auth, (req, res) => {
    try {
        const { key, hwid } = req.body;
        if (!key || !hwid) return res.status(400).json({ error: 'Key and HWID required' });

        const keyRow = db.prepare('SELECT * FROM keys WHERE key_code = ?').get(key);
        if (!keyRow) return res.status(404).json({ error: 'Key not found' });
        if (!keyRow.active) return res.status(403).json({ error: 'Key deactivated' });

        // Check if key already activated by another user
        if (keyRow.user_id && keyRow.user_id !== req.user.id) {
            return res.status(403).json({ error: 'Key already used by another account' });
        }

        // Check HWID limit
        const hashedHWID = hashHWID(hwid);
        if (keyRow.user_id === req.user.id && keyRow.hwid) {
            // Already activated — check HWID match
            if (keyRow.hwid !== hashedHWID) {
                return res.status(403).json({ error: 'HWID mismatch. Contact support for reset.' });
            }
        }

        // Activate
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + keyRow.duration_days);

        db.prepare(`UPDATE keys SET user_id = ?, hwid = ?, activated_at = datetime('now'), expires_at = ? WHERE id = ?`)
            .run(req.user.id, hashedHWID, expiresAt.toISOString(), keyRow.id);

        // Update user HWID
        db.prepare('UPDATE users SET hwid = ? WHERE id = ?').run(hashedHWID, req.user.id);

        db.prepare('INSERT INTO logs (event, user_id, hwid, details) VALUES (?, ?, ?, ?)')
            .run('activate', req.user.id, hashedHWID, key);

        res.json({ ok: true, expires: expiresAt.toISOString() });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ── Launcher: Validate + get session ──────────────────
router.post('/launcher/validate', auth, (req, res) => {
    try {
        const { hwid } = req.body;
        if (!hwid) return res.status(400).json({ error: 'HWID required' });

        const hashedHWID = hashHWID(hwid);
        const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
        if (!user) return res.status(404).json({ error: 'User not found' });

        // Check active key
        const key = db.prepare(`SELECT * FROM keys WHERE user_id = ? AND active = 1 AND expires_at > datetime('now') ORDER BY expires_at DESC LIMIT 1`)
            .get(req.user.id);
        if (!key) return res.status(403).json({ error: 'No active subscription' });

        // Check HWID
        if (key.hwid && key.hwid !== hashedHWID) {
            return res.status(403).json({ error: 'HWID mismatch' });
        }

        // Create session
        const sessionId = uuidv4();
        const sessionToken = crypto.randomBytes(32).toString('hex');
        db.prepare('INSERT INTO sessions (id, user_id, hwid, ip, token) VALUES (?, ?, ?, ?, ?)')
            .run(sessionId, req.user.id, hashedHWID, req.ip, sessionToken);

        db.prepare('INSERT INTO logs (event, user_id, hwid, ip) VALUES (?, ?, ?, ?)')
            .run('validate', req.user.id, hashedHWID, req.ip);

        // Determine display info based on key type
        let displayName, avatarUrl;
        if (key.key_type === 'admin') {
            displayName = 'J.P';
            avatarUrl = 'https://mc-heads.net/avatar/J.P/64';
        } else {
            // Generate random Minecraft name + avatar
            const randomNames = [
                'xXDarkXx', 'ShadowPlay', 'EnderCraft', 'BlockMaster',
                'NetherStar', 'CreeperSlayer', 'DiamondKing', 'RedstonePro',
                'PistonPush', 'TNTBlast', 'WitherHunter', 'EndCrystal',
                'SoulSand', 'BlazeRod', 'WitherSkull', 'ObsidianWall',
                'CaveSpider', 'IronGolem', 'SnowGolem', 'Mooshroom'
            ];
            const randomSuffix = Math.floor(Math.random() * 9000) + 1000;
            displayName = randomNames[Math.floor(Math.random() * randomNames.length)] + randomSuffix;
            avatarUrl = `https://mc-heads.net/avatar/${displayName}/64`;
        }

        res.json({
            ok: true,
            session: sessionToken,
            expires: key.expires_at,
            keyType: key.key_type,
            displayName,
            avatarUrl
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ── Launcher: Stream client JAR ───────────────────────
router.get('/launcher/client', (req, res) => {
    try {
        const sessionToken = req.headers['x-session'];
        if (!sessionToken) return res.status(401).json({ error: 'Session required' });

        const session = db.prepare('SELECT * FROM sessions WHERE token = ? AND active = 1').get(sessionToken);
        if (!session) return res.status(401).json({ error: 'Invalid session' });

        // Update last active
        db.prepare('UPDATE sessions SET last_active = datetime(\'now\') WHERE id = ?').run(session.id);

        // Read client from database (not filesystem — Render wipes files on restart)
        const clientRow = db.prepare('SELECT value FROM settings WHERE key = ?').get('client_jar');
        if (!clientRow || !clientRow.value) {
            return res.status(404).json({ error: 'Client not uploaded. Upload via admin panel.' });
        }

        const data = Buffer.from(clientRow.value, 'base64');
        const encKey = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', encKey, iv);
        const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
        const result = Buffer.concat([iv, encrypted]);

        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Length', result.length);
        res.setHeader('Content-Disposition', 'attachment; filename="client.bin"');
        res.send(result);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ── Launcher: Check for updates ───────────────────────
router.get('/launcher/version', (req, res) => {
    const versionSetting = db.prepare('SELECT value FROM settings WHERE key = ?').get('client_version');
    res.json({ version: versionSetting?.value || '1.0.0' });
});

module.exports = router;
