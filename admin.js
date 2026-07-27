// Admin API — Supabase-backed. Manages profiles (keys/licenses), players
// (telemetry) and the activity log. Auth is a single admin password (JWT).
const express = require('express');
const router = express.Router();
const path = require('path');
const jwt = require('jsonwebtoken');
const { pool, one, clientIp } = require('./sbdb');

const JWT_SECRET = process.env.JWT_SECRET || 'jartix-secret-change-in-production';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// ── auth ──────────────────────────────────────────────────────────────────
router.post('/api/login', async (req, res) => {
    const { username, password } = req.body || {};
    if (username === ADMIN_USER && password === ADMIN_PASSWORD) {
        const token = jwt.sign({ role: 'admin', username }, JWT_SECRET, { expiresIn: '24h' });
        return res.json({ ok: true, token });
    }
    res.status(401).json({ error: 'Invalid credentials' });
});

function adminAuth(req, res, next) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
        const d = jwt.verify(token, JWT_SECRET);
        if (d.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
        req.admin = d;
        next();
    } catch { res.status(401).json({ error: 'Invalid token' }); }
}

async function logAction(event, req, extra = {}) {
    try {
        await pool.query(
            'INSERT INTO activity_logs (event, username, ip, details) VALUES ($1,$2,$3,$4)',
            [event, extra.username || null, clientIp(req), extra.details || null]
        );
    } catch {}
}

// ── stats ─────────────────────────────────────────────────────────────────
router.get('/api/stats', adminAuth, async (req, res) => {
    try {
        const s = await one(`
            SELECT
              (SELECT count(*) FROM profiles)                                              AS total_users,
              (SELECT count(*) FROM profiles WHERE license_active AND active AND NOT banned) AS licensed,
              (SELECT count(*) FROM profiles WHERE banned)                                  AS banned,
              (SELECT count(*) FROM profiles WHERE license_active AND expires_at IS NOT NULL
                    AND expires_at < now() + interval '3 days' AND expires_at > now())       AS expiring_soon,
              (SELECT count(DISTINCT hwid) FROM telemetry_logs
                    WHERE created_at > now() - interval '5 minutes')                          AS online
        `);
        res.json(s);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── users / profiles ───────────────────────────────────────────────────────
router.get('/api/users', adminAuth, async (req, res) => {
    try {
        const search = (req.query.search || '').trim();
        const filter = (req.query.filter || 'all');
        const params = [];
        let where = 'WHERE 1=1';
        if (search) {
            params.push('%' + search + '%');
            where += ` AND (username ILIKE $${params.length} OR license_key ILIKE $${params.length})`;
        }
        if (filter === 'licensed') where += ' AND license_active AND active AND NOT banned';
        else if (filter === 'inactive') where += ' AND (NOT license_active OR NOT active)';
        else if (filter === 'banned') where += ' AND banned';
        else if (filter === 'expiring') where += " AND license_active AND expires_at IS NOT NULL AND expires_at < now() + interval '3 days' AND expires_at > now()";

        const { rows } = await pool.query(
            `SELECT id, username, license_key, key_type, hwid, hwid_limit, active,
                    license_active, banned, expires_at, last_ip, last_login, created_at, notes
             FROM profiles ${where} ORDER BY created_at DESC LIMIT 500`, params);
        res.json(rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.get('/api/users/:id', adminAuth, async (req, res) => {
    try {
        const p = await one('SELECT * FROM profiles WHERE id = $1', [req.params.id]);
        if (!p) return res.status(404).json({ error: 'Not found' });
        const tel = (await pool.query(
            'SELECT * FROM telemetry_logs WHERE username = $1 OR hwid = $2 ORDER BY created_at DESC LIMIT 25',
            [p.username, p.hwid])).rows;
        const acts = (await pool.query(
            'SELECT * FROM activity_logs WHERE username = $1 ORDER BY created_at DESC LIMIT 25',
            [p.username])).rows;
        res.json({ profile: p, telemetry: tel, activity: acts });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Grant / extend a license. body: { days: number|null (null = lifetime), key_type }
router.post('/api/users/:id/license', adminAuth, async (req, res) => {
    try {
        const { days, key_type } = req.body || {};
        const lifetime = days === null || days === undefined || days === 0 || days === 'lifetime';
        const type = ['admin', 'client'].includes(key_type) ? key_type : undefined;
        const expr = lifetime ? null : `now() + ($1 || ' days')::interval`;
        const params = lifetime ? [] : [String(parseInt(days, 10))];
        const p = await one(
            `UPDATE profiles SET license_active = true, active = true,
                    expires_at = ${lifetime ? 'NULL' : expr}
                    ${type ? `, key_type = '${type}'` : ''}
             WHERE id = $${params.length + 1} RETURNING username, expires_at`,
            [...params, req.params.id]);
        if (!p) return res.status(404).json({ error: 'Not found' });
        await logAction('license_grant', req, { username: p.username, details: lifetime ? 'lifetime' : days + 'd' });
        res.json({ ok: true, expires: p.expires_at });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Revoke the license but keep the key.
router.post('/api/users/:id/revoke', adminAuth, async (req, res) => {
    try {
        const p = await one('UPDATE profiles SET license_active = false WHERE id = $1 RETURNING username', [req.params.id]);
        await logAction('license_revoke', req, { username: p?.username });
        res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Annul (disable) the key entirely.
router.post('/api/users/:id/annul', adminAuth, async (req, res) => {
    try {
        const p = await one('UPDATE profiles SET active = false, license_active = false WHERE id = $1 RETURNING username', [req.params.id]);
        await logAction('key_annul', req, { username: p?.username });
        res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/api/users/:id/restore', adminAuth, async (req, res) => {
    try {
        const p = await one('UPDATE profiles SET active = true WHERE id = $1 RETURNING username', [req.params.id]);
        await logAction('key_restore', req, { username: p?.username });
        res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/api/users/:id/ban', adminAuth, async (req, res) => {
    try {
        const p = await one('UPDATE profiles SET banned = true WHERE id = $1 RETURNING username', [req.params.id]);
        await logAction('ban', req, { username: p?.username });
        res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/api/users/:id/unban', adminAuth, async (req, res) => {
    try {
        const p = await one('UPDATE profiles SET banned = false WHERE id = $1 RETURNING username', [req.params.id]);
        await logAction('unban', req, { username: p?.username });
        res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/api/users/:id/reset-hwid', adminAuth, async (req, res) => {
    try {
        const p = await one('UPDATE profiles SET hwid = NULL WHERE id = $1 RETURNING username', [req.params.id]);
        await logAction('hwid_reset', req, { username: p?.username });
        res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Issue a brand-new key for this user.
router.post('/api/users/:id/rotate-key', adminAuth, async (req, res) => {
    try {
        let p = null;
        for (let i = 0; i < 5 && !p; i++) {
            try {
                p = await one('UPDATE profiles SET license_key = generate_key() WHERE id = $1 RETURNING username, license_key', [req.params.id]);
            } catch (err) { if (!/unique/i.test(err.message)) throw err; }
        }
        if (!p) return res.status(500).json({ error: 'Could not generate key' });
        await logAction('key_rotate', req, { username: p.username, details: p.license_key });
        res.json({ ok: true, key: p.license_key });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/api/users/:id/key-type', adminAuth, async (req, res) => {
    try {
        const type = ['admin', 'client'].includes(req.body?.key_type) ? req.body.key_type : 'client';
        const p = await one('UPDATE profiles SET key_type = $1 WHERE id = $2 RETURNING username', [type, req.params.id]);
        await logAction('key_type', req, { username: p?.username, details: type });
        res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/api/users/:id/hwid-limit', adminAuth, async (req, res) => {
    try {
        const lim = Math.max(1, Math.min(10, parseInt(req.body?.hwid_limit, 10) || 1));
        const p = await one('UPDATE profiles SET hwid_limit = $1 WHERE id = $2 RETURNING username', [lim, req.params.id]);
        res.json({ ok: true, hwid_limit: lim });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/api/users/:id/notes', adminAuth, async (req, res) => {
    try {
        await pool.query('UPDATE profiles SET notes = $1 WHERE id = $2', [req.body?.notes || null, req.params.id]);
        res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.delete('/api/users/:id', adminAuth, async (req, res) => {
    try {
        const p = await one('DELETE FROM profiles WHERE id = $1 RETURNING username', [req.params.id]);
        await logAction('user_delete', req, { username: p?.username });
        res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── players (live telemetry) ────────────────────────────────────────────────
// Latest report per HWID within the window = who is currently in-game & where.
router.get('/api/players', adminAuth, async (req, res) => {
    try {
        const mins = Math.min(1440, parseInt(req.query.mins, 10) || 15);
        const { rows } = await pool.query(`
            SELECT DISTINCT ON (username) hwid, username, server, ip, brand, version, created_at,
                   motd, anarchy, dimension, gamemode, biome,
                   pos_x, pos_y, pos_z, health, max_health, ping, online_count, inventory
            FROM telemetry_logs
            WHERE created_at > now() - INTERVAL '300 seconds'
              AND username IS NOT NULL AND username != ''
            ORDER BY username, created_at DESC`, []);
        res.json(rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.get('/api/telemetry', adminAuth, async (req, res) => {
    try {
        const limit = Math.min(500, parseInt(req.query.limit, 10) || 100);
        const { rows } = await pool.query('SELECT * FROM telemetry_logs ORDER BY created_at DESC LIMIT $1', [limit]);
        res.json(rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.get('/api/logs', adminAuth, async (req, res) => {
    try {
        const limit = Math.min(500, parseInt(req.query.limit, 10) || 100);
        const { rows } = await pool.query('SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT $1', [limit]);
        res.json(rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── panel page ──────────────────────────────────────────────────────────────
router.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

module.exports = router;
