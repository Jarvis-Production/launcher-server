const express = require('express');
const cors = require('cors');
const path = require('path');
const http = require('http');
const https = require('https');
const { db } = require('./db');
const api = require('./api');
const admin = require('./admin');
const LoaderServer = require('./loader_ws');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;

// Encryption key for client JAR
let ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

// Initialize WebSocket loader server
const loaderServer = new LoaderServer(server);

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// API routes
app.use('/api', api);

// Admin panel
app.use('/admin', admin);

// Root redirect to admin
app.get('/', (req, res) => {
    res.redirect('/admin');
});

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        uptime: process.uptime(),
        ws: 'ws://localhost:' + PORT + '/ws/loader'
    });
});

// ── Download and encrypt client JAR from GitHub ────────
app.post('/api/client/download-and-encrypt', async (req, res) => {
    try {
        const { url } = req.body;
        if (!url) return res.status(400).json({ error: 'URL required' });
        
        // Get or generate encryption key
        if (!ENCRYPTION_KEY) {
            const keyRow = await db.prepare('SELECT value FROM settings WHERE key = ?').get('encryption_key');
            if (keyRow && keyRow.value) {
                ENCRYPTION_KEY = keyRow.value;
                process.env.ENCRYPTION_KEY = ENCRYPTION_KEY;
                console.log('[Crypto] Loaded encryption key from DB');
            } else {
                ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');
                await db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').run('encryption_key', ENCRYPTION_KEY);
                process.env.ENCRYPTION_KEY = ENCRYPTION_KEY;
                console.log('[Crypto] Generated and stored new encryption key');
            }
        }
        
        console.log(`[Client] Downloading from: ${url}`);
        console.log(`[Client] Encryption key hex length: ${ENCRYPTION_KEY.length}`);
        
        // Download JAR from GitHub
        const jarData = await downloadFile(url);
        console.log(`[Client] Downloaded ${jarData.length} bytes`);
        
        // Encrypt with AES-256-CBC
        const encKey = Buffer.from(ENCRYPTION_KEY, 'hex');
        console.log(`[Client] Enc key buffer length: ${encKey.length}`);
        if (encKey.length !== 32) {
            return res.status(500).json({ error: 'Invalid encryption key length', got: encKey.length });
        }
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', encKey, iv);
        const encrypted = Buffer.concat([cipher.update(jarData), cipher.final()]);
        
        // Store encrypted JAR in DB
        const encryptedBase64 = Buffer.concat([iv, encrypted]).toString('base64');
        await db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').run('client_jar', encryptedBase64);
        await db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').run('client_version', req.body.version || '1.0.0');
        
        // Store original checksum for verification
        const originalHash = crypto.createHash('sha256').update(jarData).digest('hex');
        await db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').run('client_original_hash', originalHash);
        
        await db.prepare('INSERT INTO logs (event, details) VALUES (?, ?)').run('client_download_encrypt', `${url} (${jarData.length} bytes)`);
        
        console.log(`[Client] Encrypted and stored: ${jarData.length} bytes`);
        res.json({ ok: true, size: jarData.length, hash: originalHash });
    } catch (e) {
        console.error('[Client] Download error:', e.message);
        res.status(500).json({ error: e.message });
    }
});

// ── Stream encrypted client JAR ────────────────────────
app.get('/api/client/download', async (req, res) => {
    try {
        const token = req.headers.authorization?.replace('Bearer ', '');
        if (!token) return res.status(401).json({ error: 'No token' });
        
        const jwt = require('jsonwebtoken');
        const JWT_SECRET = process.env.JWT_SECRET || 'jartix-secret-change-in-production';
        let user;
        try {
            user = jwt.verify(token, JWT_SECRET);
        } catch {
            return res.status(401).json({ error: 'Invalid token' });
        }
        
        const clientRow = await db.prepare('SELECT value FROM settings WHERE key = ?').get('client_jar');
        if (!clientRow || !clientRow.value) {
            return res.status(404).json({ error: 'Client not available' });
        }
        
        const encryptedData = Buffer.from(clientRow.value, 'base64');
        
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Length', encryptedData.length);
        res.setHeader('Content-Disposition', 'attachment; filename="client.enc"');
        res.send(encryptedData);
        
        console.log(`[Client] Streamed ${encryptedData.length} bytes to user ${user.username}`);
        await db.prepare('INSERT INTO logs (event, user_id, details) VALUES (?, ?, ?)').run('client_download', user.id, `${encryptedData.length} bytes`);
    } catch (e) {
        console.error('[Client] Stream error:', e.message);
        res.status(500).json({ error: e.message });
    }
});

// ── Get client version ─────────────────────────────────
app.get('/api/client/version', async (req, res) => {
    try {
        const versionSetting = await db.prepare('SELECT value FROM settings WHERE key = ?').get('client_version');
        const hashSetting = await db.prepare('SELECT value FROM settings WHERE key = ?').get('client_original_hash');
        res.json({ 
            version: versionSetting?.value || '1.0.0',
            hash: hashSetting?.value || null
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Helper: download file from URL
function downloadFile(url) {
    return new Promise((resolve, reject) => {
        const client = url.startsWith('https') ? https : http;
        client.get(url, (response) => {
            if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
                downloadFile(response.headers.location).then(resolve).catch(reject);
                return;
            }
            if (response.statusCode !== 200) {
                reject(new Error(`HTTP ${response.statusCode}`));
                return;
            }
            const chunks = [];
            response.on('data', chunk => chunks.push(chunk));
            response.on('end', () => resolve(Buffer.concat(chunks)));
            response.on('error', reject);
        }).on('error', reject);
    });
}

// Start server
server.listen(PORT, () => {
    console.log(`[Jartix] Server running on port ${PORT}`);
    console.log(`[Jartix] Admin panel: http://localhost:${PORT}/admin`);
    console.log(`[Jartix] WebSocket: ws://localhost:${PORT}/ws/loader`);
    console.log(`[Jartix] Encryption key: ${ENCRYPTION_KEY ? ENCRYPTION_KEY.substring(0, 8) + '...' : 'will be loaded from DB'}`);
});

process.on('SIGTERM', () => {
    console.log('[Jartix] Shutting down...');
    server.close(() => { process.exit(0); });
});
