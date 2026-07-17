const express = require('express');
const cors = require('cors');
const path = require('path');
const http = require('http');
const db = require('./db');
const api = require('./api');
const admin = require('./admin');
const LoaderServer = require('./loader_ws');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;

// Encryption key for client JAR (change in production!)
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
process.env.ENCRYPTION_KEY = ENCRYPTION_KEY;

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

// Start server
server.listen(PORT, () => {
    console.log(`[Jartix] Server running on port ${PORT}`);
    console.log(`[Jartix] Admin panel: http://localhost:${PORT}/admin`);
    console.log(`[Jartix] WebSocket: ws://localhost:${PORT}/ws/loader`);
    console.log(`[Jartix] Encryption key: ${ENCRYPTION_KEY.substring(0, 8)}...`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('[Jartix] Shutting down...');
    server.close(() => {
        process.exit(0);
    });
});
