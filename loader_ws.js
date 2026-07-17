const WebSocket = require('ws');
const crypto = require('crypto');
const { db, hashHWID } = require('./db');

// WebSocket server for DLL streaming
class LoaderServer {
    constructor(server) {
        this.wss = new WebSocket.Server({ server, path: '/ws/loader' });
        this.clients = new Map();
        
        this.wss.on('connection', (ws, req) => {
            console.log('[WS] New connection from:', req.socket.remoteAddress);
            this.handleConnection(ws);
        });
    }
    
    handleConnection(ws) {
        const clientId = crypto.randomUUID();
        this.clients.set(clientId, {
            ws,
            authenticated: false,
            userId: null,
            sessionToken: null
        });
        
        ws.on('message', (data) => {
            try {
                const msg = JSON.parse(data.toString());
                this.handleMessage(clientId, msg);
            } catch (e) {
                console.error('[WS] Invalid message:', e.message);
                ws.close(1008, 'Invalid message');
            }
        });
        
        ws.on('close', () => {
            this.clients.delete(clientId);
            console.log('[WS] Client disconnected:', clientId);
        });
        
        ws.on('error', (err) => {
            console.error('[WS] Error:', err.message);
        });
    }
    
    handleMessage(clientId, msg) {
        const client = this.clients.get(clientId);
        if (!client) return;
        
        switch (msg.type) {
            case 'auth':
                this.handleAuth(clientId, client, msg);
                break;
                
            case 'request_dll':
                if (client.authenticated) {
                    this.handleDllRequest(clientId, client);
                }
                break;
                
            case 'verify':
                if (client.authenticated) {
                    this.handleVerify(clientId, client, msg);
                }
                break;
                
            default:
                client.ws.close(1008, 'Unknown message type');
        }
    }
    
    handleAuth(clientId, client, msg) {
        const { session, privateKey } = msg;
        
        // Verify session token
        const sessionRow = db.prepare(
            'SELECT * FROM sessions WHERE token = ? AND active = 1'
        ).get(session);
        
        if (!sessionRow) {
            client.ws.send(JSON.stringify({
                status: 'error',
                error: 'Invalid session'
            }));
            return;
        }
        
        // Verify private key (stored in settings)
        const keyRow = db.prepare(
            'SELECT value FROM settings WHERE key = ?'
        ).get('loader_private_key');
        
        if (!keyRow || keyRow.value !== privateKey) {
            client.ws.send(JSON.stringify({
                status: 'error',
                error: 'Invalid private key'
            }));
            return;
        }
        
        // Verify HWID
        const user = db.prepare(
            'SELECT * FROM users WHERE id = ?'
        ).get(sessionRow.user_id);
        
        if (!user) {
            client.ws.send(JSON.stringify({
                status: 'error',
                error: 'User not found'
            }));
            return;
        }
        
        // Check subscription
        const key = db.prepare(
            `SELECT * FROM keys WHERE user_id = ? AND active = 1 AND expires_at > datetime('now')`
        ).get(user.id);
        
        if (!key) {
            client.ws.send(JSON.stringify({
                status: 'error',
                error: 'No active subscription'
            }));
            return;
        }
        
        client.authenticated = true;
        client.userId = user.id;
        client.sessionToken = session;
        
        client.ws.send(JSON.stringify({
            status: 'ok',
            message: 'Authenticated'
        }));
        
        console.log('[WS] Client authenticated:', user.username);
    }
    
    handleDllRequest(clientId, client) {
        console.log('[WS] DLL requested by:', client.userId);
        
        // Get DLL from database
        const clientRow = db.prepare(
            'SELECT value FROM settings WHERE key = ?'
        ).get('client_jar');
        
        if (!clientRow || !clientRow.value) {
            client.ws.send(JSON.stringify({
                status: 'error',
                error: 'DLL not available'
            }));
            return;
        }
        
        const dllData = Buffer.from(clientRow.value, 'base64');
        
        // Split into chunks (64KB each)
        const chunkSize = 64 * 1024;
        const totalChunks = Math.ceil(dllData.length / chunkSize);
        
        console.log(`[WS] Sending ${totalChunks} chunks (${dllData.length} bytes)`);
        
        // Send metadata first
        client.ws.send(JSON.stringify({
            type: 'metadata',
            totalChunks,
            totalSize: dllData.length
        }));
        
        // Send chunks
        for (let i = 0; i < totalChunks; i++) {
            const offset = i * chunkSize;
            const chunk = dllData.slice(offset, offset + chunkSize);
            
            // Create chunk frame: [index:4][total:4][size:4][data...]
            const frame = Buffer.alloc(12 + chunk.length);
            frame.writeUInt32LE(i, 0);
            frame.writeUInt32LE(totalChunks, 4);
            frame.writeUInt32LE(chunk.length, 8);
            chunk.copy(frame, 12);
            
            client.ws.send(frame, { binary: true });
        }
        
        console.log('[WS] DLL transfer complete');
    }
    
    handleVerify(clientId, client, msg) {
        const { checksum } = msg;
        
        // Verify checksum matches
        const clientRow = db.prepare(
            'SELECT value FROM settings WHERE key = ?'
        ).get('client_jar');
        
        if (!clientRow) {
            client.ws.send(JSON.stringify({
                status: 'error',
                error: 'DLL not found'
            }));
            return;
        }
        
        const dllData = Buffer.from(clientRow.value, 'base64');
        const hash = crypto.createHash('sha256').update(dllData).digest('hex');
        
        if (hash === checksum) {
            client.ws.send(JSON.stringify({
                status: 'ok',
                verified: true
            }));
            console.log('[WS] DLL verified for:', client.userId);
        } else {
            client.ws.send(JSON.stringify({
                status: 'error',
                verified: false,
                error: 'Checksum mismatch'
            }));
            console.log('[WS] Checksum mismatch for:', client.userId);
        }
    }
    
    // Broadcast to all authenticated clients
    broadcast(message) {
        this.clients.forEach((client) => {
            if (client.authenticated && client.ws.readyState === WebSocket.OPEN) {
                client.ws.send(JSON.stringify(message));
            }
        });
    }
    
    // Send notification to specific client
    notify(userId, message) {
        this.clients.forEach((client) => {
            if (client.userId === userId && client.ws.readyState === WebSocket.OPEN) {
                client.ws.send(JSON.stringify(message));
            }
        });
    }
}

module.exports = LoaderServer;
