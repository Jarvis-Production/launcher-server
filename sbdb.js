// Direct Postgres connection to Supabase (bypasses RLS — server-side only).
// Set DATABASE_URL on Render to the Supabase connection string:
//   Supabase Dashboard → Project Settings → Database → Connection string (URI)
//   e.g. postgresql://postgres:<password>@db.<ref>.supabase.co:5432/postgres
const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    max: 5,
    idleTimeoutMillis: 30000,
});

pool.on('error', (err) => console.error('[sbdb] pool error:', err.message));

// convenience: return first row or null
async function one(sql, params = []) {
    const { rows } = await pool.query(sql, params);
    return rows[0] || null;
}

function clientIp(req) {
    const xff = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    return xff || req.ip || '';
}

module.exports = { pool, one, clientIp };
