const express = require('express');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL) {
  console.error('Missing DATABASE_URL environment variable.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

pool.on('error', (err) => {
  console.error('Unexpected Postgres pool error:', err);
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS access_codes (
      id SERIAL PRIMARY KEY,
      code TEXT UNIQUE NOT NULL,
      used BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS comments (
      id SERIAL PRIMARY KEY,
      author TEXT NOT NULL,
      body TEXT NOT NULL,
      metadata JSONB DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

function getOwnerPassword() {
  return (
    process.env.ADMIN_PASSWORD ||
    process.env.OWNER_PASSWORD ||
    process.env.ADMIN_CODE ||
    ''
  );
}

function getJwtSecret() {
  return process.env.JWT_SECRET || process.env.JWT_KEY || '';
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('.'));

app.get('/health', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW() AS now');
    res.json({ ok: true, dbTime: result.rows[0].now });
  } catch (err) {
    console.error('Healthcheck DB error:', err);
    res.status(500).json({ ok: false, error: 'Database unavailable' });
  }
});

// Owner / Admin login route
app.post(['/api/owner/login', '/api/admin/login', '/api/login'], (req, res) => {
  const submitted =
    req.body?.password ||
    req.body?.ownerPassword ||
    req.body?.adminPassword ||
    req.body?.code ||
    '';
  const expected = getOwnerPassword();
  const secret = getJwtSecret();

  if (!expected || !secret) {
    return res.status(500).json({ error: 'Server auth environment variables missing' });
  }

  if (!submitted || submitted !== expected) {
    return res.status(401).json({ error: 'Invalid owner password' });
  }

  const token = jwt.sign({ role: 'owner' }, secret, { expiresIn: '7d' });
  return res.json({ ok: true, token, role: 'owner' });
});

// Access code validation route backed by Postgres
app.post(['/api/access-code', '/api/verify-code'], async (req, res) => {
  const code = String(req.body?.code || req.body?.accessCode || '').trim();
  const secret = getJwtSecret();

  if (!code) {
    return res.status(400).json({ error: 'Access code is required' });
  }

  try {
    const { rows } = await pool.query(
      'SELECT id, code, used FROM access_codes WHERE code = $1',
      [code]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid access code' });
    }

    const token = secret
      ? jwt.sign({ role: 'member', code: rows[0].code }, secret, { expiresIn: '7d' })
      : null;

    return res.json({ ok: true, valid: true, token });
  } catch (err) {
    console.error('Access code check error:', err);
    return res.status(500).json({ error: 'Failed to verify access code' });
  }
});

app.get('/api/comments', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, author, body, metadata, created_at FROM comments ORDER BY id DESC'
    );
    res.json(rows);
  } catch (err) {
    console.error('GET /api/comments error:', err);
    res.status(500).json({ error: 'Failed to load comments' });
  }
});

app.post('/api/comments', async (req, res) => {
  const { author, body, metadata = {} } = req.body || {};
  if (!author || !body) {
    return res.status(400).json({ error: 'author and body are required' });
  }

  try {
    const { rows } = await pool.query(
      `INSERT INTO comments (author, body, metadata)
       VALUES ($1, $2, $3)
       RETURNING id, author, body, metadata, created_at`,
      [author, body, metadata]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error('POST /api/comments error:', err);
    res.status(500).json({ error: 'Failed to save comment' });
  }
});

async function start() {
  try {
    await initDb();
    app.listen(PORT, () => {
      console.log(`Reba running on port ${PORT} with Postgres persistence`);
    });
  } catch (err) {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  }
}

start();
