const express = require('express');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = path.join(__dirname, 'uploads');

if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

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

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || '') || '.mp4';
    const safeName = `${Date.now()}-${Math.round(Math.random() * 1e9)}${ext}`;
    cb(null, safeName);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 500 * 1024 * 1024 },
});

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

function getOptionalUser(req) {
  const secret = getJwtSecret();
  if (!secret) return null;
  const authHeader = req.headers.authorization || '';
  const tokenFromHeader = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7).trim()
    : '';
  const token = tokenFromHeader || req.headers['x-auth-token'] || req.body?.token || '';
  if (!token) return null;
  try {
    return jwt.verify(token, secret);
  } catch (err) {
    return null;
  }
}

function requireOwner(req, res, next) {
  const secret = getJwtSecret();
  const authHeader = req.headers.authorization || '';
  const tokenFromHeader = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7).trim()
    : '';
  const token = tokenFromHeader || req.headers['x-auth-token'] || req.body?.token || '';

  if (!secret) {
    return res.status(500).json({ error: 'Server auth secret missing' });
  }

  if (!token) {
    return res.status(401).json({ error: 'Owner authentication required' });
  }

  try {
    const decoded = jwt.verify(token, secret);
    if (decoded.role !== 'owner') {
      return res.status(403).json({ error: 'Owner role required' });
    }
    req.user = decoded;
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

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

  await pool.query(`
    CREATE TABLE IF NOT EXISTS videos (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      filename TEXT NOT NULL,
      url TEXT NOT NULL,
      views INTEGER DEFAULT 0,
      likes INTEGER DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS chat_messages (
      id SERIAL PRIMARY KEY,
      sender TEXT NOT NULL,
      role TEXT DEFAULT 'guest',
      message TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(UPLOAD_DIR));
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

// Owner creates an access code in Postgres
app.post('/api/access-codes', requireOwner, async (req, res) => {
  const raw = String(req.body?.code || '').trim();
  const code = raw || `REBA-${Math.random().toString(36).slice(2, 8).toUpperCase()}`;

  try {
    const { rows } = await pool.query(
      `INSERT INTO access_codes (code)
       VALUES ($1)
       ON CONFLICT (code) DO UPDATE SET code = EXCLUDED.code
       RETURNING id, code, used, created_at`,
      [code]
    );
    return res.status(201).json({ ok: true, accessCode: rows[0] });
  } catch (err) {
    console.error('POST /api/access-codes error:', err);
    return res.status(500).json({ error: 'Failed to create access code' });
  }
});

// List uploaded videos (hides raw video file URL from unauthenticated visitors)
app.get('/api/videos', async (req, res) => {
  const user = getOptionalUser(req);
  const unlocked = user?.role === 'owner' || user?.role === 'member';
  const sort = String(req.query?.sort || 'new').toLowerCase();
  const search = String(req.query?.q || '').trim().toLowerCase();

  let orderBy = 'id DESC';
  if (sort === 'views' || sort === 'most_viewed') {
    orderBy = 'views DESC, id DESC';
  } else if (sort === 'likes' || sort === 'most_liked') {
    orderBy = 'likes DESC, id DESC';
  }

  try {
    const { rows } = await pool.query(
      `SELECT id, title, description, filename, url, views, likes, created_at
       FROM videos
       ORDER BY ${orderBy}`
    );

    const filtered = (search
      ? rows.filter(
          (v) =>
            String(v.title || '').toLowerCase().includes(search) ||
            String(v.description || '').toLowerCase().includes(search)
        )
      : rows
    ).map((v) => ({
      id: v.id,
      title: v.title,
      description: v.description,
      views: v.views,
      likes: v.likes,
      created_at: v.created_at,
      locked: !unlocked,
      url: unlocked ? v.url : null,
    }));

    res.json(filtered);
  } catch (err) {
    console.error('GET /api/videos error:', err);
    res.status(500).json({ error: 'Failed to load videos' });
  }
});

// Upload a video (Owner only)
app.post(
  ['/api/videos', '/api/upload', '/api/owner/upload'],
  requireOwner,
  upload.single('video'),
  async (req, res) => {
    const file = req.file;
    const title =
      String(req.body?.title || file?.originalname || 'Untitled Video').trim();
    const description = String(req.body?.description || '').trim();

    if (!file) {
      return res.status(400).json({ error: 'No video file uploaded (field name: video)' });
    }

    const fileUrl = `/uploads/${file.filename}`;

    try {
      const { rows } = await pool.query(
        `INSERT INTO videos (title, description, filename, url)
         VALUES ($1, $2, $3, $4)
         RETURNING id, title, description, filename, url, views, likes, created_at`,
        [title, description, file.filename, fileUrl]
      );
      return res.status(201).json({ ok: true, video: rows[0] });
    } catch (err) {
      console.error('POST /api/videos error:', err);
      return res.status(500).json({ error: 'Failed to save video record' });
    }
  }
);

// In-app chat routes backed by Postgres
app.get('/api/chat', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, sender, role, message, created_at
       FROM chat_messages
       ORDER BY id ASC
       LIMIT 100`
    );
    res.json(rows);
  } catch (err) {
    console.error('GET /api/chat error:', err);
    res.status(500).json({ error: 'Failed to load chat messages' });
  }
});

app.post('/api/chat', async (req, res) => {
  const user = getOptionalUser(req);
  const role = user?.role === 'owner' ? 'owner' : 'guest';
  const sender =
    role === 'owner'
      ? 'Owner'
      : String(req.body?.sender || 'Visitor').trim().slice(0, 40) || 'Visitor';
  const message = String(req.body?.message || req.body?.body || '').trim().slice(0, 1000);

  if (!message) {
    return res.status(400).json({ error: 'Message cannot be empty' });
  }

  try {
    const { rows } = await pool.query(
      `INSERT INTO chat_messages (sender, role, message)
       VALUES ($1, $2, $3)
       RETURNING id, sender, role, message, created_at`,
      [sender, role, message]
    );
    return res.status(201).json({ ok: true, message: rows[0] });
  } catch (err) {
    console.error('POST /api/chat error:', err);
    res.status(500).json({ error: 'Failed to send chat message' });
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
