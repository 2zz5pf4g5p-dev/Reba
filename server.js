const express = require('express');
const multer = require('multer');
const { DatabaseSync: Database } = require('node:sqlite');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { v2: cloudinary } = require('cloudinary');

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SECRET = process.env.JWT_SECRET;
const CLOUDINARY_READY = !!(process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET);
if (CLOUDINARY_READY) cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true,
});
if (!ADMIN_PASSWORD || !SECRET) {
  console.error('Set the ADMIN_PASSWORD and JWT_SECRET environment variables first.');
  process.exit(1);
}
// Point DATA_DIR at a persistent disk when you deploy, so videos and the database survive restarts
const DATA = process.env.DATA_DIR || __dirname;
const UPLOADS = path.join(DATA, 'uploads');
fs.mkdirSync(UPLOADS, { recursive: true });

const db = new Database(path.join(DATA, 'reba.db'));
db.exec(`
  CREATE TABLE IF NOT EXISTS codes(id INTEGER PRIMARY KEY, code TEXT UNIQUE, label TEXT, at INTEGER);
  CREATE TABLE IF NOT EXISTS videos(id INTEGER PRIMARY KEY, title TEXT, descr TEXT, file TEXT, mime TEXT, author TEXT, views INTEGER DEFAULT 0, at INTEGER);
  CREATE TABLE IF NOT EXISTS likes(who TEXT, video_id INTEGER, PRIMARY KEY(who, video_id));
  CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY, video_id INTEGER, author TEXT, body TEXT, at INTEGER);
  CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, name TEXT, contact TEXT, body TEXT, at INTEGER);
`);

// Each code can be claimed by one browser only (token + time of first use)
const codeCols = db.prepare('PRAGMA table_info(codes)').all().map(c => c.name);
if (!codeCols.includes('token')) db.exec('ALTER TABLE codes ADD COLUMN token TEXT');
if (!codeCols.includes('claimed_at')) db.exec('ALTER TABLE codes ADD COLUMN claimed_at INTEGER');
if (!codeCols.includes('alias')) db.exec('ALTER TABLE codes ADD COLUMN alias TEXT');
for (const t of ['videos', 'comments']) {
  if (!db.prepare(`PRAGMA table_info(${t})`).all().some(c => c.name === 'real_name')) db.exec(`ALTER TABLE ${t} ADD COLUMN real_name TEXT`);
}
// Public anonymous name: random letters, fixed per code. Only the owner sees the real name.
const randomAlias = () => Array.from(crypto.randomBytes(10), b => 'abcdefghijklmnopqrstuvwxyz'[b % 26]).join('');
for (const r of db.prepare('SELECT id FROM codes WHERE alias IS NULL').all()) db.prepare('UPDATE codes SET alias = ? WHERE id = ?').run(randomAlias(), r.id);
// Real names are removed from every response unless the owner is logged in
const hide = (req, rows) => {
  const owner = req.user && req.user.role === 'admin';
  const f = r => { if (!owner) delete r.real_name; return r; };
  return Array.isArray(rows) ? rows.map(f) : f(rows);
};

db.exec(`
  CREATE TABLE IF NOT EXISTS convos(id INTEGER PRIMARY KEY, token TEXT UNIQUE, name TEXT, contact TEXT, at INTEGER, owner_read INTEGER DEFAULT 0, visitor_read INTEGER DEFAULT 0);
  CREATE TABLE IF NOT EXISTS chat(id INTEGER PRIMARY KEY, convo_id INTEGER, sender TEXT, body TEXT, at INTEGER);
`);

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '20kb' }));

// ---------- Sessions (one cookie: owner or code-holder) ----------
const readCookie = (req, k) => {
  const m = (req.headers.cookie || '').split(/;\s*/).find(c => c.startsWith(k + '='));
  return m ? decodeURIComponent(m.slice(k.length + 1)) : null;
};
const setSession = (req, res, payload) => res.setHeader('Set-Cookie',
  `reba=${jwt.sign(payload, SECRET, { expiresIn: '30d' })}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000${req.secure ? '; Secure' : ''}`);

app.use((req, res, next) => {
  const t = readCookie(req, 'reba');
  if (t) {
    try {
      const p = jwt.verify(t, SECRET);
      if (p.role === 'admin') req.user = { role: 'admin', who: 'a', name: 'Owner', real: 'Owner' };
      else if (p.role === 'viewer') {
        // Checked on every request: revoking or resetting a code locks that browser out immediately
        const c = db.prepare('SELECT * FROM codes WHERE id = ?').get(p.id);
        if (c && c.token && c.token === p.t) req.user = { role: 'viewer', who: 'c' + c.id, name: c.alias || 'anon', real: c.label, codeId: c.id };
      }
    } catch {}
  }
  next();
});
const member = (req, res, next) => req.user ? next() : res.status(401).json({ error: 'Enter your access code first.' });
const admin = (req, res, next) => req.user && req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Owner only.' });

const hits = new Map();
const limit = (name, max, ms) => (req, res, next) => {
  const k = name + req.ip, now = Date.now();
  const a = (hits.get(k) || []).filter(t => now - t < ms);
  if (a.length >= max) return res.status(429).json({ error: 'Too many tries. Please wait a while.' });
  a.push(now); hits.set(k, a); next();
};
const same = (a, b) => crypto.timingSafeEqual(crypto.createHash('sha256').update(a).digest(), crypto.createHash('sha256').update(b).digest());

// ---------- Public ----------
app.get('/api/me', (req, res) => res.json(req.user ? { role: req.user.role, name: req.user.name } : null));

// ---------- Two-way chat ----------
// A visitor's chat is found with a secret token kept in their browser; nobody else can read it.
const convoOf = req => {
  const t = String(req.headers['x-chat-token'] || '');
  return t ? db.prepare('SELECT * FROM convos WHERE token = ?').get(t) : undefined;
};
const noChat = res => res.status(404).json({ error: 'Chat not found.' });

app.post('/api/chat/start', limit('chat', 5, 3600e3), (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 80);
  const contact = String(req.body.contact || '').trim().slice(0, 120);
  const body = String(req.body.message || '').trim().slice(0, 1500);
  if (!name || !body) return res.status(400).json({ error: 'Fill in your name and a message.' });
  const token = crypto.randomBytes(16).toString('hex'), now = Date.now();
  const r = db.prepare('INSERT INTO convos(token, name, contact, at, visitor_read) VALUES(?, ?, ?, ?, ?)').run(token, name, contact, now, now);
  db.prepare('INSERT INTO chat(convo_id, sender, body, at) VALUES(?, ?, ?, ?)').run(r.lastInsertRowid, 'visitor', body, now);
  res.json({ token });
});

app.get('/api/chat', (req, res) => {
  const c = convoOf(req);
  if (!c) return noChat(res);
  const messages = db.prepare('SELECT sender, body, at FROM chat WHERE convo_id = ? ORDER BY at, id').all(c.id);
  if (req.query.read) db.prepare('UPDATE convos SET visitor_read = ? WHERE id = ?').run(Date.now(), c.id);
  res.json({ name: c.name, messages });
});

app.get('/api/chat/unread', (req, res) => {
  const c = convoOf(req);
  if (!c) return noChat(res);
  res.json({ n: db.prepare("SELECT COUNT(*) AS n FROM chat WHERE convo_id = ? AND sender = 'owner' AND at > ?").get(c.id, c.visitor_read).n });
});

app.post('/api/chat/send', limit('chatsend', 40, 3600e3), (req, res) => {
  const c = convoOf(req);
  if (!c) return noChat(res);
  const body = String(req.body.body || '').trim().slice(0, 1500);
  if (!body) return res.status(400).json({ error: 'Write something first.' });
  db.prepare('INSERT INTO chat(convo_id, sender, body, at) VALUES(?, ?, ?, ?)').run(c.id, 'visitor', body, Date.now());
  res.json({ ok: true });
});

app.post('/api/redeem', limit('redeem', 10, 900e3), (req, res) => {
  const c = db.prepare('SELECT * FROM codes WHERE code = ?').get(String(req.body.code || '').trim().toUpperCase());
  if (!c) return res.status(401).json({ error: 'That code is not valid.' });
  const used = { error: 'This code has already been used on another device. Ask the owner for a new one.' };
  if (c.token) {
    // Already claimed: only the browser that claimed it may continue
    if (req.user && req.user.role === 'viewer' && req.user.codeId === c.id) return res.json({ role: 'viewer', name: c.label });
    return res.status(403).json(used);
  }
  const token = crypto.randomBytes(16).toString('hex');
  const r = db.prepare('UPDATE codes SET token = ?, claimed_at = ? WHERE id = ? AND token IS NULL').run(token, Date.now(), c.id);
  if (!r.changes) return res.status(403).json(used);
  setSession(req, res, { role: 'viewer', id: c.id, t: token });
  res.json({ role: 'viewer', name: c.label });
});

app.post('/api/admin/login', limit('admin', 10, 900e3), (req, res) => {
  if (!same(String(req.body.password || ''), ADMIN_PASSWORD)) return res.status(401).json({ error: 'Wrong password.' });
  setSession(req, res, { role: 'admin' });
  res.json({ role: 'admin', name: 'Owner' });
});

app.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'reba=; HttpOnly; Path=/; Max-Age=0');
  res.json({ ok: true });
});

// Titles are public; the files are not
const LIST = `SELECT v.id, v.title, v.author, v.real_name, v.views, v.at,
  (SELECT COUNT(*) FROM likes WHERE video_id = v.id) AS likes FROM videos v`;
app.get('/api/videos', (req, res) => {
  res.json(hide(req, db.prepare(LIST + ' WHERE v.title LIKE ? ORDER BY v.at DESC LIMIT 100').all('%' + String(req.query.q || '') + '%')));
});

// ---------- Members (code holders and owner) ----------
app.get('/api/videos/:id', member, (req, res) => {
  const v = db.prepare(LIST + ' WHERE v.id = ?').get(req.params.id);
  if (!v) return res.status(404).json({ error: 'Video not found.' });
  if (!req.query.noview) { db.prepare('UPDATE videos SET views = views + 1 WHERE id = ?').run(v.id); v.views++; }
  v.descr = db.prepare('SELECT descr FROM videos WHERE id = ?').get(v.id).descr;
  v.liked = !!db.prepare('SELECT 1 FROM likes WHERE who = ? AND video_id = ?').get(req.user.who, v.id);
  v.comments = hide(req, db.prepare('SELECT author, real_name, body, at FROM comments WHERE video_id = ? ORDER BY at DESC').all(v.id));
  res.json(hide(req, v));
});

// New video uploads go directly to Cloudinary (persistent object storage), not Render's
// temporary filesystem. Existing legacy files stored on disk remain streamable if present.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 300 * 1024 * 1024 },
  fileFilter: (req, file, cb) => cb(null, file.mimetype.startsWith('video/')),
});

function uploadVideoToCloudinary(file) {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream({
      resource_type: 'video',
      type: 'authenticated',
      folder: 'reba/videos',
      use_filename: false,
      unique_filename: true,
    }, (error, result) => error ? reject(error) : resolve(result));
    stream.end(file.buffer);
  });
}

app.post('/api/videos', member, upload.single('video'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Choose a video file.' });
  const title = String(req.body.title || '').trim().slice(0, 120);
  if (!title) return res.status(400).json({ error: 'Add a title.' });
  if (!CLOUDINARY_READY) return res.status(503).json({ error: 'Cloud video storage is not configured yet. Add the Cloudinary environment variables on Render.' });

  try {
    const uploaded = await uploadVideoToCloudinary(req.file);
    const storedFile = 'cloudinary:' + uploaded.public_id;
    const r = db.prepare('INSERT INTO videos(title, descr, file, mime, author, real_name, at) VALUES(?, ?, ?, ?, ?, ?, ?)')
      .run(title, String(req.body.descr || '').slice(0, 2000), storedFile, req.file.mimetype, req.user.name, req.user.real, Date.now());
    res.json({ id: r.lastInsertRowid });
  } catch (error) {
    console.error('Cloudinary video upload failed:', error.message);
    res.status(502).json({ error: 'The video could not be saved to cloud storage. Please try again.' });
  }
});

app.post('/api/videos/:id/like', member, (req, res) => {
  const had = db.prepare('DELETE FROM likes WHERE who = ? AND video_id = ?').run(req.user.who, req.params.id).changes;
  if (!had) db.prepare('INSERT INTO likes VALUES(?, ?)').run(req.user.who, req.params.id);
  res.json({ liked: !had, likes: db.prepare('SELECT COUNT(*) AS n FROM likes WHERE video_id = ?').get(req.params.id).n });
});

app.post('/api/videos/:id/comments', member, (req, res) => {
  const body = String(req.body.body || '').trim().slice(0, 1000);
  if (!body) return res.status(400).json({ error: 'Write something first.' });
  db.prepare('INSERT INTO comments(video_id, author, real_name, body, at) VALUES(?, ?, ?, ?, ?)').run(req.params.id, req.user.name, req.user.real, body, Date.now());
  res.json({ ok: true });
});

// Video bytes only go to members. Not a public folder, no download button, nothing cached.
app.get('/stream/:id', member, (req, res) => {
  const v = db.prepare('SELECT file, mime FROM videos WHERE id = ?').get(req.params.id);
  if (!v) return res.sendStatus(404);
  if (String(v.file).startsWith('cloudinary:')) {
    if (!CLOUDINARY_READY) return res.status(503).send('Cloud video storage is not configured.');
    const publicId = String(v.file).slice('cloudinary:'.length);
    const signedUrl = cloudinary.url(publicId, {
      resource_type: 'video', type: 'authenticated', sign_url: true, secure: true,
      format: undefined,
    });
    res.setHeader('Cache-Control', 'private, no-store');
    return res.redirect(302, signedUrl);
  }
  const p = path.join(UPLOADS, v.file);
  let size;
  try { size = fs.statSync(p).size; } catch { return res.sendStatus(404); }
  const h = { 'Content-Type': v.mime || 'video/mp4', 'Accept-Ranges': 'bytes', 'Cache-Control': 'private, no-store', 'Content-Disposition': 'inline', 'X-Content-Type-Options': 'nosniff' };
  const m = req.headers.range && /bytes=(\d*)-(\d*)/.exec(req.headers.range);
  if (!m) { res.writeHead(200, { ...h, 'Content-Length': size }); return fs.createReadStream(p).pipe(res); }
  let s = m[1] ? parseInt(m[1]) : 0, e = m[2] ? parseInt(m[2]) : size - 1;
  if (!m[1] && m[2]) { s = Math.max(0, size - parseInt(m[2])); e = size - 1; }
  e = Math.min(e, size - 1);
  if (s > e) return res.status(416).set('Content-Range', 'bytes */' + size).end();
  res.writeHead(206, { ...h, 'Content-Range': `bytes ${s}-${e}/${size}`, 'Content-Length': e - s + 1 });
  fs.createReadStream(p, { start: s, end: e }).pipe(res);
});

// ---------- Owner only ----------
app.delete('/api/videos/:id', admin, (req, res) => {
  const v = db.prepare('SELECT file FROM videos WHERE id = ?').get(req.params.id);
  if (!v) return res.status(404).json({ error: 'Not found.' });
  for (const t of ['videos', 'likes', 'comments']) db.prepare(`DELETE FROM ${t} WHERE ${t === 'videos' ? 'id' : 'video_id'} = ?`).run(req.params.id);
  if (String(v.file).startsWith('cloudinary:') && CLOUDINARY_READY) {
    const publicId = String(v.file).slice('cloudinary:'.length);
    cloudinary.uploader.destroy(publicId, { resource_type: 'video', type: 'authenticated' })
      .catch(error => console.error('Cloudinary delete failed:', error.message));
  } else {
    fs.unlink(path.join(UPLOADS, v.file), () => {});
  }
  res.json({ ok: true });
});

app.get('/api/admin/codes', admin, (req, res) => res.json(db.prepare('SELECT id, code, label, alias, at, claimed_at FROM codes ORDER BY at DESC').all()));
app.post('/api/admin/codes', admin, (req, res) => {
  const label = String(req.body.label || '').trim().slice(0, 40);
  if (!label) return res.status(400).json({ error: 'Add a name for this code.' });
  const raw = crypto.randomBytes(5).toString('hex').toUpperCase();
  const code = raw.slice(0, 5) + '-' + raw.slice(5);
  db.prepare('INSERT INTO codes(code, label, alias, at) VALUES(?, ?, ?, ?)').run(code, label, randomAlias(), Date.now());
  res.json({ code });
});
app.delete('/api/admin/codes/:id', admin, (req, res) => { db.prepare('DELETE FROM codes WHERE id = ?').run(req.params.id); res.json({ ok: true }); });
app.post('/api/admin/codes/:id/reset', admin, (req, res) => { db.prepare('UPDATE codes SET token = NULL, claimed_at = NULL WHERE id = ?').run(req.params.id); res.json({ ok: true }); });

app.get('/api/admin/chats', admin, (req, res) => res.json(db.prepare(`
  SELECT c.id, c.name, c.contact, c.at,
    (SELECT body FROM chat WHERE convo_id = c.id ORDER BY at DESC, id DESC LIMIT 1) AS last_body,
    (SELECT MAX(at) FROM chat WHERE convo_id = c.id) AS last_at,
    (SELECT COUNT(*) FROM chat WHERE convo_id = c.id AND sender = 'visitor' AND at > c.owner_read) AS unread
  FROM convos c ORDER BY last_at DESC LIMIT 200`).all()));

app.get('/api/admin/unread', admin, (req, res) => res.json({ n: db.prepare(
  "SELECT COUNT(*) AS n FROM chat ch JOIN convos c ON c.id = ch.convo_id WHERE ch.sender = 'visitor' AND ch.at > c.owner_read").get().n }));

app.get('/api/admin/chats/:id', admin, (req, res) => {
  const c = db.prepare('SELECT id, name, contact FROM convos WHERE id = ?').get(req.params.id);
  if (!c) return res.status(404).json({ error: 'Not found.' });
  const messages = db.prepare('SELECT sender, body, at FROM chat WHERE convo_id = ? ORDER BY at, id').all(c.id);
  db.prepare('UPDATE convos SET owner_read = ? WHERE id = ?').run(Date.now(), c.id);
  res.json({ ...c, messages });
});

app.post('/api/admin/chats/:id/reply', admin, (req, res) => {
  const c = db.prepare('SELECT id FROM convos WHERE id = ?').get(req.params.id);
  if (!c) return res.status(404).json({ error: 'Not found.' });
  const body = String(req.body.body || '').trim().slice(0, 1500);
  if (!body) return res.status(400).json({ error: 'Write something first.' });
  db.prepare('INSERT INTO chat(convo_id, sender, body, at) VALUES(?, ?, ?, ?)').run(c.id, 'owner', body, Date.now());
  res.json({ ok: true });
});

app.delete('/api/admin/chats/:id', admin, (req, res) => {
  db.prepare('DELETE FROM chat WHERE convo_id = ?').run(req.params.id);
  db.prepare('DELETE FROM convos WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.listen(PORT, () => console.log(`Reba running on port ${PORT}`));
