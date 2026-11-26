const express = require('express');
const multer = require('multer');
const { DatabaseSync: Database } = require('node:sqlite');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SECRET = process.env.JWT_SECRET;
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
      if (p.role === 'admin') req.user = { role: 'admin', who: 'a', name: 'Owner' };
      else if (p.role === 'viewer') {
        // Checked on every request, so revoking a code locks that person out immediately
        const c = db.prepare('SELECT * FROM codes WHERE id = ?').get(p.id);
        if (c) req.user = { role: 'viewer', who: 'c' + c.id, name: c.label };
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

app.post('/api/contact', limit('contact', 5, 3600e3), (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 80);
  const contact = String(req.body.contact || '').trim().slice(0, 120);
  const body = String(req.body.message || '').trim().slice(0, 1500);
  if (!name || !contact || !body) return res.status(400).json({ error: 'Fill in your name, how to reach you, and a message.' });
  db.prepare('INSERT INTO messages(name, contact, body, at) VALUES(?, ?, ?, ?)').run(name, contact, body, Date.now());
  res.json({ ok: true });
});

app.post('/api/redeem', limit('redeem', 10, 900e3), (req, res) => {
  const c = db.prepare('SELECT * FROM codes WHERE code = ?').get(String(req.body.code || '').trim().toUpperCase());
  if (!c) return res.status(401).json({ error: 'That code is not valid.' });
  setSession(req, res, { role: 'viewer', id: c.id });
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
const LIST = `SELECT v.id, v.title, v.author, v.views, v.at,
  (SELECT COUNT(*) FROM likes WHERE video_id = v.id) AS likes FROM videos v`;
app.get('/api/videos', (req, res) => {
  res.json(db.prepare(LIST + ' WHERE v.title LIKE ? ORDER BY v.at DESC LIMIT 100').all('%' + String(req.query.q || '') + '%'));
});

// ---------- Members (code holders and owner) ----------
app.get('/api/videos/:id', member, (req, res) => {
  const v = db.prepare(LIST + ' WHERE v.id = ?').get(req.params.id);
  if (!v) return res.status(404).json({ error: 'Video not found.' });
  if (!req.query.noview) { db.prepare('UPDATE videos SET views = views + 1 WHERE id = ?').run(v.id); v.views++; }
  v.descr = db.prepare('SELECT descr FROM videos WHERE id = ?').get(v.id).descr;
  v.liked = !!db.prepare('SELECT 1 FROM likes WHERE who = ? AND video_id = ?').get(req.user.who, v.id);
  v.comments = db.prepare('SELECT author, body, at FROM comments WHERE video_id = ? ORDER BY at DESC').all(v.id);
  res.json(v);
});

const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOADS,
    filename: (req, file, cb) => cb(null, crypto.randomBytes(12).toString('hex') + path.extname(file.originalname).toLowerCase().slice(0, 8)),
  }),
  limits: { fileSize: 300 * 1024 * 1024 },
  fileFilter: (req, file, cb) => cb(null, file.mimetype.startsWith('video/')),
});

app.post('/api/videos', member, upload.single('video'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Choose a video file.' });
  const title = String(req.body.title || '').trim().slice(0, 120);
  if (!title) { fs.unlink(req.file.path, () => {}); return res.status(400).json({ error: 'Add a title.' }); }
  const r = db.prepare('INSERT INTO videos(title, descr, file, mime, author, at) VALUES(?, ?, ?, ?, ?, ?)')
    .run(title, String(req.body.descr || '').slice(0, 2000), req.file.filename, req.file.mimetype, req.user.name, Date.now());
  res.json({ id: r.lastInsertRowid });
});

app.post('/api/videos/:id/like', member, (req, res) => {
  const had = db.prepare('DELETE FROM likes WHERE who = ? AND video_id = ?').run(req.user.who, req.params.id).changes;
  if (!had) db.prepare('INSERT INTO likes VALUES(?, ?)').run(req.user.who, req.params.id);
  res.json({ liked: !had, likes: db.prepare('SELECT COUNT(*) AS n FROM likes WHERE video_id = ?').get(req.params.id).n });
});

app.post('/api/videos/:id/comments', member, (req, res) => {
  const body = String(req.body.body || '').trim().slice(0, 1000);
  if (!body) return res.status(400).json({ error: 'Write something first.' });
  db.prepare('INSERT INTO comments(video_id, author, body, at) VALUES(?, ?, ?, ?)').run(req.params.id, req.user.name, body, Date.now());
  res.json({ ok: true });
});

// Video bytes only go to members. Not a public folder, no download button, nothing cached.
app.get('/stream/:id', member, (req, res) => {
  const v = db.prepare('SELECT file, mime FROM videos WHERE id = ?').get(req.params.id);
  if (!v) return res.sendStatus(404);
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
  fs.unlink(path.join(UPLOADS, v.file), () => {});
  res.json({ ok: true });
});

app.get('/api/admin/codes', admin, (req, res) => res.json(db.prepare('SELECT * FROM codes ORDER BY at DESC').all()));
app.post('/api/admin/codes', admin, (req, res) => {
  const label = String(req.body.label || '').trim().slice(0, 40);
  if (!label) return res.status(400).json({ error: 'Add a name for this code.' });
  const raw = crypto.randomBytes(5).toString('hex').toUpperCase();
  const code = raw.slice(0, 5) + '-' + raw.slice(5);
  db.prepare('INSERT INTO codes(code, label, at) VALUES(?, ?, ?)').run(code, label, Date.now());
  res.json({ code });
});
app.delete('/api/admin/codes/:id', admin, (req, res) => { db.prepare('DELETE FROM codes WHERE id = ?').run(req.params.id); res.json({ ok: true }); });

app.get('/api/admin/messages', admin, (req, res) => res.json(db.prepare('SELECT * FROM messages ORDER BY at DESC LIMIT 200').all()));
app.delete('/api/admin/messages/:id', admin, (req, res) => { db.prepare('DELETE FROM messages WHERE id = ?').run(req.params.id); res.json({ ok: true }); });

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.listen(PORT, () => console.log(`Reba running on port ${PORT}`));
