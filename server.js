const express = require('express');
const multer = require('multer');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
if (!ADMIN_PASSWORD || !SECRET || !DATABASE_URL) {
  console.error('Set ADMIN_PASSWORD, JWT_SECRET and DATABASE_URL environment variables first.');
  process.exit(1);
}
const DATA = process.env.DATA_DIR || __dirname;
const UPLOADS = path.join(DATA, 'uploads');
fs.mkdirSync(UPLOADS, { recursive: true });
const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 5 });
const q = (sql, params = []) => pool.query(sql.replace(/\?/g, (_, offset) => '$' + (sql.slice(0, offset).match(/\?/g) || []).length + 1), params);
const one = async (sql, params = []) => (await q(sql, params)).rows[0];
const many = async (sql, params = []) => (await q(sql, params)).rows;
const run = async (sql, params = []) => q(sql, params);

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS codes(id BIGSERIAL PRIMARY KEY, code TEXT UNIQUE, label TEXT, at BIGINT, token TEXT, claimed_at BIGINT, alias TEXT);
    CREATE TABLE IF NOT EXISTS videos(id BIGSERIAL PRIMARY KEY, title TEXT, descr TEXT, file TEXT, mime TEXT, author TEXT, views BIGINT DEFAULT 0, at BIGINT, real_name TEXT);
    CREATE TABLE IF NOT EXISTS likes(who TEXT, video_id BIGINT, PRIMARY KEY(who, video_id));
    CREATE TABLE IF NOT EXISTS comments(id BIGSERIAL PRIMARY KEY, video_id BIGINT, author TEXT, body TEXT, at BIGINT, real_name TEXT);
    CREATE TABLE IF NOT EXISTS messages(id BIGSERIAL PRIMARY KEY, name TEXT, contact TEXT, body TEXT, at BIGINT);
    CREATE TABLE IF NOT EXISTS convos(id BIGSERIAL PRIMARY KEY, token TEXT UNIQUE, name TEXT, contact TEXT, at BIGINT, owner_read BIGINT DEFAULT 0, visitor_read BIGINT DEFAULT 0);
    CREATE TABLE IF NOT EXISTS chat(id BIGSERIAL PRIMARY KEY, convo_id BIGINT, sender TEXT, body TEXT, at BIGINT);
  `);
  // Safe additive migrations only: never drop or truncate existing data.
  const additions = {
    codes: [['token','TEXT'],['claimed_at','BIGINT'],['alias','TEXT']],
    videos: [['real_name','TEXT']], comments: [['real_name','TEXT']],
    convos: [['owner_read','BIGINT DEFAULT 0'],['visitor_read','BIGINT DEFAULT 0']]
  };
  for (const [table, cols] of Object.entries(additions)) for (const [col, type] of cols)
    await pool.query(`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS ${col} ${type}`);
  const missing = await many('SELECT id FROM codes WHERE alias IS NULL');
  for (const r of missing) await run('UPDATE codes SET alias = ? WHERE id = ?', [randomAlias(), r.id]);
}
const randomAlias = () => Array.from(crypto.randomBytes(10), b => 'abcdefghijklmnopqrstuvwxyz'[b % 26]).join('');
const hide = (req, rows) => {
  const owner = req.user && req.user.role === 'admin';
  const f = r => { if (!owner && r) delete r.real_name; return r; };
  return Array.isArray(rows) ? rows.map(f) : f(rows);
};
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '20kb' }));
const readCookie = (req, k) => {
  const m = (req.headers.cookie || '').split(/;\s*/).find(c => c.startsWith(k + '='));
  return m ? decodeURIComponent(m.slice(k.length + 1)) : null;
};
const setSession = (req, res, payload) => res.setHeader('Set-Cookie', `reba=${jwt.sign(payload, SECRET, { expiresIn: '30d' })}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000${req.secure ? '; Secure' : ''}`);
app.use(async (req, res, next) => {
  const t = readCookie(req, 'reba');
  if (t) try {
    const p = jwt.verify(t, SECRET);
    if (p.role === 'admin') req.user = { role:'admin', who:'a', name:'Owner', real:'Owner' };
    else if (p.role === 'viewer') {
      const c = await one('SELECT * FROM codes WHERE id = ?', [p.id]);
      if (c && c.token && c.token === p.t) req.user = { role:'viewer', who:'c' + c.id, name:c.alias || 'anon', real:c.label, codeId:Number(c.id) };
    }
  } catch {}
  next();
});
const member = (req,res,next) => req.user ? next() : res.status(401).json({error:'Enter your access code first.'});
const admin = (req,res,next) => req.user && req.user.role === 'admin' ? next() : res.status(403).json({error:'Owner only.'});
const hits = new Map();
const limit = (name,max,ms) => (req,res,next) => { const k=name+req.ip, now=Date.now(); const a=(hits.get(k)||[]).filter(t=>now-t<ms); if(a.length>=max) return res.status(429).json({error:'Too many tries. Please wait a while.'}); a.push(now); hits.set(k,a); next(); };
const same = (a,b) => crypto.timingSafeEqual(crypto.createHash('sha256').update(a).digest(),crypto.createHash('sha256').update(b).digest());
const asyncRoute = fn => (req,res,next) => Promise.resolve(fn(req,res,next)).catch(next);
const noChat = res => res.status(404).json({error:'Chat not found.'});
const convoOf = async req => { const t=String(req.headers['x-chat-token']||''); return t ? one('SELECT * FROM convos WHERE token = ?', [t]) : undefined; };

app.get('/api/me',(req,res)=>res.json(req.user?{role:req.user.role,name:req.user.name}:null));
app.post('/api/chat/start',limit('chat',5,3600e3),asyncRoute(async(req,res)=>{
 const name=String(req.body.name||'').trim().slice(0,80), contact=String(req.body.contact||'').trim().slice(0,120), body=String(req.body.message||'').trim().slice(0,1500);
 if(!name||!body)return res.status(400).json({error:'Fill in your name and a message.'});
 const token=crypto.randomBytes(16).toString('hex'), now=Date.now(); const c=await one('INSERT INTO convos(token,name,contact,at,visitor_read) VALUES(?,?,?,?,?) RETURNING id',[token,name,contact,now,now]);
 await run('INSERT INTO chat(convo_id,sender,body,at) VALUES(?,?,?,?)',[c.id,'visitor',body,now]); res.json({token});
}));
app.get('/api/chat',asyncRoute(async(req,res)=>{const c=await convoOf(req);if(!c)return noChat(res);const messages=await many('SELECT sender,body,at FROM chat WHERE convo_id=? ORDER BY at,id',[c.id]);if(req.query.read)await run('UPDATE convos SET visitor_read=? WHERE id=?',[Date.now(),c.id]);res.json({name:c.name,messages});}));
app.get('/api/chat/unread',asyncRoute(async(req,res)=>{const c=await convoOf(req);if(!c)return noChat(res);const r=await one("SELECT COUNT(*) AS n FROM chat WHERE convo_id=? AND sender='owner' AND at>?",[c.id,c.visitor_read]);res.json({n:Number(r.n)});}));
app.post('/api/chat/send',limit('chatsend',40,3600e3),asyncRoute(async(req,res)=>{const c=await convoOf(req);if(!c)return noChat(res);const body=String(req.body.body||'').trim().slice(0,1500);if(!body)return res.status(400).json({error:'Write something first.'});await run('INSERT INTO chat(convo_id,sender,body,at) VALUES(?,?,?,?)',[c.id,'visitor',body,Date.now()]);res.json({ok:true});}));
app.post('/api/redeem',limit('redeem',10,900e3),asyncRoute(async(req,res)=>{const c=await one('SELECT * FROM codes WHERE code=?',[String(req.body.code||'').trim().toUpperCase()]);if(!c)return res.status(401).json({error:'That code is not valid.'});const used={error:'This code has already been used on another device. Ask the owner for a new one.'};if(c.token){if(req.user&&req.user.role==='viewer'&&req.user.codeId===Number(c.id))return res.json({role:'viewer',name:c.label});return res.status(403).json(used);}const token=crypto.randomBytes(16).toString('hex');const r=await run('UPDATE codes SET token=?,claimed_at=? WHERE id=? AND token IS NULL',[token,Date.now(),c.id]);if(!r.rowCount)return res.status(403).json(used);setSession(req,res,{role:'viewer',id:c.id,t:token});res.json({role:'viewer',name:c.label});}));
app.post('/api/admin/login',limit('admin',10,900e3),(req,res)=>{if(!same(String(req.body.password||''),ADMIN_PASSWORD))return res.status(401).json({error:'Wrong password.'});setSession(req,res,{role:'admin'});res.json({role:'admin',name:'Owner'});});
app.post('/api/logout',(req,res)=>{res.setHeader('Set-Cookie','reba=; HttpOnly; Path=/; Max-Age=0');res.json({ok:true});});
const LIST=`SELECT v.id,v.title,v.author,v.real_name,v.views,v.at,(SELECT COUNT(*) FROM likes WHERE video_id=v.id) AS likes FROM videos v`;
app.get('/api/videos',asyncRoute(async(req,res)=>res.json(hide(req,await many(LIST+' WHERE v.title ILIKE ? ORDER BY v.at DESC LIMIT 100',['%'+String(req.query.q||'')+'%'])))));
app.get('/api/videos/:id',member,asyncRoute(async(req,res)=>{const v=await one(LIST+' WHERE v.id=?',[req.params.id]);if(!v)return res.status(404).json({error:'Video not found.'});if(!req.query.noview){await run('UPDATE videos SET views=views+1 WHERE id=?',[v.id]);v.views=Number(v.views)+1;}v.descr=(await one('SELECT descr FROM videos WHERE id=?',[v.id])).descr;v.liked=!!(await one('SELECT 1 FROM likes WHERE who=? AND video_id=?',[req.user.who,v.id]));v.comments=hide(req,await many('SELECT author,real_name,body,at FROM comments WHERE video_id=? ORDER BY at DESC',[v.id]));res.json(hide(req,v));}));
const upload=multer({storage:multer.diskStorage({destination:UPLOADS,filename:(req,file,cb)=>cb(null,crypto.randomBytes(12).toString('hex')+path.extname(file.originalname).toLowerCase().slice(0,8))}),limits:{fileSize:300*1024*1024},fileFilter:(req,file,cb)=>cb(null,file.mimetype.startsWith('video/'))});
app.post('/api/videos',member,upload.single('video'),asyncRoute(async(req,res)=>{if(!req.file)return res.status(400).json({error:'Choose a video file.'});const title=String(req.body.title||'').trim().slice(0,120);if(!title){fs.unlink(req.file.path,()=>{});return res.status(400).json({error:'Add a title.'});}const r=await one('INSERT INTO videos(title,descr,file,mime,author,real_name,at) VALUES(?,?,?,?,?,?,?) RETURNING id',[title,String(req.body.descr||'').slice(0,2000),req.file.filename,req.file.mimetype,req.user.name,req.user.real,Date.now()]);res.json({id:r.id});}));
app.post('/api/videos/:id/like',member,asyncRoute(async(req,res)=>{const d=await run('DELETE FROM likes WHERE who=? AND video_id=?',[req.user.who,req.params.id]);if(!d.rowCount)await run('INSERT INTO likes(who,video_id) VALUES(?,?)',[req.user.who,req.params.id]);const c=await one('SELECT COUNT(*) AS n FROM likes WHERE video_id=?',[req.params.id]);res.json({liked:!d.rowCount,likes:Number(c.n)});}));
app.post('/api/videos/:id/comments',member,asyncRoute(async(req,res)=>{const body=String(req.body.body||'').trim().slice(0,1000);if(!body)return res.status(400).json({error:'Write something first.'});await run('INSERT INTO comments(video_id,author,real_name,body,at) VALUES(?,?,?,?,?)',[req.params.id,req.user.name,req.user.real,body,Date.now()]);res.json({ok:true});}));
app.get('/stream/:id',member,asyncRoute(async(req,res)=>{const v=await one('SELECT file,mime FROM videos WHERE id=?',[req.params.id]);if(!v)return res.sendStatus(404);const p=path.join(UPLOADS,v.file);let size;try{size=fs.statSync(p).size;}catch{return res.sendStatus(404);}const h={'Content-Type':v.mime||'video/mp4','Accept-Ranges':'bytes','Cache-Control':'private,no-store','Content-Disposition':'inline','X-Content-Type-Options':'nosniff'};const m=req.headers.range&&/bytes=(\d*)-(\d*)/.exec(req.headers.range);if(!m){res.writeHead(200,{...h,'Content-Length':size});return fs.createReadStream(p).pipe(res);}let s=m[1]?parseInt(m[1]):0,e=m[2]?parseInt(m[2]):size-1;if(!m[1]&&m[2]){s=Math.max(0,size-parseInt(m[2]));e=size-1;}e=Math.min(e,size-1);if(s>e)return res.status(416).set('Content-Range','bytes */'+size).end();res.writeHead(206,{...h,'Content-Range':`bytes ${s}-${e}/${size}`,'Content-Length':e-s+1});fs.createReadStream(p,{start:s,end:e}).pipe(res);}));
app.delete('/api/videos/:id',admin,asyncRoute(async(req,res)=>{const v=await one('SELECT file FROM videos WHERE id=?',[req.params.id]);if(!v)return res.status(404).json({error:'Not found.'});await run('DELETE FROM likes WHERE video_id=?',[req.params.id]);await run('DELETE FROM comments WHERE video_id=?',[req.params.id]);await run('DELETE FROM videos WHERE id=?',[req.params.id]);fs.unlink(path.join(UPLOADS,v.file),()=>{});res.json({ok:true});}));
app.get('/api/admin/codes',admin,asyncRoute(async(req,res)=>res.json(await many('SELECT id,code,label,alias,at,claimed_at FROM codes ORDER BY at DESC'))));
app.post('/api/admin/codes',admin,asyncRoute(async(req,res)=>{const label=String(req.body.label||'').trim().slice(0,40);if(!label)return res.status(400).json({error:'Add a name for this code.'});const raw=crypto.randomBytes(5).toString('hex').toUpperCase(),code=raw.slice(0,5)+'-'+raw.slice(5);await run('INSERT INTO codes(code,label,alias,at) VALUES(?,?,?,?)',[code,label,randomAlias(),Date.now()]);res.json({code});}));
app.delete('/api/admin/codes/:id',admin,asyncRoute(async(req,res)=>{await run('DELETE FROM codes WHERE id=?',[req.params.id]);res.json({ok:true});}));
app.post('/api/admin/codes/:id/reset',admin,asyncRoute(async(req,res)=>{await run('UPDATE codes SET token=NULL,claimed_at=NULL WHERE id=?',[req.params.id]);res.json({ok:true});}));
app.get('/api/admin/chats',admin,asyncRoute(async(req,res)=>res.json(await many(`SELECT c.id,c.name,c.contact,c.at,(SELECT body FROM chat WHERE convo_id=c.id ORDER BY at DESC,id DESC LIMIT 1) AS last_body,(SELECT MAX(at) FROM chat WHERE convo_id=c.id) AS last_at,(SELECT COUNT(*) FROM chat WHERE convo_id=c.id AND sender='visitor' AND at>c.owner_read) AS unread FROM convos c ORDER BY last_at DESC LIMIT 200`))));
app.get('/api/admin/unread',admin,asyncRoute(async(req,res)=>{const r=await one("SELECT COUNT(*) AS n FROM chat ch JOIN convos c ON c.id=ch.convo_id WHERE ch.sender='visitor' AND ch.at>c.owner_read");res.json({n:Number(r.n)});}));
app.get('/api/admin/chats/:id',admin,asyncRoute(async(req,res)=>{const c=await one('SELECT id,name,contact FROM convos WHERE id=?',[req.params.id]);if(!c)return res.status(404).json({error:'Not found.'});const messages=await many('SELECT sender,body,at FROM chat WHERE convo_id=? ORDER BY at,id',[c.id]);await run('UPDATE convos SET owner_read=? WHERE id=?',[Date.now(),c.id]);res.json({...c,messages});}));
app.post('/api/admin/chats/:id/reply',admin,asyncRoute(async(req,res)=>{const c=await one('SELECT id FROM convos WHERE id=?',[req.params.id]);if(!c)return res.status(404).json({error:'Not found.'});const body=String(req.body.body||'').trim().slice(0,1500);if(!body)return res.status(400).json({error:'Write something first.'});await run('INSERT INTO chat(convo_id,sender,body,at) VALUES(?,?,?,?)',[c.id,'owner',body,Date.now()]);res.json({ok:true});}));
app.delete('/api/admin/chats/:id',admin,asyncRoute(async(req,res)=>{await run('DELETE FROM chat WHERE convo_id=?',[req.params.id]);await run('DELETE FROM convos WHERE id=?',[req.params.id]);res.json({ok:true});}));
app.get('/',(req,res)=>res.sendFile(path.join(__dirname,'index.html')));
app.use((err,req,res,next)=>{console.error(err);if(res.headersSent)return next(err);res.status(500).json({error:'Server error. Please try again.'});});
initDb().then(()=>app.listen(PORT,()=>console.log(`REBA running on port ${PORT} with Neon PostgreSQL`))).catch(err=>{console.error('Database startup failed:',err);process.exit(1);});
