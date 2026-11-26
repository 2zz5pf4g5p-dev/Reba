# REBA — Neon PostgreSQL build

This version replaces the original SQLite database with Neon PostgreSQL. It keeps the existing REBA routes and page (`index.html`) and creates the required tables using `CREATE TABLE IF NOT EXISTS` plus additive `ADD COLUMN IF NOT EXISTS` migrations. It does not drop or truncate tables.

## Before deploying

1. In Neon, open the REBA project and copy its PostgreSQL connection string. Keep it private.
2. In Render → your REBA Web Service → Environment, set:
   - `DATABASE_URL` = the Neon connection string
   - `ADMIN_PASSWORD` = your existing owner password
   - `JWT_SECRET` = your existing signing secret (keep the same value so existing login cookies remain valid)
3. Deploy this ZIP's project files to the same Render service. Render will install the added `pg` dependency using `npm install` during deployment.
4. On startup, REBA creates any missing tables/columns in Neon. It does not import records from the old SQLite database automatically.

## Important: video files are separate from Neon

Neon stores REBA's database records (video details, access codes, likes, comments and chat). The actual uploaded video files are still saved in `uploads/` on the server filesystem. Render's ordinary filesystem can be ephemeral, so uploaded videos can disappear after a redeploy/restart unless you attach a Render Persistent Disk and set `DATA_DIR` to its mount path (for example `/var/data`). Set `DATA_DIR=/var/data` in Render and mount the persistent disk at `/var/data`.

This ZIP does **not** move existing video files or SQLite records into Neon. If the old SQLite database was stored only on Render's ephemeral filesystem and is already gone, those records cannot be recovered from this ZIP. If you still have the old `reba.db` and its `uploads/` directory, preserve copies before changing anything; a separate migration is needed to import them.

## Local run

Use Node.js 22.13 or newer. Set `DATABASE_URL`, `ADMIN_PASSWORD`, and `JWT_SECRET`, then run:

```sh
npm install
npm start
```

Never paste your Neon connection string or secrets into public chats or source files.
