# Reba (private video site)

Anyone can open the site and see video titles. To watch or upload, a visitor needs an
access code from the owner. Only the owner can delete videos.

## Environment variables (required)
- ADMIN_PASSWORD  your owner password
- JWT_SECRET      a long random string (30+ characters)
- DATA_DIR        optional: folder on a persistent disk for videos + database
- PORT            set automatically by most hosts

## Run on a computer
    npm install
    ADMIN_PASSWORD=yourpassword JWT_SECRET=long-random-text npm start
(On Windows cmd use: set ADMIN_PASSWORD=yourpassword  then  set JWT_SECRET=long-random-text  then  npm start)

Open http://localhost:3000

## Using it
1. Open your site address followed by /#owner (for example https://yoursite.onrender.com/#owner) and enter ADMIN_PASSWORD. Visitors never see this link.
2. In the Owner panel, create a code for each person and send it to them.
3. Chat with visitors in the same panel (a red badge shows new messages). Revoke a code to lock someone out instantly.

## Deploying
Use a host that gives you a persistent disk (Render, Railway, Fly.io, a small VPS) and set
DATA_DIR to that disk's path. Without a persistent disk, videos, codes and messages are lost
when the server restarts. Serve over HTTPS.

## About "no downloads"
The site hides the download button and never exposes a file link: videos stream only to
code holders and are not cached. That stops casual saving. Nothing can fully stop someone
who is determined (screen recording, for example), so only give codes to people you trust.
