# REBA — permanent cloud video storage

This version sends newly uploaded videos to Cloudinary using authenticated video delivery. New uploads no longer depend on Render's temporary application filesystem. Existing locally stored videos are still read from `DATA_DIR/uploads` when those files are present.

## Configure Render

1. Create a Cloudinary account and open its **API Environment variable** details.
2. In Render, open your REBA Web Service → **Environment**. Add these variables using the exact values from Cloudinary:
   - `CLOUDINARY_CLOUD_NAME`
   - `CLOUDINARY_API_KEY`
   - `CLOUDINARY_API_SECRET`
3. Keep your existing `ADMIN_PASSWORD` and `JWT_SECRET` values unchanged. Do not paste Cloudinary secrets into the website or share them publicly.
4. Deploy this project. Render will install the added `cloudinary` package.
5. Sign in to REBA and upload a small test video. Confirm it plays, then test a larger video.

Cloudinary stores new video files in the `reba/videos` folder as **authenticated** assets. REBA checks the existing member session before generating a signed playback URL. Deleting a video in the owner panel also requests deletion of its Cloudinary asset.

## Important: database is separate

The supplied `server.js` source uses Node's built-in SQLite database (`reba.db`), not Neon PostgreSQL. This cloud-storage change only makes the **video files** persistent; it does not migrate video metadata, comments, likes, access codes, or chat into Neon. Those records still need a persistent Render disk or a separate database migration. Do not replace your Neon database or change its connection settings based on this package.

## Previously disappeared videos

This change protects future uploads. It cannot automatically restore video files that were already erased from Render's temporary filesystem. Check Cloudinary Media Library, Render disk/backups, or any original copies before assuming they are unrecoverable.

## Notes

- The current upload limit remains 300 MB. Your Cloudinary plan's limits and usage still apply.
- The server temporarily holds an uploaded file in memory while sending it to Cloudinary. For very large files or low-memory Render instances, a direct-to-Cloudinary signed browser upload flow would be a better next step.
