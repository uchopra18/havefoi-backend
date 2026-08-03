# Pet Tag Backend (starter)

A minimal backend for QR-code pet profiles — no subscriptions, no accounts.
Each tag gets:
- a **public ID** → printed under the QR code, links to a read-only profile page
- a **private edit code** → given to the owner only (e.g. printed on an insert card
  or shown after checkout), used to edit the profile later

## Run it locally
No install needed — uses only Node's built-in modules.

```
node server.js
```

Then open http://localhost:3000 in a browser to create a test profile.

## How it works
- `POST /api/profiles` — create a new profile, returns `publicId` + `editToken`
- `GET /pet/:publicId` — the page a QR code scan opens (read-only)
- `GET /edit/:editToken` — the page the owner uses to update their info
- Data is stored in `db.json` (created automatically). This is fine for testing,
  but **swap it for a real database before going live** — see "Next steps" below.

## Next steps for production
1. **Real database** — replace `db.json` with Postgres/MySQL (e.g. via
   [Supabase](https://supabase.com) or [Railway](https://railway.app), both have
   free tiers and are easy to set up from India).
2. **Hosting** — deploy this on Render, Railway, or a small VPS. Point your
   domain's `/pet/*` path at it.
3. **QR generation** — when a tag is manufactured, call `POST /api/profiles`
   to get a `publicId`, generate a QR code for `https://yourdomain.com/pet/<publicId>`
   (any QR library works, e.g. `qrcode` npm package), and send that image to
   your tag manufacturer.
4. **Give the edit code to the owner** — e.g. print it on a card that ships
   with the tag, or email it after checkout (tie it to their order in your
   e-commerce system).
5. **Photo uploads** — right now `photoUrl` expects a link. For real photo
   uploads you'll want object storage (e.g. Cloudflare R2 or AWS S3).
6. **Rate limiting / abuse protection** — add basic rate limiting on the
   create/edit endpoints before this is public-facing.
