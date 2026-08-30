[README.md](https://github.com/user-attachments/files/31611390/README.md)
# Havefoi Backend

Backend for QR-code pet profiles — account-based ownership, no subscriptions,
no printed edit codes to lose. Currently live at:
**https://havefoi-backend.onrender.com**

## Run it locally
No install needed — uses only Node's built-in modules.

```
node server.js
```

Open http://localhost:3000 to try it.

## How it works
- **Tag provisioning**: `POST /api/tags` creates a blank, unclaimed tag and
  returns a `publicId` — call this at manufacture time, then print that ID
  as a QR code on the physical tag.
- **Claiming by scanning** — there's no printed code to type in. Scanning an
  unclaimed tag's QR code (`GET /pet/:publicId`) always leads to claiming it:
  - **No active session** → shown "Create an account to link this tag, or
    log in if you already have one." Both links carry `?claim=<id>`, so the
    moment signup/login succeeds, that tag is automatically claimed and the
    visitor lands on the profile editor.
  - **Already logged in** (e.g. activating tag #2 from a 2-tag order) →
    skips the login prompt, shows a one-tap "Claim this tag" button instead.
  - **Already claimed** → shows the normal finder view (name/phone/photo/note)
    to anyone, no login flow at all — this is what a stranger sees if the
    pet is ever actually lost.
- **Photo upload**: the editor has a real file picker (not a URL field) —
  photos are resized and compressed to ~600px/JPEG client-side in the
  browser, then stored directly in the profile record as the image data
  itself. No external image hosting needed for now (see "Next steps" below
  for when this stops being enough).
- **Dashboard**: `GET /api/my/profiles` lists every tag linked to the
  logged-in account — one login, multiple pets.
- **Editing**: `PUT /api/profiles/:publicId` — only works if the logged-in
  user owns that tag.
- **Public scan page**: `GET /pet/:publicId` shows only finder-safe fields
  (name, photo, phone, notes) — home address, medical notes, and other
  private fields are never exposed here.
- **Right to erasure**: `DELETE /api/profiles/:publicId` wipes personal data
  and returns the tag to unclaimed status (DPDPA compliance).
- Branded UI throughout (navy/marigold, matching havefoi.com) — home,
  signup/login, dashboard, scan/claim page, and editor.

- **Scan notifications**: when a finder views a *claimed* tag's public page,
  they're asked (not forced) to share their current location, then the owner
  gets an SMS — `POST /api/profiles/:publicId/scan` handles this, rate-limited
  to one notification per tag per hour so a curious finder refreshing the page
  doesn't spam the owner. **SMS sending is currently mocked** (`sendSMS()`
  just logs to console and to `db.smsLog`) — swap in a real gateway
  (Twilio, or MSG91/Textlocal for India-focused pricing) before launch.
  If the finder shares location, the SMS includes a Google Maps link; if not,
  it links to the profile page instead. No GPS hardware involved — this is
  the *finder's* browser location at the moment of the scan, not pet tracking.

## Deployment status
- ✅ **Live on Render**: https://havefoi-backend.onrender.com (free tier —
  spins down after 15 min idle, ~30-50s to wake back up on the next request)
- ✅ **Code on GitHub**: keeps Render auto-deploying on every push
- ⬜ **Not yet connected to havefoi.com** — currently only reachable at the
  onrender.com address, not under your main domain
- ⬜ **Still using `db.json`** — a single JSON file on disk, not a real
  database. Fine for testing, but **do not launch to real customers on
  this** — see below.

## Next steps before this handles real customers
1. **Real database** — replace `db.json` with Postgres (e.g. via
   [Supabase](https://supabase.com) or [Neon](https://neon.tech), both have
   free tiers). On Render specifically, `db.json` lives on an ephemeral
   disk — it can be wiped on redeploy, so this isn't just a nice-to-have,
   it's a real data-loss risk as-is.
2. **Connect to havefoi.com** — point a subdomain (e.g. `app.havefoi.com`)
   or a path at this Render service, so customers never see the
   onrender.com address.
3. **Real image storage** — the current photo upload stores images inline
   in the database record. Works fine for early testing, but doesn't scale
   well past a modest number of users — migrate to object storage
   (Cloudflare R2 or AWS S3) once photo volume grows.
4. **QR generation** — when a tag is provisioned, generate a QR code for
   `https://havefoi.com/pet/<publicId>` and send that image to your tag
   manufacturer (see the separate QR batch tool for bulk generation).
5. **Lock down `/api/tags`** — right now anyone can provision a blank tag;
   in production this should require an admin key or only run from your
   manufacturing pipeline.
6. **Payment integration** — checkout doesn't yet create real orders tied
   to a specific tag; this is the next major piece of work.
7. **Rate limiting** — add basic rate limiting on signup/login/create
   endpoints before this is fully public-facing.
