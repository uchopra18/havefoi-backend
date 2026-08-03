// Pet Tag Backend — accounts + QR tag claiming, no external dependencies.
// Run with: node server.js
// Data is stored in db.json (created automatically on first run).

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');

const DB_FILE = path.join(__dirname, 'db.json');
const PORT = process.env.PORT || 3000;
const SESSION_DAYS = 30;

// ---------- tiny "database" (JSON file) ----------
function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ users: {}, profiles: {}, sessions: {} }, null, 2));
  }
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}
function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function genId(bytes) { return crypto.randomBytes(bytes).toString('hex'); }

// ---------- password hashing (scrypt, built into Node, no deps) ----------
function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}
function verifyPassword(password, salt, hash) {
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(check), Buffer.from(hash));
}

// ---------- helpers ----------
function sendJSON(res, status, data, extraHeaders) {
  res.writeHead(status, Object.assign({ 'Content-Type': 'application/json' }, extraHeaders || {}));
  res.end(JSON.stringify(data));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', c => (body += c));
    req.on('end', () => { try { resolve(body ? JSON.parse(body) : {}); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}
function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach(pair => {
    const idx = pair.indexOf('=');
    if (idx > -1) out[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim());
  });
  return out;
}
function currentUser(req, db) {
  const cookies = parseCookies(req);
  const token = cookies.session;
  if (!token) return null;
  const session = db.sessions[token];
  if (!session || session.expiresAt < Date.now()) return null;
  return db.users[session.userId] || null;
}
function setSessionCookie(token) {
  const maxAge = SESSION_DAYS * 24 * 60 * 60;
  return `session=${token}; HttpOnly; Path=/; Max-Age=${maxAge}; SameSite=Lax`;
}

// ---------- field definitions ----------
const PUBLIC_FIELDS = ['petName', 'photoUrl', 'phone', 'notes'];
const PRIVATE_FIELDS = [
  'ownerName', 'address', 'altPhone', 'breed', 'age',
  'medicalNotes', 'vetName', 'vetPhone', 'microchipId'
];
const ALL_FIELDS = [...PUBLIC_FIELDS, ...PRIVATE_FIELDS];

function publicView(profile) {
  const out = {};
  for (const f of PUBLIC_FIELDS) out[f] = profile[f] || '';
  return out;
}

// ---------- routes ----------
const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const parts = parsed.pathname.split('/').filter(Boolean);

  try {
    const db = loadDB();

    // ===== AUTH =====
    // POST /api/signup { email, password }
    if (req.method === 'POST' && parsed.pathname === '/api/signup') {
      const body = await readBody(req);
      if (!body.email || !body.password) return sendJSON(res, 400, { error: 'Email and password required' });
      const existing = Object.values(db.users).find(u => u.email.toLowerCase() === body.email.toLowerCase());
      if (existing) return sendJSON(res, 409, { error: 'An account with this email already exists' });

      const { salt, hash } = hashPassword(body.password);
      const userId = genId(8);
      db.users[userId] = { id: userId, email: body.email, salt, hash, createdAt: new Date().toISOString() };

      const token = genId(24);
      db.sessions[token] = { userId, expiresAt: Date.now() + SESSION_DAYS * 86400000 };
      saveDB(db);
      return sendJSON(res, 201, { success: true }, { 'Set-Cookie': setSessionCookie(token) });
    }

    // POST /api/login { email, password }
    if (req.method === 'POST' && parsed.pathname === '/api/login') {
      const body = await readBody(req);
      const user = Object.values(db.users).find(u => u.email.toLowerCase() === (body.email || '').toLowerCase());
      if (!user || !verifyPassword(body.password || '', user.salt, user.hash)) {
        return sendJSON(res, 401, { error: 'Invalid email or password' });
      }
      const token = genId(24);
      db.sessions[token] = { userId: user.id, expiresAt: Date.now() + SESSION_DAYS * 86400000 };
      saveDB(db);
      return sendJSON(res, 200, { success: true }, { 'Set-Cookie': setSessionCookie(token) });
    }

    // POST /api/logout
    if (req.method === 'POST' && parsed.pathname === '/api/logout') {
      const cookies = parseCookies(req);
      if (cookies.session) { delete db.sessions[cookies.session]; saveDB(db); }
      return sendJSON(res, 200, { success: true }, { 'Set-Cookie': 'session=; HttpOnly; Path=/; Max-Age=0' });
    }

    // GET /api/me
    if (req.method === 'GET' && parsed.pathname === '/api/me') {
      const user = currentUser(req, db);
      if (!user) return sendJSON(res, 401, { error: 'Not logged in' });
      return sendJSON(res, 200, { email: user.email });
    }

    // ===== TAG PROVISIONING (you'd call this at manufacture time, e.g. behind an admin key) =====
    // POST /api/tags -> creates a blank, unclaimed tag. Returns publicId for the QR code.
    if (req.method === 'POST' && parsed.pathname === '/api/tags') {
      const publicId = genId(4); // 8 chars
      db.profiles[publicId] = { publicId, ownerId: null, createdAt: new Date().toISOString() };
      for (const f of ALL_FIELDS) db.profiles[publicId][f] = '';
      saveDB(db);
      return sendJSON(res, 201, { publicId, publicUrl: `/pet/${publicId}` });
    }

    // ===== CLAIMING A TAG =====
    // POST /api/tags/:publicId/claim  (requires login) — links an unclaimed tag to your account
    if (req.method === 'POST' && parts[0] === 'api' && parts[1] === 'tags' && parts[3] === 'claim') {
      const user = currentUser(req, db);
      if (!user) return sendJSON(res, 401, { error: 'Log in first' });
      const profile = db.profiles[parts[2]];
      if (!profile) return sendJSON(res, 404, { error: 'No tag with that code' });
      if (profile.ownerId && profile.ownerId !== user.id) return sendJSON(res, 409, { error: 'This tag is already linked to another account' });
      profile.ownerId = user.id;
      saveDB(db);
      return sendJSON(res, 200, { success: true });
    }

    // ===== OWNER'S DASHBOARD DATA =====
    // GET /api/my/profiles (requires login) — all tags linked to your account
    if (req.method === 'GET' && parsed.pathname === '/api/my/profiles') {
      const user = currentUser(req, db);
      if (!user) return sendJSON(res, 401, { error: 'Log in first' });
      const mine = Object.values(db.profiles).filter(p => p.ownerId === user.id);
      return sendJSON(res, 200, mine);
    }

    // ===== PUBLIC VIEW (what scanning the QR code returns) =====
    // GET /api/profiles/:publicId
    if (req.method === 'GET' && parts[0] === 'api' && parts[1] === 'profiles' && parts[2]) {
      const profile = db.profiles[parts[2]];
      if (!profile) return sendJSON(res, 404, { error: 'Not found' });
      const view = publicView(profile);
      view.claimed = !!profile.ownerId;
      return sendJSON(res, 200, view);
    }

    // ===== EDIT / DELETE a profile (requires login + ownership) =====
    // PUT /api/profiles/:publicId
    if (req.method === 'PUT' && parts[0] === 'api' && parts[1] === 'profiles' && parts[2]) {
      const user = currentUser(req, db);
      if (!user) return sendJSON(res, 401, { error: 'Log in first' });
      const profile = db.profiles[parts[2]];
      if (!profile) return sendJSON(res, 404, { error: 'Not found' });
      if (profile.ownerId !== user.id) return sendJSON(res, 403, { error: 'This tag is not linked to your account' });

      const body = await readBody(req);
      if (body.consentGiven !== undefined) profile.consentGiven = !!body.consentGiven;
      for (const f of ALL_FIELDS) if (body[f] !== undefined) profile[f] = body[f];
      saveDB(db);
      return sendJSON(res, 200, { success: true });
    }

    // DELETE /api/profiles/:publicId — right-to-erasure: wipes personal data, keeps tag unclaimed & reusable
    if (req.method === 'DELETE' && parts[0] === 'api' && parts[1] === 'profiles' && parts[2]) {
      const user = currentUser(req, db);
      if (!user) return sendJSON(res, 401, { error: 'Log in first' });
      const profile = db.profiles[parts[2]];
      if (!profile) return sendJSON(res, 404, { error: 'Not found' });
      if (profile.ownerId !== user.id) return sendJSON(res, 403, { error: 'This tag is not linked to your account' });

      const publicId = profile.publicId;
      db.profiles[publicId] = { publicId, ownerId: null, createdAt: profile.createdAt };
      for (const f of ALL_FIELDS) db.profiles[publicId][f] = '';
      saveDB(db);
      return sendJSON(res, 200, { success: true });
    }

    // ---------- simple HTML pages ----------
    if (req.method === 'GET' && parsed.pathname === '/') return serveHtml(res, homePageHtml());
    if (req.method === 'GET' && parsed.pathname === '/signup') return serveHtml(res, authPageHtml('signup'));
    if (req.method === 'GET' && parsed.pathname === '/login') return serveHtml(res, authPageHtml('login'));
    if (req.method === 'GET' && parsed.pathname === '/dashboard') return serveHtml(res, dashboardPageHtml());
    if (req.method === 'GET' && parts[0] === 'pet' && parts[1]) return serveHtml(res, publicPageHtml(parts[1]));
    if (req.method === 'GET' && parts[0] === 'edit' && parts[1]) return serveHtml(res, editPageHtml(parts[1]));

    sendJSON(res, 404, { error: 'Not found' });
  } catch (err) {
    sendJSON(res, 500, { error: err.message });
  }
});

function serveHtml(res, html) {
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(html);
}

// ---------- shared branded layout ----------
const BRAND_CSS = `
  :root {
    --ink: #1C2A4A; --ink-soft: #3D4A68; --bg: #FAF7F2; --bg-raised: #FFFFFF;
    --marigold: #F2A93B; --marigold-dark: #D98F1E; --teal: #2F6F5E;
    --line: #E4DED2; --muted: #8A8578;
  }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: 'Inter', system-ui, sans-serif; color: var(--ink); background: var(--bg); line-height: 1.6; }
  .wrap { max-width: 460px; margin: 0 auto; padding: 0 20px; }
  header.site { border-bottom: 1px solid var(--line); padding: 18px 0; margin-bottom: 36px; }
  header.site .wrap { display: flex; align-items: center; justify-content: space-between; max-width: 460px; }
  .logo { font-family: 'Fraunces', Georgia, serif; font-size: 1.25rem; font-weight: 700; text-decoration: none; color: var(--ink); }
  .logo span { color: var(--marigold-dark); }
  main.wrap { padding-bottom: 60px; }
  h1, h2, h3 { font-family: 'Fraunces', Georgia, serif; font-weight: 600; margin: 0 0 12px; color: var(--ink); }
  h1 { font-size: 1.5rem; } h2 { font-size: 1.3rem; } h3 { font-size: 1.1rem; }
  p { margin: 0 0 16px; color: var(--ink-soft); }
  a { color: var(--teal); }
  .btn { display: inline-block; padding: 12px 24px; border-radius: 999px; font-weight: 600; font-size: 0.95rem;
    text-decoration: none; border: none; cursor: pointer; font-family: inherit; }
  .btn-primary { background: var(--marigold); color: var(--ink); }
  .btn-primary:hover { background: var(--marigold-dark); }
  .btn-ghost { background: transparent; color: var(--ink); border: 1.5px solid var(--ink); }
  .btn-ghost:hover { background: var(--ink); color: var(--bg); }
  .btn-block { display: block; width: 100%; text-align: center; }
  .btn + .btn { margin-left: 10px; }
  input, textarea { width: 100%; padding: 11px 14px; border: 1px solid var(--line); border-radius: 10px;
    font-family: inherit; font-size: 0.95rem; background: #fff; margin-bottom: 12px; }
  input:focus, textarea:focus { outline: 2px solid var(--teal); border-color: var(--teal); }
  label { font-size: 0.9rem; color: var(--ink-soft); display: flex; align-items: center; gap: 8px; margin-bottom: 16px; }
  .card { background: var(--bg-raised); border: 1px solid var(--line); border-radius: 16px; padding: 24px; margin-bottom: 16px; }
  .muted { color: var(--muted); font-size: 0.88rem; }
  .error { color: #B0281E; font-size: 0.9rem; }
  .success { color: var(--teal); font-size: 0.9rem; font-weight: 600; }
  .divider { border: none; border-top: 1px solid var(--line); margin: 28px 0; }
  .tag-row { border: 1px solid var(--line); border-radius: 12px; padding: 14px 16px; margin-bottom: 10px; background: var(--bg-raised); }
  .tag-row b { font-family: 'Fraunces', Georgia, serif; }
  .tag-row a { font-size: 0.88rem; margin-right: 12px; }
  .field-section-label { font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); margin: 20px 0 10px; }
`;

function layout(bodyHtml) {
  return `<!doctype html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,600;9..144,700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>${BRAND_CSS}</style></head><body>
  <header class="site"><div class="wrap"><a href="/" class="logo">Have<span>foi</span></a></div></header>
  <main class="wrap">${bodyHtml}</main>
  </body></html>`;
}

// ---------- pages ----------
function homePageHtml() {
  return layout(`
  <h1>Pet Tag Demo</h1>
  <p><a href="/signup">Sign up</a> or <a href="/login">log in</a> to manage your pet tags.</p>
  <div class="card">
    <p class="muted" style="margin-bottom:14px">To simulate manufacturing a new tag (what you'd do before printing a QR code), create one below:</p>
    <button id="mk" class="btn btn-primary">Provision a new blank tag</button>
    <pre id="out" style="white-space:pre-wrap; font-size:0.85rem; margin-top:16px; color:var(--ink-soft)"></pre>
  </div>
  <script>
    document.getElementById('mk').onclick = async () => {
      const r = await fetch('/api/tags', { method: 'POST' });
      const j = await r.json();
      document.getElementById('out').textContent = 'New tag code (goes under the QR): ' + j.publicId +
        '\\nPublic page: ' + location.origin + j.publicUrl;
    };
  </script>`);
}

function authPageHtml(mode) {
  const isSignup = mode === 'signup';
  return layout(`
  <h1>${isSignup ? 'Create your account' : 'Log in'}</h1>
  <div class="card">
    <form id="f">
      <input name="email" type="email" placeholder="Email" required>
      <input name="password" type="password" placeholder="Password" required>
      <button type="submit" class="btn btn-primary btn-block">${isSignup ? 'Create account' : 'Log in'}</button>
    </form>
    <p id="err" class="error" style="margin-top:12px"></p>
  </div>
  <p id="switchLink" class="muted"></p>
  <script>
    const params = new URLSearchParams(location.search);
    const claimId = params.get('claim');

    document.getElementById('switchLink').innerHTML = ${isSignup}
      ? 'Already have an account? <a href="/login' + (claimId ? '?claim=' + claimId : '') + '">Log in</a>'
      : 'New here? <a href="/signup' + (claimId ? '?claim=' + claimId : '') + '">Sign up</a>';

    document.getElementById('f').onsubmit = async (e) => {
      e.preventDefault();
      const data = Object.fromEntries(new FormData(e.target));
      const r = await fetch('/api/${isSignup ? 'signup' : 'login'}', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(data) });
      if (!r.ok) { const j = await r.json(); document.getElementById('err').textContent = j.error; return; }

      if (claimId) {
        const claimR = await fetch('/api/tags/' + claimId + '/claim', { method: 'POST' });
        if (claimR.ok) { location.href = '/edit/' + claimId; return; }
      }
      location.href = '/dashboard';
    };
  </script>`);
}

function dashboardPageHtml() {
  return layout(`
  <h1>Your pets</h1>
  <p><a href="#" id="logout" class="muted">Log out</a></p>
  <div id="list"></div>
  <hr class="divider">
  <h3>Link a new tag</h3>
  <p class="muted">Got a tag code from a manual entry or support request? Enter it here:</p>
  <form id="claimForm" style="display:flex; gap:8px">
    <input name="code" placeholder="Tag code" required style="margin-bottom:0">
    <button type="submit" class="btn btn-ghost">Link</button>
  </form>
  <p id="claimMsg" class="success" style="margin-top:10px"></p>
  <script>
    async function load() {
      const meR = await fetch('/api/me');
      if (!meR.ok) { location.href = '/login'; return; }
      const r = await fetch('/api/my/profiles');
      const profiles = await r.json();
      const el = document.getElementById('list');
      el.innerHTML = profiles.length ? '' : '<p class="muted">No pets linked yet.</p>';
      profiles.forEach(p => {
        const div = document.createElement('div');
        div.className = 'tag-row';
        div.innerHTML = '<b>' + (p.petName || '(unnamed)') + '</b><br>' +
          '<a href="/edit/' + p.publicId + '">Edit profile</a>' +
          '<a href="/pet/' + p.publicId + '" target="_blank">View public page</a>';
        el.appendChild(div);
      });
    }
    load();
    document.getElementById('logout').onclick = async (e) => {
      e.preventDefault();
      await fetch('/api/logout', { method: 'POST' });
      location.href = '/login';
    };
    document.getElementById('claimForm').onsubmit = async (e) => {
      e.preventDefault();
      const code = new FormData(e.target).get('code').trim();
      const r = await fetch('/api/tags/' + code + '/claim', { method: 'POST' });
      const j = await r.json();
      document.getElementById('claimMsg').textContent = r.ok ? 'Linked!' : ('Error: ' + j.error);
      document.getElementById('claimMsg').className = r.ok ? 'success' : 'error';
      if (r.ok) { setTimeout(load, 400); e.target.reset(); }
    };
  </script>`);
}

function publicPageHtml(publicId) {
  return layout(`
  <div id="c"><p class="muted">Loading...</p></div>
  <script>
    const publicId = '${publicId}';

    async function render() {
      const r = await fetch('/api/profiles/' + publicId);
      const p = await r.json();
      const el = document.getElementById('c');
      if (p.error) { el.innerHTML = '<h1>Pet Profile</h1><p>Tag not found.</p>'; return; }

      if (p.claimed) {
        el.innerHTML =
          '<div class="card">' +
          (p.photoUrl ? '<img src="'+p.photoUrl+'" style="width:100%; border-radius:12px; margin-bottom:16px">' : '') +
          '<h1>' + (p.petName || 'Unnamed pet') + '</h1>' +
          '<p style="font-size:1.1rem; color:var(--ink); font-weight:600; margin-bottom:4px">' + (p.phone||'') + '</p>' +
          '<p class="muted" style="margin-bottom:0">' + (p.notes||'') + '</p>' +
          '</div>' +
          '<p class="muted" style="text-align:center">Found this pet? Please call the number above.</p>';
        return;
      }

      const meR = await fetch('/api/me');
      if (meR.ok) {
        el.innerHTML =
          '<h1>Set up this tag</h1>' +
          '<div class="card">' +
          '<p>This tag isn\\'t linked to an account yet.</p>' +
          '<button id="claimBtn" class="btn btn-primary btn-block">Claim this tag</button>' +
          '<p id="claimMsg" class="error" style="margin-top:10px; margin-bottom:0"></p>' +
          '</div>';
        document.getElementById('claimBtn').onclick = async () => {
          const res = await fetch('/api/tags/' + publicId + '/claim', { method: 'POST' });
          if (res.ok) { location.href = '/edit/' + publicId; }
          else { document.getElementById('claimMsg').textContent = 'Something went wrong — try again.'; }
        };
      } else {
        el.innerHTML =
          '<h1>Set up this tag</h1>' +
          '<div class="card">' +
          '<p style="margin-bottom:20px">This tag isn\\'t linked to an account yet. Create an account to link it, or log in if you already have one.</p>' +
          '<a href="/signup?claim=' + publicId + '" class="btn btn-primary">Create account</a>' +
          '<a href="/login?claim=' + publicId + '" class="btn btn-ghost">Log in</a>' +
          '</div>';
      }
    }
    render();
  </script>`);
}

function editPageHtml(publicId) {
  const fields = ['petName','photoUrl','phone','notes','ownerName','address','altPhone','breed','age','medicalNotes','vetName','vetPhone','microchipId'];
  return layout(`
  <h1>Edit pet profile</h1>
  <div id="gate" class="error"></div>
  <form id="f" style="display:none">
    <div class="card">
      <p class="field-section-label" style="margin-top:0">Shown to anyone who scans the tag</p>
      <input name="petName" placeholder="Pet name">
      <input name="photoUrl" placeholder="Photo URL">
      <input name="phone" placeholder="Phone shown to finder">
      <textarea name="notes" placeholder="Notes for finder" rows="3"></textarea>
    </div>
    <div class="card">
      <p class="field-section-label" style="margin-top:0">Private — only visible to you</p>
      <input name="ownerName" placeholder="Owner full name">
      <input name="address" placeholder="Home address">
      <input name="altPhone" placeholder="Alternate phone">
      <input name="breed" placeholder="Breed">
      <input name="age" placeholder="Age">
      <textarea name="medicalNotes" placeholder="Medical notes" rows="2"></textarea>
      <input name="vetName" placeholder="Vet name">
      <input name="vetPhone" placeholder="Vet phone">
      <input name="microchipId" placeholder="Microchip ID">
      <label><input type="checkbox" name="consentGiven" style="width:auto; margin:0"> I consent to this data being stored</label>
    </div>
    <button type="submit" class="btn btn-primary btn-block">Save</button>
  </form>
  <p id="status" class="success"></p>
  <p><a href="/dashboard" class="muted">&larr; Back to dashboard</a></p>
  <script>
    const publicId = '${publicId}';
    const fields = ${JSON.stringify(fields)};
    (async () => {
      const meR = await fetch('/api/me');
      if (!meR.ok) { location.href = '/login'; return; }
      const r = await fetch('/api/my/profiles');
      const mine = await r.json();
      const profile = mine.find(p => p.publicId === publicId);
      if (!profile) { document.getElementById('gate').textContent = 'This tag is not linked to your account.'; return; }
      document.getElementById('f').style.display = 'block';
      for (const k of fields) {
        const el = document.querySelector('[name='+k+']');
        if (el) el.value = profile[k] || '';
      }
      document.querySelector('[name=consentGiven]').checked = !!profile.consentGiven;
    })();
    document.getElementById('f').onsubmit = async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const data = Object.fromEntries(fd);
      data.consentGiven = fd.get('consentGiven') === 'on';
      const r = await fetch('/api/profiles/' + publicId, { method: 'PUT', headers: {'Content-Type':'application/json'}, body: JSON.stringify(data) });
      document.getElementById('status').textContent = r.ok ? 'Saved!' : 'Error saving.';
      document.getElementById('status').className = r.ok ? 'success' : 'error';
    };
  </script>`);
}

server.listen(PORT, () => console.log(`Pet tag backend running at http://localhost:${PORT}`));
