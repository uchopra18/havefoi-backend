// Pet Tag Backend — accounts + QR tag claiming.
// Run with: node server.js  (requires DATABASE_URL env var — see README)

const http = require('http');
const crypto = require('crypto');
const url = require('url');
const db = require('./db');
const Razorpay = require('razorpay');

// TODO: set RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET as environment variables
// (same way as DATABASE_URL) once you have a Razorpay account. Get test-mode
// keys first from Razorpay Dashboard -> Settings -> API Keys, test the whole
// flow with those (no real money moves), then switch to live keys once
// Razorpay approves your account for live payments.
const razorpay = process.env.RAZORPAY_KEY_ID
  ? new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET })
  : null;

const PORT = process.env.PORT || 3000;
const SESSION_DAYS = 30;

function genId(bytes) { return crypto.randomBytes(bytes).toString('hex'); }

// ---------- SMS notifications (MSG91) ----------
// TODO before this sends real messages:
//   1. Create an account at https://msg91.com
//   2. Complete DLT registration (required by Indian telecom law for any SMS
//      to Indian numbers) — register as an "entity", register a sender ID
//      (6 letters, e.g. HAVFOI), and register the exact message template
//      below word-for-word (DLT only allows pre-approved templates with
//      {#var#} placeholders — you cannot send arbitrary free text).
//      Suggested template to register:
//        "{#var#}'s tag was just scanned. {#var#}"
//      (first var = pet name, second var = either a maps link or profile link)
//   3. Once approved, get your authkey (Dashboard -> API) and your approved
//      flow_id (Dashboard -> Campaigns -> API -> Flows), then set these as
//      Render environment variables: MSG91_AUTH_KEY, MSG91_SENDER_ID, MSG91_FLOW_ID
const https = require('https');

function sendSMS(toPhone, petName, detail) {
  if (!process.env.MSG91_AUTH_KEY) {
    console.log(`[SMS mock -> ${toPhone}]: ${petName}'s tag was just scanned. ${detail}`);
    return;
  }

  const payload = JSON.stringify({
    flow_id: process.env.MSG91_FLOW_ID,
    sender: process.env.MSG91_SENDER_ID,
    mobiles: '91' + toPhone.replace(/\D/g, '').slice(-10), // MSG91 wants country code, no symbols
    var: petName,   // matches {#var#} #1 in the registered template
    var1: detail,   // matches {#var#} #2
  });

  const req = https.request({
    hostname: 'control.msg91.com',
    path: '/api/v5/flow',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'authkey': process.env.MSG91_AUTH_KEY,
      'Content-Length': Buffer.byteLength(payload),
    },
  }, (res) => {
    let body = '';
    res.on('data', (c) => body += c);
    res.on('end', () => {
      if (res.statusCode >= 400) console.error(`[SMS] MSG91 error (${res.statusCode}):`, body);
      else console.log(`[SMS] sent to ${toPhone}`);
    });
  });
  req.on('error', (e) => console.error('[SMS] Failed to reach MSG91:', e.message));
  req.write(payload);
  req.end();
}

// Minimum time between two "scan" notifications for the same tag, so a finder
// refreshing the page (or the owner scanning their own tag) doesn't spam the owner.
const SCAN_NOTIFY_COOLDOWN_MS = 60 * 60 * 1000; // 1 hour

// ---------- Email (Resend) ----------
// TODO: sign up at https://resend.com, verify a sending domain (or use their
// shared onboarding domain for quick testing), get an API key from the
// dashboard, and set it as RESEND_API_KEY in Render's environment variables.
// Much faster to set up than SMS/payment — no lengthy approval process.
function sendEmail(to, subject, html) {
  if (!process.env.RESEND_API_KEY) {
    console.log(`[EMAIL mock -> ${to}] Subject: ${subject}\n${html}`);
    return;
  }
  const payload = JSON.stringify({
    from: process.env.RESEND_FROM_EMAIL || 'Havefoi <noreply@havefoi.com>',
    to: [to],
    subject,
    html,
  });
  const req = https.request({
    hostname: 'api.resend.com',
    path: '/emails',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
      'Content-Length': Buffer.byteLength(payload),
    },
  }, (res) => {
    let body = '';
    res.on('data', (c) => body += c);
    res.on('end', () => {
      if (res.statusCode >= 400) console.error(`[EMAIL] Resend error (${res.statusCode}):`, body);
      else console.log(`[EMAIL] sent to ${to}`);
    });
  });
  req.on('error', (e) => console.error('[EMAIL] Failed to reach Resend:', e.message));
  req.write(payload);
  req.end();
}

const PASSWORD_RESET_EXPIRY_MS = 60 * 60 * 1000; // 1 hour


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
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function sendJSON(res, status, data, extraHeaders) {
  res.writeHead(status, Object.assign({ 'Content-Type': 'application/json' }, extraHeaders || {}));
  res.end(JSON.stringify(data));
}
const MAX_BODY_BYTES = 2 * 1024 * 1024; // 2MB — enough for a compressed photo, not enough to abuse

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    let bytes = 0;
    req.on('data', c => {
      bytes += c.length;
      if (bytes > MAX_BODY_BYTES) {
        reject(new Error('PAYLOAD_TOO_LARGE'));
        req.destroy();
        return;
      }
      body += c;
    });
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
async function currentUser(req) {
  const cookies = parseCookies(req);
  const token = cookies.session;
  if (!token) return null;
  const session = await db.getSession(token);
  if (!session || session.expiresAt < Date.now()) return null;
  return db.getUserById(session.userId);
}
function setSessionCookie(token) {
  const maxAge = SESSION_DAYS * 24 * 60 * 60;
  return `session=${token}; HttpOnly; Path=/; Max-Age=${maxAge}; SameSite=Lax`;
}

// ---------- admin auth ----------
// TODO: set ADMIN_KEY as a Render environment variable — pick a long random
// string, not a memorable password. This gates the fulfillment/orders view.
function isAdmin(req) {
  const cookies = parseCookies(req);
  return !!process.env.ADMIN_KEY && cookies.adminKey === process.env.ADMIN_KEY;
}

// ---------- field definitions ----------
const { PUBLIC_FIELDS, ALL_FIELDS } = db;

function publicView(profile) {
  const out = {};
  for (const f of PUBLIC_FIELDS) out[f] = profile[f] || '';
  return out;
}

// Requests to /api/* can come from havefoi.com (Netlify) even though this
// server runs on a different domain (Render) — browsers block that
// cross-origin call by default unless we explicitly allow it here.
const ALLOWED_ORIGINS = [
  'https://havefoi.com',
  'https://www.havefoi.com',
  'https://zingy-bonbon-815ecf.netlify.app',
  'http://localhost:3000', // for local testing
];
function applyCors(req, res) {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  }
}

// ---------- routes ----------
const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const parts = parsed.pathname.split('/').filter(Boolean);
  console.log(`[REQ] ${req.method} ${parsed.pathname}`);

  applyCors(req, res);
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  try {
    // ===== AUTH =====
    // POST /api/signup { email, password }
    if (req.method === 'POST' && parsed.pathname === '/api/signup') {
      const body = await readBody(req);
      if (!body.email || !body.password) return sendJSON(res, 400, { error: 'Email and password required' });
      const existing = await db.getUserByEmail(body.email);
      if (existing) return sendJSON(res, 409, { error: 'An account with this email already exists' });

      const { salt, hash } = hashPassword(body.password);
      const userId = genId(8);
      await db.createUser({ id: userId, email: body.email, salt, hash });

      const token = genId(24);
      const expiresAt = Date.now() + SESSION_DAYS * 86400000;
      await db.createSession(token, userId, expiresAt);
      return sendJSON(res, 201, { success: true }, { 'Set-Cookie': setSessionCookie(token) });
    }

    // POST /api/login { email, password }
    if (req.method === 'POST' && parsed.pathname === '/api/login') {
      const body = await readBody(req);
      const user = await db.getUserByEmail(body.email || '');
      if (!user || !verifyPassword(body.password || '', user.salt, user.hash)) {
        return sendJSON(res, 401, { error: 'Invalid email or password' });
      }
      const token = genId(24);
      const expiresAt = Date.now() + SESSION_DAYS * 86400000;
      await db.createSession(token, user.id, expiresAt);
      return sendJSON(res, 200, { success: true }, { 'Set-Cookie': setSessionCookie(token) });
    }

    // POST /api/logout
    if (req.method === 'POST' && parsed.pathname === '/api/logout') {
      const cookies = parseCookies(req);
      if (cookies.session) await db.deleteSession(cookies.session);
      return sendJSON(res, 200, { success: true }, { 'Set-Cookie': 'session=; HttpOnly; Path=/; Max-Age=0' });
    }

    // GET /api/me
    if (req.method === 'GET' && parsed.pathname === '/api/me') {
      const user = await currentUser(req);
      if (!user) return sendJSON(res, 401, { error: 'Not logged in' });
      return sendJSON(res, 200, { email: user.email });
    }

    // ===== PASSWORD RECOVERY =====
    // POST /api/contact { name, email, orderId, message } — from the Contact Us page
    if (req.method === 'POST' && parsed.pathname === '/api/contact') {
      const body = await readBody(req);
      if (!body.name || !body.email || !body.message) {
        return sendJSON(res, 400, { error: 'Name, email, and message are all required' });
      }
      sendEmail(
        'support@havefoi.com',
        `Contact form: ${escapeHtml(body.name)}`,
        `<p><strong>From:</strong> ${escapeHtml(body.name)} (${escapeHtml(body.email)})</p>
         ${body.orderId ? `<p><strong>Order ID:</strong> ${escapeHtml(body.orderId)}</p>` : ''}
         <p><strong>Message:</strong></p>
         <p>${escapeHtml(body.message).replace(/\n/g, '<br>')}</p>`
      );
      return sendJSON(res, 200, { success: true });
    }

    // POST /api/forgot-password { email }
    // Always responds the same way whether or not the email exists — this
    // is deliberate, so this endpoint can't be used to check which emails
    // have accounts (a common way real sites leak that information).
    if (req.method === 'POST' && parsed.pathname === '/api/forgot-password') {
      const body = await readBody(req);
      const user = await db.getUserByEmail(body.email || '');
      if (user) {
        const token = genId(24);
        await db.createPasswordReset(token, user.id, Date.now() + PASSWORD_RESET_EXPIRY_MS);
        const resetLink = `${req.headers.origin || 'https://havefoi-backend.onrender.com'}/reset-password?token=${token}`;
        sendEmail(
          user.email,
          'Reset your Havefoi password',
          `<p>Someone requested a password reset for your Havefoi account.</p>
           <p><a href="${resetLink}">Click here to set a new password</a> (link expires in 1 hour).</p>
           <p>If you didn't request this, you can safely ignore this email.</p>`
        );
      }
      return sendJSON(res, 200, { success: true });
    }

    // GET /forgot-password — the "request a reset" form
    if (req.method === 'GET' && parsed.pathname === '/forgot-password') {
      return serveHtml(res, forgotPasswordPageHtml());
    }

    // GET /reset-password?token=... — the page the link in the email opens
    if (req.method === 'GET' && parsed.pathname === '/reset-password') {
      return serveHtml(res, resetPasswordPageHtml(parsed.query.token || ''));
    }

    // POST /api/reset-password { token, newPassword }
    if (req.method === 'POST' && parsed.pathname === '/api/reset-password') {
      const body = await readBody(req);
      if (!body.token || !body.newPassword) return sendJSON(res, 400, { error: 'Missing token or new password' });
      if (body.newPassword.length < 8) return sendJSON(res, 400, { error: 'Password must be at least 8 characters' });

      const reset = await db.getPasswordReset(body.token);
      if (!reset || reset.expiresAt < Date.now()) {
        return sendJSON(res, 400, { error: 'This reset link is invalid or has expired. Request a new one.' });
      }

      const { salt, hash } = hashPassword(body.newPassword);
      await db.updateUserPassword(reset.userId, salt, hash);
      await db.deletePasswordReset(body.token); // single-use
      return sendJSON(res, 200, { success: true });
    }

    // ===== TAG PROVISIONING (you'd call this at manufacture time, e.g. behind an admin key) =====
    // POST /api/tags -> creates a blank, unclaimed tag. Returns publicId for the QR code.
    // NOTE: for your real 500 manufactured tags, don't call this — use import_tags.js
    // to load their actual printed IDs instead, so the app never invents an ID that
    // doesn't match a real physical tag.
    if (req.method === 'POST' && parsed.pathname === '/api/tags') {
      const publicId = genId(4); // 8 chars
      await db.createBlankProfile(publicId);
      return sendJSON(res, 201, { publicId, publicUrl: `/pet/${publicId}` });
    }

    // ===== CLAIMING A TAG =====
    // POST /api/tags/:publicId/claim  (requires login) — links an unclaimed tag to your account
    if (req.method === 'POST' && parts[0] === 'api' && parts[1] === 'tags' && parts[3] === 'claim') {
      const user = await currentUser(req);
      if (!user) return sendJSON(res, 401, { error: 'Log in first' });
      const profile = await db.getProfile(parts[2]);
      if (!profile) return sendJSON(res, 404, { error: 'No tag with that code' });
      if (profile.ownerId && profile.ownerId !== user.id) return sendJSON(res, 409, { error: 'This tag is already linked to another account' });
      await db.claimProfile(parts[2], user.id);
      return sendJSON(res, 200, { success: true });
    }

    // ===== OWNER'S DASHBOARD DATA =====
    // GET /api/my/profiles (requires login) — all tags linked to your account
    if (req.method === 'GET' && parsed.pathname === '/api/my/profiles') {
      const user = await currentUser(req);
      if (!user) return sendJSON(res, 401, { error: 'Log in first' });
      const mine = await db.getProfilesByOwner(user.id);
      return sendJSON(res, 200, mine);
    }

    // ===== PUBLIC VIEW (what scanning the QR code returns) =====
    // GET /api/profiles/:publicId
    if (req.method === 'GET' && parts[0] === 'api' && parts[1] === 'profiles' && parts[2] && !parts[3]) {
      const profile = await db.getProfile(parts[2]);
      if (!profile) return sendJSON(res, 404, { error: 'Not found' });
      const view = publicView(profile);
      view.claimed = !!profile.ownerId;
      return sendJSON(res, 200, view);
    }

    // ===== SCAN NOTIFICATION =====
    // POST /api/profiles/:publicId/scan — called by the public page when a finder
    // views a *claimed* profile. Sends the owner an SMS, rate-limited so repeat
    // views within the cooldown window don't spam them. Optional {lat, lng} from
    // the finder's browser (only if they consented) gets included as a map link.
    if (req.method === 'POST' && parts[0] === 'api' && parts[1] === 'profiles' && parts[2] && parts[3] === 'scan') {
      const profile = await db.getProfile(parts[2]);
      if (!profile || !profile.ownerId) return sendJSON(res, 404, { error: 'Not found' });

      const body = await readBody(req);
      const now = Date.now();
      const lastNotified = profile.lastScanNotifiedAt ? new Date(profile.lastScanNotifiedAt).getTime() : 0;

      if (now - lastNotified < SCAN_NOTIFY_COOLDOWN_MS) {
        return sendJSON(res, 200, { notified: false, reason: 'cooldown' });
      }
      if (!profile.phone) {
        return sendJSON(res, 200, { notified: false, reason: 'no_contact_number' });
      }

      const petName = profile.petName || 'Your pet';
      let detail;
      if (body.lat && body.lng) {
        detail = `The finder shared their location: https://maps.google.com/?q=${body.lat},${body.lng}`;
      } else {
        detail = `View their profile: ${req.headers.origin || ''}/pet/${parts[2]}`;
      }
      const logMessage = `${petName}'s tag was just scanned. ${detail}`;

      sendSMS(profile.phone, petName, detail);
      await db.setScanNotified(parts[2]);
      await db.logSMS(parts[2], profile.phone, logMessage);
      return sendJSON(res, 200, { notified: true });
    }

    // ===== PAYMENT: create an order =====
    // POST /api/orders/create { quantity, name, phone, email, address, city, pincode, petName }
    // Creates the order on Razorpay's side AND a 'pending' row in our own
    // orders table, before any payment has happened. The frontend then opens
    // Razorpay's checkout using the returned razorpayOrderId.
    if (req.method === 'POST' && parsed.pathname === '/api/orders/create') {
      if (!razorpay) return sendJSON(res, 500, { error: 'Payment gateway is not configured yet (missing RAZORPAY_KEY_ID/SECRET)' });
      const body = await readBody(req);
      const qty = Math.max(1, Math.min(10, parseInt(body.quantity, 10) || 1));
      const UNIT_PRICE_RUPEES = 249; // keep in sync with order.html's UNIT_PRICE — includes free shipping
      const amountPaise = UNIT_PRICE_RUPEES * qty * 100;

      if (!body.name || !body.phone || !body.email || !body.address || !body.city || !body.pincode) {
        return sendJSON(res, 400, { error: 'All customer details are required' });
      }

      const orderId = genId(8);
      const rpOrder = await razorpay.orders.create({
        amount: amountPaise,
        currency: 'INR',
        receipt: orderId,
      });

      await db.createOrder({
        id: orderId,
        razorpayOrderId: rpOrder.id,
        quantity: qty,
        amountPaise,
        customerName: body.name,
        customerPhone: body.phone,
        customerEmail: body.email,
        address: body.address,
        city: body.city,
        pincode: body.pincode,
        petName: body.petName || null,
      });

      return sendJSON(res, 201, {
        orderId,
        razorpayOrderId: rpOrder.id,
        razorpayKeyId: process.env.RAZORPAY_KEY_ID,
        amount: amountPaise,
      });
    }

    // ===== PAYMENT: verify after Razorpay's checkout completes =====
    // POST /api/orders/verify { razorpay_order_id, razorpay_payment_id, razorpay_signature }
    // CRITICAL: this is the step that actually confirms payment happened.
    // Razorpay's checkout widget calls a success handler in the browser
    // regardless of what the browser "thinks" happened, so we never trust
    // that alone — we recompute the expected signature server-side using
    // our secret key and compare, exactly as Razorpay's docs specify.
    if (req.method === 'POST' && parsed.pathname === '/api/orders/verify') {
      const body = await readBody(req);
      const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = body;
      if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
        return sendJSON(res, 400, { error: 'Missing payment verification fields' });
      }

      const expectedSignature = crypto
        .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
        .update(razorpay_order_id + '|' + razorpay_payment_id)
        .digest('hex');

      if (expectedSignature !== razorpay_signature) {
        console.error(`[PAYMENT] Signature mismatch for order ${razorpay_order_id} — possible tampering attempt`);
        return sendJSON(res, 400, { error: 'Payment verification failed' });
      }

      await db.markOrderPaid(razorpay_order_id, razorpay_payment_id);
      const order = await db.getOrderByRazorpayOrderId(razorpay_order_id);
      console.log(`[PAYMENT] Order ${order.id} verified paid — ₹${(order.amount_paise/100).toLocaleString('en-IN')}`);

      const itemLine = order.quantity === 1 ? 'Single Tag' : `${order.quantity}× Single Tag`;

      if (order.customer_email) {
        const petLabel = order.pet_name || 'your pet';
        const petSubject = order.pet_name || 'them'; // avoids "your pet...every pet" repetition in the opening line
        sendEmail(
          order.customer_email,
          'Your Havefoi order is confirmed',
          `<p>Hi ${order.customer_name || ''},</p>
           <p>You just gave ${petSubject} something every pet deserves — a way home, no matter what.</p>
           <p>Here's your order:</p>
           <ul>
             <li><strong>Order ID:</strong> ${order.id}</li>
             <li><strong>Item:</strong> ${itemLine}${order.pet_name ? ' · for ' + order.pet_name : ''}</li>
             <li><strong>Amount paid:</strong> ₹${(order.amount_paise / 100).toLocaleString('en-IN')}</li>
           </ul>
           <p>We'll dispatch your tag within 1-2 business days. Once it arrives, scan the QR code with your phone to set up ${petLabel}'s profile — takes under a minute. From then on, any stranger who finds ${petLabel} will know exactly how to reach you, day or night.</p>
           <p>— The Havefoi team</p>`
        );
      }

      // Merchant alert — lets you know a real order came in without needing
      // to keep checking /admin manually. Fires regardless of whether the
      // customer's own email is on file, since this is about you knowing
      // about the order, not about the customer's confirmation.
      sendEmail(
        'support@havefoi.com',
        `New order — ₹${(order.amount_paise / 100).toLocaleString('en-IN')} (${order.id})`,
        `<p>New paid order just came in:</p>
         <ul>
           <li><strong>Order ID:</strong> ${order.id}</li>
           <li><strong>Item:</strong> ${itemLine}${order.pet_name ? ' · for ' + order.pet_name : ''}</li>
           <li><strong>Amount:</strong> ₹${(order.amount_paise / 100).toLocaleString('en-IN')}</li>
           <li><strong>Customer:</strong> ${order.customer_name} · ${order.customer_phone} · ${order.customer_email}</li>
           <li><strong>Ship to:</strong> ${order.address}, ${order.city} ${order.pincode}</li>
         </ul>
         <p><a href="https://havefoi-backend.onrender.com/admin">Open the fulfillment dashboard</a> to assign a tag and mark it shipped.</p>`
      );

      return sendJSON(res, 200, { success: true, orderId: order.id });
    }

    // GET /api/orders/:id — used by the confirmation page to show order details
    if (req.method === 'GET' && parts[0] === 'api' && parts[1] === 'orders' && parts[2]) {
      const order = await db.getOrderById(parts[2]);
      if (!order) return sendJSON(res, 404, { error: 'Order not found' });
      return sendJSON(res, 200, {
        id: order.id,
        status: order.status,
        quantity: order.quantity,
        amount: order.amount_paise,
        petName: order.pet_name,
        customerName: order.customer_name,
      });
    }

    // ===== ADMIN (fulfillment) =====
    // GET /admin — shows a login form, or the paid-orders view if already authenticated
    if (req.method === 'GET' && parsed.pathname === '/admin') {
      if (!isAdmin(req)) return serveHtml(res, adminLoginPageHtml());
      const orders = await db.getPaidOrders();
      return serveHtml(res, adminOrdersPageHtml(orders));
    }

    // POST /admin/login { key }
    if (req.method === 'POST' && parsed.pathname === '/admin/login') {
      const body = await readBody(req);
      if (!process.env.ADMIN_KEY || body.key !== process.env.ADMIN_KEY) {
        return sendJSON(res, 401, { error: 'Incorrect admin key' });
      }
      return sendJSON(res, 200, { success: true }, {
        'Set-Cookie': `adminKey=${body.key}; HttpOnly; Path=/; Max-Age=${12*60*60}; SameSite=Lax`
      });
    }

    // POST /admin/logout — clears the admin session immediately
    if (req.method === 'POST' && parsed.pathname === '/admin/logout') {
      return sendJSON(res, 200, { success: true }, {
        'Set-Cookie': 'adminKey=; HttpOnly; Path=/; Max-Age=0'
      });
    }

    // POST /api/admin/orders/:id/assign-tags { tagIds: "abc123,def456" }
    // Splits on commas, checks each tag actually exists, and checks none of
    // them are already assigned to a *different* order — the safeguard
    // against accidentally shipping the same physical tag to two customers.
    if (req.method === 'POST' && parts[0] === 'api' && parts[1] === 'admin' && parts[2] === 'orders' && parts[3] && parts[4] === 'assign-tags') {
      if (!isAdmin(req)) return sendJSON(res, 401, { error: 'Admin login required' });
      const orderId = parts[3];
      const body = await readBody(req);
      const tagIds = (body.tagIds || '').split(',').map(t => t.trim()).filter(Boolean);

      for (const tagId of tagIds) {
        const profile = await db.getProfile(tagId);
        if (!profile) return sendJSON(res, 400, { error: `Tag ${tagId} doesn't exist — check for typos` });
        const conflicts = await db.findOrdersUsingTag(tagId, orderId);
        if (conflicts.length > 0) {
          return sendJSON(res, 400, { error: `Tag ${tagId} is already assigned to order ${conflicts[0].id} — a physical tag can't go to two orders` });
        }
      }

      await db.assignTagsToOrder(orderId, tagIds.join(','));
      return sendJSON(res, 200, { success: true });
    }

    // POST /api/admin/orders/:id/ship
    if (req.method === 'POST' && parts[0] === 'api' && parts[1] === 'admin' && parts[2] === 'orders' && parts[3] && parts[4] === 'ship') {
      if (!isAdmin(req)) return sendJSON(res, 401, { error: 'Admin login required' });
      await db.markOrderShipped(parts[3]);
      return sendJSON(res, 200, { success: true });
    }

    // ===== EDIT / DELETE a profile (requires login + ownership) =====
    // PUT /api/profiles/:publicId
    if (req.method === 'PUT' && parts[0] === 'api' && parts[1] === 'profiles' && parts[2]) {
      const user = await currentUser(req);
      if (!user) return sendJSON(res, 401, { error: 'Log in first' });
      const profile = await db.getProfile(parts[2]);
      if (!profile) return sendJSON(res, 404, { error: 'Not found' });
      if (profile.ownerId !== user.id) return sendJSON(res, 403, { error: 'This tag is not linked to your account' });

      const body = await readBody(req);
      await db.updateProfile(parts[2], body);
      return sendJSON(res, 200, { success: true });
    }

    // DELETE /api/profiles/:publicId — right-to-erasure: wipes personal data, keeps tag unclaimed & reusable
    if (req.method === 'DELETE' && parts[0] === 'api' && parts[1] === 'profiles' && parts[2]) {
      const user = await currentUser(req);
      if (!user) return sendJSON(res, 401, { error: 'Log in first' });
      const profile = await db.getProfile(parts[2]);
      if (!profile) return sendJSON(res, 404, { error: 'Not found' });
      if (profile.ownerId !== user.id) return sendJSON(res, 403, { error: 'This tag is not linked to your account' });

      await db.eraseProfile(parts[2]);
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
    if (err.message === 'PAYLOAD_TOO_LARGE') {
      return sendJSON(res, 413, { error: 'Photo is too large. Try a smaller image.' });
    }
    console.error(`[ERROR] ${req.method} ${req.url} ->`, err);
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
  <header class="site"><div class="wrap"><a href="https://havefoi.com" class="logo">Have<span>foi</span></a></div></header>
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
  ${isSignup ? '' : '<p><a href="/forgot-password" class="muted">Forgot password?</a></p>'}
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

function adminLoginPageHtml() {
  return layout(`
  <h1>Admin</h1>
  <div class="card">
    <form id="f">
      <input name="key" type="password" placeholder="Admin key" required>
      <button type="submit" class="btn btn-primary btn-block">Log in</button>
    </form>
    <p id="err" class="error" style="margin-top:12px"></p>
  </div>
  <script>
    document.getElementById('f').onsubmit = async (e) => {
      e.preventDefault();
      const data = Object.fromEntries(new FormData(e.target));
      const r = await fetch('/admin/login', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(data) });
      if (!r.ok) { document.getElementById('err').textContent = 'Incorrect key'; return; }
      location.reload();
    };
  </script>`);
}

function adminOrdersPageHtml(orders) {
  const rows = orders.map(o => `
    <div class="card" style="margin-bottom:16px">
      <p><strong>${o.id}</strong> ${o.shipped ? '<span style="color:var(--teal)">✓ shipped</span>' : ''}</p>
      <p class="muted">${o.customer_name} · ${o.customer_phone} · ${o.customer_email}</p>
      <p class="muted">${o.address}, ${o.city} ${o.pincode}</p>
      <p>${o.quantity === 1 ? 'Single Tag' : o.quantity + '× Single Tag'}${o.pet_name ? ' · for ' + o.pet_name : ''} — ₹${(o.amount_paise/100).toLocaleString('en-IN')}</p>
      <div style="display:flex; gap:8px; margin-top:10px">
        <input type="text" value="${o.assigned_tag_ids || ''}" placeholder="Tag ID(s), comma-separated" data-order="${o.id}" class="tagInput" style="flex:1">
        <button class="btn btn-primary saveBtn" data-order="${o.id}">Save</button>
        ${!o.shipped ? `<button class="btn btn-block shipBtn" data-order="${o.id}" style="width:auto">Mark shipped</button>` : ''}
      </div>
      <p class="msg" data-order="${o.id}" style="margin-top:6px; font-size:0.85rem"></p>
    </div>
  `).join('');

  return layout(`
  <div style="display:flex; justify-content:space-between; align-items:center">
    <h1>Orders to fulfill</h1>
    <button class="btn" id="logoutBtn" style="width:auto">Log out</button>
  </div>
  <p class="muted">${orders.length} paid order${orders.length === 1 ? '' : 's'}</p>
  ${rows || '<p class="muted">No paid orders yet.</p>'}
  <script>
    document.getElementById('logoutBtn').onclick = async () => {
      await fetch('/admin/logout', { method: 'POST' });
      location.reload();
    };
    document.querySelectorAll('.saveBtn').forEach(btn => {
      btn.onclick = async () => {
        const orderId = btn.dataset.order;
        const tagIds = document.querySelector('.tagInput[data-order="' + orderId + '"]').value;
        const msg = document.querySelector('.msg[data-order="' + orderId + '"]');
        const r = await fetch('/api/admin/orders/' + orderId + '/assign-tags', {
          method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ tagIds })
        });
        const j = await r.json();
        msg.textContent = r.ok ? 'Saved.' : j.error;
        msg.style.color = r.ok ? 'var(--teal)' : '#B23A3A';
      };
    });
    document.querySelectorAll('.shipBtn').forEach(btn => {
      btn.onclick = async () => {
        await fetch('/api/admin/orders/' + btn.dataset.order + '/ship', { method: 'POST' });
        location.reload();
      };
    });
  </script>`);
}

function forgotPasswordPageHtml() {
  return layout(`
  <h1>Reset your password</h1>
  <div class="card">
    <form id="f">
      <input name="email" type="email" placeholder="Your account email" required>
      <button type="submit" class="btn btn-primary btn-block">Send reset link</button>
    </form>
    <p id="msg" style="margin-top:12px"></p>
  </div>
  <script>
    document.getElementById('f').onsubmit = async (e) => {
      e.preventDefault();
      const data = Object.fromEntries(new FormData(e.target));
      await fetch('/api/forgot-password', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(data) });
      document.getElementById('f').style.display = 'none';
      document.getElementById('msg').textContent = "If an account exists for that email, we've sent a reset link. Check your inbox.";
    };
  </script>`);
}

function resetPasswordPageHtml(token) {
  return layout(`
  <h1>Set a new password</h1>
  <div class="card">
    <form id="f">
      <input name="newPassword" type="password" placeholder="New password (min. 8 characters)" required minlength="8">
      <button type="submit" class="btn btn-primary btn-block">Update password</button>
    </form>
    <p id="msg" style="margin-top:12px"></p>
  </div>
  <script>
    document.getElementById('f').onsubmit = async (e) => {
      e.preventDefault();
      const data = Object.fromEntries(new FormData(e.target));
      data.token = ${JSON.stringify(token)};
      const r = await fetch('/api/reset-password', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(data) });
      const j = await r.json();
      if (!r.ok) { document.getElementById('msg').textContent = j.error; document.getElementById('msg').className = 'error'; return; }
      document.getElementById('f').style.display = 'none';
      document.getElementById('msg').textContent = 'Password updated. You can now log in.';
      setTimeout(() => location.href = '/login', 1500);
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
          '<p class="muted" style="text-align:center">Found this pet? Please call the number above.</p>' +
          '<div class="card" id="locationPrompt">' +
          '<p style="margin-bottom:14px">Help ' + (p.petName || 'their') + '\\'s owner reach you faster — share your current location?</p>' +
          '<button id="shareLocBtn" class="btn btn-primary btn-block" style="margin-bottom:8px">Share my location</button>' +
          '<button id="skipLocBtn" class="btn btn-ghost btn-block">Skip</button>' +
          '</div>';

        function notifyOwner(coords) {
          fetch('/api/profiles/' + publicId + '/scan', {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify(coords || {})
          }).finally(() => {
            document.getElementById('locationPrompt').innerHTML = '<p class="muted" style="margin:0; text-align:center">Thanks — the owner has been notified.</p>';
          });
        }

        document.getElementById('shareLocBtn').onclick = () => {
          if (!navigator.geolocation) { notifyOwner(null); return; }
          navigator.geolocation.getCurrentPosition(
            (pos) => notifyOwner({ lat: pos.coords.latitude, lng: pos.coords.longitude }),
            () => notifyOwner(null),
            { timeout: 8000 }
          );
        };
        document.getElementById('skipLocBtn').onclick = () => notifyOwner(null);
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

      <div style="margin-bottom:16px">
        <img id="photoPreview" style="display:none; width:100%; max-width:220px; border-radius:12px; margin-bottom:10px">
        <input type="hidden" name="photoUrl">
        <input type="file" id="photoFile" accept="image/*">
        <p id="photoMsg" class="muted" style="margin:6px 0 0; font-size:0.82rem"></p>
        <a href="#" id="removePhoto" class="muted" style="display:none; font-size:0.82rem">Remove photo</a>
      </div>

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

    function showPreview(dataUrl) {
      const preview = document.getElementById('photoPreview');
      const removeLink = document.getElementById('removePhoto');
      if (dataUrl) {
        preview.src = dataUrl;
        preview.style.display = 'block';
        removeLink.style.display = 'inline';
      } else {
        preview.style.display = 'none';
        removeLink.style.display = 'none';
      }
    }

    // Resize + compress the image client-side before it ever leaves the browser,
    // so a 5MB phone photo doesn't blow past the server's upload limit.
    function resizeImage(file, maxDim, quality) {
      return new Promise((resolve, reject) => {
        const img = new Image();
        const reader = new FileReader();
        reader.onload = (e) => { img.src = e.target.result; };
        reader.onerror = reject;
        img.onload = () => {
          let { width, height } = img;
          if (width > height && width > maxDim) { height *= maxDim / width; width = maxDim; }
          else if (height > maxDim) { width *= maxDim / height; height = maxDim; }
          const canvas = document.createElement('canvas');
          canvas.width = width; canvas.height = height;
          canvas.getContext('2d').drawImage(img, 0, 0, width, height);
          resolve(canvas.toDataURL('image/jpeg', quality));
        };
        img.onerror = reject;
        reader.readAsDataURL(file);
      });
    }

    document.getElementById('photoFile').addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      const msg = document.getElementById('photoMsg');
      msg.textContent = 'Processing...';
      try {
        const dataUrl = await resizeImage(file, 600, 0.7);
        document.querySelector('[name=photoUrl]').value = dataUrl;
        showPreview(dataUrl);
        msg.textContent = 'Photo ready — click Save to keep it.';
      } catch (err) {
        msg.textContent = 'Could not process that image — try a different file.';
      }
    });

    document.getElementById('removePhoto').onclick = (e) => {
      e.preventDefault();
      document.querySelector('[name=photoUrl]').value = '';
      document.getElementById('photoFile').value = '';
      document.getElementById('photoMsg').textContent = '';
      showPreview(null);
    };

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
      showPreview(profile.photoUrl || null);
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
