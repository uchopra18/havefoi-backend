// Data access layer — Postgres-backed, replaces the old db.json file.
// Requires DATABASE_URL env var (Supabase gives you this on your project's
// Settings > Database page — use the "Connection string" in URI format).
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('supabase')
    ? { rejectUnauthorized: false }
    : false,
});

const PUBLIC_FIELDS = ['petName', 'photoUrl', 'phone', 'notes'];
const PRIVATE_FIELDS = [
  'ownerName', 'address', 'altPhone', 'breed', 'age',
  'medicalNotes', 'vetName', 'vetPhone', 'microchipId'
];
const ALL_FIELDS = [...PUBLIC_FIELDS, ...PRIVATE_FIELDS];

// camelCase <-> snake_case column mapping for the profile fields
const FIELD_TO_COLUMN = {
  petName: 'pet_name', photoUrl: 'photo_url', phone: 'phone', notes: 'notes',
  ownerName: 'owner_name', address: 'address', altPhone: 'alt_phone',
  breed: 'breed', age: 'age', medicalNotes: 'medical_notes',
  vetName: 'vet_name', vetPhone: 'vet_phone', microchipId: 'microchip_id',
};

function rowToProfile(row) {
  if (!row) return null;
  const p = { publicId: row.public_id, ownerId: row.owner_id, createdAt: row.created_at };
  for (const f of ALL_FIELDS) p[f] = row[FIELD_TO_COLUMN[f]] || '';
  p.consentGiven = row.consent_given;
  p.lastScanNotifiedAt = row.last_scan_notified_at;
  return p;
}

// ---------- users ----------
async function createUser({ id, email, salt, hash }) {
  await pool.query(
    'INSERT INTO users (id, email, salt, hash) VALUES ($1, $2, $3, $4)',
    [id, email, salt, hash]
  );
}
async function getUserById(id) {
  const r = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  return r.rows[0] || null;
}
async function getUserByEmail(email) {
  const r = await pool.query('SELECT * FROM users WHERE lower(email) = lower($1)', [email]);
  return r.rows[0] || null;
}

// ---------- sessions ----------
async function createSession(token, userId, expiresAt) {
  await pool.query(
    'INSERT INTO sessions (token, user_id, expires_at) VALUES ($1, $2, $3)',
    [token, userId, new Date(expiresAt)]
  );
}
async function getSession(token) {
  const r = await pool.query('SELECT * FROM sessions WHERE token = $1', [token]);
  const row = r.rows[0];
  if (!row) return null;
  return { userId: row.user_id, expiresAt: row.expires_at.getTime() };
}
async function deleteSession(token) {
  await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
}

// ---------- profiles ----------
async function createBlankProfile(publicId) {
  await pool.query('INSERT INTO profiles (public_id) VALUES ($1)', [publicId]);
}
async function getProfile(publicId) {
  const r = await pool.query('SELECT * FROM profiles WHERE public_id = $1', [publicId]);
  return rowToProfile(r.rows[0]);
}
async function getProfilesByOwner(ownerId) {
  const r = await pool.query('SELECT * FROM profiles WHERE owner_id = $1 ORDER BY created_at', [ownerId]);
  return r.rows.map(rowToProfile);
}
async function claimProfile(publicId, ownerId) {
  await pool.query('UPDATE profiles SET owner_id = $1 WHERE public_id = $2', [ownerId, publicId]);
}
async function updateProfile(publicId, fields) {
  const sets = [];
  const values = [];
  let i = 1;
  for (const f of ALL_FIELDS) {
    if (fields[f] !== undefined) {
      sets.push(`${FIELD_TO_COLUMN[f]} = $${i++}`);
      values.push(fields[f]);
    }
  }
  if (fields.consentGiven !== undefined) {
    sets.push(`consent_given = $${i++}`);
    values.push(!!fields.consentGiven);
  }
  if (!sets.length) return;
  values.push(publicId);
  await pool.query(`UPDATE profiles SET ${sets.join(', ')} WHERE public_id = $${i}`, values);
}
async function eraseProfile(publicId) {
  // "Right to erasure" — wipe personal data but keep the tag row itself,
  // reset to unclaimed so it can be linked to a new account.
  await pool.query(
    `UPDATE profiles SET owner_id = NULL, consent_given = false, last_scan_notified_at = NULL,
     ${ALL_FIELDS.map(f => `${FIELD_TO_COLUMN[f]} = ''`).join(', ')}
     WHERE public_id = $1`,
    [publicId]
  );
}
async function setScanNotified(publicId) {
  await pool.query('UPDATE profiles SET last_scan_notified_at = now() WHERE public_id = $1', [publicId]);
}

// ---------- SMS log ----------
async function logSMS(publicId, toPhone, message) {
  await pool.query(
    'INSERT INTO sms_log (public_id, to_phone, message) VALUES ($1, $2, $3)',
    [publicId, toPhone, message]
  );
}

// ---------- orders ----------
async function createOrder(order) {
  await pool.query(
    `INSERT INTO orders (id, razorpay_order_id, status, quantity, amount_paise, customer_name, customer_phone, customer_email, address, city, pincode, pet_name)
     VALUES ($1,$2,'pending',$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
    [order.id, order.razorpayOrderId, order.quantity, order.amountPaise, order.customerName, order.customerPhone, order.customerEmail, order.address, order.city, order.pincode, order.petName]
  );
}
async function getOrderByRazorpayOrderId(razorpayOrderId) {
  const r = await pool.query('SELECT * FROM orders WHERE razorpay_order_id = $1', [razorpayOrderId]);
  return r.rows[0] || null;
}
async function getOrderById(id) {
  const r = await pool.query('SELECT * FROM orders WHERE id = $1', [id]);
  return r.rows[0] || null;
}
async function markOrderPaid(razorpayOrderId, razorpayPaymentId) {
  await pool.query(
    `UPDATE orders SET status = 'paid', razorpay_payment_id = $1 WHERE razorpay_order_id = $2`,
    [razorpayPaymentId, razorpayOrderId]
  );
}

async function updateUserPassword(userId, salt, hash) {
  await pool.query('UPDATE users SET salt = $1, hash = $2 WHERE id = $3', [salt, hash, userId]);
}

// ---------- password resets ----------
async function createPasswordReset(token, userId, expiresAt) {
  await pool.query(
    'INSERT INTO password_resets (token, user_id, expires_at) VALUES ($1, $2, $3)',
    [token, userId, new Date(expiresAt)]
  );
}
async function getPasswordReset(token) {
  const r = await pool.query('SELECT * FROM password_resets WHERE token = $1', [token]);
  const row = r.rows[0];
  if (!row) return null;
  return { userId: row.user_id, expiresAt: row.expires_at.getTime() };
}
async function deletePasswordReset(token) {
  await pool.query('DELETE FROM password_resets WHERE token = $1', [token]);
}

async function getPaidOrders() {
  const r = await pool.query("SELECT * FROM orders WHERE status = 'paid' ORDER BY created_at");
  return r.rows;
}
async function assignTagsToOrder(orderId, tagIdsCsv) {
  await pool.query('UPDATE orders SET assigned_tag_ids = $1 WHERE id = $2', [tagIdsCsv, orderId]);
}
async function markOrderShipped(orderId) {
  await pool.query('UPDATE orders SET shipped = true WHERE id = $1', [orderId]);
}
async function findOrdersUsingTag(tagId, excludeOrderId) {
  // used to stop the same physical tag being assigned to two different orders
  const r = await pool.query(
    `SELECT id FROM orders WHERE assigned_tag_ids IS NOT NULL
     AND (',' || assigned_tag_ids || ',') LIKE $1 AND id != $2`,
    [`%,${tagId},%`, excludeOrderId]
  );
  return r.rows;
}

module.exports = {
  pool, PUBLIC_FIELDS, PRIVATE_FIELDS, ALL_FIELDS,
  createUser, getUserById, getUserByEmail, updateUserPassword,
  createSession, getSession, deleteSession,
  createBlankProfile, getProfile, getProfilesByOwner, claimProfile, updateProfile, eraseProfile, setScanNotified,
  logSMS,
  createOrder, getOrderByRazorpayOrderId, getOrderById, markOrderPaid,
  createPasswordReset, getPasswordReset, deletePasswordReset,
  getPaidOrders, assignTagsToOrder, markOrderShipped, findOrdersUsingTag,
};
