'use strict';

/* =========================================================
   SYSOFT STORE — API server  (Express + MySQL + Paypack)
   Works locally and on Vercel (exports the app).

   What changed vs. the previous version
   - The SERVER decides the price. The browser only sends product ids and quantities.
   - The order is created first (stock reserved), THEN the Mobile Money request is sent.
   - Payments are VERIFIED with Paypack (polling + optional webhook) — no more trusting the browser.
   - Unpaid orders are released automatically (stock goes back on the shelf).
   - Admin passwords are bcrypt-hashed (old plain-text passwords upgrade themselves on next login).
   - Real product categories, sale prices, featured items, order items, tracking, dashboard stats.
   ========================================================= */

const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = Number(process.env.PORT || 5000);
const isVercel = Boolean(process.env.VERCEL);
const isProd = isVercel || process.env.NODE_ENV === 'production';
const publicDir = path.join(__dirname, 'public');
const uploadsDir = path.join(__dirname, 'uploads');

const HOLD_MINUTES = Math.max(5, Number(process.env.ORDER_HOLD_MINUTES || 15)); // unpaid orders are released after this
const LOW_STOCK = Number(process.env.LOW_STOCK_THRESHOLD || 30);
const MIN_AMOUNT = 100;            // RWF, Paypack minimum
const MAX_AMOUNT = 10000000;       // RWF
const JWT_SECRET = process.env.JWT_SECRET || '';

const STORE = {
  name: 'SYSOFT Store',
  whatsapp: String(process.env.STORE_WHATSAPP || '250798557207').replace(/\D/g, ''),
  phone: process.env.STORE_PHONE || '0798557207',
  email: process.env.STORE_EMAIL || 'amahorojustin04@gmail.com',
  instagram: process.env.STORE_INSTAGRAM || 'https://instagram.com/Ni_stein24',
};

const allowedOrigins = (process.env.FRONTEND_URLS || process.env.FRONTEND_URL || '')
  .split(',').map(value => value.trim()).filter(Boolean);

if (!JWT_SECRET || JWT_SECRET.length < 16) {
  console.warn('WARNING: JWT_SECRET is missing or too short (use 32+ random characters). Admin sign-in is disabled until it is set.');
}
if (!allowedOrigins.length) {
  console.warn('NOTE: FRONTEND_URLS is not set, so any website may call this API. Set it to your store address to lock it down.');
}

/* =========================================================
   MIDDLEWARE
   ========================================================= */

app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (isProd) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  if (req.path.startsWith('/admin')) res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  next();
});
app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(Object.assign(new Error('This website is not allowed to call the API.'), { status: 403 }));
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Paypack-Secret'],
}));
app.use(express.json({ limit: '1mb' }));

/* ---- tiny in-memory rate limiter (no extra dependency; per server instance) ---- */
const clientIp = req => String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket?.remoteAddress || 'unknown';

function rateLimit({ name, windowMs, max, message }) {
  const hits = new Map();
  return (req, res, next) => {
    const now = Date.now();
    const key = `${name}:${clientIp(req)}`;
    let entry = hits.get(key);
    if (!entry || entry.reset <= now) { entry = { count: 0, reset: now + windowMs }; hits.set(key, entry); }
    entry.count += 1;
    if (hits.size > 5000) for (const [k, v] of hits) if (v.reset <= now) hits.delete(k);
    if (entry.count > max) {
      res.setHeader('Retry-After', Math.ceil((entry.reset - now) / 1000));
      return res.status(429).json({ success: false, error: message || 'Too many requests. Please slow down.' });
    }
    return next();
  };
}
const loginLimiter = rateLimit({ name: 'login', windowMs: 15 * 60 * 1000, max: 10, message: 'Too many sign-in attempts. Try again in 15 minutes.' });
const checkoutLimiter = rateLimit({ name: 'checkout', windowMs: 10 * 60 * 1000, max: 8, message: 'Too many checkout attempts. Please wait a few minutes.' });
const trackLimiter = rateLimit({ name: 'track', windowMs: 60 * 1000, max: 60, message: 'Too many requests. Please slow down.' });
const publicLimiter = rateLimit({ name: 'public', windowMs: 60 * 1000, max: 240, message: 'Too many requests. Please slow down.' });

/* =========================================================
   FILE UPLOADS  (Cloudinary in production, local disk for development)
   ========================================================= */

let cloudinary = null;
if (process.env.CLOUDINARY_URL) {
  cloudinary = require('cloudinary').v2;
  cloudinary.config({ secure: true });
}
if (!isVercel) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  app.use('/uploads', express.static(uploadsDir, { maxAge: '7d' }));
}

const IMAGE_TYPES = { 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp', 'image/gif': '.gif' };

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 4 * 1024 * 1024, files: 1 },   // Vercel rejects request bodies above ~4.5 MB
  fileFilter: (_req, file, callback) => {
    if (IMAGE_TYPES[file.mimetype]) return callback(null, true);
    return callback(httpError('Use a JPEG, PNG, WebP, or GIF image.'));
  },
});

// Check the file's real signature, not just the type the browser claims.
function looksLikeImage(file) {
  const b = file.buffer;
  if (!b || b.length < 12) return false;
  switch (file.mimetype) {
    case 'image/jpeg': return b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff;
    case 'image/png': return b[0] === 0x89 && b.toString('ascii', 1, 4) === 'PNG';
    case 'image/gif': return b.toString('ascii', 0, 4) === 'GIF8';
    case 'image/webp': return b.toString('ascii', 0, 4) === 'RIFF' && b.toString('ascii', 8, 12) === 'WEBP';
    default: return false;
  }
}

async function storeImage(file) {
  if (!file) return '';
  if (!looksLikeImage(file)) throw httpError('That file is not a valid image.');
  if (cloudinary) {
    const result = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        { folder: process.env.CLOUDINARY_FOLDER || 'sysoft-products', resource_type: 'image' },
        (error, uploaded) => (error ? reject(error) : resolve(uploaded)),
      );
      stream.end(file.buffer);
    });
    return result.secure_url;
  }
  if (isVercel) throw httpError('Image storage is not configured. Add CLOUDINARY_URL in Vercel.', 503);
  const filename = `${crypto.randomUUID()}${IMAGE_TYPES[file.mimetype]}`;
  await fs.promises.writeFile(path.join(uploadsDir, filename), file.buffer);
  return `/uploads/${filename}`;
}

/* =========================================================
   DATABASE
   ========================================================= */

const corePool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'defaultdb',
  port: Number(process.env.DB_PORT || 17499),
  waitForConnections: true,
  connectionLimit: Number(process.env.DB_CONNECTION_LIMIT || 10),
  queueLimit: 0,
  timezone: 'Z',
  charset: 'utf8mb4',
  ...(process.env.DB_SSL === 'true' ? { ssl: { rejectUnauthorized: false } } : {}),
});
corePool.on('connection', connection => connection.query("SET time_zone = '+00:00'", () => {}));
const db = corePool.promise();

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS admins (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  ) CHARACTER SET utf8mb4`,
  `CREATE TABLE IF NOT EXISTS products (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    price DECIMAL(12,2) NOT NULL DEFAULT 0,
    stock_quantity INT NOT NULL DEFAULT 0,
    description TEXT,
    image_url VARCHAR(500) NOT NULL DEFAULT '',
    category VARCHAR(60) NOT NULL DEFAULT 'Other',
    compare_price DECIMAL(12,2) NULL,
    featured TINYINT(1) NOT NULL DEFAULT 0,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  ) CHARACTER SET utf8mb4`,
  `CREATE TABLE IF NOT EXISTS orders (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    order_number VARCHAR(30) NULL,
    full_name VARCHAR(150) NOT NULL,
    email VARCHAR(150) NOT NULL,
    phone VARCHAR(20) NOT NULL,
    district VARCHAR(100) NULL,
    delivery_address VARCHAR(500) NULL,
    total_amount DECIMAL(12,2) NOT NULL DEFAULT 0,
    payment_method VARCHAR(30) NOT NULL DEFAULT 'MTN_MOMO',
    transaction_reference VARCHAR(100) NULL,
    payment_status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    delivery_status VARCHAR(20) NOT NULL DEFAULT 'PROCESSING',
    products_ordered TEXT,
    admin_note VARCHAR(255) NULL,
    stock_restored TINYINT(1) NOT NULL DEFAULT 0,
    paid_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  ) CHARACTER SET utf8mb4`,
  `CREATE TABLE IF NOT EXISTS order_items (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    order_id INT UNSIGNED NOT NULL,
    product_id INT UNSIGNED NULL,
    product_name VARCHAR(150) NOT NULL,
    unit_price DECIMAL(12,2) NOT NULL DEFAULT 0,
    quantity INT NOT NULL DEFAULT 1
  ) CHARACTER SET utf8mb4`,
];

// Columns added to tables that already exist in your database (safe to run repeatedly).
const NEW_COLUMNS = [
  ['products', 'category', "VARCHAR(60) NOT NULL DEFAULT 'Other'"],
  ['products', 'compare_price', 'DECIMAL(12,2) NULL'],
  ['products', 'featured', 'TINYINT(1) NOT NULL DEFAULT 0'],
  ['products', 'is_active', 'TINYINT(1) NOT NULL DEFAULT 1'],
  ['products', 'created_at', 'TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP'],
  ['orders', 'order_number', 'VARCHAR(30) NULL'],
  ['orders', 'delivery_status', "VARCHAR(20) NOT NULL DEFAULT 'PROCESSING'"],
  ['orders', 'admin_note', 'VARCHAR(255) NULL'],
  ['orders', 'stock_restored', 'TINYINT(1) NOT NULL DEFAULT 0'],
  ['orders', 'paid_at', 'TIMESTAMP NULL'],
  ['orders', 'created_at', 'TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP'],
];

async function columnMap(table) {
  const [rows] = await db.query(
    'SELECT COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?',
    [table],
  );
  return new Map(rows.map(row => [String(row.COLUMN_NAME).toLowerCase(), row]));
}

async function ensureSchema() {
  for (const statement of SCHEMA) await db.query(statement);

  for (const [table, column, definition] of NEW_COLUMNS) {
    try {
      const columns = await columnMap(table);
      if (!columns.has(column)) {
        await db.query(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
        console.log(`Database upgraded: ${table}.${column}`);
      }
    } catch (error) {
      console.error(`Could not add ${table}.${column}: ${error.message}. Run the SQL in schema-upgrade.sql with an admin database user.`);
    }
  }

  try { // bcrypt hashes are 60 characters; older tables may have a shorter password column
    const adminColumns = await columnMap('admins');
    const length = Number(adminColumns.get('password')?.CHARACTER_MAXIMUM_LENGTH || 255);
    if (length < 100) await db.query('ALTER TABLE admins MODIFY password VARCHAR(255) NOT NULL');
  } catch (error) { console.error('Could not widen admins.password:', error.message); }

  try { // allow more payment methods than the old single-value setup
    const orderColumns = await columnMap('orders');
    if (String(orderColumns.get('payment_method')?.DATA_TYPE).toLowerCase() === 'enum') {
      await db.query("ALTER TABLE orders MODIFY payment_method VARCHAR(30) NOT NULL DEFAULT 'MTN_MOMO'");
    }
  } catch (error) { console.error('Could not relax orders.payment_method:', error.message); }

  try { // friendly order numbers for existing orders
    const [missing] = await db.query("SELECT id FROM orders WHERE order_number IS NULL OR order_number = ''");
    for (const row of missing) await db.query('UPDATE orders SET order_number = ? WHERE id = ?', [orderNumberFor(row.id), row.id]);
  } catch (error) { console.error('Could not number existing orders:', error.message); }

  // Optional first admin from environment variables (only if no admin exists yet).
  const username = cleanText(process.env.ADMIN_USERNAME, 100);
  const password = String(process.env.ADMIN_PASSWORD || '');
  if (username && password.length >= 10) {
    const [admins] = await db.query('SELECT id FROM admins LIMIT 1');
    if (!admins.length) {
      await db.query('INSERT INTO admins (username, password) VALUES (?, ?)', [username, await bcrypt.hash(password, 12)]);
      console.log(`Admin account created: ${username}`);
    }
  }
}

let schemaPromise = null;
function ready(_req, _res, next) {
  if (!schemaPromise) schemaPromise = ensureSchema().catch(error => { schemaPromise = null; throw error; });
  schemaPromise.then(() => next(), next);
}

/* =========================================================
   HELPERS
   ========================================================= */

const ah = handler => (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);

function httpError(message, status = 400, extra = {}) {
  return Object.assign(new Error(message), { status, ...extra });
}

function cleanText(value, maxLength = 500) {
  return String(value ?? '').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim().slice(0, maxLength);
}

function clampInt(value, fallback, min, max) {
  const n = Number.parseInt(value, 10);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fallback;
}

const escapeLike = value => value.replace(/[\\%_]/g, '\\$&');
const orderNumberFor = id => `SYS-${String(id).padStart(6, '0')}`;
const isTrue = value => ['1', 'true', 'on', 'yes'].includes(String(value).toLowerCase());
const isFalse = value => ['0', 'false', 'off', 'no'].includes(String(value).toLowerCase());
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function normalizePhone(raw) {
  let phone = String(raw || '').replace(/[\s()+-]/g, '');
  if (phone.startsWith('0')) phone = `250${phone.slice(1)}`;
  return phone;
}
const PHONE_RE = /^2507[2389]\d{7}$/;     // MTN 078/079 and Airtel 072/073
const providerFor = phone => (/^2507[89]/.test(phone) ? 'MTN_MOMO' : 'AIRTEL_MONEY');

function toDate(value) {
  if (value instanceof Date) return value;
  const text = String(value || '');
  return new Date(/[zZ]|[+-]\d{2}:?\d{2}$/.test(text) ? text : `${text.replace(' ', 'T')}Z`);
}
const validDate = value => { const d = value ? toDate(value) : null; return d && !Number.isNaN(d.getTime()) ? d : null; };
const toIso = value => (validDate(value) ? validDate(value).toISOString() : null);

function appendNote(existing, note) {
  const stamp = new Date().toISOString().slice(0, 16).replace('T', ' ');
  return [existing, `${stamp} ${note}`].filter(Boolean).join(' | ').slice(-255);
}

function publicProduct(row) {
  return {
    id: Number(row.id),
    name: row.name,
    price: Number(row.price),
    compare_price: row.compare_price == null ? null : Number(row.compare_price),
    stock_quantity: Number(row.stock_quantity),
    description: row.description || '',
    image_url: row.image_url || '',
    category: row.category || 'Other',
    featured: Boolean(Number(row.featured)),
    created_at: toIso(row.created_at),
  };
}

function productValues(body, { partial = false } = {}) {
  const out = {};
  const has = key => body[key] !== undefined;

  if (!partial || has('name')) {
    out.name = cleanText(body.name, 150);
    if (!out.name) throw httpError('Product name is required.');
  }
  if (!partial || has('price')) {
    out.price = Number(body.price);
    if (!Number.isFinite(out.price) || out.price < 0 || out.price > MAX_AMOUNT) throw httpError('Price must be a number between 0 and 10,000,000.');
    out.price = Math.round(out.price);
  }
  if (!partial || has('stock_quantity')) {
    out.stock = body.stock_quantity === '' || body.stock_quantity == null ? 0 : Number(body.stock_quantity);
    if (!Number.isInteger(out.stock) || out.stock < 0 || out.stock > 1000000) throw httpError('Stock quantity must be a non-negative whole number.');
  }
  if (!partial || has('description')) out.description = cleanText(body.description, 2000);
  if (!partial || has('category')) out.category = cleanText(body.category, 60) || 'Other';
  if (!partial || has('compare_price')) {
    const raw = body.compare_price;
    const compare = raw === '' || raw == null ? null : Math.round(Number(raw));
    if (compare !== null && (!Number.isFinite(compare) || compare < 0)) throw httpError('The old price must be a number.');
    const price = out.price ?? Number(body.price);
    out.comparePrice = compare !== null && Number.isFinite(price) && compare > price ? compare : null;
  }
  if (!partial || has('featured')) out.featured = isTrue(body.featured) ? 1 : 0;
  if (!partial || has('is_active')) out.isActive = has('is_active') && isFalse(body.is_active) ? 0 : 1;
  return out;
}

/* =========================================================
   PAYPACK (Mobile Money)
   ========================================================= */

const PAYPACK_BASE = 'https://payments.paypack.rw/api';
const paymentsConfigured = () => Boolean(process.env.PAYPACK_CLIENT_ID && process.env.PAYPACK_CLIENT_SECRET);
let paypackAuth = { token: '', expires: 0 };

async function paypackToken(forceRefresh = false) {
  if (!forceRefresh && paypackAuth.token && paypackAuth.expires > Date.now()) return paypackAuth.token;
  const response = await axios.post(`${PAYPACK_BASE}/auth/agents/authorize`, {
    client_id: process.env.PAYPACK_CLIENT_ID,
    client_secret: process.env.PAYPACK_CLIENT_SECRET,
  }, { headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, timeout: 15000 });
  paypackAuth = { token: response.data.access, expires: Date.now() + 4 * 60 * 1000 };
  return paypackAuth.token;
}

async function paypackRequest(method, url, data) {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const token = await paypackToken(attempt > 0);
    try {
      return await axios({
        method, url, data, timeout: 15000,
        headers: { 'Content-Type': 'application/json', Accept: 'application/json', Authorization: `Bearer ${token}` },
      });
    } catch (error) {
      if (error.response?.status === 401 && attempt === 0) continue;   // token expired: get a new one and retry once
      throw error;
    }
  }
  throw new Error('Paypack request failed.');
}

async function paypackCashin(amount, number) {
  const response = await paypackRequest('post', `${PAYPACK_BASE}/transactions/cashin`, { amount, number });
  if (!response.data?.ref) throw new Error('Paypack did not return a transaction reference.');
  return String(response.data.ref);
}

// Reduce whatever Paypack returns to: 'successful' | 'failed' | 'pending'
function readGatewayStatus(data) {
  const candidates = [];
  const visit = node => {
    if (!node || typeof node !== 'object') return;
    if (typeof node.status === 'string') candidates.push(node.status);
    ['data', 'transaction', 'event'].forEach(key => visit(node[key]));
    ['transactions', 'events'].forEach(key => Array.isArray(node[key]) && node[key].slice(0, 5).forEach(visit));
  };
  visit(data);
  const text = candidates.join(' ').toLowerCase();
  if (/success|complete|paid/.test(text)) return 'successful';
  if (/fail|reject|declin|cancel|expire|timeout/.test(text)) return 'failed';
  return 'pending';
}

async function paypackStatus(ref) {
  try {
    const response = await paypackRequest('get', `${PAYPACK_BASE}/transactions/find/${encodeURIComponent(ref)}`);
    return readGatewayStatus(response.data);
  } catch (error) {
    if (![404, 405].includes(error.response?.status)) throw error;
    const events = await paypackRequest('get', `${PAYPACK_BASE}/events/transactions?ref=${encodeURIComponent(ref)}&limit=10`);
    return readGatewayStatus(events.data);
  }
}

/* =========================================================
   ORDER LIFECYCLE
   created -> PENDING (stock reserved) -> COMPLETED (paid) -> SHIPPED -> DELIVERED
                                       \-> CANCELLED (failed / expired / admin) -> stock returned
   ========================================================= */

async function inTransaction(work) {
  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();
    const result = await work(connection);
    await connection.commit();
    return result;
  } catch (error) {
    await connection.rollback().catch(() => {});
    throw error;
  } finally {
    connection.release();
  }
}

async function createOrderWithReservation(customer, lines, expectedTotal) {
  return inTransaction(async connection => {
    const ids = [...new Set(lines.map(line => line.id))].sort((a, b) => a - b);
    const [rows] = await connection.query('SELECT id, name, price, stock_quantity, is_active FROM products WHERE id IN (?) ORDER BY id FOR UPDATE', [ids]);
    const byId = new Map(rows.map(row => [Number(row.id), row]));

    let total = 0;
    const items = [];
    for (const line of lines) {
      const product = byId.get(line.id);
      if (!product || !Number(product.is_active)) throw httpError('One of the products in your cart is no longer available. Please review your cart.', 409);
      if (Number(product.stock_quantity) < line.quantity) {
        const left = Number(product.stock_quantity);
        throw httpError(left > 0 ? `Only ${left} left of "${product.name}". Please lower the quantity.` : `"${product.name}" just sold out.`, 409);
      }
      const unitPrice = Math.round(Number(product.price));
      total += unitPrice * line.quantity;
      items.push({ productId: Number(product.id), name: product.name, unitPrice, quantity: line.quantity });
    }

    // The shopper saw a price on screen. If it changed since, stop BEFORE any money is requested.
    if (Number.isFinite(expectedTotal) && expectedTotal > 0 && expectedTotal !== total) {
      throw httpError('Some prices changed since you added these items. Please review your cart and try again.', 409, { publicCode: 'PRICE_CHANGED' });
    }
    if (total < MIN_AMOUNT) throw httpError(`The minimum order is ${MIN_AMOUNT.toLocaleString('en-US')} RWF.`);
    if (total > MAX_AMOUNT) throw httpError(`Orders above ${MAX_AMOUNT.toLocaleString('en-US')} RWF must be arranged with our team on WhatsApp.`);

    for (const item of items) {
      await connection.query('UPDATE products SET stock_quantity = stock_quantity - ? WHERE id = ?', [item.quantity, item.productId]);
    }

    const summary = items.map(item => `${item.name} (x${item.quantity})`).join(', ').slice(0, 4000);
    const [inserted] = await connection.query(
      `INSERT INTO orders (full_name, email, phone, district, delivery_address, total_amount, payment_method, payment_status, delivery_status, products_ordered, transaction_reference, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', 'PROCESSING', ?, ?, NOW())`,
      [customer.fullName, customer.email, customer.phone, customer.district, customer.deliveryAddress, total, providerFor(customer.phone), summary, `${PLACEHOLDER_REF}${crypto.randomUUID()}`],
    );
    const orderId = Number(inserted.insertId);
    const orderNumber = orderNumberFor(orderId);
    await connection.query('UPDATE orders SET order_number = ? WHERE id = ?', [orderNumber, orderId]);
    for (const item of items) {
      await connection.query(
        'INSERT INTO order_items (order_id, product_id, product_name, unit_price, quantity) VALUES (?, ?, ?, ?, ?)',
        [orderId, item.productId, item.name, item.unitPrice, item.quantity],
      );
    }
    return { id: orderId, orderNumber, total, items };
  });
}

// Put the reserved stock back and mark the order cancelled.
async function cancelOrder(orderId, note, { allowPaid = false } = {}) {
  return inTransaction(async connection => {
    const [rows] = await connection.query('SELECT * FROM orders WHERE id = ? FOR UPDATE', [orderId]);
    const order = rows[0];
    if (!order) throw httpError('Order not found.', 404);
    if (order.payment_status === 'CANCELLED') return order;
    if (order.payment_status === 'COMPLETED' && !allowPaid) throw httpError('This order is already paid.', 409);

    let restored = Number(order.stock_restored) === 1;
    if (!restored) {
      const [items] = await connection.query('SELECT product_id, quantity FROM order_items WHERE order_id = ?', [orderId]);
      for (const item of items) {
        if (item.product_id) await connection.query('UPDATE products SET stock_quantity = stock_quantity + ? WHERE id = ?', [item.quantity, item.product_id]);
      }
      restored = items.length > 0;   // older orders have no item rows, so there is nothing to return
    }
    await connection.query(
      "UPDATE orders SET payment_status = 'CANCELLED', delivery_status = 'CANCELLED', stock_restored = ?, admin_note = ? WHERE id = ?",
      [restored ? 1 : 0, appendNote(order.admin_note, note), orderId],
    );
    return { ...order, payment_status: 'CANCELLED' };
  });
}

// Record a payment. If the order had already been released, try to take the stock again.
async function markPaid(orderId, note) {
  return inTransaction(async connection => {
    const [rows] = await connection.query('SELECT * FROM orders WHERE id = ? FOR UPDATE', [orderId]);
    const order = rows[0];
    if (!order) throw httpError('Order not found.', 404);
    if (order.payment_status === 'COMPLETED') return order;

    let adminNote = appendNote(order.admin_note, note);
    let stockRestored = Number(order.stock_restored);

    if (order.payment_status === 'CANCELLED' && stockRestored === 1) {
      const [items] = await connection.query('SELECT product_id, quantity FROM order_items WHERE order_id = ?', [orderId]);
      let enough = true;
      for (const item of items) {
        const [stock] = await connection.query('SELECT stock_quantity FROM products WHERE id = ? FOR UPDATE', [item.product_id]);
        if (!stock[0] || Number(stock[0].stock_quantity) < item.quantity) enough = false;
      }
      if (enough) {
        for (const item of items) await connection.query('UPDATE products SET stock_quantity = stock_quantity - ? WHERE id = ?', [item.quantity, item.product_id]);
        stockRestored = 0;
      } else {
        adminNote = appendNote(adminNote, 'PAID AFTER CANCELLATION and stock is short: contact the customer or refund');
      }
    }

    const delivery = order.delivery_status === 'CANCELLED' ? 'PROCESSING' : (order.delivery_status || 'PROCESSING');
    await connection.query(
      "UPDATE orders SET payment_status = 'COMPLETED', delivery_status = ?, stock_restored = ?, admin_note = ?, paid_at = NOW() WHERE id = ?",
      [delivery, stockRestored, adminNote, orderId],
    );
    return { ...order, payment_status: 'COMPLETED' };
  });
}

const PLACEHOLDER_REF = 'pending-';   // stored until Paypack gives us the real reference
const realRef = ref => Boolean(ref) && !String(ref).startsWith(PLACEHOLDER_REF);
const gatewayChecks = new Map();   // ref -> { at: when we last asked Paypack, ok: did Paypack actually answer }
const minutesSince = value => (validDate(value) ? (Date.now() - validDate(value).getTime()) / 60000 : 0);

async function hasItems(orderId) {
  const [rows] = await db.query('SELECT COUNT(*) AS n FROM order_items WHERE order_id = ?', [orderId]);
  return Number(rows[0].n) > 0;
}

// Ask Paypack what happened, then update the order. Safe to call often (it throttles itself).
// An order is only auto-cancelled for being unpaid if Paypack really answered "not paid".
// If Paypack could not be reached, the order stays PENDING with a note, so a real payment is never thrown away.
async function syncPayment(order, { force = false } = {}) {
  const ref = order.transaction_reference;
  const canCheck = paymentsConfigured() && realRef(ref);
  const eligible = order.payment_status === 'PENDING' || (force && order.payment_status === 'CANCELLED');

  if (eligible && canCheck) {
    const last = gatewayChecks.get(ref);
    if (force || !last || Date.now() - last.at > 2500) {
      let status = 'pending';
      let answered = false;
      try { status = await paypackStatus(ref); answered = true; }
      catch (error) { console.warn('Paypack status check failed:', error.response?.status || error.message); }
      gatewayChecks.set(ref, { at: Date.now(), ok: answered });
      if (status === 'successful') await markPaid(order.id, 'Payment confirmed by Paypack');
      else if (status === 'failed' && order.payment_status === 'PENDING') await cancelOrder(order.id, 'Payment failed or was declined');
    }
  }

  let [rows] = await db.query('SELECT * FROM orders WHERE id = ?', [order.id]);
  let current = rows[0];
  if (current.payment_status === 'PENDING' && minutesSince(current.created_at) > HOLD_MINUTES && await hasItems(current.id)) {
    if (canCheck && gatewayChecks.get(ref)?.ok === true) {
      await cancelOrder(current.id, 'Payment not completed in time');
    } else {
      // We could not confirm the payment status, so do NOT cancel: flag it for a human to check.
      await db.query(
        "UPDATE orders SET admin_note = ? WHERE id = ? AND (admin_note IS NULL OR admin_note NOT LIKE '%could not be verified%')",
        [appendNote(current.admin_note, 'Payment status could not be verified with Paypack: check it manually'), current.id],
      );
    }
    [rows] = await db.query('SELECT * FROM orders WHERE id = ?', [order.id]);
    current = rows[0];
  }
  return current;
}

// Release stock held by abandoned orders (runs at most once a minute per server instance).
let lastSweep = 0;
async function sweepExpiredOrders() {
  if (Date.now() - lastSweep < 60 * 1000) return;
  lastSweep = Date.now();
  try {
    const [rows] = await db.query(
      `SELECT * FROM orders o
       WHERE o.payment_status = 'PENDING' AND o.created_at < (NOW() - INTERVAL ? MINUTE)
         AND EXISTS (SELECT 1 FROM order_items i WHERE i.order_id = o.id)
       ORDER BY o.id LIMIT 20`,
      [HOLD_MINUTES],
    );
    for (const order of rows) await syncPayment(order);
  } catch (error) {
    console.warn('Could not release expired orders:', error.message);
  }
}

/* =========================================================
   ADMIN AUTH
   ========================================================= */

const isBcryptHash = value => /^\$2[aby]\$\d{2}\$.{53}$/.test(String(value || ''));
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', 10);

async function verifyAdminPassword(admin, password) {
  if (isBcryptHash(admin.password)) return bcrypt.compare(password, admin.password);
  // Older installs stored plain text. Compare safely, then upgrade it to a hash.
  const stored = Buffer.from(String(admin.password || ''));
  const given = Buffer.from(password);
  const ok = stored.length === given.length && crypto.timingSafeEqual(stored, given);
  if (ok) {
    try { await db.query('UPDATE admins SET password = ? WHERE id = ?', [await bcrypt.hash(password, 12), admin.id]); }
    catch (error) { console.error('Could not upgrade the stored admin password:', error.message); }
  }
  return ok;
}

function verifyAdminSession(req, res, next) {
  if (!JWT_SECRET || JWT_SECRET.length < 16) return res.status(503).json({ success: false, error: 'Admin sign-in is not configured on the server (JWT_SECRET).' });
  const token = req.get('authorization')?.match(/^Bearer\s+(.+)$/i)?.[1];
  if (!token) return res.status(401).json({ success: false, error: 'Sign in is required.' });
  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({ success: false, error: 'Your admin session has expired. Please sign in again.', code: 'SESSION_EXPIRED' });
  }
}

/* =========================================================
   PUBLIC API
   ========================================================= */

app.get('/robots.txt', (_req, res) => res.type('text/plain').send('User-agent: *\nDisallow: /admin\nDisallow: /api/\n'));

app.use('/api', ready);

app.get('/api/health', ah(async (_req, res) => {
  await db.query('SELECT 1');
  res.json({ success: true, service: 'sysoft-api', payments: paymentsConfigured(), time: new Date().toISOString() });
}));

app.get('/api/config', (_req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=60');
  res.json({
    success: true,
    store: STORE.name,
    currency: 'RWF',
    payments: { enabled: paymentsConfigured(), providers: ['MTN MoMo', 'Airtel Money'] },
    holdMinutes: HOLD_MINUTES,
    lowStock: LOW_STOCK,
    contact: { whatsapp: STORE.whatsapp, phone: STORE.phone, email: STORE.email, instagram: STORE.instagram },
  });
});

app.get('/api/categories', publicLimiter, ah(async (_req, res) => {
  const [rows] = await db.query('SELECT category AS name, COUNT(*) AS count FROM products WHERE is_active = 1 GROUP BY category ORDER BY count DESC, category ASC');
  res.setHeader('Cache-Control', 'public, max-age=30');
  res.json(rows.map(row => ({ name: row.name || 'Other', count: Number(row.count) })));
}));

const SORTS = {
  featured: 'featured DESC, id DESC',
  newest: 'id DESC',
  price_asc: 'price ASC, id DESC',
  price_desc: 'price DESC, id DESC',
  name: 'name ASC',
};
const PRODUCT_COLUMNS = 'id, name, price, compare_price, stock_quantity, description, image_url, category, featured, created_at';

app.get('/api/products', publicLimiter, ah(async (req, res) => {
  await sweepExpiredOrders();
  const search = cleanText(req.query.search, 100);
  const category = cleanText(req.query.category, 60);
  const where = ['is_active = 1'];
  const params = [];

  if (search) {
    where.push('(name LIKE ? OR description LIKE ? OR category LIKE ?)');
    const like = `%${escapeLike(search)}%`;
    params.push(like, like, like);
  }
  if (category && category !== 'All') { where.push('category = ?'); params.push(category); }
  if (isTrue(req.query.in_stock)) where.push('stock_quantity > 0');
  if (isTrue(req.query.featured)) where.push('featured = 1');
  const minPrice = Number(req.query.min_price);
  const maxPrice = Number(req.query.max_price);
  if (Number.isFinite(minPrice) && minPrice > 0) { where.push('price >= ?'); params.push(minPrice); }
  if (Number.isFinite(maxPrice) && maxPrice > 0) { where.push('price <= ?'); params.push(maxPrice); }

  const order = SORTS[req.query.sort] || SORTS.featured;
  const legacy = req.query.page === undefined && req.query.limit === undefined;   // old clients expect a plain array
  const limit = legacy ? 100 : clampInt(req.query.limit, 12, 1, 60);
  const page = clampInt(req.query.page, 1, 1, 100000);

  const [[{ total }]] = await db.query(`SELECT COUNT(*) AS total FROM products WHERE ${where.join(' AND ')}`, params);
  const [rows] = await db.query(
    `SELECT ${PRODUCT_COLUMNS} FROM products WHERE ${where.join(' AND ')} ORDER BY ${order} LIMIT ? OFFSET ?`,
    [...params, limit, (page - 1) * limit],
  );
  const items = rows.map(publicProduct);
  res.setHeader('Cache-Control', 'public, max-age=10, stale-while-revalidate=30');
  if (legacy) return res.json(items);
  return res.json({ items, total: Number(total), page, pages: Math.max(1, Math.ceil(Number(total) / limit)) });
}));

// Fresh prices and stock for the items in a visitor's cart.
app.get('/api/products/by-ids', publicLimiter, ah(async (req, res) => {
  const ids = [...new Set(String(req.query.ids || '').split(',').map(Number).filter(n => Number.isInteger(n) && n > 0))].slice(0, 50);
  if (!ids.length) return res.json([]);
  const [rows] = await db.query(`SELECT ${PRODUCT_COLUMNS} FROM products WHERE is_active = 1 AND id IN (?)`, [ids]);
  res.setHeader('Cache-Control', 'no-store');
  res.json(rows.map(publicProduct));
}));

app.get('/api/products/:id', publicLimiter, ah(async (req, res) => {
  const id = clampInt(req.params.id, 0, 0, 2147483647);
  const [rows] = await db.query(`SELECT ${PRODUCT_COLUMNS} FROM products WHERE id = ? AND is_active = 1`, [id]);
  if (!rows.length) throw httpError('Product not found.', 404);
  const product = publicProduct(rows[0]);
  const [related] = await db.query(
    `SELECT ${PRODUCT_COLUMNS} FROM products WHERE is_active = 1 AND category = ? AND id <> ? ORDER BY stock_quantity > 0 DESC, id DESC LIMIT 4`,
    [product.category, id],
  );
  res.json({ ...product, related: related.map(publicProduct) });
}));

/* ---------- checkout ---------- */

function readCustomer(body) {
  const fullName = cleanText(body.fullName, 150);
  const email = cleanText(body.email, 150).toLowerCase();
  const phone = normalizePhone(cleanText(body.phone, 20));
  const district = cleanText(body.district, 100);
  const deliveryAddress = cleanText(body.deliveryAddress, 500);
  if (fullName.length < 2) throw httpError('Please enter your full name.');
  if (!EMAIL_RE.test(email)) throw httpError('Please enter a valid email address.');
  if (!PHONE_RE.test(phone)) throw httpError('Enter a valid Rwanda Mobile Money number, for example 0781234567.');
  if (!district) throw httpError('Please choose your district.');
  if (deliveryAddress.length < 3) throw httpError('Please enter your delivery address or landmark.');
  return { fullName, email, phone, district, deliveryAddress };
}

function readLines(items) {
  if (!Array.isArray(items) || !items.length) throw httpError('Your cart is empty.');
  const merged = new Map();
  for (const item of items.slice(0, 60)) {
    const id = Number(item?.id);
    const quantity = Number(item?.quantity);
    if (!Number.isInteger(id) || id < 1 || !Number.isInteger(quantity) || quantity < 1 || quantity > 100) throw httpError('Your cart contains an invalid item.');
    merged.set(id, Math.min(100, (merged.get(id) || 0) + quantity));
  }
  return [...merged].map(([id, quantity]) => ({ id, quantity }));
}

app.post('/api/checkout', checkoutLimiter, ah(async (req, res) => {
  const customer = readCustomer(req.body || {});
  const lines = readLines(req.body?.items);

  if (!paymentsConfigured()) throw httpError('Mobile Money payments are temporarily unavailable. Please order on WhatsApp.', 503);

  await sweepExpiredOrders();
  const [[recent]] = await db.query(
    "SELECT COUNT(*) AS n FROM orders WHERE phone = ? AND payment_status = 'PENDING' AND created_at > (NOW() - INTERVAL ? MINUTE)",
    [customer.phone, HOLD_MINUTES],
  );
  if (Number(recent.n) >= 3) throw httpError('You already have unpaid orders waiting. Please complete or wait for them to expire.', 429);

  const order = await createOrderWithReservation(customer, lines, Number(req.body?.expectedTotal));

  let txRef;
  try {
    txRef = await paypackCashin(order.total, customer.phone);
  } catch (error) {
    console.error('PAYPACK CASHIN ERROR:', error.response?.data || error.message);
    await cancelOrder(order.id, 'Could not send the payment request').catch(err => console.error('Cancel failed:', err.message));
    throw httpError(error.response?.status === 400
      ? 'The payment provider rejected this number or amount. Check your Mobile Money number and try again.'
      : 'We could not send the Mobile Money request right now. Please try again in a moment.', 502);
  }
  await db.query('UPDATE orders SET transaction_reference = ? WHERE id = ?', [txRef, order.id]);

  res.status(201).json({
    success: true,
    orderNumber: order.orderNumber,
    totalAmount: order.total,
    paymentStatus: 'PENDING',
    holdMinutes: HOLD_MINUTES,
  });
}));

// The old two-step flow let the browser choose the amount. It is retired.
app.post('/api/initiate-payment', (_req, res) => res.status(410).json({ success: false, error: 'This page is out of date. Please refresh the store and try again.' }));

/* ---------- order tracking + payment status ---------- */

function describeOrder(order, items) {
  const created = validDate(order.created_at) || new Date();
  return {
    orderNumber: order.order_number || orderNumberFor(order.id),
    paymentStatus: order.payment_status,
    deliveryStatus: order.delivery_status || 'PROCESSING',
    paymentMethod: order.payment_method,
    total: Number(order.total_amount),
    createdAt: created.toISOString(),
    paidAt: toIso(order.paid_at),
    expiresAt: new Date(created.getTime() + HOLD_MINUTES * 60000).toISOString(),
    holdMinutes: HOLD_MINUTES,
    district: order.district,
    customerName: String(order.full_name || '').split(' ')[0],
    items: items.map(item => ({ name: item.product_name, quantity: Number(item.quantity), unitPrice: Number(item.unit_price) })),
    summary: order.products_ordered || '',
  };
}

app.post('/api/orders/track', trackLimiter, ah(async (req, res) => {
  const orderNumber = cleanText(req.body?.orderNumber, 30).toUpperCase();
  const phone = normalizePhone(cleanText(req.body?.phone, 20));
  if (!orderNumber || !phone) throw httpError('Enter your order number and phone number.');

  const [rows] = await db.query('SELECT * FROM orders WHERE order_number = ? LIMIT 1', [orderNumber]);
  const order = rows[0];
  // Same message for "no such order" and "wrong phone" so order numbers cannot be probed.
  if (!order || normalizePhone(order.phone) !== phone) throw httpError('We could not find an order with those details.', 404);

  const current = await syncPayment(order);
  const [items] = await db.query('SELECT product_name, unit_price, quantity FROM order_items WHERE order_id = ?', [current.id]);
  res.setHeader('Cache-Control', 'no-store');
  res.json({ success: true, order: describeOrder(current, items) });
}));

// Paypack calls this when a payment finishes. We never trust the body: we re-check with Paypack.
app.post('/api/paypack/webhook', ah(async (req, res) => {
  const secret = process.env.PAYPACK_WEBHOOK_SECRET;
  if (secret) {
    const given = String(req.get('x-paypack-secret') || req.query.secret || '');
    const ok = given.length === secret.length && crypto.timingSafeEqual(Buffer.from(given), Buffer.from(secret));
    if (!ok) return res.status(401).json({ success: false });
  }
  const ref = cleanText(req.body?.data?.ref || req.body?.ref, 100);
  if (ref) {
    const [rows] = await db.query('SELECT * FROM orders WHERE transaction_reference = ? LIMIT 1', [ref]);
    if (rows[0]) await syncPayment(rows[0], { force: true });
  }
  res.json({ success: true });
}));

/* =========================================================
   ADMIN API
   ========================================================= */

app.post('/api/admin/login', loginLimiter, ah(async (req, res) => {
  if (!JWT_SECRET || JWT_SECRET.length < 16) throw httpError('Admin sign-in is not configured on the server (JWT_SECRET).', 503);
  const username = cleanText(req.body?.username, 100);
  const password = String(req.body?.password || '');
  if (!username || !password) throw httpError('Enter your username and password.');

  const [admins] = await db.query('SELECT id, username, password FROM admins WHERE username = ? LIMIT 1', [username]);
  const admin = admins[0];
  const valid = admin ? await verifyAdminPassword(admin, password) : (await bcrypt.compare(password, DUMMY_HASH), false);
  if (!valid) return res.status(401).json({ success: false, message: 'Invalid username or password.', error: 'Invalid username or password.' });

  const token = jwt.sign({ adminId: admin.id, username: admin.username }, JWT_SECRET, { expiresIn: '8h' });
  res.json({ success: true, token, expiresIn: '8h', username: admin.username });
}));

app.get('/api/admin/me', verifyAdminSession, (req, res) => res.json({ success: true, username: req.admin.username }));

app.post('/api/admin/change-password', verifyAdminSession, ah(async (req, res) => {
  const current = String(req.body?.currentPassword || '');
  const next = String(req.body?.newPassword || '');
  if (next.length < 10) throw httpError('The new password must be at least 10 characters.');
  const [admins] = await db.query('SELECT id, username, password FROM admins WHERE id = ? LIMIT 1', [req.admin.adminId]);
  if (!admins[0] || !(await verifyAdminPassword(admins[0], current))) throw httpError('Your current password is not correct.', 403);
  await db.query('UPDATE admins SET password = ? WHERE id = ?', [await bcrypt.hash(next, 12), req.admin.adminId]);
  res.json({ success: true });
}));

app.get('/api/admin/stats', verifyAdminSession, ah(async (_req, res) => {
  await sweepExpiredOrders();
  const [byStatus] = await db.query('SELECT payment_status AS status, COUNT(*) AS n, COALESCE(SUM(total_amount), 0) AS amount FROM orders GROUP BY payment_status');
  const status = Object.fromEntries(byStatus.map(row => [row.status, { count: Number(row.n), amount: Number(row.amount) }]));
  const [[today]] = await db.query("SELECT COUNT(*) AS n, COALESCE(SUM(total_amount), 0) AS amount FROM orders WHERE payment_status = 'COMPLETED' AND paid_at >= (NOW() - INTERVAL 1 DAY)");
  const [days] = await db.query(
    "SELECT DATE(paid_at) AS day, COUNT(*) AS n, COALESCE(SUM(total_amount), 0) AS amount FROM orders WHERE payment_status = 'COMPLETED' AND paid_at >= (NOW() - INTERVAL 7 DAY) GROUP BY DATE(paid_at) ORDER BY day",
  );
  const [top] = await db.query(
    `SELECT i.product_name AS name, SUM(i.quantity) AS qty, SUM(i.quantity * i.unit_price) AS amount
     FROM order_items i JOIN orders o ON o.id = i.order_id
     WHERE o.payment_status = 'COMPLETED'
     GROUP BY i.product_id, i.product_name ORDER BY qty DESC LIMIT 5`,
  );
  const [[products]] = await db.query('SELECT COUNT(*) AS n,COALESCE(SUM(stock_quantity <= 30 AND is_active = 1), 0) AS low,COALESCE(SUM(stock_quantity = 0 AND is_active = 1), 0) AS out_of_stock FROM products', [LOW_STOCK]);

  res.json({
    success: true,
    revenue: status.COMPLETED?.amount || 0,
    paidOrders: status.COMPLETED?.count || 0,
    pendingOrders: status.PENDING?.count || 0,
    pendingAmount: status.PENDING?.amount || 0,
    cancelledOrders: status.CANCELLED?.count || 0,
    totalOrders: byStatus.reduce((sum, row) => sum + Number(row.n), 0),
    last24h: { orders: Number(today.n), amount: Number(today.amount) },
    daily: days.map(row => ({ day: String(row.day instanceof Date ? row.day.toISOString() : row.day).slice(0, 10), orders: Number(row.n), amount: Number(row.amount) })),
    topProducts: top.map(row => ({ name: row.name, quantity: Number(row.qty), amount: Number(row.amount) })),
    products: { total: Number(products.n), lowStock: Number(products.low), outOfStock: Number(products.out_of_stock), threshold: LOW_STOCK },
  });
}));

/* ---------- products (admin) ---------- */

const adminProduct = row => ({ ...publicProduct(row), is_active: Boolean(Number(row.is_active)) });

app.get('/api/admin/products', verifyAdminSession, ah(async (req, res) => {
  const search = cleanText(req.query.search, 100);
  const params = [];
  let where = '';
  if (search) { where = 'WHERE name LIKE ? OR category LIKE ?'; params.push(`%${escapeLike(search)}%`, `%${escapeLike(search)}%`); }
  const [rows] = await db.query(`SELECT ${PRODUCT_COLUMNS}, is_active FROM products ${where} ORDER BY id DESC LIMIT 500`, params);
  res.json(rows.map(adminProduct));
}));

app.post('/api/admin/products', verifyAdminSession, upload.single('productImage'), ah(async (req, res) => {
  const v = productValues(req.body);
  const imageUrl = await storeImage(req.file);
  const [result] = await db.query(
    'INSERT INTO products (name, price, stock_quantity, description, image_url, category, compare_price, featured, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [v.name, v.price, v.stock, v.description, imageUrl, v.category, v.comparePrice, v.featured, v.isActive],
  );
  res.status(201).json({ success: true, productId: result.insertId, imageUrl });
}));

app.put('/api/admin/products/:id', verifyAdminSession, upload.single('productImage'), ah(async (req, res) => {
  const id = clampInt(req.params.id, 0, 0, 2147483647);
  if (id < 1) throw httpError('Invalid product ID.');
  const v = productValues(req.body);
  const imageUrl = req.file ? await storeImage(req.file) : null;
  const fields = 'name=?, price=?, stock_quantity=?, description=?, category=?, compare_price=?, featured=?, is_active=?';
  const values = [v.name, v.price, v.stock, v.description, v.category, v.comparePrice, v.featured, v.isActive];
  const [result] = imageUrl
    ? await db.query(`UPDATE products SET ${fields}, image_url=? WHERE id=?`, [...values, imageUrl, id])
    : await db.query(`UPDATE products SET ${fields} WHERE id=?`, [...values, id]);
  if (!result.affectedRows) throw httpError('Product not found.', 404);
  res.json({ success: true, imageUrl });
}));

// Quick toggles from the product table (visible / featured / stock).
app.patch('/api/admin/products/:id', verifyAdminSession, ah(async (req, res) => {
  const id = clampInt(req.params.id, 0, 0, 2147483647);
  if (id < 1) throw httpError('Invalid product ID.');
  const v = productValues(req.body, { partial: true });
  const sets = [];
  const values = [];
  if (v.stock !== undefined) { sets.push('stock_quantity = ?'); values.push(v.stock); }
  if (v.featured !== undefined) { sets.push('featured = ?'); values.push(v.featured); }
  if (v.isActive !== undefined) { sets.push('is_active = ?'); values.push(v.isActive); }
  if (!sets.length) throw httpError('Nothing to update.');
  const [result] = await db.query(`UPDATE products SET ${sets.join(', ')} WHERE id = ?`, [...values, id]);
  if (!result.affectedRows) throw httpError('Product not found.', 404);
  res.json({ success: true });
}));

app.delete('/api/admin/products/:id', verifyAdminSession, ah(async (req, res) => {
  const id = clampInt(req.params.id, 0, 0, 2147483647);
  const [result] = await db.query('DELETE FROM products WHERE id = ?', [id]);
  if (!result.affectedRows) throw httpError('Product not found.', 404);
  res.json({ success: true });
}));

/* ---------- orders (admin) ---------- */

async function loadOrders({ where = '', params = [], limit = 25, offset = 0 } = {}) {
  const [[{ total }]] = await db.query(`SELECT COUNT(*) AS total FROM orders ${where}`, params);
  const [orders] = await db.query(`SELECT * FROM orders ${where} ORDER BY id DESC LIMIT ? OFFSET ?`, [...params, limit, offset]);
  let items = [];
  if (orders.length) [items] = await db.query('SELECT order_id, product_id, product_name, unit_price, quantity FROM order_items WHERE order_id IN (?)', [orders.map(o => o.id)]);
  const grouped = new Map();
  for (const item of items) {
    if (!grouped.has(item.order_id)) grouped.set(item.order_id, []);
    grouped.get(item.order_id).push({ product_id: item.product_id, name: item.product_name, unit_price: Number(item.unit_price), quantity: Number(item.quantity) });
  }
  return {
    total: Number(total),
    orders: orders.map(order => ({
      ...order,
      order_number: order.order_number || orderNumberFor(order.id),
      total_amount: Number(order.total_amount),
      created_at: toIso(order.created_at),
      paid_at: toIso(order.paid_at),
      items: grouped.get(order.id) || [],
    })),
  };
}

function orderFilters(query) {
  const clauses = [];
  const params = [];
  const status = String(query.status || '').toUpperCase();
  if (['PENDING', 'COMPLETED', 'CANCELLED'].includes(status)) { clauses.push('payment_status = ?'); params.push(status); }
  const delivery = String(query.delivery || '').toUpperCase();
  if (['PROCESSING', 'SHIPPED', 'DELIVERED'].includes(delivery)) { clauses.push('delivery_status = ?'); params.push(delivery); }
  const q = cleanText(query.q, 100);
  if (q) {
    const like = `%${escapeLike(q)}%`;
    clauses.push('(order_number LIKE ? OR full_name LIKE ? OR phone LIKE ? OR email LIKE ? OR transaction_reference LIKE ?)');
    params.push(like, like, like, like, like);
  }
  return { where: clauses.length ? `WHERE ${clauses.join(' AND ')}` : '', params };
}

app.get('/api/admin/orders', verifyAdminSession, ah(async (req, res) => {
  await sweepExpiredOrders();
  const filters = orderFilters(req.query);
  const legacy = req.query.page === undefined && req.query.limit === undefined;
  const limit = legacy ? 200 : clampInt(req.query.limit, 25, 1, 100);
  const page = clampInt(req.query.page, 1, 1, 100000);
  const { orders, total } = await loadOrders({ ...filters, limit, offset: (page - 1) * limit });
  if (legacy) return res.json(orders);
  return res.json({ orders, total, page, pages: Math.max(1, Math.ceil(total / limit)) });
}));

const csvCell = value => {
  let text = String(value ?? '');
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;          // stop spreadsheet formula injection
  return `"${text.replace(/"/g, '""')}"`;
};

app.get('/api/admin/orders/export', verifyAdminSession, ah(async (req, res) => {
  const { orders } = await loadOrders({ ...orderFilters(req.query), limit: 5000, offset: 0 });
  const header = ['Order', 'Date', 'Customer', 'Phone', 'Email', 'District', 'Address', 'Items', 'Total (RWF)', 'Payment', 'Delivery', 'Reference', 'Note'];
  const lines = orders.map(o => [
    o.order_number, o.created_at, o.full_name, o.phone, o.email, o.district, o.delivery_address,
    o.items.length ? o.items.map(i => `${i.name} x${i.quantity}`).join('; ') : o.products_ordered,
    o.total_amount, o.payment_status, o.delivery_status, o.transaction_reference, o.admin_note,
  ].map(csvCell).join(','));
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="sysoft-orders-${new Date().toISOString().slice(0, 10)}.csv"`);
  res.send(`\uFEFF${[header.map(csvCell).join(','), ...lines].join('\r\n')}`);
}));

async function orderById(id) {
  const [rows] = await db.query('SELECT * FROM orders WHERE id = ?', [id]);
  if (!rows[0]) throw httpError('Order not found.', 404);
  return rows[0];
}

app.patch('/api/admin/orders/:id/status', verifyAdminSession, ah(async (req, res) => {
  const id = clampInt(req.params.id, 0, 0, 2147483647);
  const order = await orderById(id);
  const payment = req.body?.payment_status ? String(req.body.payment_status).toUpperCase() : null;
  const delivery = req.body?.delivery_status ? String(req.body.delivery_status).toUpperCase() : null;

  if (payment) {
    if (!['COMPLETED', 'CANCELLED'].includes(payment) && payment !== order.payment_status) throw httpError('Invalid order status.');
    if (payment === 'COMPLETED') await markPaid(id, 'Marked as paid by admin');
    if (payment === 'CANCELLED') await cancelOrder(id, order.payment_status === 'COMPLETED' ? 'Cancelled by admin AFTER payment: refund the customer' : 'Cancelled by admin', { allowPaid: true });
  }
  if (delivery) {
    if (!['PROCESSING', 'SHIPPED', 'DELIVERED'].includes(delivery)) throw httpError('Invalid delivery status.');
    const fresh = await orderById(id);
    if (fresh.payment_status !== 'COMPLETED') throw httpError('Only paid orders can be shipped or delivered.', 409);
    await db.query('UPDATE orders SET delivery_status = ? WHERE id = ?', [delivery, id]);
  }
  if (!payment && !delivery) throw httpError('Nothing to update.');
  res.json({ success: true });
}));

// Re-check a payment with Paypack right now (useful for older orders and stuck payments).
app.post('/api/admin/orders/:id/verify', verifyAdminSession, ah(async (req, res) => {
  const order = await orderById(clampInt(req.params.id, 0, 0, 2147483647));
  if (!paymentsConfigured()) throw httpError('Paypack is not configured on the server.', 503);
  if (!realRef(order.transaction_reference)) throw httpError('This order has no payment reference to check.');
  const updated = await syncPayment(order, { force: true });
  res.json({ success: true, paymentStatus: updated.payment_status });
}));

app.delete('/api/admin/orders/:id', verifyAdminSession, ah(async (req, res) => {
  const id = clampInt(req.params.id, 0, 0, 2147483647);
  const order = await orderById(id);
  if (order.payment_status === 'PENDING') await cancelOrder(id, 'Deleted by admin');   // returns the reserved stock first
  await db.query('DELETE FROM order_items WHERE order_id = ?', [id]);
  await db.query('DELETE FROM orders WHERE id = ?', [id]);
  res.json({ success: true });
}));

/* =========================================================
   PAGES + ERRORS
   ========================================================= */

app.use(express.static(publicDir, { maxAge: isProd ? '1h' : 0 }));
app.get('/admin', (_req, res) => res.sendFile(path.join(publicDir, 'admin.html')));

app.use('/api', (_req, res) => res.status(404).json({ success: false, error: 'API route not found.' }));
app.get(/.*/, (_req, res) => res.sendFile(path.join(publicDir, 'index.html')));

app.use((error, _req, res, _next) => {
  if (error instanceof multer.MulterError) {
    return res.status(400).json({ success: false, error: error.code === 'LIMIT_FILE_SIZE' ? 'That image is too large (maximum 4 MB).' : error.message });
  }
  const dbDown = ['ECONNREFUSED', 'ETIMEDOUT', 'ENOTFOUND', 'PROTOCOL_CONNECTION_LOST', 'ER_ACCESS_DENIED_ERROR', 'ER_BAD_DB_ERROR'].includes(error.code);
  const status = dbDown ? 503 : (error.status || 500);
  if (status >= 500) console.error(error.response?.data || error);
  const message = status >= 500 && isProd
    ? (dbDown ? 'The store is temporarily unavailable. Please try again shortly.' : 'Something went wrong on our side. Please try again.')
    : (error.message || 'Internal server error.');
  res.status(status).json({ success: false, error: message, message, ...(error.publicCode ? { code: error.publicCode } : {}) });
});

if (require.main === module) app.listen(PORT, () => console.log(`SYSOFT Store API listening on port ${PORT}`));
module.exports = app;
