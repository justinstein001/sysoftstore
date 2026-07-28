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
const uploadsDir = path.join(__dirname, 'uploads');
const allowedOrigins = (process.env.FRONTEND_URLS || process.env.FRONTEND_URL || '')
  .split(',').map(value => value.trim()).filter(Boolean);

if (!process.env.JWT_SECRET) {
  console.warn('WARNING: JWT_SECRET is not set. Admin logins will not work until it is configured.');
}

app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});
app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('This website is not allowed to call the API.'));
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Images must use Cloudinary in Vercel production. Local disk is only a local-development fallback.
let cloudinary = null;
if (process.env.CLOUDINARY_URL) {
  cloudinary = require('cloudinary').v2;
  cloudinary.config({ secure: true });
}
if (!isVercel) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  app.use('/uploads', express.static(uploadsDir));
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 4 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, callback) => {
    const types = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
    if (types.includes(file.mimetype)) return callback(null, true);
    return callback(new Error('Use a JPEG, PNG, WebP, or GIF image.'));
  },
});

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'defaultdb',
  port: Number(process.env.DB_PORT || 17499),
  waitForConnections: true,
  connectionLimit: Number(process.env.DB_CONNECTION_LIMIT || 10),
  queueLimit: 0,
  ...(process.env.DB_SSL === 'true' ? { ssl: { rejectUnauthorized: false } } : {}),
});
const db = pool.promise();

function httpError(message, status = 400) {
  return Object.assign(new Error(message), { status });
}

function cleanText(value, maxLength = 500) {
  return String(value || '').trim().slice(0, maxLength);
}

function readAdminToken(req) {
  return req.get('authorization')?.match(/^Bearer\s+(.+)$/i)?.[1];
}

function verifyAdminSession(req, res, next) {
  const token = readAdminToken(req);
  if (!token) return res.status(401).json({ success: false, error: 'Sign in is required.' });
  try {
    req.admin = jwt.verify(token, process.env.JWT_SECRET);
    return next();
  } catch {
    return res.status(403).json({ success: false, error: 'Your admin session has expired. Please sign in again.' });
  }
}

function productValues(body) {
  const name = cleanText(body.name, 150);
  const description = cleanText(body.description, 2000);
  const price = Number(body.price);
  const stockQuantity = body.stock_quantity === '' || body.stock_quantity == null ? 0 : Number(body.stock_quantity);
  if (!name) throw httpError('Product name is required.');
  if (!Number.isFinite(price) || price < 0) throw httpError('Price must be a non-negative number.');
  if (!Number.isInteger(stockQuantity) || stockQuantity < 0) throw httpError('Stock quantity must be a non-negative whole number.');
  return { name, description, price, stockQuantity };
}

async function storeImage(file) {
  if (!file) return '';
  if (cloudinary) {
    const result = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        { folder: process.env.CLOUDINARY_FOLDER || 'sysoft-products', resource_type: 'image' },
        (error, result) => error ? reject(error) : resolve(result),
      );
      stream.end(file.buffer);
    });
    return result.secure_url;
  }
  if (isVercel) throw httpError('Image storage is not configured. Add CLOUDINARY_URL in Vercel.', 503);
  const extension = path.extname(file.originalname).toLowerCase() || '.jpg';
  const filename = `${crypto.randomUUID()}${extension}`;
  await fs.promises.writeFile(path.join(uploadsDir, filename), file.buffer);
  return `/uploads/${filename}`;
}

function publicImageUrl(imageUrl) {
  return imageUrl || '';
}

app.get('/api/health', async (_req, res, next) => {
  try {
    await db.query('SELECT 1');
    res.json({ success: true, service: 'sysoft-api', time: new Date().toISOString() });
  } catch (error) { next(error); }
});

app.post('/api/admin/login', async (req, res, next) => {
  try {
    const username = cleanText(req.body.username, 100);
    const password = String(req.body.password || '');
    
    const [admins] = await db.query('SELECT id, username, password FROM admins WHERE username = ? LIMIT 1', [username]);
    const admin = admins[0];
    
    if (!admin || admin.password !== password) {
      return res.status(401).json({ success: false, message: 'Invalid username or password.' });
    }

    const token = jwt.sign({ adminId: admin.id, username: admin.username }, process.env.JWT_SECRET, { expiresIn: '8h' });
    res.json({ success: true, token, expiresIn: '8h' });
  } catch (error) { next(error); }
});

app.get('/api/products', async (req, res, next) => {
  try {
    const search = cleanText(req.query.search, 100);
    const [products] = await db.query(
      'SELECT id, name, price, stock_quantity, description, image_url FROM products WHERE name LIKE ? OR description LIKE ? ORDER BY id DESC LIMIT 100',
      [`%${search}%`, `%${search}%`],
    );
    res.json(products.map(product => ({ ...product, image_url: publicImageUrl(product.image_url) })));
  } catch (error) { next(error); }
});

app.post('/api/admin/products', verifyAdminSession, upload.single('productImage'), async (req, res, next) => {
  try {
    const { name, price, stockQuantity, description } = productValues(req.body);
    const imageUrl = await storeImage(req.file);
    const [result] = await db.query(
      'INSERT INTO products (name, price, stock_quantity, description, image_url) VALUES (?, ?, ?, ?, ?)',
      [name, price, stockQuantity, description, imageUrl],
    );
    res.status(201).json({ success: true, productId: result.insertId, imageUrl });
  } catch (error) { next(error); }
});

app.put('/api/admin/products/:id', verifyAdminSession, upload.single('productImage'), async (req, res, next) => {
  try {
    const productId = Number(req.params.id);
    if (!Number.isInteger(productId) || productId < 1) throw httpError('Invalid product ID.');
    const { name, price, stockQuantity, description } = productValues(req.body);
    const imageUrl = req.file ? await storeImage(req.file) : null;
    const [result] = imageUrl
      ? await db.query('UPDATE products SET name=?, price=?, stock_quantity=?, description=?, image_url=? WHERE id=?', [name, price, stockQuantity, description, imageUrl, productId])
      : await db.query('UPDATE products SET name=?, price=?, stock_quantity=?, description=? WHERE id=?', [name, price, stockQuantity, description, productId]);
    if (!result.affectedRows) return res.status(404).json({ success: false, error: 'Product not found.' });
    res.json({ success: true, imageUrl });
  } catch (error) { next(error); }
});

app.delete('/api/admin/products/:id', verifyAdminSession, async (req, res, next) => {
  try {
    const [result] = await db.query('DELETE FROM products WHERE id = ?', [req.params.id]);
    if (!result.affectedRows) return res.status(404).json({ success: false, error: 'Product not found.' });
    res.json({ success: true });
  } catch (error) { next(error); }
});

app.post('/api/initiate-payment', async (req, res, next) => {
  try {
    const amount = Number(req.body.amount);
    let phone = cleanText(req.body.phone, 20).replace(/[\s+-]/g, '');
    if (phone.startsWith('0')) phone = `250${phone.slice(1)}`;

    // Define your minimum and maximum limits here
    const MIN_AMOUNT = 100;       // Minimum allowed amount in RWF
    const MAX_AMOUNT = 10000000;   // Maximum allowed amount in RWF

    // Check if amount is valid and within the min/max range
    if (!Number.isFinite(amount) || amount < MIN_AMOUNT || amount > MAX_AMOUNT || !/^2507\d{8}$/.test(phone)) {
      throw httpError(`Amount must be between ${MIN_AMOUNT.toLocaleString()} RWF and ${MAX_AMOUNT.toLocaleString()} RWF, and phone number must be valid.`);
    }

    if (!process.env.PAYPACK_CLIENT_ID || !process.env.PAYPACK_CLIENT_SECRET) {
      throw httpError('Payment gateway is not configured.', 503);
    }

    const auth = await axios.post('https://payments.paypack.rw/api/auth/agents/authorize', { 
      client_id: process.env.PAYPACK_CLIENT_ID, 
      client_secret: process.env.PAYPACK_CLIENT_SECRET 
    }, { timeout: 15000 });

    const payment = await axios.post('https://payments.paypack.rw/api/transactions/cashin', { 
      amount, 
      number: phone 
    }, { 
      headers: { Authorization: `Bearer ${auth.data.access}` }, 
      timeout: 15000 
    });

    res.json({ success: true, txRef: payment.data.ref });
  } catch (error) { 
    next(error); 
  }
});

app.post('/api/checkout', async (req, res, next) => {
  let connection;
  try {
    const { fullName, email, phone, district, deliveryAddress, txRef, items } = req.body;
    if (!cleanText(fullName, 150) || !cleanText(email, 150) || !cleanText(phone, 20) || !Array.isArray(items) || !items.length || !cleanText(txRef, 100)) throw httpError('Order details are incomplete.');
    connection = await db.getConnection();
    await connection.beginTransaction();
    const orderItems = [];
    let total = 0;
    for (const item of items) {
      const id = Number(item.id); const quantity = Number(item.quantity);
      if (!Number.isInteger(id) || !Number.isInteger(quantity) || quantity < 1) throw httpError('Invalid cart item.');
      const [rows] = await connection.query('SELECT id, name, price, stock_quantity FROM products WHERE id = ? FOR UPDATE', [id]);
      const product = rows[0];
      if (!product || Number(product.stock_quantity) < quantity) throw httpError('One or more products are out of stock.', 409);
      await connection.query('UPDATE products SET stock_quantity = stock_quantity - ? WHERE id = ?', [quantity, id]);
      total += Number(product.price) * quantity;
      orderItems.push(`${product.name} (x${quantity})`);
    }
    const [result] = await connection.query(
      "INSERT INTO orders (full_name, email, phone, district, delivery_address, total_amount, payment_method, transaction_reference, payment_status, products_ordered) VALUES (?, ?, ?, ?, ?, ?, 'MTN_MOMO', ?, 'PENDING', ?)",
      [cleanText(fullName, 150), cleanText(email, 150), cleanText(phone, 20), cleanText(district, 100), cleanText(deliveryAddress, 500) || 'Not provided', total, cleanText(txRef, 100), orderItems.join(', ')],
    );
    await connection.commit();
    res.status(201).json({ success: true, orderId: result.insertId, totalAmount: total, paymentStatus: 'PENDING' });
  } catch (error) {
    if (connection) await connection.rollback();
    next(error);
  } finally { if (connection) connection.release(); }
});

app.get('/api/admin/orders', verifyAdminSession, async (_req, res, next) => {
  try { const [orders] = await db.query('SELECT * FROM orders ORDER BY id DESC LIMIT 200'); res.json(orders); } catch (error) { next(error); }
});

app.patch('/api/admin/orders/:id/status', verifyAdminSession, async (req, res, next) => {
  try {
    const allowed = ['PENDING', 'COMPLETED', 'CANCELLED'];
    const status = String(req.body.payment_status || '').toUpperCase();
    if (!allowed.includes(status)) throw httpError('Invalid order status.');
    const [result] = await db.query('UPDATE orders SET payment_status = ? WHERE id = ?', [status, req.params.id]);
    if (!result.affectedRows) return res.status(404).json({ success: false, error: 'Order not found.' });
    res.json({ success: true });
  } catch (error) { next(error); }
});

app.delete('/api/admin/orders/:id', verifyAdminSession, async (req, res, next) => {
  try {
    const [result] = await db.query('DELETE FROM orders WHERE id = ?', [req.params.id]);
    if (!result.affectedRows) return res.status(404).json({ success: false, error: 'Order not found.' });
    res.json({ success: true });
  } catch (error) { next(error); }
});

app.use('/api', (_req, res) => res.status(404).json({ success: false, error: 'API route not found.' }));
app.get(/.*/, (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.use((error, _req, res, _next) => {
  console.error(error.response?.data || error);
  if (error instanceof multer.MulterError) return res.status(400).json({ success: false, error: error.message });
  res.status(error.status || 500).json({ success: false, error: error.message || 'Internal server error.' });
});

if (require.main === module) app.listen(PORT, () => console.log(`SYSOFT API listening on port ${PORT}`));
module.exports = app;
