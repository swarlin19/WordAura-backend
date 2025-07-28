const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const Razorpay = require("razorpay");
const fs = require('fs'); 


const app = express();
const SECRET_KEY = 'wordaura_secret';

// Razorpay Config
const razorpay = new Razorpay({
  key_id: "rzp_test_EH1UEwLILEPXCj",
  key_secret: "ppM7JhyVpBtycmMcFGxYdacw",
});

app.use(cors({
  origin:'*',
  Credentials:true
}));
app.use(express.json());
app.use('/images', express.static(path.join(__dirname, 'images')));

// MySQL Connection
let db;
const connectDB = async () => {
  try {
    db = await mysql.createConnection({
      host: 'database-1.cr2ue6u44sny.eu-north-1.rds.amazonaws.com',
      user: 'admin',
      password: 'ramchin123',
      database: 'bookstore',
    });
    console.log('✅ Connected to MySQL (bookstore)');
  } catch (err) {
    console.error('❌ MySQL Connection Error:', err);
  }
};
connectDB();

/* ---------- AUTH ROUTES ---------- */
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ error: "All fields are required" });

  try {
    const [existing] = await db.query("SELECT * FROM users WHERE email = ?", [email]);
    if (existing.length > 0)
      return res.status(409).json({ error: "Email already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.query(
      "INSERT INTO users (username, email, password, raw_password) VALUES (?, ?, ?, ?)",
      [username, email, hashedPassword, password]
    );
    res.status(201).json({ message: "Signup successful" });
  } catch (err) {
    console.error("Signup Error:", err);
    res.status(500).json({ error: "Signup failed" });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await db.query("SELECT * FROM users WHERE email = ?", [email]);
    if (rows.length === 0)
      return res.status(401).json({ error: "Invalid email or password" });

    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(401).json({ error: "Invalid email or password" });

    const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: '1h' });
    res.json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        fullName: user.username,
        email: user.email
      }
    });
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

app.post('/reset-password', async (req, res) => {
  const { email, newPassword } = req.body;
  if (!email || !newPassword)
    return res.status(400).json({ error: "Email and new password are required" });

  try {
    const [rows] = await db.query("SELECT * FROM users WHERE email = ?", [email]);
    if (rows.length === 0)
      return res.status(404).json({ error: "Email not found" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db.query(
      "UPDATE users SET password = ?, raw_password = ? WHERE email = ?",
      [hashedPassword, newPassword, email]
    );
    res.json({ message: "Password reset successful" });
  } catch (err) {
    console.error("Reset Password Error:", err);
    res.status(500).json({ error: "Password reset failed" });
  }
});

/* ---------- BOOK ROUTES ---------- */
app.get('/api/books', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM books');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch books" });
  }
});

app.get('/api/books/genre/:genre', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM books WHERE genre = ?', [req.params.genre]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch books by genre" });
  }
});

app.get('/api/books/:id', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM books WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Book not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

/* ---------- STATIONERY ROUTES ---------- */
app.get('/api/stationery', async (req, res) => {
  const { type } = req.query;
  try {
    const query = type
      ? 'SELECT * FROM stationery WHERE LOWER(type) = ?'
      : 'SELECT * FROM stationery';
    const [rows] = await db.query(query, type ? [type.toLowerCase()] : []);
    res.json(rows);
  } catch (err) {
    res.status(500).send('Internal Server Error');
  }
});

app.get('/api/stationery/type/:type', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM stationery WHERE LOWER(type) = ?',
      [req.params.type.toLowerCase()]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch stationery by type' });
  }
});

app.get('/api/stationery/:id', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM stationery WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Stationery item not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).send('Error fetching stationery');
  }
});

/* ---------- CART & STOCK ROUTES ---------- */
app.get('/cart', async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT c.id, c.quantity, c.product_type,
             CASE WHEN c.product_type = 'book' THEN b.title ELSE s.name END AS name,
             CASE WHEN c.product_type = 'book' THEN b.image ELSE s.image END AS image,
             CASE WHEN c.product_type = 'book' THEN b.price ELSE s.price END AS price
      FROM cart c
      LEFT JOIN books b ON c.product_type = 'book' AND c.product_id = b.id
      LEFT JOIN stationery s ON c.product_type = 'stationery' AND c.product_id = s.id
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching cart items' });
  }
});

app.post('/api/reduce-stock', async (req, res) => {
  const { id, quantity, type } = req.body;
  if (!['books', 'stationery'].includes(type))
    return res.status(400).json({ message: 'Invalid type' });

  try {
    const [rows] = await db.query(`SELECT stock FROM ${type} WHERE id = ?`, [id]);
    if (rows.length === 0)
      return res.status(404).json({ message: 'Item not found' });

    const currentStock = rows[0].stock;
    if (currentStock < quantity)
      return res.status(400).json({ message: 'Not enough stock' });

    await db.query(`UPDATE ${type} SET stock = stock - ? WHERE id = ?`, [quantity, id]);
    res.json({ message: 'Stock updated successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Internal server error' });
  }
});

/* ---------- UPI PAYMENT ---------- */
app.post('/api/generate-upi-link', (req, res) => {
  const { amount, orderId } = req.body;
  console.log("🧾 UPI Request Received:", { amount, orderId });

  if (!amount || !orderId)
    return res.status(400).json({ error: 'Amount and Order ID required' });

  const upiId = '7598162840@axl';
  const upiLink = `upi://pay?pa=${upiId}&pn=WordAura&am=${amount}&tn=${orderId}&cu=INR`;
  console.log("✅ UPI Link Generated:", upiLink);

  res.json({ upiLink, qrData: upiLink });
});


/* ---------- ORDER ROUTES ---------- */
app.post('/api/save-order', async (req, res) => {
  const {
    orderId, transactionId, trackingId,
    fullName, email, phone, address, city, zip,
    paymentMethod, totalAmount, items
  } = req.body;

  const conn = await mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'RYSF@rysf123',
    database: 'bookstore',
  });

  try {
    await conn.beginTransaction();

    // 1. Insert into orders table
    const [orderResult] = await conn.execute(
      `INSERT INTO orders (orderId, transactionId, trackingId, fullName, email, phone, address, city, zip, paymentMethod, totalAmount)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [orderId, transactionId, trackingId, fullName, email, phone, address, city, zip, paymentMethod, totalAmount]
    );

    const orderDbId = orderResult.insertId;

    // 2. Insert each item and update stock
    for (const item of items) {
      const productName = item.title || item.name || "Untitled";
      const itemType = item.title ? 'books' : 'stationery'; // ✅ Corrected logic

      // Insert into order_items
      await conn.execute(
        `INSERT INTO order_items (order_id, product_name, quantity, price)
         VALUES (?, ?, ?, ?)`,
        [orderDbId, productName, item.quantity, item.price]
      );

      // ✅ Reduce stock from books or stationery table
      await conn.execute(
        `UPDATE ${itemType} SET stock = stock - ? WHERE id = ?`,
        [item.quantity, item.id]
      );
    }

    // 3. Save address only if not already present
    const [existing] = await conn.execute(
      `SELECT * FROM saved_addresses 
       WHERE user_email = ? AND fullName = ? AND phone = ? AND address = ? AND city = ? AND zip = ?`,
      [email, fullName, phone, address, city, zip]
    );

    if (existing.length === 0) {
      await conn.execute(
        `INSERT INTO saved_addresses (user_email, fullName, phone, address, city, zip)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [email, fullName, phone, address, city, zip]
      );
    }

    await conn.commit();
    res.status(201).json({ message: "Order placed and stock updated ✅" });

  } catch (err) {
    await conn.rollback();
    console.error("❌ Order save or stock update failed:", err);
    res.status(500).json({ error: "Order placement failed" });
  } finally {
    conn.end();
  }
});
// ✅ Fetch orders by user email
app.get("/api/orders", async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: "Email is required" });

  try {
    const [orders] = await db.query(
      "SELECT * FROM orders WHERE email = ? ORDER BY id DESC",
      [email]
    );
    res.json(orders);
  } catch (err) {
    console.error("Error fetching orders:", err);
    res.status(500).json({ error: "Failed to fetch orders" });
  }
});
app.get("/api/order-details/:orderId", async (req, res) => {
  const { orderId } = req.params;
  try {
    const [rows] = await db.query("SELECT * FROM orders WHERE orderId = ?", [orderId]);
    if (rows.length === 0)
      return res.status(404).json({ error: "Order not found" });
    res.json(rows[0]); 
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch order details" });
  }
});

app.get("/api/saved-addresses/:email", async (req, res) => {
  const { email } = req.params;
  try {
    const [rows] = await db.query(
      'SELECT * FROM saved_addresses WHERE user_email = ?',
      [email]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});
// ✅ Delete User by Email
app.delete('/api/delete-user', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });

  try {
    // 1. Delete user's orders (if needed)
    await db.query('DELETE FROM orders WHERE email = ?', [email]);

    // 2. Delete saved addresses
    await db.query('DELETE FROM saved_addresses WHERE user_email = ?', [email]);

    // 3. Delete user account
    await db.query('DELETE FROM users WHERE email = ?', [email]);

    res.json({ message: 'Account deleted successfully' });
  } catch (err) {
    console.error('❌ Account deletion error:', err);
    res.status(500).json({ error: 'Failed to delete account' });
  }
});
// ✅ Save Address Manually from AddAddress.jsx
app.post("/api/save-address", async (req, res) => {
  const { fullName, phone, address, city, zip, user_email } = req.body;

  console.log("📩 Address Request Body:", req.body);

  if (!user_email || !fullName || !phone || !address || !city || !zip) {
    console.log("❌ Missing fields");
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const [existing] = await db.query(
      `SELECT * FROM saved_addresses 
       WHERE user_email = ? AND fullName = ? AND phone = ? AND address = ? AND city = ? AND zip = ?`,
      [user_email, fullName, phone, address, city, zip]
    );

    if (existing.length === 0) {
      await db.query(
        `INSERT INTO saved_addresses (user_email, fullName, phone, address, city, zip)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [user_email, fullName, phone, address, city, zip]
      );
      res.status(201).json({ message: "Address saved successfully" });
    } else {
      res.status(200).json({ message: "Address already exists" });
    }
  } catch (err) {
    console.error("❌ Save Address Error:", err);
    res.status(500).json({ error: "Failed to save address" });
  }
});
app.post('/api/create-order', async (req, res) => {
  const { amount, currency = 'INR', receipt } = req.body;
  try {
    console.log("💳 Razorpay Order Request:", { amount, receipt });

    const options = { amount: amount * 100, currency, receipt };
    const order = await razorpay.orders.create(options);

    console.log("✅ Razorpay Order Created:", order);
    res.json({ success: true, order });
  } catch (error) {
    console.error("❌ Razorpay Error:", error.message);
    res.status(500).json({ success: false, message: 'Failed to create order' });
  }
});

// 🔥 Route to convert image file to base64 and send to frontend
app.get('/api/image-base64/:filename', (req, res) => {
  const filename = req.params.filename;
  const imagePath = path.join(__dirname, 'images', filename); // images folder inside backend

  try {
    // Check if image file exists
    if (!fs.existsSync(imagePath)) {
      return res.status(404).json({ error: 'Image not found' });
    }

    const ext = path.extname(filename).slice(1); // jpg, png etc
    const base64 = fs.readFileSync(imagePath, { encoding: 'base64' });

    res.json({
      image: `data:image/${ext};base64,${base64}` // send base64 with correct MIME type
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to convert image', details: err.message });
  }
});

/* ---------- START SERVER ---------- */
const PORT = 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});