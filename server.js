// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 5000;

// ---------- Mail Transporter ----------
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// ---------- Middleware ----------
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname)); // serve static files

// ---------- MongoDB connection ----------
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// ---------- Models ----------
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String
});
const User = mongoose.model('User', userSchema);

const productSchema = new mongoose.Schema({
  id: Number,
  name: String,
  desc: String,
  price: Number,
  category: String,
  material: String,
  img: String
});
const Product = mongoose.model('Product', productSchema);

const orderSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  items: Array,
  total: Number,
  shipping: Object,
  paymentMethod: String,
  createdAt: { type: Date, default: Date.now }
});
const Order = mongoose.model('Order', orderSchema);

// ---------- Auth Middleware ----------
function authMiddleware(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ success: false, message: 'No token provided' });

  const token = auth.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Invalid token' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ success: false, message: 'Unauthorized' });
    req.userId = decoded.id;
    next();
  });
}

// ---------- Routes ----------
app.get('/health', (req, res) => {
  res.json({ success: true, message: 'Server is running' });
});

app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find();
    return res.json({ success: true, products: products || [] });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Error fetching products' });
  }
});

app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ success: false, message: 'All fields required' });
  }

  try {
    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }

    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashed });
    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Signup failed' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ success: false, message: 'All fields required' });

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ success: false, message: 'User not found' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ success: false, message: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Login failed' });
  }
});

app.post('/api/orders', authMiddleware, async (req, res) => {
  const { items, total, shipping, paymentMethod } = req.body;
  if (!items || !total || !shipping) {
    return res.status(400).json({ success: false, message: 'Missing order details' });
  }

  try {
    const order = new Order({
      user: req.userId,
      items,
      total,
      shipping,
      paymentMethod
    });
    await order.save();

    // Send Confirmation Email
    if (shipping.email) {
      try {
        const mailOptions = {
          from: process.env.EMAIL_FROM,
          to: shipping.email,
          subject: `Order Confirmation - Pearl Jewels`,
          html: `
            <div style="font-family:Arial,sans-serif;color:#333;">
              <h2>Thank you for your order, ${shipping.name}!</h2>
              <p>Your order <strong>#${order._id}</strong> has been received.</p>
              <h3>Order Summary:</h3>
              <ul>
                ${items.map(i => `<li>${i.name} - ₹${i.price} × ${i.qty}</li>`).join('')}
              </ul>
              <p><strong>Total:</strong> ₹${total.toLocaleString()}</p>
              <p><strong>Payment Method:</strong> ${paymentMethod}</p>
              <p>We’ll deliver your order soon to:</p>
              <p>${shipping.address}, ${shipping.city}, ${shipping.state} - ${shipping.pincode}</p>
              <br>
              <p style="color:#888;">– Pearl Jewels Team</p>
            </div>
          `
        };

        await transporter.sendMail(mailOptions);
        console.log(`📧 Confirmation email sent to ${shipping.email}`);
      } catch (mailErr) {
        console.error("❌ Failed to send confirmation email:", mailErr);
      }
    }

    res.json({ success: true, message: 'Order placed successfully', orderId: order._id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Order failed' });
  }
});

// ---------- Serve frontend ----------
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ---------- Start server ----------
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
