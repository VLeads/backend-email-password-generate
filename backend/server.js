import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import User from './models/User.js';

const app = express();
const port = 5000;

app.use(express.json());

mongoose.connect('mongodb://localhost/your_db_name', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('MongoDB connected'));

// Static admin credentials
const adminCredentials = {
  username: 'admin',
  password: 'adminpassword',
};

// Email sender setup
const sendEmail = async (email, username, password) => {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'your-email@gmail.com',
      pass: 'your-email-password',
    },
  });

  const mailOptions = {
    from: 'your-email@gmail.com',
    to: email,
    subject: 'Login Credentials',
    text: `Your username: ${username}\nYour password: ${password}`,
  };

  await transporter.sendMail(mailOptions);
};

// Register route
app.post('/register', async (req, res) => {
  const { username, email } = req.body;

  // Check if user already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) return res.status(400).json({ message: 'User already exists' });

  // Generate random password and hash it
  const password = Math.random().toString(36).slice(-8);
  const hashedPassword = await bcrypt.hash(password, 10);

  const user = new User({ username, email, password: hashedPassword });
  await user.save();

  // Send email with login credentials
  await sendEmail(email, username, password);

  res.status(201).json({ message: 'User registered. Check your email for credentials' });
});

// Login route for users
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Find the user by username
  const user = await User.findOne({ username });
  if (!user) return res.status(400).json({ message: 'User not found' });

  // Check if password is correct
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

  // Generate JWT
  const token = jwt.sign({ id: user._id, role: user.role }, 'secretKey', { expiresIn: '1h' });

  res.json({ token, role: user.role });
});

// Admin login route
app.post('/admin-login', async (req, res) => {
  const { username, password } = req.body;

  // Verify static credentials
  if (username === adminCredentials.username && password === adminCredentials.password) {
    const token = jwt.sign({ role: 'admin' }, 'secretKey', { expiresIn: '1h' });
    return res.json({ token, role: 'admin' });
  }

  res.status(400).json({ message: 'Invalid admin credentials' });
});

// Middleware for token verification
const verifyToken = (req, res, next) => {
  const token = req.header('Authorization').replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'Access denied' });

  try {
    const verified = jwt.verify(token, 'secretKey');
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).json({ message: 'Invalid token' });
  }
};

// Middleware for admin-only routes
const adminOnly = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin access only' });
  }
  next();
};

app.listen(port, () => console.log(`Server running on port ${port}`));
