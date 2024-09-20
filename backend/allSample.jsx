


//express server
const express = require('express');
const mongoose = require('mongoose');
const app = express();
const port = 5000;

app.use(express.json());

mongoose.connect('mongodb://localhost/your_db_name', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('MongoDB connected'));

app.listen(port, () => console.log(`Server running on port ${port}`));




// user and admin schema
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'user'], default: 'user' },
});

module.exports = mongoose.model('User', userSchema);



// nodemailer for email verification
const nodemailer = require('nodemailer');

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



// routes for register and login
const bcrypt = require('bcryptjs');
const User = require('./models/User');

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



//login route
const jwt = require('jsonwebtoken');
const User = require('./models/User');
const bcrypt = require('bcryptjs');

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


// admin static login
const adminCredentials = {
    username: 'admin',
    password: 'adminpassword',
  };
  
  app.post('/admin-login', async (req, res) => {
    const { username, password } = req.body;
  
    // Verify static credentials
    if (username === adminCredentials.username && password === adminCredentials.password) {
      const token = jwt.sign({ role: 'admin' }, 'secretKey', { expiresIn: '1h' });
      return res.json({ token, role: 'admin' });
    }
  
    res.status(400).json({ message: 'Invalid admin credentials' });
  });

  

//   middleware to protect route
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
  
  const adminOnly = (req, res, next) => {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Admin access only' });
    }
    next();
  };

  





  //frontend-----------------------

//   login form
import { useState } from 'react';
import axios from 'axios';

const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('');

  const handleLogin = async () => {
    try {
      const response = await axios.post('/login', { username, password });
      setRole(response.data.role);
      localStorage.setItem('token', response.data.token);
    } catch (err) {
      console.error(err.response.data.message);
    }
  };

  return (
    <div>
      <input type="text" placeholder="Username" onChange={(e) => setUsername(e.target.value)} />
      <input type="password" placeholder="Password" onChange={(e) => setPassword(e.target.value)} />
      <button onClick={handleLogin}>Login</button>
      <p>{role ? `You are logged in as: ${role}` : ''}</p>
    </div>
  );
};

export default Login;



// protected route based on role
import { useEffect, useState } from 'react';
import jwtDecode from 'jwt-decode';

const Dashboard = () => {
  const [role, setRole] = useState('');

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      const decoded = jwtDecode(token);
      setRole(decoded.role);
    }
  }, []);

  if (role === 'admin') {
    return <div>Welcome Admin</div>;
  } else if (role === 'user') {
    return <div>Welcome User</div>;
  } else {
    return <div>Access Denied</div>;
  }
};

export default Dashboard;
