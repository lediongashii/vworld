const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const router = express.Router();

const users = []; // { email, username, password }

// Middleware për të mbrojtur rruget
const verifyToken = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) return res.redirect('/login');

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.clearCookie('token');
    return res.redirect('/login');
  }
};

// ===== ROUTES =====

// sistemet
router.get('/', (req, res) => res.render('home'));

// Register
router.get('/register', (req, res) => res.render('register'));
router.post('/register', async (req, res) => {
  const { email, username, password } = req.body;

  const userExists = users.find(u => u.username === username);
  if (userExists) return res.send('Username already taken');

  const hashed = await bcrypt.hash(password, 10);
  users.push({ email, username, password: hashed });

  res.redirect('/login');
});

// Login
router.get('/login', (req, res) => res.render('login'));
router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const user = users.find(u => u.username === username);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.send('Invalid credentials');
  }

  const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET, {
    expiresIn: '1h',
  });

  res.cookie('token', token, {
    httpOnly: true,
    secure: false, // vendose true në produksion me HTTPS
  });

  res.redirect('/sistemet');
});

// Logout
router.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/');
});

// Protected Routes
router.get('/sistemet', verifyToken, (req, res) => res.render('sistemet'));
router.get('/doctor', verifyToken, (req, res) => res.render('doctor'));
router.get('/teacher', verifyToken, (req, res) => res.render('teacher'));
router.get('/programmer', verifyToken, (req, res) => res.render('programmer'));

module.exports = router;
