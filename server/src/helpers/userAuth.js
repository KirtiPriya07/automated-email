const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('./db');
require('dotenv').config();

const router = express.Router();

const generateAccessToken = (user) => {
  return jwt.sign(user, process.env.JWT_SECRET, { expiresIn: '1800s' });
};

router.use(express.json());

router.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).send('Username and password are required.');
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  db.query(
    'INSERT INTO users (username, password) VALUES (?, ?)',
    [username, hashedPassword],
    (err) => {
      if (err) {
        return res.status(500).send('Error registering user.');
      }
      res.status(201).send('User registered successfully.');
    }
  );
});

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  db.query(
    'SELECT * FROM users WHERE username = ?',
    [username],
    async (err, results) => {
      if (err) {
        return res.status(500).send('Error during login.');
      }
      if (results.length === 0 || !(await bcrypt.compare(password, results[0].password))) {
        return res.status(401).send('Invalid username or password.');
      }

      const token = generateAccessToken({ username: results[0].username });
      res.json({ token });
    }
  );
});

const authenticateJWT = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) {
    return res.status(403).send('A token is required for authentication');
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(401).send('Invalid Token');
    }
    req.user = user;
    next();
  });
};

module.exports = { router, authenticateJWT };
