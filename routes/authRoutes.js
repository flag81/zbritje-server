import express from 'express';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import db from '../connection.js';
import {
  appleSignIn,
  appleCallback,
  googleCallback,
  handleInitialize,
  checkSession,
  dashboardLogin,
  initializeAnonymous,
} from '../controllers/authController.js';
import logger from '../services/logger.js';

const router = express.Router();

router.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', process.env.FRONTEND_URL);
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});

const verificationCodes = {};

router.post('/send-verification-code', async (req, res) => {
  try {
    if (!req.body || !req.body.email) {
      return res.status(400).json({ success: false, message: 'Email is required' });
    }
    const { email } = req.body;
    const code = Math.floor(100000 + Math.random() * 900000);
    verificationCodes[email] = code;

    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
      return res.status(500).json({ success: false, message: 'Email service is not configured properly' });
    }

    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 587,
      secure: false,
      requireTLS: true,
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
      tls: { rejectUnauthorized: false },
      debug: true,
      logger: true,
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Kodi i Verifikimit nga Meniven.com',
      text: `Kodi i Verifikimit eshte: ${code}`,
    };

    await new Promise((resolve, reject) => {
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) return reject(error);
        resolve(info);
      });
    });

    return res.json({ success: true, message: 'Verification code sent successfully.' });
  } catch (err) {
    logger.error('Error sending verification code:', err);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
});

router.post('/verify-code', (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) {
    return res.status(400).json({ success: false, message: 'Email and code are required' });
  }

  if (!verificationCodes[email]?.toString() || verificationCodes[email]?.toString() !== code) {
    return res.status(400).json({ success: false, message: 'Invalid code' });
  }

  delete verificationCodes[email];

  const checkUserQuery = `SELECT userId FROM users WHERE email = ?`;
  db.query(checkUserQuery, [email], (err, results) => {
    if (err) return res.status(500).json({ success: false, message: 'Database error' });
    let userId;
    if (results.length > 0) {
      userId = results[0].userId;
      const token = jwt.sign({ userId, email }, process.env.TOKEN_SECRET, { expiresIn: '7d' });
      res.cookie('jwt', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });
      return res.json({ success: true, userId });
    } else {
      const insertQuery = `INSERT INTO users (email, userName) VALUES (?, ?)`;
      db.query(insertQuery, [email, email], (insertErr, result) => {
        if (insertErr) return res.status(500).json({ success: false, message: 'Database error' });
        userId = result.insertId;
        const token = jwt.sign({ userId, email }, process.env.TOKEN_SECRET, { expiresIn: '7d' });
        res.cookie('jwt', token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          maxAge: 7 * 24 * 60 * 60 * 1000,
        });
        return res.json({ success: true, userId });
      });
    }
  });
});

router.get('/check-session', (req, res) => {
  const token = req.cookies.jwt;
  if (!token) return res.json({ userId: null, loggedIn: false });
  try {
    const decoded = jwt.verify(token, process.env.TOKEN_SECRET);
    const userId = decoded.userId;
    const query = `SELECT userId, email, googleId FROM users WHERE userId = ?`;
    db.query(query, [userId], (err, results) => {
      if (err) return res.status(500).json({ userId: null, loggedIn: false });
      if (results.length === 0) {
        res.clearCookie('jwt');
        return res.json({ userId: null, loggedIn: false });
      }
      res.json({
        userId: results[0].userId,
        email: results[0].email,
        loginMethod: results[0].googleId ? 'Google' : 'Email',
        loggedIn: true,
      });
    });
  } catch (error) {
    res.clearCookie('jwt');
    return res.json({ userId: null, loggedIn: false });
  }
});

router.get('/check-session2', (req, res) => {
  const token = req.cookies.jwt;
  if (!token) return res.json({ userId: null, loggedIn: false });
  try {
    const decoded = jwt.verify(token, process.env.TOKEN_SECRET);
    const userId = decoded.userId;
    const query = `SELECT userId, email, googleId FROM users WHERE userId = ?`;
    db.query(query, [userId], (err, results) => {
      if (err) return res.status(500).json({ userId: null, loggedIn: false });
      if (results.length === 0) {
        res.clearCookie('jwt');
        return res.json({ userId: null, loggedIn: false });
      }
      res.json({
        userId: results[0].userId,
        email: results[0].email,
        loginMethod: results[0].googleId ? 'Google' : 'Email',
        loggedIn: true,
      });
    });
  } catch (error) {
    res.clearCookie('jwt');
    return res.json({ userId: null, loggedIn: false });
  }
});

router.get('/logout', (req, res) => {
  res.clearCookie('jwt', { httpOnly: true, sameSite: 'Lax' });
  res.json({ success: true, message: 'Logged out and session cleared.' });
});

router.post('/apple', appleSignIn);
router.post('/apple/callback', appleCallback);

export default router;
