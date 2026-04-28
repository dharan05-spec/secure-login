const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const db = require('../db/database');
const { requireAuth, requireGuest } = require('../middleware/auth');

const SALT_ROUNDS = 12;

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many login attempts. Please try again in 15 minutes.',
});

// ── REGISTER ──
router.get('/register', requireGuest, (req, res) => {
  const flash = req.session.flash;
  delete req.session.flash;
  res.render('register', { flash, errors: [] });
});

router.post('/register', requireGuest, [
  body('username').trim().isLength({ min: 3, max: 30 }).withMessage('Username must be 3–30 characters')
    .matches(/^[a-zA-Z0-9_]+$/).withMessage('Letters, numbers, and underscores only'),
  body('email').trim().isEmail().withMessage('Enter a valid email').normalizeEmail(),
  body('password').isLength({ min: 8 }).withMessage('Min 8 characters')
    .matches(/[A-Z]/).withMessage('Must include an uppercase letter')
    .matches(/[0-9]/).withMessage('Must include a number'),
  body('confirmPassword').custom((val, { req }) => {
    if (val !== req.body.password) throw new Error('Passwords do not match');
    return true;
  }),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.render('register', { flash: null, errors: errors.array() });

  const { username, email, password } = req.body;
  try {
    if (db.findUserByEmail(email)) {
      return res.render('register', { flash: null, errors: [{ msg: 'Email already in use.' }] });
    }
    if (db.findUserByUsername(username)) {
      return res.render('register', { flash: null, errors: [{ msg: 'Username already taken.' }] });
    }
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    db.createUser(username, email, passwordHash);
    req.session.flash = { type: 'success', message: 'Account created! Please log in.' };
    res.redirect('/login');
  } catch (err) {
    console.error(err);
    res.render('register', { flash: null, errors: [{ msg: 'Something went wrong.' }] });
  }
});

// ── LOGIN ──
router.get('/login', requireGuest, (req, res) => {
  const flash = req.session.flash;
  delete req.session.flash;
  res.render('login', { flash, errors: [] });
});

router.post('/login', requireGuest, loginLimiter, [
  body('email').trim().isEmail().withMessage('Enter a valid email').normalizeEmail(),
  body('password').notEmpty().withMessage('Password is required'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.render('login', { flash: null, errors: errors.array() });

  const { email, password } = req.body;
  try {
    const user = db.findUserByEmail(email);
    if (!user) {
      return res.render('login', { flash: null, errors: [{ msg: 'Invalid email or password.' }] });
    }
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.render('login', { flash: null, errors: [{ msg: 'Invalid email or password.' }] });
    }
    if (user.two_fa_enabled) {
      req.session.pending2FA = user.id;
      return res.redirect('/2fa/verify');
    }
    req.session.regenerate((err) => {
      if (err) throw err;
      req.session.userId = user.id;
      req.session.username = user.username;
      db.updateLastLogin(user.id);
      res.redirect('/dashboard');
    });
  } catch (err) {
    console.error(err);
    res.render('login', { flash: null, errors: [{ msg: 'Something went wrong.' }] });
  }
});

// ── LOGOUT ──
router.post('/logout', requireAuth, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

// ── DASHBOARD ──
router.get('/dashboard', requireAuth, (req, res) => {
  const user = db.findUserById(req.session.userId);
  const flash = req.session.flash;
  delete req.session.flash;
  res.render('dashboard', { user, flash });
});

// ── 2FA SETUP ──
router.get('/2fa/setup', requireAuth, async (req, res) => {
  const user = db.findUserById(req.session.userId);
  if (user.two_fa_enabled) {
    req.session.flash = { type: 'info', message: '2FA is already enabled.' };
    return res.redirect('/dashboard');
  }
  const secret = speakeasy.generateSecret({ name: `SecureApp (${user.email})` });
  req.session.temp2FASecret = secret.base32;
  const qrDataURL = await QRCode.toDataURL(secret.otpauth_url);
  res.render('2fa-setup', { qrDataURL, secret: secret.base32, errors: [] });
});

router.post('/2fa/setup', requireAuth, (req, res) => {
  const { token } = req.body;
  const secret = req.session.temp2FASecret;
  if (!secret) return res.redirect('/2fa/setup');

  const verified = speakeasy.totp.verify({ secret, encoding: 'base32', token, window: 1 });
  if (!verified) {
    return res.render('2fa-setup', { qrDataURL: null, secret, errors: [{ msg: 'Invalid code. Try again.' }] });
  }
  db.save2FASecret(req.session.userId, secret);
  delete req.session.temp2FASecret;
  req.session.flash = { type: 'success', message: '2FA enabled successfully!' };
  res.redirect('/dashboard');
});

// ── 2FA VERIFY (on login) ──
router.get('/2fa/verify', (req, res) => {
  if (!req.session.pending2FA) return res.redirect('/login');
  res.render('2fa-verify', { errors: [] });
});

router.post('/2fa/verify', (req, res) => {
  const userId = req.session.pending2FA;
  if (!userId) return res.redirect('/login');

  const { token } = req.body;
  const user = db.findUserById(userId);
  const verified = speakeasy.totp.verify({
    secret: user.two_fa_secret, encoding: 'base32', token, window: 1,
  });

  if (!verified) {
    return res.render('2fa-verify', { errors: [{ msg: 'Invalid code. Try again.' }] });
  }
  req.session.regenerate((err) => {
    if (err) throw err;
    req.session.userId = user.id;
    req.session.username = user.username;
    db.updateLastLogin(user.id);
    res.redirect('/dashboard');
  });
});

// ── 2FA DISABLE ──
router.post('/2fa/disable', requireAuth, (req, res) => {
  db.disable2FA(req.session.userId);
  req.session.flash = { type: 'success', message: '2FA has been disabled.' };
  res.redirect('/dashboard');
});

module.exports = router;
