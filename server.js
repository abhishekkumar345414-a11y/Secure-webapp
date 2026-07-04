'use strict';
/**
 * server.js — Secure Web Application
 * 
 * Security layers implemented:
 *  1. Helmet.js        — sets 14 security-related HTTP headers
 *  2. CSRF protection  — csurf token on every state-changing request
 *  3. Rate limiting    — caps requests per IP to throttle brute force
 *  4. Session security — httpOnly, sameSite, secure flags; session regeneration
 *  5. Input validation — server-side with whitelist regex + length limits
 *  6. XSS prevention  — output escaping + CSP header via Helmet
 *  7. SQL injection    — parameterized query pattern (no string interpolation)
 *  8. Account lockout  — 5 failed logins → 15-minute lockout
 *  9. Password hashing — bcrypt, cost factor 12
 * 10. No info leakage  — generic error messages, no stack traces in prod
 */

const express  = require('express');
const session  = require('express-session');
const helmet   = require('helmet');
const csrf     = require('csurf');
const rateLimit = require('express-rate-limit');
const path     = require('path');
const crypto   = require('crypto');

const db         = require('./db');
const { validateSignup, validateLogin } = require('./validators');

const app  = express();
const PORT = 3000;
const isProd = process.env.NODE_ENV === 'production';

// ── 1. Helmet — HTTP security headers ────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'"],       // no inline scripts
      styleSrc:   ["'self'", "'unsafe-inline'"],  // allow inline style for demo
      imgSrc:     ["'self'", 'data:'],
      connectSrc: ["'self'"],
      fontSrc:    ["'self'"],
      objectSrc:  ["'none'"],
      frameAncestors: ["'none'"],   // clickjacking protection (also X-Frame-Options)
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// ── 2. Body parsing (limited payload size) ───────────────────────────────────
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// ── 3. Rate limiting ─────────────────────────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, errors: ['Too many requests — please try again later.'] },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,                    // only 20 auth attempts per 15 min per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, errors: ['Too many login attempts from this IP. Try again in 15 minutes.'] },
});

app.use(globalLimiter);

// ── 4. Session configuration ─────────────────────────────────────────────────
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex');

// The __Host- cookie name prefix is a browser-enforced contract: a cookie
// named __Host-* is REJECTED by the browser unless it also carries the
// Secure flag (HTTPS-only) and Path=/. Using the prefix while running
// plain HTTP locally (secure: isProd === false here) silently breaks
// sessions — the browser discards the cookie before it's ever stored,
// so no CSRF token, login state, or anything session-based can work.
// The prefix is only meaningful in production behind HTTPS, so the name
// itself is conditional on the same flag that controls the Secure attribute.
const SESSION_COOKIE_NAME = isProd ? '__Host-sid' : 'sid';

app.use(session({
  secret: SESSION_SECRET,
  name: SESSION_COOKIE_NAME,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,            // JS cannot read the cookie
    secure: isProd,            // HTTPS only in production — required for __Host- prefix to be honored
    sameSite: 'strict',        // CSRF mitigation at cookie level
    maxAge: 30 * 60 * 1000,   // 30-minute idle timeout
  },
}));

// ── 5. CSRF protection ───────────────────────────────────────────────────────
const csrfProtection = csrf();
app.use(csrfProtection);

// Attach CSRF token to every response so templates/XHR can include it
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  next();
});

// ── 6. Static files ──────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public'), {
  index: false,     // disable automatic index.html serving
  dotfiles: 'deny', // block .htaccess / .env etc
}));

// ── Helper: require authentication ───────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ ok: false, errors: ['Not authenticated'] });
  }
  next();
}

// ── Routes ───────────────────────────────────────────────────────────────────

// Serve SPA shell for all page routes
app.get(['/', '/login', '/signup', '/dashboard'], (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── GET /api/csrf — fetch a fresh token (called on page load) ────────────────
app.get('/api/csrf', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// ── GET /api/me — session status ─────────────────────────────────────────────
app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.json({ loggedIn: false });
  const user = db.findUserById(req.session.userId);
  if (!user) {
    req.session.destroy(() => {});
    return res.json({ loggedIn: false });
  }
  res.json({ loggedIn: true, username: user.username, email: user.email });
});

// ── POST /api/signup ──────────────────────────────────────────────────────────
app.post('/api/signup', authLimiter, validateSignup, async (req, res) => {
  try {
    const { username, email, password } = req.validated;

    // Check uniqueness — parameterized lookup (no raw interpolation)
    if (db.findUserByEmail(email)) {
      return res.status(409).json({ ok: false, errors: ['Email already registered'] });
    }
    if (db.findUserByUsername(username)) {
      return res.status(409).json({ ok: false, errors: ['Username already taken'] });
    }

    const user = await db.createUser(username, email, password);

    // Regenerate session after privilege change (session fixation prevention)
    req.session.regenerate((err) => {
      if (err) throw err;
      req.session.userId    = user.id;
      req.session.username  = user.username;
      req.session.createdAt = Date.now();
      res.status(201).json({ ok: true, username: user.username });
    });
  } catch (err) {
    console.error('[signup]', err.message);
    // Never leak internal errors to the client
    res.status(500).json({ ok: false, errors: ['Server error — please try again'] });
  }
});

// ── POST /api/login ───────────────────────────────────────────────────────────
app.post('/api/login', authLimiter, validateLogin, async (req, res) => {
  try {
    const { email, password } = req.validated;

    // Account lockout check
    if (db.isAccountLocked(email)) {
      const secs = db.remainingLockoutSeconds(email);
      const mins = Math.ceil(secs / 60);
      return res.status(429).json({
        ok: false,
        errors: [`Account temporarily locked. Try again in ${mins} minute${mins !== 1 ? 's' : ''}.`],
      });
    }

    const user = db.findUserByEmail(email);
    // Constant-time comparison path: always call verifyPassword
    // even when user doesn't exist, to prevent timing attacks
    const dummyHash = '$2a$12$invalidhashpaddingtomakeittimeconst....';
    const passwordOk = user
      ? await db.verifyPassword(user, password)
      : await require('bcryptjs').compare(password, dummyHash);

    if (!user || !passwordOk) {
      const remaining = db.recordFailedAttempt(email);
      const msg = remaining > 0
        ? `Invalid credentials. ${remaining} attempt${remaining !== 1 ? 's' : ''} remaining.`
        : 'Account locked for 15 minutes due to too many failed attempts.';
      // Deliberate delay to slow down automation
      await new Promise(r => setTimeout(r, 500 + Math.random() * 500));
      return res.status(401).json({ ok: false, errors: [msg] });
    }

    // Successful login
    db.resetAttempts(email);

    // Session fixation prevention — regenerate session ID on login
    req.session.regenerate((err) => {
      if (err) throw err;
      req.session.userId    = user.id;
      req.session.username  = user.username;
      req.session.createdAt = Date.now();
      res.json({ ok: true, username: user.username });
    });
  } catch (err) {
    console.error('[login]', err.message);
    res.status(500).json({ ok: false, errors: ['Server error — please try again'] });
  }
});

// ── POST /api/logout ──────────────────────────────────────────────────────────
app.post('/api/logout', requireAuth, (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ ok: false });
    res.clearCookie(SESSION_COOKIE_NAME);
    res.json({ ok: true });
  });
});

// ── CSRF error handler ───────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ ok: false, errors: ['Invalid or expired CSRF token. Refresh and try again.'] });
  }
  next(err);
});

// ── Generic error handler (no stack traces to client) ────────────────────────
app.use((err, req, res, _next) => {
  console.error('[error]', err.message);
  res.status(500).json({ ok: false, errors: ['An unexpected error occurred'] });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🔒 Secure Web App running → http://localhost:${PORT}`);
  console.log('   Security layers: Helmet · CSRF · Rate-limit · Session · bcrypt · Lockout\n');
});

module.exports = app;
