/**
 * validators.js — Server-side input validation
 * 
 * SECURITY: Never trust client-side validation alone.
 * All input is validated and sanitized on the server.
 */

const validator = require('validator');

// ── Sanitization helpers ─────────────────────────────────────────────────────

/**
 * Strips HTML tags and trims whitespace.
 * Prevents XSS if output ever hits a template.
 */
function sanitizeString(str) {
  if (typeof str !== 'string') return '';
  return validator.escape(str.trim());
}

// ── Field rules ──────────────────────────────────────────────────────────────

const RULES = {
  username: {
    minLength: 3,
    maxLength: 30,
    pattern: /^[a-zA-Z0-9_]+$/,
    patternMsg: 'only letters, numbers, and underscores',
  },
  password: {
    minLength: 8,
    maxLength: 128,
    // Must have: uppercase, lowercase, digit, special char
    pattern: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).+$/,
    patternMsg: 'must include uppercase, lowercase, number, and special character',
  },
  email: {
    maxLength: 254,
  },
};

// ── Validators ───────────────────────────────────────────────────────────────

function validateUsername(raw) {
  const errors = [];
  if (!raw || raw.trim() === '') { errors.push('Username is required'); return errors; }
  const val = raw.trim();
  if (val.length < RULES.username.minLength) errors.push(`At least ${RULES.username.minLength} characters`);
  if (val.length > RULES.username.maxLength) errors.push(`At most ${RULES.username.maxLength} characters`);
  if (!RULES.username.pattern.test(val))     errors.push(`Username: ${RULES.username.patternMsg}`);
  return errors;
}

function validateEmail(raw) {
  const errors = [];
  if (!raw || raw.trim() === '') { errors.push('Email is required'); return errors; }
  const val = raw.trim();
  if (val.length > RULES.email.maxLength)    errors.push('Email too long');
  if (!validator.isEmail(val))               errors.push('Invalid email address');
  return errors;
}

function validatePassword(raw) {
  const errors = [];
  if (!raw) { errors.push('Password is required'); return errors; }
  if (raw.length < RULES.password.minLength) errors.push(`At least ${RULES.password.minLength} characters`);
  if (raw.length > RULES.password.maxLength) errors.push('Password too long');
  if (!RULES.password.pattern.test(raw))     errors.push(`Password ${RULES.password.patternMsg}`);
  return errors;
}

// ── Middleware factories ─────────────────────────────────────────────────────

function validateSignup(req, res, next) {
  const { username, email, password, confirm_password } = req.body;
  const errors = [
    ...validateUsername(username),
    ...validateEmail(email),
    ...validatePassword(password),
  ];
  if (password !== confirm_password) errors.push('Passwords do not match');

  if (errors.length) {
    return res.status(400).json({ ok: false, errors });
  }
  // Attach sanitized values (passwords are NOT sanitized — hashed as-is)
  req.validated = {
    username: username.trim().toLowerCase(),
    email: email.trim().toLowerCase(),
    password,                         // plain — will be hashed in route
  };
  next();
}

function validateLogin(req, res, next) {
  const { email, password } = req.body;
  const errors = [];
  if (!email || email.trim() === '')  errors.push('Email is required');
  if (!password)                      errors.push('Password is required');
  // Deliberately vague — don't confirm which field is wrong
  if (errors.length) return res.status(400).json({ ok: false, errors });

  req.validated = { email: email.trim().toLowerCase(), password };
  next();
}

module.exports = { validateSignup, validateLogin, sanitizeString, validatePassword };
