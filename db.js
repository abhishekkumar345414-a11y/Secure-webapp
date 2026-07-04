/**
 * db.js — Lightweight in-memory "database" with parameterized query pattern
 * 
 * In a real app this would be SQLite/PostgreSQL with prepared statements.
 * We simulate the same parameterized pattern here so the security concept
 * is identical: user input NEVER touches the query string.
 */

const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

// In-memory user store  { id, username, email, passwordHash, createdAt, loginAttempts, lockedUntil }
const users = new Map();

// In-memory session store (express-session uses its own, this tracks login attempts)
const loginAttempts = new Map(); // email -> { count, firstAttempt }

const SALT_ROUNDS = 12;
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS   = 15 * 60 * 1000; // 15 minutes

// ── Parameterized-style helpers ──────────────────────────────────────────────
// These mirror what a real DB driver does: the query template is fixed,
// only bound parameters change — so no injection is possible.

function findUserByEmail(email) {
  // SELECT * FROM users WHERE email = $1
  for (const u of users.values()) {
    if (u.email === email.toLowerCase()) return u;
  }
  return null;
}

function findUserByUsername(username) {
  // SELECT * FROM users WHERE username = $1
  for (const u of users.values()) {
    if (u.username === username.toLowerCase()) return u;
  }
  return null;
}

function findUserById(id) {
  // SELECT * FROM users WHERE id = $1
  return users.get(id) || null;
}

async function createUser(username, email, plainPassword) {
  // INSERT INTO users (id, username, email, password_hash, created_at)
  // VALUES ($1, $2, $3, $4, $5)
  const passwordHash = await bcrypt.hash(plainPassword, SALT_ROUNDS);
  const user = {
    id: uuidv4(),
    username: username.toLowerCase(),
    email: email.toLowerCase(),
    passwordHash,
    createdAt: new Date().toISOString(),
    loginAttempts: 0,
    lockedUntil: null,
  };
  users.set(user.id, user);
  return { id: user.id, username: user.username, email: user.email };
}

async function verifyPassword(user, plainPassword) {
  return bcrypt.compare(plainPassword, user.passwordHash);
}

// ── Brute-force / account lockout ───────────────────────────────────────────

function isAccountLocked(email) {
  const rec = loginAttempts.get(email.toLowerCase());
  if (!rec) return false;
  if (rec.count < MAX_ATTEMPTS) return false;
  if (Date.now() < rec.lockedUntil) return true;
  // Lock expired — reset
  loginAttempts.delete(email.toLowerCase());
  return false;
}

function recordFailedAttempt(email) {
  const key = email.toLowerCase();
  const rec = loginAttempts.get(key) || { count: 0, firstAttempt: Date.now() };
  rec.count += 1;
  rec.lockedUntil = Date.now() + LOCKOUT_MS;
  loginAttempts.set(key, rec);
  return MAX_ATTEMPTS - rec.count; // remaining attempts
}

function resetAttempts(email) {
  loginAttempts.delete(email.toLowerCase());
}

function remainingLockoutSeconds(email) {
  const rec = loginAttempts.get(email.toLowerCase());
  if (!rec || !rec.lockedUntil) return 0;
  return Math.ceil((rec.lockedUntil - Date.now()) / 1000);
}

module.exports = {
  findUserByEmail,
  findUserByUsername,
  findUserById,
  createUser,
  verifyPassword,
  isAccountLocked,
  recordFailedAttempt,
  resetAttempts,
  remainingLockoutSeconds,
  MAX_ATTEMPTS,
};
