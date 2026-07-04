'use strict';

// ── State ─────────────────────────────────────────────────────────────
let csrfToken = '';

// ── Event wiring ─────────────────────────────────────────────────────
// Helmet's CSP sets `script-src-attr 'none'` by default whenever
// contentSecurityPolicy is configured at all — this blocks inline
// onclick="..."/oninput="..." attributes the same way `script-src`
// blocks inline <script> tags, since both are equally valid ways to
// smuggle attacker-controlled JS into a page (XSS via injected HTML
// attributes is just as real as XSS via injected <script> tags).
// Every interactive element in index.html therefore has a stable id
// and no inline handler; this function is the single place that wires
// id -> behavior, called once after the DOM is ready.
function bindEvents() {
  const on = (id, evt, fn) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener(evt, fn);
    else console.warn(`[bindEvents] #${id} not found in DOM`);
  };

  // Navbar
  on('navBrand',  'click', (e) => { e.preventDefault(); navigate('home'); });
  on('navLogin',  'click', () => navigate('login'));
  on('navSignup', 'click', () => navigate('signup'));

  // Signup page
  on('su-username', 'input', (e) => liveValidateUsername(e.target));
  on('su-email',     'input', (e) => liveValidateEmail(e.target));
  on('su-password',  'input', (e) => liveValidatePassword(e.target));
  on('su-confirm',   'input', (e) => liveValidateConfirm(e.target));
  on('toggle-su-password', 'click', (e) => togglePw('su-password', e.currentTarget));
  on('toggle-su-confirm',  'click', (e) => togglePw('su-confirm', e.currentTarget));
  on('signup-btn', 'click', doSignup);
  on('goto-login-from-signup', 'click', (e) => { e.preventDefault(); navigate('login'); });

  // Login page
  on('li-password', 'keydown', (e) => { if (e.key === 'Enter') doLogin(); });
  on('toggle-li-password', 'click', (e) => togglePw('li-password', e.currentTarget));
  on('login-btn', 'click', doLogin);
  on('goto-signup-from-login', 'click', (e) => { e.preventDefault(); navigate('signup'); });

  // Dashboard
  on('logout-btn', 'click', doLogout);
}

// ── Startup ───────────────────────────────────────────────────────────
// Wrapped in try/catch: if the backend isn't reachable (e.g. this file is
// being previewed standalone without `node server.js` running), we still
// want every function below to load and the login/signup UI to be usable
// once the real server is up — a network failure here must never stop
// the rest of this script from executing.
document.addEventListener('DOMContentLoaded', () => {
  bindEvents();

  (async () => {
    try {
      await fetchCsrf();
      const me = await apiFetch('/api/me');
      if (me.loggedIn) {
        showDashboard(me.username, me.email);
        return;
      }
    } catch (err) {
      console.warn('[startup] Could not reach /api — is the server running? (node server.js)', err.message);
    }
    navigate('login');
  })();
});

// ── Navigation ────────────────────────────────────────────────────────
function navigate(page) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  const el = document.getElementById(`page-${page}`);
  if (el) el.classList.add('active');

  // Update navbar
  const navLogin  = document.getElementById('navLogin');
  const navSignup = document.getElementById('navSignup');
  if (page === 'dashboard') {
    navLogin.textContent  = '';
    navSignup.textContent = '';
    navLogin.style.display  = 'none';
    navSignup.style.display = 'none';
  } else {
    navLogin.style.display  = '';
    navSignup.style.display = '';
  }
}

function showDashboard(username, email) {
  document.getElementById('dash-username').textContent = username;
  document.getElementById('si-user').textContent  = username;
  document.getElementById('si-email').textContent = email;
  // Show partial CSRF token for demo
  document.getElementById('si-csrf').textContent =
    csrfToken ? csrfToken.substring(0, 16) + '…' : 'unavailable';
  navigate('dashboard');
}

// ── CSRF fetch ────────────────────────────────────────────────────────
async function fetchCsrf() {
  try {
    const data = await apiFetch('/api/csrf');
    csrfToken = data.csrfToken || '';
  } catch {}
}

// ── Generic fetch wrapper ─────────────────────────────────────────────
async function apiFetch(url, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  if (opts.method && opts.method !== 'GET') {
    headers['CSRF-Token'] = csrfToken;   // attach CSRF header on mutations
  }
  try {
    const res = await fetch(url, { ...opts, headers, credentials: 'same-origin' });
    return await res.json();
  } catch (err) {
    // Network failure (server not running, CORS, offline, etc.) — return a
    // shape callers already know how to handle instead of throwing and
    // breaking the calling function's control flow.
    console.warn(`[apiFetch] ${url} failed:`, err.message);
    return { ok: false, loggedIn: false, errors: ['Could not reach the server. Is it running?'] };
  }
}

// ── Signup ────────────────────────────────────────────────────────────
async function doSignup() {
  clearAlerts('signup');
  const username = document.getElementById('su-username').value;
  const email    = document.getElementById('su-email').value;
  const password = document.getElementById('su-password').value;
  const confirm  = document.getElementById('su-confirm').value;

  // Basic client-side check (server re-validates everything)
  if (!username || !email || !password || !confirm) {
    showAlert('signup-alert', 'Please fill in all fields.');
    return;
  }
  if (password !== confirm) {
    showAlert('signup-alert', 'Passwords do not match.');
    return;
  }

  const btn = document.getElementById('signup-btn');
  setLoading(btn, true);

  // NOTE: input is NOT escaped client-side — the server sanitizes it.
  // We send raw values and the server applies validator.escape() + bcrypt.
  const data = await apiFetch('/api/signup', {
    method: 'POST',
    body: JSON.stringify({ username, email, password, confirm_password: confirm }),
  }).catch(() => ({ ok: false, errors: ['Network error'] }));

  setLoading(btn, false);
  await fetchCsrf();   // refresh token after state change

  if (data.ok) {
    showAlert('signup-success', `Account created! Welcome, ${escapeHtml(data.username)}.`);
    setTimeout(() => showDashboard(data.username, email), 1000);
  } else {
    showAlert('signup-alert', (data.errors || ['Unknown error']).join('<br>'));
  }
}

// ── Login ─────────────────────────────────────────────────────────────
async function doLogin() {
  clearAlerts('login');
  const email    = document.getElementById('li-email').value;
  const password = document.getElementById('li-password').value;

  if (!email || !password) {
    showAlert('login-alert', 'Please enter your email and password.');
    return;
  }

  const btn = document.getElementById('login-btn');
  setLoading(btn, true);

  const data = await apiFetch('/api/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  }).catch(() => ({ ok: false, errors: ['Network error'] }));

  setLoading(btn, false);
  await fetchCsrf();

  if (data.ok) {
    const me = await apiFetch('/api/me');
    showDashboard(data.username, me.email || email);
  } else {
    const msgs = data.errors || ['Login failed'];
    // Show lockout as warning, credentials error as error
    const isLock = msgs[0].toLowerCase().includes('lock');
    showAlert(isLock ? 'login-warn' : 'login-alert', msgs.join('<br>'));
  }
}

// ── Logout ────────────────────────────────────────────────────────────
async function doLogout() {
  await apiFetch('/api/logout', { method: 'POST' });
  await fetchCsrf();
  navigate('login');
  // Re-show nav buttons
  document.getElementById('navLogin').style.display  = '';
  document.getElementById('navSignup').style.display = '';
}

// ── Live validation (UX only — server still validates) ────────────────
function liveValidateUsername(inp) {
  const val = inp.value;
  const ok  = /^[a-zA-Z0-9_]{3,30}$/.test(val);
  setFieldState(inp, 'err-username',
    ok ? '' : val.length < 3 ? '3–30 characters required'
           : !/^[a-zA-Z0-9_]+$/.test(val) ? 'Only letters, numbers, underscores'
           : 'Too long');
}

function liveValidateEmail(inp) {
  const val = inp.value;
  const ok  = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val);
  setFieldState(inp, 'err-email', ok ? '' : 'Enter a valid email address');
}

function liveValidatePassword(inp) {
  const val = inp.value;
  const checks = {
    'req-len':     val.length >= 8,
    'req-upper':   /[A-Z]/.test(val),
    'req-lower':   /[a-z]/.test(val),
    'req-digit':   /\d/.test(val),
    'req-special': /[^a-zA-Z\d]/.test(val),
    'req-max':     val.length <= 128,
  };
  Object.entries(checks).forEach(([id, met]) => {
    const el = document.getElementById(id);
    if (el) el.classList.toggle('met', met);
  });

  const score = Object.values(checks).filter(Boolean).length;
  const bar   = document.getElementById('strength-bar');
  const label = document.getElementById('strength-label');
  const levels = [
    { pct: 0,   color: 'transparent',     txt: 'Enter a password' },
    { pct: 20,  color: '#f85149',         txt: 'Very weak' },
    { pct: 40,  color: '#d29922',         txt: 'Weak' },
    { pct: 60,  color: '#e3b341',         txt: 'Fair' },
    { pct: 80,  color: '#3fb950',         txt: 'Strong' },
    { pct: 100, color: '#58a6ff',         txt: 'Very strong' },
  ];
  const lvl = levels[score] || levels[0];
  bar.style.width      = lvl.pct + '%';
  bar.style.background = lvl.color;
  label.textContent    = lvl.txt;
  label.style.color    = lvl.color;

  const allOk = Object.values(checks).every(Boolean);
  setFieldState(inp, 'err-password', allOk ? '' : '');
}

function liveValidateConfirm(inp) {
  const pw = document.getElementById('su-password').value;
  setFieldState(inp, 'err-confirm',
    inp.value === pw ? '' : 'Passwords do not match');
}

// ── UI helpers ────────────────────────────────────────────────────────
function setFieldState(inp, errId, msg) {
  inp.classList.toggle('error', !!msg);
  inp.classList.toggle('ok', !msg && inp.value.length > 0);
  const el = document.getElementById(errId);
  if (el) { el.textContent = msg; el.classList.toggle('visible', !!msg); }
}

function showAlert(id, html) {
  const el = document.getElementById(id);
  if (!el) return;
  el.innerHTML = html;  // server errors are plain text; we escape dynamic values above
  el.classList.add('visible');
}

function clearAlerts(prefix) {
  ['alert', 'success', 'warn'].forEach(type => {
    const el = document.getElementById(`${prefix}-${type}`);
    if (el) { el.textContent = ''; el.classList.remove('visible'); }
  });
}

function setLoading(btn, loading) {
  btn.disabled   = loading;
  btn.innerHTML  = loading
    ? '<span class="spinner"></span> Please wait…'
    : btn.id === 'signup-btn' ? 'Create account' : 'Log in';
}

function togglePw(inputId, btn) {
  const inp = document.getElementById(inputId);
  const show = inp.type === 'password';
  inp.type   = show ? 'text' : 'password';
  btn.textContent = show ? '🙈' : '👁';
}

/**
 * escapeHtml — client-side XSS protection for dynamic content
 * inserted into the DOM. textContent is always preferred;
 * this is used only where innerHTML is unavoidable.
 */
function escapeHtml(str) {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}
