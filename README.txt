SecureAuth  Secure Web Application
Major Project | BCA Cybersecurity | Kristu Jayanti University
Student :  Abhishek Kumar

---

 Project Overview

A full-stack secure web application implementing industry-standard security measures
across sign-up, login, session management, and protection against OWASP Top 10 vulnerabilities.

---

How to Run

First unzip the file and inside folder secure-webapp on the search bar type cmd.

bash in CMD

1. Install dependencies

npm install

2. Start the server

node server.js

3. Open in browser
http://localhost:3000


Requirements: Node.js v16+

---

Security Features Implemented

1.  Password Hashing  bcrypt
- **File:** `db.js` → `createUser()`, `verifyPassword()`
- Plaintext passwords are **never stored**
- bcrypt with **cost factor 12** (2^12 = 4096 iterations)
- Each hash includes a unique salt — rainbow tables ineffective
- Output: `$2b$12$<22-char-salt><31-char-hash>`

 2.  CSRF Protection — csurf middleware
- **File:** `server.js` → `csrfProtection` middleware
- Every state-changing request (POST) requires a valid CSRF token
- Token is tied to the user's session — forged cross-site requests fail
- Returns **HTTP 403** for missing/invalid tokens
- Client JS includes `CSRF-Token` header on every mutation

3.  Rate Limiting — express-rate-limit
- **File:** `server.js` → `globalLimiter`, `authLimiter`
- **Global:** 200 requests / 15 minutes per IP
- **Auth endpoints:** 20 requests / 15 minutes per IP
- Returns **HTTP 429** when exceeded
- Prevents automated brute-force attacks

4.  Secure Session Management — express-session
- **File:** `server.js` → `session()` config
- Cookie flags: `httpOnly` (JS can't read it), `sameSite: strict`, `secure` (HTTPS in prod)
- Cookie name: `__Host-` prefix used in production (requires HTTPS); falls back to a plain `sid` name in local development, since browsers silently reject `__Host-`-prefixed cookies sent without the `Secure` flag over plain HTTP
- **Session regeneration** on login/signup prevents session fixation
- 30-minute idle timeout

 5.  Input Validation — server-side (never trust client)
- **File:** `validators.js`
- Username: 3–30 chars, alphanumeric + underscore only (regex whitelist)
- Email: RFC-compliant validation via `validator` library
- Password: min 8, max 128, requires uppercase + lowercase + digit + special char
- All fields checked for length limits before DB operations

6.  SQL Injection Prevention — Parameterized Queries
- **File:** `db.js` → all query functions
- User input **never concatenated** into query strings
- All DB lookups use bound parameters (values passed separately from the query template)
- Same pattern as `pg` / `mysql2` prepared statements

 7.  XSS Prevention — Multiple Layers
- **File:** `server.js` (Helmet CSP), `validators.js` (server escape), `public/index.html` (client escape)
- **Content-Security-Policy** header via Helmet blocks inline scripts
- `validator.escape()` sanitizes user input server-side
- Client: `textContent` used for dynamic DOM; custom `escapeHtml()` for innerHTML
- Malicious usernames like `<script>alert(1)</script>` rejected at validation

8.  Security Headers — Helmet.js
- **File:** `server.js` → `helmet()` middleware
- Sets **14 HTTP security headers** automatically:
  - `X-Content-Type-Options: nosniff` — prevents MIME sniffing
  - `X-Frame-Options: DENY` — clickjacking protection
  - `X-XSS-Protection: 1; mode=block`
  - `Strict-Transport-Security` — enforces HTTPS
  - `Content-Security-Policy` — restricts resource origins
  - `Referrer-Policy: no-referrer`
  - And more…

 9.  Account Lockout — Brute Force Defense
- **File:** `db.js` → `recordFailedAttempt()`, `isAccountLocked()`
- After **5 consecutive failed logins**, account locked for **15 minutes**
- Error messages are **intentionally vague** (no "wrong password" vs "wrong email")
- Prevents user enumeration attacks

 10.  Timing Attack Prevention
- **File:** `server.js` → `/api/login` handler
- When email doesn't exist, bcrypt.compare still runs on a dummy hash
- Ensures **constant response time** whether email exists or not
- Prevents attackers timing requests to discover valid emails
- Additional random 500–1000ms delay on failed attempts

---

 File Structure

secure-webapp/
├── server.js          # Express app + all security middleware
├── db.js              # In-memory DB with parameterized query pattern
├── validators.js      # Input validation & sanitization middleware
├── package.json       # Dependencies
├── public/
│   └── index.html     # SPA frontend (signup, login, dashboard)
└── README.md          # This file

Dependencies

| Package | Purpose |
|---|---|
| `express` | Web framework |
| `helmet` | Security HTTP headers (14 headers) |
| `express-session` | Secure session management |
| `csurf` | CSRF token generation & validation |
| `express-rate-limit` | IP-based rate limiting |
| `bcryptjs` | Password hashing (cost factor 12) |
| `validator` | Email & string sanitization |
| `uuid` | Cryptographically random user IDs |

---

 Test Results

| Test | Result |
|---|---|
| Valid signup accepted |  PASS |
| Weak password blocked |  BLOCKED |
| XSS payload in username blocked |  BLOCKED |
| SQL injection in email blocked |  BLOCKED |
| Password mismatch blocked |  BLOCKED |
| Account locked after 5 fails |  LOCKED (15 min) |
| bcrypt hashing verified |  PASS (cost: $2b$12$) |
| CSRF token required on all mutations |  ENFORCED |
| Session regenerated after login |  ACTIVE |

---

 OWASP Coverage

| OWASP Top 10 | Mitigation |
|---|---|
| A01 Broken Access Control | requireAuth middleware, session checks |
| A02 Cryptographic Failures | bcrypt cost-12, HTTPS-ready |
| A03 Injection (SQLi, XSS) | Parameterized queries, CSP, escaping |
| A04 Insecure Design | Lockout, rate limit, constant-time compare |
| A05 Security Misconfiguration | Helmet, CSP, no stack traces to client |
| A07 Auth Failures | Session regeneration, lockout, timing defense |
| A09 Logging & Monitoring | Server-side error logging (console.error) |
