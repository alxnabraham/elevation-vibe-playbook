const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = 3001;

// Credentials — local preview only, not deployed to Vercel
const USERNAME = process.env.DOCS_USER || 'elevation';
const PASSWORD = process.env.DOCS_PASS || 'vibe2026';

// ── Rate limiting (brute force protection) ──────────────────────
const loginAttempts = new Map(); // IP -> { count, lastAttempt }
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes

function isRateLimited(ip) {
  const record = loginAttempts.get(ip);
  if (!record) return false;
  if (Date.now() - record.lastAttempt > LOCKOUT_MS) {
    loginAttempts.delete(ip);
    return false;
  }
  return record.count >= MAX_ATTEMPTS;
}

function recordFailedAttempt(ip) {
  const record = loginAttempts.get(ip) || { count: 0, lastAttempt: 0 };
  record.count += 1;
  record.lastAttempt = Date.now();
  loginAttempts.set(ip, record);
}

function clearAttempts(ip) {
  loginAttempts.delete(ip);
}

// ── Timing-safe string comparison ───────────────────────────────
function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    // Compare against self to keep constant time, then return false
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

// ── Middleware ───────────────────────────────────────────────────

// Body parser with size limit (prevent large payload attacks)
app.use(express.urlencoded({ extended: false, limit: '1kb' }));

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:;");
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

// Session with hardened cookie
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  name: '_eai_sid', // non-default cookie name
  cookie: {
    httpOnly: true,    // not accessible via document.cookie in console
    sameSite: 'lax',   // CSRF protection
    secure: false,     // set to true if behind HTTPS
    maxAge: 4 * 60 * 60 * 1000, // 4 hour expiry
  },
}));

// Auth middleware
function requireAuth(req, res, next) {
  if (req.path === '/login' || req.session.authenticated) return next();
  res.redirect('/login');
}

// ── Routes ──────────────────────────────────────────────────────

// Login page
app.get('/login', (req, res) => {
  const ip = req.ip;
  const locked = isRateLimited(ip);
  const showError = req.query.e === '1';
  const errorHtml = locked
    ? '<p class="error">Too many failed attempts. Try again in 15 minutes.</p>'
    : showError
      ? '<p class="error">Invalid username or password.</p>'
      : '';
  const disabledAttr = locked ? 'disabled' : '';

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Sign In — Elevation AI Docs</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&display=swap" rel="stylesheet" />
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'DM Sans', -apple-system, BlinkMacSystemFont, sans-serif;
      background: #FAFAFA;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      -webkit-font-smoothing: antialiased;
    }
    .login-card {
      background: #fff;
      border: 1px solid #E4E4E7;
      border-radius: 12px;
      padding: 48px 40px 40px;
      width: 100%;
      max-width: 400px;
      box-shadow: 0 4px 24px rgba(0,0,0,0.06);
    }
    .logo {
      display: flex;
      align-items: center;
      gap: 10px;
      justify-content: center;
      margin-bottom: 32px;
    }
    .logo-mark {
      width: 36px; height: 36px;
      background: #4361EE;
      border-radius: 9px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #fff;
      font-weight: 700;
      font-size: 16px;
    }
    .logo-text {
      font-weight: 700;
      font-size: 18px;
      color: #18181B;
      letter-spacing: -0.01em;
    }
    h1 {
      font-size: 22px;
      font-weight: 700;
      color: #18181B;
      text-align: center;
      margin-bottom: 6px;
      letter-spacing: -0.015em;
    }
    .subtitle {
      font-size: 14px;
      color: #71717A;
      text-align: center;
      margin-bottom: 28px;
    }
    label {
      display: block;
      font-size: 13px;
      font-weight: 600;
      color: #3F3F46;
      margin-bottom: 6px;
    }
    input {
      width: 100%;
      padding: 10px 14px;
      font-size: 14px;
      font-family: inherit;
      border: 1px solid #E4E4E7;
      border-radius: 8px;
      outline: none;
      transition: border-color 180ms ease;
      margin-bottom: 18px;
      color: #18181B;
    }
    input:focus {
      border-color: #4361EE;
      box-shadow: 0 0 0 3px rgba(67, 97, 238, 0.1);
    }
    input:disabled { opacity: 0.5; cursor: not-allowed; }
    button {
      width: 100%;
      padding: 11px 0;
      font-size: 14px;
      font-weight: 600;
      font-family: inherit;
      background: #4361EE;
      color: #fff;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      transition: background 180ms ease;
    }
    button:hover { background: #3651D4; }
    button:disabled { background: #A1A1AA; cursor: not-allowed; }
    .error {
      background: #FEF2F2;
      border: 1px solid #FECACA;
      color: #991B1B;
      font-size: 13px;
      padding: 10px 14px;
      border-radius: 8px;
      margin-bottom: 18px;
      text-align: center;
    }
    .footer {
      text-align: center;
      font-size: 12px;
      color: #A1A1AA;
      margin-top: 24px;
    }
  </style>
</head>
<body>
  <div class="login-card">
    <div class="logo">
      <span class="logo-mark">E</span>
      <span class="logo-text">Elevation AI</span>
    </div>
    <h1>Sign in to Docs</h1>
    <p class="subtitle">Internal documentation — authorized access only</p>
    ${errorHtml}
    <form method="POST" action="/login">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" autocomplete="username" required autofocus ${disabledAttr} />
      <label for="password">Password</label>
      <input type="password" id="password" name="password" autocomplete="current-password" required ${disabledAttr} />
      <button type="submit" ${disabledAttr}>Sign In</button>
    </form>
    <p class="footer">Confidential &mdash; Elevation AI</p>
  </div>
</body>
</html>`);
});

// Login handler
app.post('/login', (req, res) => {
  const ip = req.ip;

  // Check rate limit
  if (isRateLimited(ip)) {
    return res.redirect('/login?e=1');
  }

  const { username, password } = req.body;

  // Validate input exists and is a string
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.redirect('/login?e=1');
  }

  // Timing-safe credential comparison
  const userOk = safeCompare(username, USERNAME);
  const passOk = safeCompare(password, PASSWORD);

  if (userOk && passOk) {
    clearAttempts(ip);
    // Regenerate session to prevent session fixation
    req.session.regenerate((err) => {
      if (err) return res.redirect('/login?e=1');
      req.session.authenticated = true;
      res.redirect('/');
    });
  } else {
    recordFailedAttempt(ip);
    res.redirect('/login?e=1');
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('_eai_sid');
    res.redirect('/login');
  });
});

// Protect all static files
app.use(requireAuth);
app.use(express.static(path.join(__dirname, 'public'), {
  dotfiles: 'deny', // block access to .env, .git, etc.
}));

// Catch-all — no information leakage
app.use((req, res) => {
  res.status(404).redirect('/login');
});

app.listen(PORT, () => {
  console.log(`Elevation AI Docs running at http://localhost:${PORT}`);
});
