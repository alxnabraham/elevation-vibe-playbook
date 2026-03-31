const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = 3001;

// Credentials — override via env vars on Vercel
const USERNAME = process.env.DOCS_USER || 'elevation';
const PASSWORD = process.env.DOCS_PASS || 'vibe2026';
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

// ── Rate limiting (best-effort — resets per serverless instance) ─
const loginAttempts = new Map();
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

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
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

// ── Cookie helpers (no cookie-parser dependency) ────────────────
function parseCookies(header) {
  const cookies = {};
  if (!header) return cookies;
  header.split(';').forEach(function (part) {
    const eq = part.indexOf('=');
    if (eq < 0) return;
    const key = part.substring(0, eq).trim();
    const val = part.substring(eq + 1).trim();
    cookies[key] = decodeURIComponent(val);
  });
  return cookies;
}

// ── Middleware ───────────────────────────────────────────────────

app.use(express.urlencoded({ extended: false, limit: '1kb' }));

// Security headers
app.use(function (req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:;");
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

// Auth middleware — verify JWT from cookie
function requireAuth(req, res, next) {
  if (req.path === '/login') return next();

  var cookies = parseCookies(req.headers.cookie);
  var token = cookies._eai_token;
  if (!token) return res.redirect('/login');

  try {
    jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    res.redirect('/login');
  }
}

// ── Routes ──────────────────────────────────────────────────────

app.get('/login', function (req, res) {
  // If already authenticated, redirect to home
  var cookies = parseCookies(req.headers.cookie);
  if (cookies._eai_token) {
    try {
      jwt.verify(cookies._eai_token, JWT_SECRET);
      return res.redirect('/');
    } catch (e) { /* token invalid, show login */ }
  }

  var ip = req.ip;
  var locked = isRateLimited(ip);
  var showError = req.query.e === '1';
  var errorHtml = locked
    ? '<p class="error">Too many failed attempts. Try again in 15 minutes.</p>'
    : showError
      ? '<p class="error">Invalid username or password.</p>'
      : '';
  var disabledAttr = locked ? 'disabled' : '';

  res.send('<!DOCTYPE html>\n\
<html lang="en">\n\
<head>\n\
  <meta charset="UTF-8" />\n\
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />\n\
  <title>Sign In — Elevation AI Docs</title>\n\
  <link rel="preconnect" href="https://fonts.googleapis.com" />\n\
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />\n\
  <link href="https://fonts.googleapis.com/css2?family=Instrument+Sans:wght@400;500;600;700&display=swap" rel="stylesheet" />\n\
  <style>\n\
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }\n\
    body {\n\
      font-family: "Instrument Sans", -apple-system, BlinkMacSystemFont, sans-serif;\n\
      background: #fafbfc;\n\
      display: flex;\n\
      align-items: center;\n\
      justify-content: center;\n\
      min-height: 100vh;\n\
      -webkit-font-smoothing: antialiased;\n\
    }\n\
    .login-card {\n\
      background: #fff;\n\
      border: 1px solid #e4e7ec;\n\
      border-radius: 14px;\n\
      padding: 48px 40px 40px;\n\
      width: 100%;\n\
      max-width: 400px;\n\
      box-shadow: 0 4px 24px rgba(0,0,0,0.06);\n\
    }\n\
    .logo {\n\
      display: flex;\n\
      align-items: center;\n\
      gap: 10px;\n\
      justify-content: center;\n\
      margin-bottom: 32px;\n\
    }\n\
    .logo-mark {\n\
      width: 36px; height: 36px;\n\
      background: #0e62fd;\n\
      border-radius: 9px;\n\
      display: flex;\n\
      align-items: center;\n\
      justify-content: center;\n\
      color: #fff;\n\
      font-weight: 700;\n\
      font-size: 16px;\n\
    }\n\
    .logo-text {\n\
      font-weight: 700;\n\
      font-size: 18px;\n\
      color: #09090b;\n\
      letter-spacing: -0.01em;\n\
    }\n\
    h1 {\n\
      font-size: 22px;\n\
      font-weight: 700;\n\
      color: #09090b;\n\
      text-align: center;\n\
      margin-bottom: 6px;\n\
      letter-spacing: -0.015em;\n\
    }\n\
    .subtitle {\n\
      font-size: 14px;\n\
      color: #71717a;\n\
      text-align: center;\n\
      margin-bottom: 28px;\n\
    }\n\
    label {\n\
      display: block;\n\
      font-size: 13px;\n\
      font-weight: 600;\n\
      color: #585f6f;\n\
      margin-bottom: 6px;\n\
    }\n\
    input {\n\
      width: 100%;\n\
      padding: 10px 14px;\n\
      font-size: 14px;\n\
      font-family: inherit;\n\
      border: 1px solid #e4e7ec;\n\
      border-radius: 8px;\n\
      outline: none;\n\
      transition: border-color 180ms ease;\n\
      margin-bottom: 18px;\n\
      color: #09090b;\n\
    }\n\
    input:focus {\n\
      border-color: #0e62fd;\n\
      box-shadow: 0 0 0 3px rgba(67, 97, 238, 0.1);\n\
    }\n\
    input:disabled { opacity: 0.5; cursor: not-allowed; }\n\
    button {\n\
      width: 100%;\n\
      padding: 11px 0;\n\
      font-size: 14px;\n\
      font-weight: 600;\n\
      font-family: inherit;\n\
      background: #0e62fd;\n\
      color: #fff;\n\
      border: none;\n\
      border-radius: 8px;\n\
      cursor: pointer;\n\
      transition: background 180ms ease;\n\
    }\n\
    button:hover { background: #0d58e4; }\n\
    button:disabled { background: #71717a; cursor: not-allowed; }\n\
    .error {\n\
      background: #FEF2F2;\n\
      border: 1px solid #FECACA;\n\
      color: #991B1B;\n\
      font-size: 13px;\n\
      padding: 10px 14px;\n\
      border-radius: 8px;\n\
      margin-bottom: 18px;\n\
      text-align: center;\n\
    }\n\
    .footer {\n\
      text-align: center;\n\
      font-size: 12px;\n\
      color: #71717a;\n\
      margin-top: 24px;\n\
    }\n\
  </style>\n\
</head>\n\
<body>\n\
  <div class="login-card">\n\
    <div class="logo">\n\
      <span class="logo-mark">E</span>\n\
      <span class="logo-text">Elevation AI</span>\n\
    </div>\n\
    <h1>Sign in to Docs</h1>\n\
    <p class="subtitle">Internal documentation — authorized access only</p>\n\
    ' + errorHtml + '\n\
    <form method="POST" action="/login">\n\
      <label for="username">Username</label>\n\
      <input type="text" id="username" name="username" autocomplete="username" required autofocus ' + disabledAttr + ' />\n\
      <label for="password">Password</label>\n\
      <input type="password" id="password" name="password" autocomplete="current-password" required ' + disabledAttr + ' />\n\
      <button type="submit" ' + disabledAttr + '>Sign In</button>\n\
    </form>\n\
    <p class="footer">Confidential &mdash; Elevation AI</p>\n\
  </div>\n\
</body>\n\
</html>');
});

app.post('/login', function (req, res) {
  var ip = req.ip;

  if (isRateLimited(ip)) {
    return res.redirect('/login?e=1');
  }

  var username = req.body ? req.body.username : undefined;
  var password = req.body ? req.body.password : undefined;

  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.redirect('/login?e=1');
  }

  var userOk = safeCompare(username, USERNAME);
  var passOk = safeCompare(password, PASSWORD);

  if (userOk && passOk) {
    clearAttempts(ip);
    var token = jwt.sign({ authenticated: true }, JWT_SECRET, { expiresIn: '4h' });
    var isSecure = process.env.VERCEL === '1';
    var cookieStr = '_eai_token=' + token + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=14400' + (isSecure ? '; Secure' : '');
    res.setHeader('Set-Cookie', cookieStr);
    res.redirect('/');
  } else {
    recordFailedAttempt(ip);
    res.redirect('/login?e=1');
  }
});

app.get('/logout', function (req, res) {
  res.setHeader('Set-Cookie', '_eai_token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
  res.redirect('/login');
});

// Protect all static files
app.use(requireAuth);
app.use(express.static(path.join(__dirname, 'public'), {
  dotfiles: 'deny',
}));

// Catch-all
app.use(function (req, res) {
  res.status(404).redirect('/login');
});

// Local dev: listen on port. Vercel: export the app.
if (require.main === module) {
  app.listen(PORT, function () {
    console.log('Elevation AI Docs running at http://localhost:' + PORT);
  });
}

module.exports = app;
