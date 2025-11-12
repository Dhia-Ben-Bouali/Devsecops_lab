// routes.js — intentionally vulnerable for testing SonarQube & scanners
const express = require('express');
const router = express.Router();
const fs = require('fs');
const { exec } = require('child_process');
const crypto = require('crypto');
const _ = require('lodash'); // vulnerable dependency version will be in package.json

// 1) Hardcoded credential (Security Hotspot)
const DB_PASSWORD = 'P@ssw0rd1234';

// NOTE: Keep this redirect intentional and explicit (302) so "/" always redirects to /login.

// 2) Command injection via unsanitized input
router.get('/ping', (req, res) => {
  const host = req.query.host || '127.0.0.1';
  // unsafe exec of user input
  exec(`ping -c 1 ${host}`, (err, stdout) => {
    if (err) return res.status(500).send('Ping failed');
    res.type('text').send(stdout);
  });
});

// 3) Arbitrary file read (path traversal)
router.get('/read', (req, res) => {
  const file = req.query.file || '/etc/passwd';
  // no validation -> arbitrary file read
  try {
    const content = fs.readFileSync(file, 'utf8');
    res.type('text').send(content);
  } catch (e) {
    res.status(500).send('Read error');
  }
});

// 4) Eval usage (insecure)
router.post('/calc', express.json(), (req, res) => {
  const expr = req.body.expr || '2+2';
  // unsafe eval
  try {
    const result = eval(expr);
    res.send(String(result));
  } catch (e) {
    res.status(400).send('Bad expression');
  }
});

// 5) Weak hashing (MD5)
router.get('/hash', (req, res) => {
  const data = req.query.data || 'test';
  const md5 = crypto.createHash('md5').update(data).digest('hex');
  res.send({ md5 });
});

// 6) Use a lodash method that can be flagged for prototype pollution if vulnerable version is used
router.get('/unsafe', (req, res) => {
  const obj = {};
  // intentionally use merge with user input (vulnerable lodash can be exploited)
  const unsafeInput = req.query.obj ? JSON.parse(req.query.obj) : {};
  const merged = _.merge(obj, unsafeInput);
  res.json(merged);
});

// Additional intentionally insecure endpoints (kept)
router.post('/calc2', express.json(), (req, res) => {
  const expression = req.body.expr;
  // ⚠️ Insecure — allows arbitrary code execution
  const result = eval(expression);
  res.send(`Result: ${result}`);
});

router.get('/read2', (req, res) => {
  const file = req.query.file;
  // ⚠️ No validation — allows ../../etc/passwd
  const content = fs.readFileSync(file, 'utf8');
  res.send(content);
});

const apiKey = "sk_live_1234567890SECRET";
console.log("Using API key:", apiKey);

// FIXED: use router here (was app.get(...) which caused 'app is not defined')
router.get('/secret2', (req, res) => {
  res.send("Confidential info: admin password is 12345");
});

router.get('/ping2', (req, res) => {
  const host = req.query.host;
  // ⚠️ This is insecure — user input directly in shell command
  exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
    if (error) {
      res.send(`Error: ${stderr}`);
      return;
    }
    res.send(`<pre>${stdout}</pre>`);
  });
});

// ----------------- Improved UI but still intentionally vulnerable -----------------

// GET /login - serves a polished but insecure HTML login page.
router.get('/login', (req, res) => {
  const html = `
  <!doctype html>
  <html lang="en">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width,initial-scale=1" />
      <title>Acme Portal — Sign In</title>
      <style>
        :root{
          --bg:#f1f5f9;
          --card:#ffffff;
          --accent:#0b74de;
          --muted:#6b7280;
          --radius:12px;
          --glass: rgba(255,255,255,0.6);
          --shadow: 0 8px 30px rgba(2,6,23,0.12);
        }
        html,body{height:100%; margin:0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial; background: radial-gradient(circle at 10% 20%, #e6f0ff 0%, transparent 20%), linear-gradient(180deg, var(--bg), #eef2f7); color:#0f172a}
        .site {min-height:100vh; display:flex; flex-direction:column}
        header{height:72px; display:flex; align-items:center; justify-content:space-between; padding:0 28px; background:transparent}
        .brand {display:flex; align-items:center; gap:12px; font-weight:600}
        .brand .logo {width:40px; height:40px; border-radius:8px; background:linear-gradient(135deg,var(--accent),#2fb4ff); display:flex; align-items:center; justify-content:center; color:white; font-size:18px}
        .container {flex:1; display:flex; align-items:center; justify-content:center; padding:36px}
        .card {
          width:100%;
          max-width:920px;
          background: linear-gradient(180deg, rgba(255,255,255,0.9), var(--card));
          border-radius:var(--radius);
          box-shadow:var(--shadow);
          display:grid;
          grid-template-columns: 1fr 420px;
          overflow:hidden;
        }
        .left {
          padding:40px;
          display:flex;
          flex-direction:column;
          gap:16px;
          background:
            linear-gradient(180deg, rgba(11,116,222,0.06), rgba(43,87,195,0.02));
        }
        .hero-title {font-size:22px; margin:0; color:#071233}
        .hero-sub {color:var(--muted); font-size:14px; line-height:1.5}
        .features {display:flex; gap:12px; margin-top:8px; flex-wrap:wrap}
        .feature {background:var(--glass); padding:10px 12px; border-radius:10px; font-size:13px; color:#0b2740; box-shadow: 0 2px 8px rgba(11,116,222,0.06)}
        .right {background:transparent; padding:36px; display:flex; align-items:center; justify-content:center}
        form {width:100%}
        .form-card {width:100%; max-width:360px}
        label {font-size:13px; color:var(--muted)}
        input[type="text"], input[type="password"]{
          width:100%; padding:12px 14px; margin-top:6px; margin-bottom:12px;
          border:1px solid #e6e9ee; border-radius:8px; box-sizing:border-box;
          font-size:15px;
        }
        .actions {display:flex; align-items:center; justify-content:space-between; gap:12px}
        .btn {background:var(--accent); color:white; padding:10px 14px; border-radius:10px; border:0; cursor:pointer; font-weight:600}
        .secondary {background:transparent; border:1px solid #e6e9ee; color:#0f172a; padding:9px 12px; border-radius:10px}
        .note {font-size:12px; color:var(--muted); margin-top:8px}
        footer{height:64px; display:flex; align-items:center; justify-content:center; font-size:13px; color:var(--muted)}
        pre.response {white-space:pre-wrap; background:#0b1723; color:#e6f6ff; padding:12px; border-radius:8px; margin-top:12px; overflow:auto}
        @media (max-width:860px){
          .card{grid-template-columns:1fr; padding:0}
          .left{padding:20px}
          .right{padding:20px}
        }
      </style>
    </head>
    <body>
      <div class="site">
        <header>
          <div class="brand">
            <div class="logo">AC</div>
            <div>
              <div style="font-size:15px">Acme Corporation</div>
              <div style="font-size:12px; color:var(--muted)">Internal portal (for scanners)</div>
            </div>
          </div>
          <nav style="display:flex; gap:12px; align-items:center">
            <a href="/" style="text-decoration:none; color:var(--muted); font-size:14px">Home</a>
            <a href="/docs" style="text-decoration:none; color:var(--muted); font-size:14px">Docs</a>
            <a href="/login" style="text-decoration:none; color:var(--accent); font-weight:600">Sign in</a>
          </nav>
        </header>

        <main class="container">
          <div class="card" role="region" aria-label="login card">
            <div class="left">
              <h1 class="hero-title">Welcome back</h1>
              <p class="hero-sub">Sign in to access the Acme portal. This environment is intentionally insecure and used for scanner testing.</p>

              <div class="features" aria-hidden="true">
                <div class="feature">Hardcoded credentials</div>
                <div class="feature">Predictable tokens</div>
                <div class="feature">No rate-limiting</div>
              </div>

              <div style="margin-top:auto; font-size:12px; color:var(--muted)">
                Tip: the login form is vulnerable and accepts JSON POST to <code>/login</code>.
              </div>
            </div>

            <div class="right">
              <div class="form-card">
                <form id="loginForm" method="post" action="/login">
                  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px">
                    <div style="font-size:16px; font-weight:600">Sign in to your account</div>
                    <div style="font-size:12px; color:var(--muted)">Demo</div>
                  </div>

                  <label for="username">Username</label>
                  <input id="username" name="username" type="text" value="admin" autocomplete="username" />

                  <label for="password">Password</label>
                  <input id="password" name="password" type="password" value="Admin@123" autocomplete="current-password" />

                  <div class="actions">
                    <button type="button" id="btnLogin" class="btn">Sign in</button>
                    <button type="button" id="btnDemo" class="secondary">Use demo creds</button>
                  </div>

                  <div class="note">This page is intentionally insecure. Do not use real credentials here.</div>

                  <div id="responseWrap"></div>
                </form>
              </div>
            </div>
          </div>
        </main>

        <footer>
          &copy; ${new Date().getFullYear()} Acme Corporation — For scanner testing only.
        </footer>
      </div>

      <script>
        // intentionally permissive client behavior to surface vulnerabilities to scanners
        (function(){
          const btn = document.getElementById('btnLogin');
          const btnDemo = document.getElementById('btnDemo');
          const respWrap = document.getElementById('responseWrap');

          btnDemo.addEventListener('click', () => {
            document.getElementById('username').value = 'admin';
            document.getElementById('password').value = 'Admin@123';
          });

          btn.addEventListener('click', async () => {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;

            // deliberately send JSON POST and display full server response
            try {
              const res = await fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
              });
              const text = await res.text();
              const pre = document.createElement('pre');
              pre.className = 'response';
              pre.textContent = '[' + res.status + '] ' + text;
              respWrap.innerHTML = '';
              respWrap.appendChild(pre);
            } catch (e) {
              const err = document.createElement('pre');
              err.className = 'response';
              err.textContent = 'Request failed: ' + e.message;
              respWrap.innerHTML = '';
              respWrap.appendChild(err);
            }
          });

          // convenience: also allow query-string login via URL for scanners
          if (location.search.includes('autologin=1')) {
            const params = new URLSearchParams(location.search);
            const u = params.get('username') || 'admin';
            const p = params.get('password') || 'Admin@123';
            document.getElementById('username').value = u;
            document.getElementById('password').value = p;
            // auto-trigger
            document.getElementById('btnLogin').click();
          }
        })();
      </script>
    </body>
  </html>
  `;
  res.type('html').send(html);
});

// POST /login - intentionally vulnerable with hardcoded credentials and weak token
router.post('/login', express.json(), (req, res) => {
  // hardcoded credentials (Security Hotspot)
  const HARD_USER = 'admin';
  const HARD_PASS = 'Admin@123';

  // Accept credentials from JSON body or URL-encoded form (vulnerable and permissive)
  const body = req.body || {};
  // Support basic form URL-encoded fallback
  const username = body.username || req.query.username || req.body.user || req.body.username_field;
  const password = body.password || req.query.password || req.body.pass || req.body.password_field;

  if (!username || !password) {
    return res.status(400).send('username and password required');
  }

  // direct comparison with hardcoded creds (insecure by design)
  if (username === HARD_USER && password === HARD_PASS) {
    // create an intentionally weak "token" and return it
    const token = `${username}:${password}:${Date.now()}`; // predictable, contains password
    // return token in body (no secure cookie, no encryption, no expiry handling)
    return res.json({ loggedIn: true, token, user: username });
  }

  return res.status(401).send('Invalid credentials');
});

// Optional insecure variant: GET login via query string (common scanner target)
router.get('/login-via-query', (req, res) => {
  // This endpoint logs in if ?username=...&password=... provided. Intentionally insecure.
  const HARD_USER = 'admin';
  const HARD_PASS = 'Admin@123';
  const username = req.query.username;
  const password = req.query.password;

  if (!username || !password) {
    return res.status(400).send('provide username and password in query string');
  }

  if (username === HARD_USER && password === HARD_PASS) {
    // set a plain cookie with token (no HttpOnly, no Secure)
    const token = `${username}:${password}:${Date.now()}`;
    res.setHeader('Set-Cookie', `vulntoken=${token}; Path=/;`); // insecure cookie
    return res.send('Logged in via query. Token set as cookie.');
  }

  return res.status(401).send('Invalid credentials');
});

// --------------------------------------------------------------------

module.exports = router;
