// routes.js — intentionally vulnerable for testing SonarQube & scanners
const express = require('express');
const router = express.Router();
const fs = require('fs');
const { exec } = require('child_process');
const crypto = require('crypto');
const _ = require('lodash'); // vulnerable dependency version will be in package.json

// 1) Hardcoded credential (Security Hotspot)
const DB_PASSWORD = 'P@ssw0rd1234';

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

// ----------------- Vulnerable login interface & route -----------------
// GET /login - serves a simple HTML login form. Intentionally insecure.
router.get('/login', (req, res) => {
  // Note: form submits credentials in plain body or query depending on method used.
  const html = `
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8">
        <title>Vulnerable Login (for scanners)</title>
        <style>
          body { font-family: Arial, sans-serif; padding: 40px; background:#f7f7f7 }
          .card { max-width:400px; margin:0 auto; padding:20px; background:#fff; border:1px solid #ddd; border-radius:6px; box-shadow: 0 2px 4px rgba(0,0,0,0.05) }
          input { width:100%; padding:8px; margin:8px 0; box-sizing:border-box }
          button { padding:10px 15px }
          .note { font-size:12px; color:#666 }
        </style>
      </head>
      <body>
        <div class="card">
          <h2>Login</h2>
          <form id="loginForm" method="post" action="/login">
            <label>Username</label>
            <input name="username" id="username" value="admin" />
            <label>Password</label>
            <input name="password" id="password" value="Admin@123" />
            <div style="margin-top:12px">
              <button type="submit">Login</button>
            </div>
          </form>

          <p class="note">
            This page is intentionally insecure. Credentials are hardcoded and form posts plain data.
          </p>

          <p class="note">
            You can also send JSON POST to /login with { "username": "...", "password": "..." }.
          </p>
        </div>

        <script>
          // deliberately insecure: submit form via fetch and show response inline
          document.getElementById('loginForm').addEventListener('submit', function(e){
            e.preventDefault();
            const u = document.getElementById('username').value;
            const p = document.getElementById('password').value;

            // intentionally send JSON and then display raw response
            fetch('/login', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ username: u, password: p })
            })
            .then(r => r.text())
            .then(t => {
              const pre = document.createElement('pre');
              pre.textContent = t;
              document.body.appendChild(pre);
            })
            .catch(err => alert('Request failed'));
          });
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
