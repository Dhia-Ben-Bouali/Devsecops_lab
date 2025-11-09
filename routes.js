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

module.exports = router;
