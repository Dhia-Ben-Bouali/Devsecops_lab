const express = require('express');
const router = express.Router();
const fs = require('fs');

// 1. Hardcoded credentials (SonarQube flag)
const DB_PASSWORD = '123456';

// 2. Command injection (SonarQube may detect)
router.get('/ping', (req, res) => {
    const host = req.query.host;
    const exec = require('child_process').exec;
    exec(`ping -c 1 ${host}`, (err, stdout) => {
        if (err) return res.send('Error');
        res.send(`<pre>${stdout}</pre>`);
    });
});

// 3. Insecure file access
router.get('/read', (req, res) => {
    const file = req.query.file;
    const content = fs.readFileSync(file, 'utf8');
    res.send(`<pre>${content}</pre>`);
});

module.exports = router;
