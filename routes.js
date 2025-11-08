const express = require('express');
const router = express.Router();

// A simple vulnerable endpoint for demo (XSS)
router.get('/greet', (req, res) => {
    const name = req.query.name || 'Guest';
    res.send(`<h1>Hello ${name}</h1>`); // could be XSS if user input is malicious
});

module.exports = router;