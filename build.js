const fs = require('fs');
const path = require('path');

const dist = path.join(__dirname, 'dist');
if (!fs.existsSync(dist)) fs.mkdirSync(dist, { recursive: true });

fs.copyFileSync('app.js', path.join(dist, 'app.js'));
fs.copyFileSync('routes.js', path.join(dist, 'routes.js'));

console.log('Build completed.');
