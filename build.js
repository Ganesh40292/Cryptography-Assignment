const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const rootDir = __dirname;
const webDir = path.join(rootDir, 'chacha20-cipher', 'web');
const webDist = path.join(webDir, 'dist');
const cipherDist = path.join(rootDir, 'chacha20-cipher', 'dist');
const rootDist = path.join(rootDir, 'dist');

console.log('[build.js] Step 1: Installing web dependencies...');
execSync('npm install', { cwd: webDir, stdio: 'inherit' });

console.log('[build.js] Step 2: Building Vite production bundle...');
execSync('npm run build', { cwd: webDir, stdio: 'inherit' });

console.log('[build.js] Step 3: Synchronizing output directories...');
if (fs.existsSync(webDist)) {
  fs.mkdirSync(cipherDist, { recursive: true });
  fs.cpSync(webDist, cipherDist, { recursive: true });

  fs.mkdirSync(rootDist, { recursive: true });
  fs.cpSync(webDist, rootDist, { recursive: true });

  console.log('[build.js] Verified build outputs in:');
  console.log('  -> ' + webDist);
  console.log('  -> ' + cipherDist);
  console.log('  -> ' + rootDist);
} else {
  console.error('[build.js] Error: web/dist does not exist after build!');
  process.exit(1);
}

console.log('[build.js] Build completed successfully!');
