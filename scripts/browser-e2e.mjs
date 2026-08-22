// Browser end-to-end check: signs in to the admin UI, creates a link,
// uploads files through the real uploader (vot-wasm in Chromium), and
// verifies the bytes on disk. AGPL-3.0-only.
//
// Requires: `npm i playwright` (with its Chromium), a running votport, and:
//   BASE_URL        e.g. http://127.0.0.1:8080
//   ADMIN_PASSWORD  the admin password of that instance
//   RECEIVE_DIR     the instance's receive root, from this process's view
//
//   node scripts/browser-e2e.mjs

import { chromium } from 'playwright';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const base = process.env.BASE_URL || 'http://127.0.0.1:8080';
const adminPassword = process.env.ADMIN_PASSWORD;
const receiveDir = process.env.RECEIVE_DIR;
if (!adminPassword || !receiveDir) {
  console.error('set BASE_URL, ADMIN_PASSWORD and RECEIVE_DIR');
  process.exit(2);
}

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'votport-e2e-'));
fs.writeFileSync(path.join(dir, 'Résumé Draft.pdf'), 'unicode names travel\n');
// Multiple server-sized ranges exercise the bounded parallel upload path.
const big = Buffer.alloc(40 * 1024 * 1024 + 99);
for (let i = 0; i < big.length; i += 1) big[i] = (i * 7) % 253;
fs.writeFileSync(path.join(dir, 'archive.tar'), big);

// A UTF-8 locale is required for Chromium to accept non-ASCII file names.
const browser = await chromium.launch({
  env: { ...process.env, LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8' },
});
const page = await browser.newPage();
const errors = [];
page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));

await page.goto(base);
await page.waitForSelector('#login:not([hidden])');
await page.fill('#login-password', adminPassword);
await page.click('#login-form button[type=submit]');
// Signed-in users land on /links; the create form is the first element.
await page.waitForSelector('#create-form:not([hidden])', { timeout: 15000 });

const dest = `e2e-${Date.now().toString(36)}`;
await page.fill('#create-label', 'browser e2e');
await page.fill('#create-dest', dest);
await page.click('#create-form button[type=submit]');
await page.waitForSelector('#new-link:not([hidden])');
const linkUrl = (await page.textContent('#new-link-url')).trim();
console.log('link:', linkUrl);

await page.goto(linkUrl);
await page.waitForSelector('#uploader:not([hidden])', { timeout: 15000 });
await page.setInputFiles('#file-input', [
  path.join(dir, 'Résumé Draft.pdf'),
  path.join(dir, 'archive.tar'),
]);
await page.click('#send');
await page.waitForSelector('#done-card:not([hidden])', { timeout: 120000 });
console.log('uploaded:', (await page.textContent('#done-list')).trim().replace(/\s+/g, ' '));
const ids = await page.$$eval('#done-list .file-id', (els) => els.map((el) => el.textContent));
if (
  ids.length !== 2 ||
  ids.some((id) => !/^[a-z0-9]+:[0-9a-f]{64}$/.test(id))
) {
  throw new Error(`object card identity malformed: ${JSON.stringify(ids)}`);
}
await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
await page.click('#done-list li:first-child .file-id');
const copied = await page.evaluate(() => navigator.clipboard.readText());
if (copied !== ids[0]) {
  throw new Error(`copy mismatch: ${copied}`);
}
await browser.close();

const stored = path.join(receiveDir, dest);
if (fs.readFileSync(path.join(stored, 'Résumé Draft.pdf'), 'utf8') !== 'unicode names travel\n') {
  throw new Error('unicode-named file mismatch');
}
if (!fs.readFileSync(path.join(stored, 'archive.tar')).equals(big)) {
  throw new Error('archive.tar mismatch');
}
if (errors.length) {
  console.error(errors.join('\n'));
  process.exit(1);
}
console.log('ok: files verified on disk');
