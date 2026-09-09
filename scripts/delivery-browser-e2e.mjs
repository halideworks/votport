import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import fs from 'node:fs/promises';
import path from 'node:path';

const base = process.env.BASE_URL;
const root = process.env.WORKFLOW_TEST_ROOT;
if (!base || !root || !process.env.ADMIN_PASSWORD) throw new Error('Set BASE_URL, WORKFLOW_TEST_ROOT and ADMIN_PASSWORD for an isolated test instance.');
const project = `browser-${Date.now()}`;
const directory = path.join(root, 'library', project);
await fs.mkdir(directory, { recursive: true });
await fs.writeFile(path.join(directory, 'saved.bin'), 'Recipient verification fixture.\n');
const browser = await chromium.launch();
const context = await browser.newContext();
const page = await context.newPage();
const errors = [];
page.on('pageerror', (error) => errors.push(error.message));
await page.addInitScript(() => {
  Object.defineProperty(navigator, 'clipboard', { value: { writeText: async (text) => { window.copiedText = text; } } });
});
const request = async (route, data, method = data ? 'POST' : 'GET') => {
  const response = await context.request.fetch(`${base}/api/${route}`, { method, data, headers: { 'X-Votport': '1' } });
  assert.ok(response.ok(), `${route}: ${response.status()} ${await response.text()}`);
  return response.status() === 204 ? null : response.json();
};
try {
  await request('admin/login', { password: process.env.ADMIN_PASSWORD });
  await page.goto(`${base}/s/fixture`);
  await page.locator('#delivery-evidence').evaluate((node) => { node.open = true; });
  await page.locator('#evidence-copy-key').click();
  await page.waitForFunction(() => /^[0-9a-f]{64}$/.test(window.copiedText));
  const holder = await page.evaluate(() => window.copiedText);
  assert.match(await page.locator('#evidence-open-app').getAttribute('href'), /^votport:\/\/s\//);
  await page.goto(`${base}/deliver#workflows`);
  await page.locator('#workflow-project-panel').waitFor({ state: 'visible' });
  await page.locator('#workflow-project-panel').evaluate((node) => { node.open = true; });
  await page.fill('#wp-id', project);
  await page.fill('#wp-label', 'Browser delivery');
  await page.fill('#wp-directory', project);
  await page.fill('#wp-metadata', 'client');
  await page.fill('#wp-recipients', `recipient@example.com ${holder}`);
  await page.fill('#wp-domains', 'example.com');
  await page.locator('#workflow-save-project button[type=submit]').click();
  await page.getByRole('dialog', { name: 'Save project rules' }).getByRole('button', { name: 'Save rules', exact: true }).click();
  await page.waitForFunction((id) => [...document.querySelector('#workflow-project').options].some((option) => option.value === id), project);
  await page.selectOption('#workflow-project', project);
  await page.fill('#workflow-label', 'Recipient package');
  await page.locator('#workflow-metadata input').fill('Example customer');
  await page.locator('#workflow-recipients input').check();
  const responsePromise = page.waitForResponse((response) => response.url().endsWith('/api/workflows/jobs') && response.request().method() === 'POST');
  await page.locator('#workflow-create button[type=submit]').click();
  const issued = await (await responsePromise).json();
  const id = issued.job.id;
  let ready;
  for (let index = 0; index < 100; index += 1) {
    ready = await request(`workflows/jobs/${id}`);
    if (ready.job.state === 'ready') break;
    assert.notEqual(ready.job.state, 'failed', JSON.stringify(ready));
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.ok(ready.url, JSON.stringify(ready));
  await page.click('#workflow-refresh');
  await page.locator('#workflow-jobs article').filter({ hasText: ready.job.manifest }).getByRole('button', { name: 'Copy download link', exact: true }).click();
  await page.waitForFunction((url) => window.copiedText === url, ready.url);
  await page.waitForTimeout(250);
  assert.equal(await page.locator('dialog[open]').count(), 0);
  await page.screenshot({ path: path.join(root, 'workflow-admin.png'), fullPage: true });
  await page.goto(ready.url);
  await page.locator('#delivery-evidence').evaluate((node) => { node.open = true; });
  await page.setInputFiles('#evidence-files', path.join(directory, 'saved.bin'));
  await page.click('#evidence-verify');
  await page.waitForFunction(() => document.querySelector('#evidence-records').textContent.includes('Verified: recorded'));
  let evidence = await request(`workflows/jobs/${id}/evidence`);
  assert.equal(evidence.evidence.length, 1);
  // An expired acceptance of an older challenge must not hide fresh acceptance.
  await page.evaluate(async () => {
    const db = await new Promise((resolve, reject) => { const open = indexedDB.open('votport-delivery-evidence'); open.onsuccess = () => resolve(open.result); open.onerror = () => reject(open.error); });
    const records = await new Promise((resolve) => { const get = db.transaction('records').objectStore('records').getAll(); get.onsuccess = () => resolve(get.result); });
    const expired = structuredClone(records.find((record) => record?.evidence?.kind === 'verified'));
    expired.id = 'expired-fixture'; expired.status = 'expired'; expired.evidence.kind = 'accepted'; expired.evidence.authorization.signature = 'old-challenge';
    await new Promise((resolve, reject) => { const tx = db.transaction('records', 'readwrite'); tx.objectStore('records').put(expired, 'evidence:expired-fixture'); tx.oncomplete = resolve; tx.onabort = () => reject(tx.error); });
    db.close();
  });
  await request(`admin/outbound-grants/${id}`, undefined, 'DELETE');
  await page.reload();
  await page.locator('#delivery-evidence').evaluate((node) => { node.open = true; });
  await page.click('#evidence-refresh');
  await page.getByRole('button', { name: 'Accept verified delivery', exact: true }).waitFor();
  await page.route('**/api/evidence', (route) => route.fulfill({ status: 503, contentType: 'application/json', body: '{}' }));
  page.once('dialog', (dialog) => dialog.accept());
  await page.getByRole('button', { name: 'Accept verified delivery', exact: true }).click();
  await page.waitForFunction(() => document.querySelector('#evidence-records').textContent.includes('Acceptance: pending'));
  await page.unroute('**/api/evidence');
  await page.click('#evidence-retry');
  await page.waitForFunction(() => document.querySelector('#evidence-records').textContent.includes('Acceptance: recorded'));
  evidence = await request(`workflows/jobs/${id}/evidence`);
  assert.deepEqual(evidence.evidence.map((record) => record.evidence.kind).sort(), ['accepted', 'verified']);
  await page.screenshot({ path: path.join(root, 'recipient-evidence.png'), fullPage: true });
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), 'Evidence must wrap within the viewport');
  assert.deepEqual(errors, []);
  console.log('Project UI, recipient-key admission, copy/open actions, saved-file verification, revoked-link recovery and queued acceptance: passed');
} finally {
  await browser.close();
}
