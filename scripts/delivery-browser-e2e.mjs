import { openAncestors } from './browser-helpers.mjs';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import fs from 'node:fs/promises';
import path from 'node:path';

const base = process.env.BASE_URL;
const root = process.env.WORKFLOW_TEST_ROOT;
if (!base || !root || !process.env.ADMIN_PASSWORD) throw new Error('Set BASE_URL, WORKFLOW_TEST_ROOT and ADMIN_PASSWORD for an isolated test instance.');
const project = `browser-${Date.now()}`;
const directory = path.join(root, 'library', project);
for (const part of ['a', 'b']) {
  await fs.mkdir(path.join(directory, part), { recursive: true });
  await fs.writeFile(path.join(directory, part, 'saved.bin'), 'Recipient verification fixture.\n');
}
const browser = await chromium.launch();
const context = await browser.newContext();
const page = await context.newPage();
const errors = [];
page.on('pageerror', (error) => { errors.push(error.message); console.error(error.message); });
await page.addInitScript(() => {
  window.showDirectoryPicker = () => window.savedDirectory;
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
  await openAncestors(page.locator('#evidence-copy-key')); await page.locator('#evidence-copy-key').click();
  await page.waitForFunction(() => /^[0-9a-f]{64}$/.test(window.copiedText));
  const holder = await page.evaluate(() => window.copiedText);
  assert.match(await page.locator('#evidence-open-app').getAttribute('href'), /^votport:\/\/s\//);
  await page.goto(`${base}/deliver#workflows`);
  await page.waitForURL('**/workflows');
  assert.deepEqual(await page.locator('#workflow-filter-state option').evaluateAll((options) => options.filter((option) => option.value).map((option) => ({ id: option.value, label: option.textContent }))), [
    { id: 'queued', label: 'Scheduled' },
    { id: 'preparing', label: 'Preparing files' },
    { id: 'awaiting_approval', label: 'Needs approval' },
    { id: 'exporting', label: 'Delivering copies' },
    { id: 'retrying', label: 'Retry scheduled' },
    { id: 'ready', label: 'Ready to share' },
    { id: 'failed', label: 'Needs attention' },
    { id: 'cancelled', label: 'Cancelled' },
    { id: 'retiring', label: 'Cleaning up' },
    { id: 'retired', label: 'Archived' },
    { id: 'suspended', label: 'Held after restore' },
  ]);
  await page.getByRole('link', { name: 'Projects', exact: true }).click();
  await page.click('#workflow-new-project');
  await openAncestors(page.locator('#wp-id')); await page.fill('#wp-id', project);
  await page.fill('#wp-label', 'Browser delivery');
  await page.fill('#wp-directory', project);
  await openAncestors(page.locator('#wp-add-metadata')); await page.click('#wp-add-metadata');
  await page.locator('#wp-metadata input').fill('client');
  await page.click('#wp-add-recipient');
  await page.locator('#wp-recipients input[type=email]').fill('recipient@example.com');
  await page.locator('#wp-recipients input[data-key=holder]').fill(holder);
  await page.fill('#wp-domains', 'example.com');
  await page.locator('#workflow-save-project button[type=submit]').click();
  await page.getByRole('dialog', { name: 'Save project rules' }).getByRole('button', { name: 'Save rules', exact: true }).click();
  await page.waitForFunction((id) => [...document.querySelector('#workflow-project').options].some((option) => option.value === id), project);
  await page.click('#workflow-new');
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
  await page.locator(`#job-${id}`).getByRole('button', { name: 'Copy delivery link', exact: true }).click();
  await page.waitForFunction((url) => window.copiedText === url, ready.url);
  await page.waitForTimeout(250);
  assert.equal(await page.locator('dialog[open]').count(), 0);
  await page.screenshot({ path: path.join(root, 'workflow-admin.png'), fullPage: true });
  let refreshedRevision = ready.job.project.revision + 1;
  const reprocessRequests = [];
  await page.route('**/api/workflows/projects', async (route) => {
    const response = await route.fetch();
    const body = await response.json();
    body.projects = body.projects.map((item) => item.id === project ? { ...item, receive: true, revision: refreshedRevision } : item);
    await route.fulfill({ response, json: body });
  });
  await page.route('**/api/workflows/jobs?*', async (route) => {
    const response = await route.fetch();
    const body = await response.json();
    body.jobs = body.jobs.map((entry) => entry.job.id === id ? { ...entry, job: { ...entry.job, received: {} } } : entry);
    await route.fulfill({ response, json: body });
  });
  await page.route(`**/api/workflows/jobs/${id}/reprocess`, async (route) => {
    reprocessRequests.push(route.request().postDataJSON());
    await route.fulfill({ json: { job: { id: 'replacement' } } });
  });
  await page.click('#workflow-refresh');
  const reprocess = page.locator(`#job-${id}`).getByRole('button', { name: 'Reprocess with current rules', exact: true });
  await reprocess.waitFor();
  refreshedRevision += 1;
  await reprocess.click();
  const confirmation = page.getByRole('dialog', { name: 'Reprocess with current rules', exact: true });
  await confirmation.waitFor();
  assert.match(await confirmation.textContent(), new RegExp(`revision ${refreshedRevision}`));
  assert.match(await confirmation.textContent(), /may create new copies/);
  await confirmation.getByRole('button', { name: 'Cancel', exact: true }).click();
  assert.equal(reprocessRequests.length, 0);
  await reprocess.click();
  await confirmation.getByRole('button', { name: 'Create new delivery', exact: true }).click();
  await page.waitForURL('**/workflows#job-replacement');
  assert.deepEqual(reprocessRequests, [{ manifest: ready.job.manifest, project_revision: refreshedRevision }]);
  await page.unroute('**/api/workflows/projects');
  await page.unroute('**/api/workflows/jobs?*');
  await page.unroute(`**/api/workflows/jobs/${id}/reprocess`);

  await page.goto(ready.url);
  await page.locator('#delivery-evidence').evaluate((node) => { node.open = true; });
  await page.waitForSelector('#download-content:not([hidden])');
  await page.evaluate(async () => {
    window.savedDirectory = await navigator.storage.getDirectory();
    const file = await window.savedDirectory.getFileHandle('saved.bin', { create: true });
    const writable = await file.createWritable();
    await writable.write('Keep this existing file.');
    await writable.close();
  });
  await page.route('**/api/s/*/files/1', (route) => route.fulfill({ status: 404 }));
  await page.getByRole('button', { name: 'Download all files', exact: true }).click();
  await page.waitForFunction(() => document.getElementById('separate-download-status').textContent.startsWith('Downloaded 1/2.'), null, { timeout: 10000 }).catch(async (error) => { console.error(await page.locator('#separate-download-status').textContent()); throw error; });
  await page.evaluate(async () => {
    const selected = new DataTransfer();
    selected.items.add(await (await window.savedDirectory.getFileHandle('saved (2).bin')).getFile());
    document.getElementById('evidence-files').files = selected.files;
    window.partialEntries = new Set();
    for await (const name of window.savedDirectory.keys()) window.partialEntries.add(name);
  });
  await page.click('#evidence-verify');
  await page.waitForFunction(() => document.getElementById('evidence-status').textContent.startsWith('Missing or wrong-sized file:') || document.getElementById('evidence-records').textContent.includes('Verification reported to the sender.'), null, { timeout: 10000 });
  assert.match(await page.locator('#evidence-status').textContent(), /^Missing or wrong-sized file:/, 'one saved file must not verify both identical manifest entries');
  assert.equal((await request(`workflows/jobs/${id}/evidence`)).evidence.length, 0);
  await page.unroute('**/api/s/*/files/1');
  await page.getByRole('button', { name: 'Download all files', exact: true }).click();
  await page.waitForFunction(() => document.getElementById('separate-download-status').textContent === 'Downloaded 2 files.', null, { timeout: 10000 });
  await page.evaluate(async () => {
    const existing = await window.savedDirectory.getFileHandle('saved.bin');
    if (await (await existing.getFile()).text() !== 'Keep this existing file.') throw new Error('existing file was overwritten');
    const selected = new DataTransfer();
    for await (const [name, handle] of window.savedDirectory.entries()) {
      if (!window.partialEntries.has(name)) selected.items.add(await handle.getFile());
    }
    document.getElementById('evidence-files').files = selected.files;
  });
  const refreshed = page.waitForResponse((response) => response.url().includes('/api/s/') && response.url().includes('offset=0'));
  await page.evaluate(() => {
    document.getElementById('download-password').value = 'unused';
    document.getElementById('download-password-form').requestSubmit();
  });
  await refreshed;
  await page.waitForFunction(() => !document.getElementById('download-password-submit').disabled, null, { timeout: 10000 });
  await page.evaluate(async () => {
    const input = document.getElementById('evidence-files');
    window.savedSelection = input.files;
    const altered = new DataTransfer();
    const bytes = new Uint8Array(await input.files[0].arrayBuffer());
    bytes[0] ^= 1;
    altered.items.add(new File([bytes], input.files[0].name));
    for (const file of [...input.files].slice(1)) altered.items.add(file);
    input.files = altered.files;
  });
  await page.click('#evidence-verify');
  await page.waitForFunction(() => document.getElementById('evidence-status').textContent.startsWith('Verification failed:'), null, { timeout: 10000 });
  assert.equal((await request(`workflows/jobs/${id}/evidence`)).evidence.length, 0);
  await page.evaluate(() => { document.getElementById('evidence-files').files = window.savedSelection; });
  await page.click('#evidence-verify');
  await page.waitForFunction(() => document.querySelector('#evidence-records').textContent.includes('Verification reported to the sender.') || document.querySelector('#evidence-status').textContent.startsWith('Missing or wrong-sized file:'), null, { timeout: 10000 });
  assert.match(await page.locator('#evidence-records').textContent(), /Verification reported to the sender\./, await page.locator('#evidence-status').textContent());
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
  await openAncestors(page.locator('#evidence-refresh')); await page.click('#evidence-refresh');
  await page.getByRole('button', { name: 'Accept verified delivery', exact: true }).waitFor();
  await page.route('**/api/evidence', (route) => route.fulfill({ status: 503, contentType: 'application/json', body: '{}' }));
  page.once('dialog', (dialog) => dialog.accept());
  await page.getByRole('button', { name: 'Accept verified delivery', exact: true }).click();
  await page.waitForFunction(() => document.querySelector('#evidence-records').textContent.includes('report: pending'));
  await page.unroute('**/api/evidence');
  await openAncestors(page.locator('#evidence-retry')); await page.click('#evidence-retry');
  await page.waitForFunction(() => document.querySelector('#evidence-records').textContent.includes('Delivery accepted and reported to the sender.'));
  evidence = await request(`workflows/jobs/${id}/evidence`);
  assert.deepEqual(evidence.evidence.map((record) => record.evidence.kind).sort(), ['accepted', 'verified']);
  await page.screenshot({ path: path.join(root, 'recipient-evidence.png'), fullPage: true });
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), 'Evidence must wrap within the viewport');
  const grantDirectory = `${project}-keyboard`;
  await fs.mkdir(path.join(root, 'library', grantDirectory));
  await fs.writeFile(path.join(root, 'library', grantDirectory, 'sample.txt'), 'Keyboard fixture.');
  const createdGrant = await request('admin/outbound-grants', { directory: grantDirectory, label: 'Keyboard grant' });
  const pages = [];
  await page.route('**/api/admin/outbound-grants?*', async (route) => {
    const offset = Number(new URL(route.request().url()).searchParams.get('offset'));
    pages.push(offset);
    await route.fulfill({ json: {
      grants: Array.from({ length: 50 }, (_, index) => ({ ...createdGrant.grant, id: `older-${offset + index}`, label: `Other grant ${offset + index}` })),
      total: 5000, has_more: true, offset, limit: 50,
    } });
  });
  await page.goto(`${base}/deliver#grant-${createdGrant.grant.id}`);
  await page.locator(`#grant-${createdGrant.grant.id}`).waitFor();
  assert.deepEqual(pages, [0], 'A deep link looks up its grant without scanning history');
  await page.locator('#outbound-grants-load-more').click();
  await page.waitForFunction(() => document.querySelectorAll('#outbound-grants .link-item').length === 101);
  assert.deepEqual(pages, [0, 50], 'The separately revealed grant does not advance pagination');
  assert.equal(await page.locator(`#grant-${createdGrant.grant.id}`).count(), 1);
  await page.unroute('**/api/admin/outbound-grants?*');
  await page.goto(`${base}/deliver`);
  const grantCard = page.locator('#outbound-grants .card').filter({ has: page.getByRole('heading', { name: 'Keyboard grant', exact: true }) });
  await grantCard.waitFor();
  await page.route('**/api/admin/outbound-grants?*', async (route) => {
    const response = await route.fetch();
    await page.locator('#global-search-input').focus();
    await route.fulfill({ response });
  }, { times: 1 });
  await grantCard.getByRole('button', { name: /^Extend 7 days: / }).focus();
  await page.keyboard.press('Enter'); await page.locator('#confirm-ok').press('Enter');
  await page.waitForFunction(() => document.querySelector('#outbound-grants-status').textContent.startsWith('Delivery extended until'));
  assert.ok(await page.locator('#global-search-input').evaluate((node) => node === document.activeElement), 'A delayed grant refresh preserves newly moved focus');
  for (const [action, name, message] of [['Replace link', /^Replace link: /, 'Delivery link replaced.'], ['Extend 7 days', /^Extend 7 days: /, 'Delivery extended until'], ['Revoke', /^Revoke: /, 'Delivery revoked.']]) {
    if (action === 'Revoke') await page.route('**/api/admin/outbound-grants?*', (route) => route.fulfill({ status: 503 }), { times: 1 });
    await grantCard.getByRole('button', { name }).focus();
    await page.keyboard.press('Enter'); await page.locator('#confirm-ok').press('Enter');
    await page.waitForFunction((text) => document.querySelector('#outbound-grants-status').textContent.startsWith(text), message);
    const resultFocus = action === 'Replace link' ? '#outbound-url' : '#outbound-grants-status';
    assert.ok(await page.locator(resultFocus).evaluate((node) => node === document.activeElement), `${action} focuses its result`);
    if (action === 'Replace link') assert.match(await page.inputValue('#outbound-url'), /^https?:\/\//);
  }
  await page.getByText('Deliveries could not be loaded.', { exact: true }).waitFor();
  assert.deepEqual(errors, []);
  console.log('Project UI, recipient-key admission, copy/open actions, saved-file verification, revoked-link recovery and queued acceptance: passed');
} finally {
  await browser.close();
}
