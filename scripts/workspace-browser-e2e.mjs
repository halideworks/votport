import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { chromium } from 'playwright';

const base = process.env.BASE_URL, root = process.env.WORKFLOW_TEST_ROOT;
if (!base || !root || !process.env.ADMIN_PASSWORD) throw new Error('Use BASE_URL, WORKFLOW_TEST_ROOT and ADMIN_PASSWORD for an isolated instance.');
const id = `workspace-${Date.now()}`;
await fs.mkdir(path.join(root, 'library', id), { recursive: true });
await fs.writeFile(path.join(root, 'library', id, 'master.txt'), 'UI delivery fixture\n');
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'reduce' });
const page = await context.newPage(), errors = [];
page.on('pageerror', (error) => errors.push(error.message));
const api = async (route, data, method = data ? 'POST' : 'GET') => {
  const response = await context.request.fetch(`${base}/api/${route}`, { method, data, headers: { 'X-Votport': '1' } });
  assert.ok(response.ok(), `${route}: ${response.status()} ${await response.text()}`);
  return response.json();
};
async function layout(name) {
  for (const width of [1440, 900, 640, 390, 320]) {
    await page.setViewportSize({ width, height: 1000 });
    const theme = width < 640 ? 'light' : 'dark';
    if (await page.evaluate(() => document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark')) !== theme) await page.click('#theme-toggle');
    const defects = await page.evaluate(() => {
      const result = [];
      if (document.documentElement.scrollWidth > innerWidth) result.push(`Page overflows by ${document.documentElement.scrollWidth - innerWidth}px`);
      const controls = [...document.querySelectorAll('input:not([type=hidden]),select,textarea,button')].filter((node) => node.checkVisibility()).map((node) => {
        const box = node.getBoundingClientRect(), rect = { left: box.left, right: box.right, top: box.top, bottom: box.bottom };
        for (let parent = node.parentElement; parent; parent = parent.parentElement) {
          const style = getComputedStyle(parent), clip = parent.getBoundingClientRect();
          if (/(auto|scroll|hidden|clip)/.test(style.overflowX)) { rect.left = Math.max(rect.left, clip.left); rect.right = Math.min(rect.right, clip.right); }
          if (/(auto|scroll|hidden|clip)/.test(style.overflowY)) { rect.top = Math.max(rect.top, clip.top); rect.bottom = Math.min(rect.bottom, clip.bottom); }
        }
        return { id: node.id || node.textContent.trim(), rect };
      }).filter(({ rect }) => rect.right > rect.left && rect.bottom > rect.top);
      for (let i = 0; i < controls.length; i++) for (let j = i + 1; j < controls.length; j++) {
        const a = controls[i], b = controls[j];
        if (Math.min(a.rect.right, b.rect.right) - Math.max(a.rect.left, b.rect.left) > 1 && Math.min(a.rect.bottom, b.rect.bottom) - Math.max(a.rect.top, b.rect.top) > 1) result.push(`${a.id} overlaps ${b.id}`);
      }
      return result;
    });
    if (defects.length) await page.screenshot({ path: path.join(root, `${name}-${width}-failure.png`), fullPage: true });
    assert.deepEqual(defects, [], `${name} at ${width}px`);
    if (width === 1440 || width === 390) await page.screenshot({ path: path.join(root, `${name}-${width}.png`), fullPage: true });
  }
  await page.setViewportSize({ width: 1440, height: 1000 });
}
async function saveProject() {
  await page.locator('#workflow-save-project button[type=submit]').click();
  await page.getByRole('dialog', { name: 'Save project rules' }).getByRole('button', { name: 'Save rules', exact: true }).click();
  await page.locator('#workflow-save-project').waitFor({ state: 'hidden' });
}
async function saveStorage() {
  const response = page.waitForResponse((r) => r.url().endsWith('/api/workflows/storage') && r.request().method() === 'PUT');
  await page.locator('#workflow-save-storage button[type=submit]').click();
  assert.equal((await response).status(), 200);
  await page.waitForFunction(() => document.querySelector('#ws-auth').value === 'keep');
  await page.waitForFunction(() => !document.querySelector('#storage-test').disabled && !document.querySelector('#workflow-save-storage button[type=submit]').disabled);
}
try {
  await api('admin/login', { password: process.env.ADMIN_PASSWORD });
  await page.goto(`${base}/deliver`);
  await page.locator('#nav a[aria-current=page]').waitFor();
  await layout('deliver');
  await page.getByRole('link', { name: 'Workflows', exact: true }).click();
  await page.getByRole('link', { name: 'Projects', exact: true }).click();
  await page.click('#workflow-new-project');
  await page.fill('#wp-label', 'Studio masters');
  assert.equal(await page.inputValue('#wp-id'), 'studio-masters');
  await page.fill('#wp-id', id); await page.fill('#wp-directory', id);
  await page.click('#wp-add-member');
  await page.locator('#wp-members input').fill('producer@example.com');
  await page.locator('#wp-members select').selectOption('approver');
  await page.click('#wp-add-metadata'); await page.locator('#wp-metadata input').fill('Client');
  await page.click('#wp-add-recipient');
  await page.locator('#wp-recipients input[type=email]').fill('client@example.com');
  await page.locator('#wp-recipients input[data-key=holder]').fill('a'.repeat(64));
  await page.check('#wp-sequence-enabled'); await page.check('#wp-media-enabled');
  await layout('project-editor');
  await page.uncheck('#wp-sequence-enabled'); await page.uncheck('#wp-media-enabled');
  await page.getByRole('button', { name: 'Remove recipient', exact: true }).click();
  await saveProject();
  assert.equal((await api('workflows/projects')).projects.find((p) => p.id === id).members['producer@example.com'], 'approver');
  await page.click('#workflow-new'); await page.selectOption('#workflow-project', id);
  await page.fill('#workflow-label', 'Final master'); await page.locator('#workflow-metadata input').fill('Example studio');
  await layout('delivery-editor');
  let issued;
  await page.route('**/api/workflows/jobs', async (route) => {
    const response = await route.fetch(); issued = await response.json();
    await route.fulfill({ status: 503, json: { error: 'Lost response fixture' } });
  }, { times: 1 });
  await page.locator('#workflow-create button[type=submit]').click();
  await page.getByText('Lost response fixture', { exact: true }).waitFor();
  await page.reload(); await page.click('#workflow-new');
  await page.locator('#workflow-create').waitFor();
  assert.equal(await page.inputValue('#workflow-label'), 'Final master');
  assert.equal(await page.locator('#workflow-metadata input').inputValue(), 'Example studio');
  await page.route('**/api/workflows/jobs', (route) => route.fulfill({ status: 403, json: { error: 'Retry denied fixture' } }), { times: 1 });
  await page.locator('#workflow-create button[type=submit]').click();
  await page.getByText('Retry denied fixture', { exact: true }).waitFor();
  assert.equal(await page.evaluate(() => JSON.parse(sessionStorage.getItem('votport-workflow-draft:')).operation_id), issued.job.request.operation_id);
  let jobReads = 0;
  await page.route('**/api/workflows/jobs?*', async (route) => {
    const response = await route.fetch(), body = await response.json(); jobReads++;
    if (jobReads === 1) for (const entry of body.jobs) if (entry.job.id === issued.job.id) { entry.job.state = 'preparing'; entry.url = null; }
    await route.fulfill({ response, json: body });
  });
  await page.locator('#workflow-create button[type=submit]').click();
  await page.locator(`#job-${issued.job.id}`).getByText('Preparing files', { exact: true }).waitFor();
  await page.locator(`#job-${issued.job.id}`).getByRole('button', { name: 'Copy download link', exact: true }).waitFor({ timeout: 20000 });
  assert.ok(jobReads >= 2, 'Preparation should refresh automatically even when the API returns a next cursor');
  assert.equal((await api('workflows/jobs?limit=100')).jobs.filter((entry) => entry.job.project.id === id).length, 1, 'Retry recovers the committed job');
  await page.unroute('**/api/workflows/jobs?*');
  await page.getByRole('link', { name: 'Projects', exact: true }).click();
  await page.locator('#workflow-project-list article').filter({ hasText: id }).getByRole('button', { name: 'Edit project' }).click();
  await page.fill('#wp-label', 'Studio masters updated'); await saveProject();
  await page.getByRole('link', { name: 'Deliveries', exact: true }).click();
  await page.locator(`#job-${issued.job.id}`).waitFor();
  await page.locator(`#job-${issued.job.id}`).getByRole('button', { name: 'Copy download link', exact: true }).waitFor({ state: 'hidden' });
  assert.equal(await page.locator(`#job-${issued.job.id}`).getByRole('button', { name: 'Copy download link', exact: true }).count(), 0, 'Changed project rules must remove the cached link');

  let eventPage = 0;
  const records = [1, 2].map((n) => ({ id: n, kind: 'delivery_created', created_at: n, signature: `signature-${n}` }));
  await page.route('**/api/workflows/events?*', (route) => route.fulfill({ json: { events: eventPage < 2 ? [records[eventPage++]] : [], next: Math.min(eventPage, 2) } }));
  await page.getByRole('link', { name: 'Activity', exact: true }).click();
  await page.locator('#workflow-events .event-row').waitFor();
  await page.locator('#workflow-events-next').evaluate((button) => { button.click(); button.click(); });
  await page.waitForFunction(() => document.querySelectorAll('#workflow-events .event-row').length === 2);
  await page.click('#workflow-events-next'); await page.getByRole('button', { name: 'Check for new activity' }).waitFor();
  const download = page.waitForEvent('download'); await page.click('#workflow-events-export');
  assert.deepEqual(JSON.parse(await fs.readFile(await (await download).path(), 'utf8')), records);

  await page.getByRole('link', { name: 'Storage', exact: true }).click();
  await page.click('#storage-new'); await page.fill('#ws-label', id); await page.fill('#ws-bucket', process.env.S3_TEST_BUCKET || 'fixture-bucket');
  await page.selectOption('#ws-provider', 'custom'); await page.fill('#ws-endpoint', 'http://127.0.0.1:19000');
  await page.fill('#ws-access-key', 'votport-fixture'); await page.fill('#ws-secret-key', 'votport-fixture-secret');
  await layout('storage-editor');
  let releaseSave, saveStarted;
  const pendingSave = new Promise((resolve) => releaseSave = resolve), savingStarted = new Promise((resolve) => saveStarted = resolve);
  await page.route('**/api/workflows/storage', async (route) => {
    if (route.request().method() !== 'PUT') return route.fulfill({ status: 503, json: { error: 'List refresh failed fixture' } });
    const response = await route.fetch(); saveStarted(); await pendingSave; await route.fulfill({ response });
  });
  const saving = saveStorage(); await savingStarted;
  assert.ok(await page.locator('#workflow-save-storage').evaluate((form) => form.inert), 'Inputs stay locked until the saved revision is available');
  releaseSave(); await saving; await page.unroute('**/api/workflows/storage');
  await page.getByText('List refresh failed fixture', { exact: true }).waitFor();
  await page.fill('#ws-label', `${id} recovered`); await saveStorage();
  const storageId = id.replaceAll('-', '_');
  const storage = (await api('workflows/storage')).storage.find((item) => item.id === storageId);
  assert.equal(storage.credential_source, 'saved'); assert.ok(!JSON.stringify(storage).includes('votport-fixture-secret'));
  assert.equal(await page.inputValue('#ws-secret-key'), '');
  if (process.env.S3_TEST_BUCKET) { await page.click('#storage-test'); await page.getByText(/Connection verified\. Bucket listing works/).waitFor(); }
  for (const change of ['input', 'editor']) {
    let release, started;
    const pending = new Promise((resolve) => release = resolve), requestStarted = new Promise((resolve) => started = resolve);
    await page.route('**/api/workflows/storage/*/test', async (route) => { started(); await pending; await route.fulfill({ json: { ok: true, message: 'Stale test success' } }); }, { times: 1 });
    await page.click('#storage-test'); await requestStarted;
    if (change === 'input') await page.fill('#ws-label', `${id} changed`);
    else await page.click('#storage-new');
    const response = page.waitForResponse((r) => r.url().endsWith('/test')); release(); await response;
    await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    assert.ok(!await page.locator('#storage-test-result').textContent().then((text) => text.includes('Stale test success')));
    assert.ok(await page.locator('#storage-test').isDisabled());
    await page.locator('#storage-list article').filter({ hasText: id }).getByRole('button', { name: 'Edit connection', exact: true }).click();
  }
  await page.fill('#ws-label', `${id} renamed`); await saveStorage();
  assert.equal((await api('workflows/storage')).storage.find((item) => item.id === storageId).credential_source, 'saved');
  const project = (await api('workflows/projects')).projects.find((item) => item.id === id);
  await api('workflows/projects', { ...project, export_storage: storageId }, 'PUT');
  const { credential_source, ...disabled } = (await api('workflows/storage')).storage.find((item) => item.id === storageId);
  assert.equal(credential_source, 'saved');
  await api('workflows/storage', { storage: { ...disabled, enabled: false } }, 'PUT');
  await page.goto(`${base}/workflows#projects`);
  await page.locator('#workflow-project-list article').filter({ hasText: id }).getByRole('button', { name: 'Edit project' }).click();
  assert.equal(await page.inputValue('#wp-export'), storageId, 'Unavailable storage must remain selected in an existing policy');
  await saveProject();
  assert.equal((await api('workflows/projects')).projects.find((item) => item.id === id).export_storage, storageId);
  await page.getByRole('link', { name: 'Automation', exact: true }).click();
  await page.locator('#automation-token-form').waitFor(); await layout('automation');
  for (const name of ['receive', 'audit', 'tenants', 'system']) {
    await page.goto(`${base}/${name}`);
    await page.locator('#nav a[aria-current=page]').waitFor();
    await page.waitForLoadState('networkidle');
    await layout(name);
  }

  const session = await api('admin/session');
  await page.route('**/api/admin/session', (route) => route.fulfill({ json: { ...session, role: 'operator', tenant: 'named-tenant' } }));
  await page.goto(`${base}/workflows#projects`); await page.locator('#workflow-project-list article').first().waitFor();
  assert.ok(await page.locator('#workflow-new-project').isHidden());
  assert.equal(await page.getByRole('button', { name: 'Edit project', exact: true }).count(), 0);
  await page.goto(`${base}/storage`); await page.locator('#storage-access').waitFor();
  assert.ok(await page.locator('#storage-new').isHidden());
  assert.equal(await page.getByRole('button', { name: 'Edit connection', exact: true }).count(), 0);
  assert.deepEqual(errors, []);
  console.log('Responsive admin forms, project creation, lost-response recovery, automatic status refresh, policy invalidation, cumulative event export, private storage credentials and stale connection tests: passed');
} finally { await browser.close(); }
