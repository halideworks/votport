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
  await page.route('**/api/workflows/jobs?*', async (route) => {
    const response = await route.fetch(), body = await response.json();
    body.jobs = body.jobs.filter(({ job }) => job.id !== issued.job.id);
    await route.fulfill({ response, json: body });
  });
  await page.goto(`${base}/deliver`);
  const olderJob = page.waitForResponse((response) => response.url().endsWith(`/api/workflows/jobs/${issued.job.id}`));
  await page.goto(`${base}/workflows#job-${issued.job.id}`);
  assert.equal((await olderJob).status(), 200);
  await page.locator(`#job-${issued.job.id} details[open]`).waitFor();
  await page.unroute('**/api/workflows/jobs?*');
  const jobA = 'a'.repeat(32), jobB = 'b'.repeat(32);
  for (let lookup = 0; lookup < 2; lookup++) {
    let releaseJob, jobStarted;
    const heldJob = new Promise((resolve) => releaseJob = resolve), jobPending = new Promise((resolve) => jobStarted = resolve);
    await page.route(`**/api/workflows/jobs/${jobA}`, async (route) => { jobStarted(); await heldJob; await route.fulfill({ json: { ...issued, job: { ...issued.job, id: jobA } } }); });
    await page.route(`**/api/workflows/jobs/${jobB}`, (route) => route.fulfill({ json: { ...issued, job: { ...issued.job, id: jobB } } }));
    await page.evaluate((id) => { window.location.hash = `job-${id}`; }, jobA); await jobPending;
    await page.evaluate((id) => { window.location.hash = `job-${id}`; }, jobB);
    await page.locator(`#job-${jobB}`).waitFor();
    const oldResponse = page.waitForResponse((response) => response.url().endsWith(`/api/workflows/jobs/${jobA}`));
    releaseJob(); await (await oldResponse).finished();
    await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    assert.equal(await page.locator(`#job-${jobB}`).count(), 1, 'A delayed previous lookup cannot replace the current job');
    assert.equal(await page.locator(`#job-${jobA}`).count(), 0);
    await page.unroute(`**/api/workflows/jobs/${jobA}`); await page.unroute(`**/api/workflows/jobs/${jobB}`);
  }

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
  await page.locator('#receiving-storage').waitFor();
  await page.click('#receiving-check');
  await page.getByText('Storage checks passed. Ready to receive.', { exact: true }).waitFor();
  await layout('receiving-storage');
  const nas = { path: '/storage/production/receiving', storage: { path: '/storage/production/receiving', filesystem: 'cifs', source: '//studio-nas/production', mount_root: '/', inode: '9007199254740993', service_uid: 1000 }, nas: true, ready: false, qualified: null, error: 'This share requires qualification before receiving.' };
  let qualification;
  await page.route('**/api/admin/receiving-storage', async (route) => {
    if (route.request().method() === 'POST') {
      qualification = route.request().postDataJSON();
      await route.fulfill({ json: { ...nas, ready: true, error: null } });
    } else await route.fulfill({ json: nas });
  });
  await page.reload(); await page.locator('#receiving-nas-contract').waitFor();
  await layout('receiving-nas-qualification');
  await page.click('#receiving-check');
  assert.equal(qualification, undefined, 'NAS qualification requires both acknowledgments');
  await page.check('#receiving-stable'); await page.check('#receiving-private');
  await page.click('#receiving-check');
  await page.getByText('Storage checks passed. Ready to receive.', { exact: true }).waitFor();
  assert.deepEqual(qualification, { storage: nas.storage, enable: true, stable_acknowledgments: true, private_namespace: true });
  assert.ok(await page.locator('#receiving-nas-contract').isHidden());
  await layout('receiving-nas-ready');
  await page.unroute('**/api/admin/receiving-storage');
  const local = { ...nas, nas: false, storage: { ...nas.storage, filesystem: 'ext4', source: '/dev/fixture' }, error: 'Protect the private control folder before receiving.' };
  let localChecked = false;
  await page.route('**/api/admin/receiving-storage', async (route) => {
    if (route.request().method() === 'POST') {
      assert.deepEqual(route.request().postDataJSON().storage, local.storage);
      localChecked = true;
      await route.fulfill({ json: { ...local, ready: true, error: null } });
    } else await route.fulfill({ json: local });
  });
  await page.reload(); await page.locator('#receiving-storage').waitFor();
  assert.ok(await page.locator('#receiving-check').isEnabled(), 'Local storage can be checked after permissions are repaired');
  await page.click('#receiving-check');
  await page.getByText('Storage checks passed. Ready to receive.', { exact: true }).waitFor();
  assert.ok(localChecked);
  await page.unroute('**/api/admin/receiving-storage');
  await page.reload(); await page.locator('#receiving-storage').waitFor();
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
  await api('workflows/projects', { ...project, destinations: [storageId] }, 'PUT');
  const { credential_source, ...disabled } = (await api('workflows/storage')).storage.find((item) => item.id === storageId);
  assert.equal(credential_source, 'saved');
  await api('workflows/storage', { storage: { ...disabled, enabled: false } }, 'PUT');
  await page.goto(`${base}/workflows#projects`);
  await page.locator('#workflow-project-list article').filter({ hasText: id }).getByRole('button', { name: 'Edit project' }).click();
  assert.ok(await page.locator(`#wp-destinations input[value="${storageId}"]`).isChecked(), 'Unavailable storage must remain selected in an existing policy');
  await saveProject();
  assert.equal((await api('workflows/projects')).projects.find((item) => item.id === id).destinations[0], storageId);
  await page.getByRole('link', { name: 'Automation', exact: true }).click();
  await page.locator('#automation-token-form').waitFor(); await layout('automation');
  for (const name of ['receive', 'audit', 'tenants', 'system']) {
    await page.goto(`${base}/${name}`);
    await page.locator('#nav a[aria-current=page]').waitFor();
    await page.waitForLoadState('networkidle');
    await layout(name);
  }
  await page.route('**/api/admin/audit?*', (route) => route.fulfill({ contentType: 'application/x-ndjson', body: JSON.stringify({ at: 1, rowid: 1, event: 'automation_refused', actor: `automation:${'a'.repeat(32)}`, detail: { permission: 'deliveries:create' } }) + '\n' }));
  await page.goto(`${base}/audit`); await page.locator('.audit-actor').waitFor();
  await layout('audit-automation-identity');
  await page.unroute('**/api/admin/audit?*');

  await page.goto(`${base}/storage`); await page.click('#storage-new');
  await page.selectOption('#ws-kind', 'folder'); await page.fill('#ws-label', 'Shared reception');
  await page.fill('#ws-id', `${storageId}_folder`); await page.fill('#ws-directory', path.join(root, 'shared'));
  await fs.mkdir(path.join(root, 'shared'), { recursive: true });
  await layout('shared-folder-editor');
  let saved = page.waitForResponse((response) => response.url().endsWith('/api/workflows/storage') && response.request().method() === 'PUT');
  await page.locator('#workflow-save-storage button[type=submit]').click(); assert.equal((await saved).status(), 200);
  await page.waitForFunction(() => !document.querySelector('#storage-test').disabled);
  await page.click('#storage-test'); await page.getByText(/The server can read this shared folder/).waitFor();
  const request = await api('admin/links', { label: 'Peer connection fixture' });
  await page.click('#storage-new'); await page.selectOption('#ws-kind', 'votport');
  await page.fill('#ws-label', 'Connected studio'); await page.fill('#ws-id', `${storageId}_peer`);
  await page.fill('#ws-port-link', request.link.url); await layout('peer-port-editor');
  saved = page.waitForResponse((response) => response.url().endsWith('/api/workflows/storage') && response.request().method() === 'PUT');
  await page.locator('#workflow-save-storage button[type=submit]').click(); assert.equal((await saved).status(), 200);
  await page.waitForFunction(() => document.querySelector('#ws-port-auth').value === 'keep');
  assert.equal(await page.inputValue('#ws-port-link'), '', 'Saved receive capability stays private');
  const reception = await api('workflows/projects', { ...project, id: `${storageId}_reception`, directory: `${id}-incoming`, revision: 0, label: `Reception ${id}`, receive: true, release: 'local', destinations: [`${storageId}_folder`], recipients: [], require_approval: false, sequence: null, media: null, scan_required: false }, 'PUT');
  await page.goto(`${base}/workflows#projects`);
  await page.locator('#workflow-project-list article').filter({ hasText: `Reception ${id}` }).getByRole('button', { name: 'Edit project' }).click();
  assert.ok(await page.locator('#wp-receive').isChecked());
  assert.equal(await page.inputValue('#wp-release'), 'local'); await layout('reception-project-editor');
  await page.goto(`${base}/receive`); await page.locator('#create-workflow select').selectOption(reception.id);
  await page.fill('#create-label', `Incoming ${id}`);
  for (const input of await page.locator('#create-workflow input[data-metadata]').all()) await input.fill('Example studio');
  await layout('reception-request-editor');
  await page.locator('#create-form button[type=submit]').click(); await page.locator('#new-link:not([hidden])').waitFor();
  const requests = await api('admin/links');
  const incoming = requests.links.find((link) => link.label === `Incoming ${id}`);
  assert.equal(incoming.workflow.project_id, reception.id);
  await page.locator(`#link-${incoming.id}`).getByText('Reception workflow', { exact: true }).click();
  await layout('existing-reception-workflow');

  const status = await api('admin/status'); status.receiving = [];
  await page.route('**/api/admin/status?*', (route) => route.fulfill({ json: status }));
  async function pollStatus() {
    status.sessions_active++;
    await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
    await page.waitForFunction((count) => document.querySelector('#stat-active').textContent === String(count), status.sessions_active);
  }
  await page.goto(`${base}/receive?search=${incoming.id}#link-${incoming.id}`);
  const card = page.locator(`#link-${incoming.id}`), editor = card.locator('.reception-workflow');
  await editor.waitFor(); await page.waitForLoadState('networkidle');
  await editor.evaluate((node) => { node.open = false; });
  let releaseList, listStarted, listReads = 0;
  const heldList = new Promise((resolve) => releaseList = resolve), listPending = new Promise((resolve) => listStarted = resolve);
  await page.route('**/api/admin/links?*', async (route) => {
    listReads++; const response = await route.fetch(); listStarted(); await heldList;
    await route.fulfill({ response });
  });
  status.receiving = [{ link_id: incoming.id, received: 1, total: 100, started_at: status.now, transport: 'http' }];
  await pollStatus();
  await listPending;
  await editor.evaluate((node) => { node.open = true; });
  await editor.locator('input[data-metadata]').fill('Unsaved reception draft');
  releaseList(); await page.waitForLoadState('networkidle');
  assert.equal(await editor.locator('input[data-metadata]').inputValue(), 'Unsaved reception draft', 'A response already in flight preserves the draft');
  await editor.evaluate((node) => { node.open = false; });
  status.receiving = [];
  await pollStatus();
  await page.waitForLoadState('networkidle');
  assert.equal(listReads, 1, 'A closed dirty editor still prevents poll replacement');
  let releasePatch, patchStarted;
  const heldPatch = new Promise((resolve) => releasePatch = resolve), patchPending = new Promise((resolve) => patchStarted = resolve);
  await page.route(`**/api/admin/links/${incoming.id}`, async (route) => { patchStarted(); await heldPatch; await route.continue(); });
  await editor.evaluate((node) => { node.open = true; });
  await editor.getByRole('button', { name: 'Save reception workflow' }).click(); await patchPending;
  assert.ok(await editor.locator('input[data-metadata]').isDisabled(), 'Inputs cannot create an unsaved revision while PATCH is in flight');
  await editor.evaluate((node) => { node.open = false; });
  await pollStatus();
  assert.equal(listReads, 1, 'A pending save preserves its editor');
  releasePatch(); await page.waitForFunction(() => document.querySelector('.reception-workflow [role=status]').textContent.startsWith('Saved.'));
  assert.match(await editor.locator('[role=status]').textContent(), /^Saved\./);
  await pollStatus();
  await page.waitForFunction(() => !document.querySelector('.reception-workflow [role=status]').textContent);
  assert.equal(listReads, 2, 'The deferred refresh runs after editing finishes');
  await page.unroute('**/api/admin/status?*'); await page.unroute('**/api/admin/links?*'); await page.unroute(`**/api/admin/links/${incoming.id}`);

  await page.goto(`${base}/storage`);
  let releaseInitial, initialStarted, initialReads = 0;
  const heldInitial = new Promise((resolve) => releaseInitial = resolve), initialPending = new Promise((resolve) => initialStarted = resolve);
  await page.route('**/api/workflows/jobs?*', async (route) => {
    initialReads++; const response = await route.fetch();
    if (initialReads === 1) { initialStarted(); await heldInitial; }
    await route.fulfill({ response });
  });
  await page.goto(`${base}/workflows`); await initialPending;
  await page.getByRole('link', { name: 'Projects', exact: true }).click();
  await page.locator('#workflow-project-list article').first().waitFor();
  const initialResponse = page.waitForResponse((response) => response.url().includes('/api/workflows/jobs?'));
  releaseInitial(); await (await initialResponse).finished();
  await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  await page.getByRole('link', { name: 'Deliveries', exact: true }).click();
  await page.locator('#workflow-jobs article').first().waitFor();
  assert.equal(initialReads, 2, 'An abandoned initial request must not mark an unrendered panel loaded');
  await page.unroute('**/api/workflows/jobs?*');

  const session = await api('admin/session');
  await page.goto(`${base}/receive`);
  await page.route(/\/(workflows|storage)$/, async (route) => {
    const response = await route.fetch();
    const body = (await response.text()).replace(/(<script id="admin-session" type="application\/json">)[\s\S]*?(<\/script>)/, (_, start, end) => start + JSON.stringify({ ...session, role: 'operator', tenant: 'named-tenant' }) + end);
    await route.fulfill({ response, body });
  });
  await page.goto(`${base}/workflows#projects`); await page.locator('#workflow-project-list article').first().waitFor();
  assert.ok(await page.locator('#workflow-new-project').isHidden());
  assert.equal(await page.getByRole('button', { name: 'Edit project', exact: true }).count(), 0);
  await page.goto(`${base}/storage`); await page.locator('#storage-access').waitFor();
  assert.ok(await page.locator('#storage-new').isHidden());
  assert.ok(await page.locator('#receiving-storage').isHidden());
  assert.equal(await page.getByRole('button', { name: 'Edit connection', exact: true }).count(), 0);
  assert.deepEqual(errors, []);
  console.log('Responsive admin forms, project creation, lost-response recovery, automatic status refresh, policy invalidation, cumulative event export, private storage credentials and stale connection tests: passed');
} finally { await browser.close(); }
