import { openAncestors } from './browser-helpers.mjs';
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
page.on('dialog', (dialog) => dialog.accept());
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
    if (!await page.locator('dialog[open]').count() && await page.evaluate(() => document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark')) !== theme) await page.click('#theme-toggle');
    const defects = await page.evaluate(() => {
      const result = [];
      if (document.documentElement.scrollWidth > innerWidth) result.push(`Page overflows by ${document.documentElement.scrollWidth - innerWidth}px`);
      const controls = [...(document.querySelector('dialog[open]') || document).querySelectorAll('input:not([type=hidden]),select,textarea,button')].filter((node) => node.checkVisibility()).map((node) => {
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
    if (name === 'audit-automation-identity') assert.ok(await page.locator('.audit-field').evaluateAll((fields) => fields.every((field) => field.scrollWidth <= field.clientWidth + 1)), `Audit values stay within their fields at ${width}px`);
    if (defects.length) await page.screenshot({ path: path.join(root, `${name}-${width}-failure.png`), fullPage: true });
    assert.deepEqual(defects, [], `${name} at ${width}px`);
    if (name === 'receive-request-page') await page.locator('#links-range').scrollIntoViewIfNeeded();
    if (width === 1440 || width === 390) await page.screenshot({ path: path.join(root, `${name}-${width}.png`), fullPage: name !== 'receive-request-page' && !await page.locator('dialog[open]').count() });
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
  await page.locator('#nav a[aria-current=page]').waitFor({ state: 'attached' });
  await layout('deliver');
  await page.getByRole('link', { name: 'Workflows', exact: true }).click();
  await page.getByRole('link', { name: 'Projects', exact: true }).click();
  await page.click('#workflow-new-project');
  await page.fill('#wp-label', 'Studio masters');
  assert.equal(await page.inputValue('#wp-id'), 'studio-masters');
  await openAncestors(page.locator('#wp-id'));
  await page.fill('#wp-id', id); await page.fill('#wp-directory', id);
  await openAncestors(page.locator('#wp-add-member'));
  await page.click('#wp-add-member');
  await page.locator('#wp-members input').fill('producer@example.com');
  await page.locator('#wp-members select').selectOption('approver');
  await page.click('#wp-add-metadata'); await page.locator('#wp-metadata input').fill('Client');
  await page.click('#wp-add-recipient');
  await page.locator('#wp-recipients input[type=email]').fill('client@example.com');
  await page.locator('#wp-recipients input[data-key=holder]').fill('a'.repeat(64));
  assert.equal(await page.getByRole('button', { name: 'Remove team member: producer@example.com', exact: true }).count(), 1);
  assert.equal(await page.getByRole('button', { name: 'Remove required field: Client', exact: true }).count(), 1);
  assert.equal(await page.getByRole('button', { name: 'Remove recipient: client@example.com', exact: true }).count(), 1);
  await page.check('#wp-sequence-enabled'); await page.check('#wp-media-enabled');
  await layout('project-editor');
  await page.uncheck('#wp-sequence-enabled'); await page.uncheck('#wp-media-enabled');
  await page.getByRole('button', { name: /^Remove recipient/ }).click();
  await saveProject();
  assert.equal((await api('workflows/projects')).projects.find((p) => p.id === id).members['producer@example.com'], 'approver');
  await page.click('#workflow-new');
  await page.locator('#workflow-create').waitFor();
  const recipientHelp = page.getByRole('button', { name: /Help about enrolled recipients/ });
  assert.equal(await recipientHelp.count(), 1, 'New delivery keeps the enrolled recipient help');
  await page.selectOption('#workflow-project', '');
  assert.equal(await recipientHelp.count(), 1, 'Changing to no project keeps the enrolled recipient help');
  await page.selectOption('#workflow-project', id);
  assert.equal(await recipientHelp.count(), 1, 'Changing project keeps the enrolled recipient help');
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
  assert.equal(await page.evaluate(() => JSON.parse(sessionStorage.getItem(Object.keys(sessionStorage).find((key) => key.startsWith('votport-workflow-draft:')))).operation_id), issued.job.request.operation_id);
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
  assert.deepEqual(JSON.parse(await fs.readFile(await (await download).path(), 'utf8')), { complete_chain: false, events: records });

  await page.locator('#nav .nav-more > summary').click();
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
  const { credential_source, trade_route, ...disabled } = (await api('workflows/storage')).storage.find((item) => item.id === storageId);
  assert.equal(credential_source, 'saved');
  await api('workflows/storage', { storage: { ...disabled, enabled: false } }, 'PUT');
  await page.goto(`${base}/workflows#projects`);
  await page.locator('#workflow-project-list article').filter({ hasText: id }).getByRole('button', { name: 'Edit project' }).click();
  assert.ok(await page.locator(`#wp-destinations input[value="${storageId}"]`).isChecked(), 'Unavailable storage must remain selected in an existing policy');
  await saveProject();
  assert.equal((await api('workflows/projects')).projects.find((item) => item.id === id).destinations[0], storageId);
  await page.locator('#nav .nav-more > summary').click();
  await page.getByRole('link', { name: 'Automation', exact: true }).click();
  await page.locator('#automation-token-form').waitFor(); await layout('automation');
  for (const name of ['receive', 'audit', 'tenants', 'system']) {
    await page.goto(`${base}/${name}`);
    await page.locator('#nav a[aria-current=page]').waitFor({ state: 'attached' });
    await page.waitForLoadState('networkidle');
    await layout(name);
  }
  await page.route('**/api/admin/audit?*', (route) => route.fulfill({ contentType: 'application/x-ndjson', body: JSON.stringify({ at: 1, rowid: 1, event: 'automation_refused', tenant: 'a'.repeat(128), actor: `automation:${'a'.repeat(128)}`, detail: { permission: 'deliveries:create' } }) + '\n' }));
  await page.goto(`${base}/audit`); await page.locator('.audit-actor').waitFor();
  await layout('audit-automation-identity');
  await page.unroute('**/api/admin/audit?*');

  const auditRows = Array.from({ length: 1501 }, (_, index) => ({ rowid: index + 1, at: 100 + Math.floor(index / 400), tenant: '', actor: 'fixture', event: `event_${index + 1}`, subject: `row ${index + 1}`, detail: { sequence: index + 1 } }));
  const hiddenEvent = 'admin_login';
  const auditRequests = [];
  let failAudit = false, holdAudit = null;
  await page.route('**/api/admin/audit?*', async (route) => {
    const query = new URL(route.request().url()).searchParams;
    assert.equal(query.get('limit'), '250');
    auditRequests.push(query.toString());
    if (holdAudit) { holdAudit.started(); await holdAudit.wait; holdAudit = null; }
    if (failAudit) { failAudit = false; return route.fulfill({ status: 503, body: 'Audit fixture failure' }); }
    let rows = auditRows.filter((row) => (!query.get('event') || row.event === query.get('event')) && (!query.get('q') || row.subject.includes(query.get('q'))));
    if (query.get('event') === hiddenEvent) rows = [{ rowid: 9000, at: 200, tenant: '', actor: 'fixture', event: hiddenEvent, subject: 'hidden event row', detail: {} }];
    if (query.has('before_rowid')) rows = rows.filter((row) => row.rowid < Number(query.get('before_rowid'))).reverse();
    else rows = rows.filter((row) => row.at > Number(query.get('since')) || (row.at === Number(query.get('since')) && row.rowid > Number(query.get('after_rowid'))));
    await route.fulfill({ contentType: 'application/x-ndjson', body: rows.slice(0, 250).map((row) => JSON.stringify(row)).join('\n') });
  });
  async function auditAction(action) {
    const response = page.waitForResponse((response) => response.url().includes('/api/admin/audit?'));
    await action(); await (await response).finished();
    await page.waitForFunction(() => !document.querySelector('#load-more').disabled);
  }
  async function moreAudit() { await page.locator('#load-more').focus(); await page.keyboard.press('Enter'); }
  for (const order of ['newest', 'oldest']) {
    await auditAction(() => order === 'newest' ? page.goto(`${base}/audit`) : page.selectOption('#audit-order', order));
    const ordered = order === 'newest' ? [...auditRows].reverse() : auditRows;
    const firstRow = page.locator('.audit-row').first();
    assert.deepEqual(await firstRow.locator('.audit-field-label').allTextContents(), ['Time:', 'Tenant:', 'Event:', 'Subject:', 'Actor:']);
    assert.equal(await firstRow.locator('.audit-event').textContent(), ordered[0].event);
    assert.equal(await firstRow.locator('.audit-subject').textContent(), ordered[0].subject);
    assert.equal(await firstRow.locator('.audit-actor').textContent(), 'fixture');
    await page.setViewportSize({ width: 320, height: 1000 });
    assert.equal(await firstRow.locator('.audit-field-label').count(), 5);
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Audit rows fit at 320px');
    await page.setViewportSize({ width: 1440, height: 1000 });
    let retainedDetail;
    for (let number = 1; number <= 7; number++) {
      if (number > 1) {
        if (number === 5 && order === 'newest') {
          let started, release;
          const pending = new Promise((resolve) => { started = resolve; });
          holdAudit = { started, wait: new Promise((resolve) => { release = resolve; }) };
          await auditAction(async () => {
            await moreAudit(); await pending;
            await page.locator('.audit-row summary').first().focus(); release();
          });
          assert.equal(await page.evaluate(() => document.activeElement.id), 'audit-range', 'Evicting the focused row moves focus to the range');
        } else {
          await auditAction(moreAudit);
          assert.equal(await page.evaluate(() => document.activeElement.id), number === 7 ? 'audit-range' : 'load-more', 'Keyboard pagination retains useful focus');
        }
      }
      const end = Math.min(number * 250, ordered.length), expected = ordered.slice(Math.max(0, end - 1000), end);
      assert.equal(await page.locator('.audit-row').count(), expected.length, 'The Audit page retains at most 1,000 rows');
      assert.deepEqual(await page.locator('.audit-subject').allTextContents(), expected.map((row) => row.subject));
      assert.ok(await page.locator(`#audit-event-options option[value="${expected[0].event}"]`).count(), 'Unknown loaded event remains selectable');
      assert.ok(await page.locator(`#audit-event-options option[value="${hiddenEvent}"]`).count(), 'Known event remains selectable before its first row loads');
      assert.equal(await page.locator('#audit-range').textContent(), `Showing rows ${end - expected.length + 1} to ${end}.`);
      if (number === 3) {
        retainedDetail = await page.locator('.audit-row details').nth(500).elementHandle();
        await retainedDetail.evaluate((node) => { node.open = true; });
      }
      if (number === 6) assert.ok(await retainedDetail.evaluate((node) => node.isConnected && node.open), 'Retained rows keep their open details');
    }
    assert.ok(await page.locator('#load-more').isHidden());
  }
  await page.fill('#audit-query', ''); await page.fill('#audit-event', hiddenEvent);
  await auditAction(() => page.locator('#audit-filters button[type=submit]').click());
  assert.deepEqual(await page.locator('.audit-subject').allTextContents(), ['hidden event row'], 'A known event can filter rows outside the current page');
  await page.fill('#audit-query', 'row 900'); await page.fill('#audit-event', 'event_900');
  await auditAction(() => page.locator('#audit-filters button[type=submit]').click());
  assert.deepEqual(await page.locator('.audit-subject').allTextContents(), ['row 900']);
  const auditExport = new URL(await page.locator('#export').getAttribute('href'), base);
  assert.equal(auditExport.searchParams.get('q'), 'row 900'); assert.equal(auditExport.searchParams.get('event'), 'event_900');
  assert.equal(auditExport.searchParams.get('limit'), '10000');
  await page.fill('#audit-query', 'missing');
  await auditAction(() => page.locator('#audit-filters button[type=submit]').click());
  assert.equal(await page.locator('.audit-row').count(), 0); assert.ok(await page.locator(`#audit-event-options option[value="${hiddenEvent}"]`).count());
  assert.ok(await page.getByText('No audit rows yet.', { exact: true }).isVisible());
  await auditAction(() => page.click('#audit-clear'));
  assert.equal(await page.locator('.audit-subject').first().textContent(), 'row 1');
  assert.equal(await page.locator('.audit-row').count(), 250);
  failAudit = true; await auditAction(moreAudit);
  const failedAuditQuery = auditRequests.at(-1);
  assert.equal(await page.locator('.audit-row').count(), 250);
  await page.locator('#audit-range').filter({ hasText: '503' }).waitFor();
  await auditAction(moreAudit);
  assert.equal(auditRequests.at(-1), failedAuditQuery, 'A failed continuation must retry the same cursor');
  assert.equal(await page.locator('.audit-row').count(), 500);
  failAudit = true; await auditAction(() => page.click('#refresh'));
  await page.locator('#audit-log').filter({ hasText: '503' }).waitFor();
  assert.ok(await page.locator(`#audit-event-options option[value="${hiddenEvent}"]`).count(), 'Known events remain available after a failed reset');
  await auditAction(() => page.click('#refresh'));
  assert.equal(await page.locator('.audit-row').count(), 250);
  assert.equal(await page.locator('.audit-subject').first().textContent(), 'row 1');
  assert.equal(await page.locator('#audit-range').getAttribute('role'), 'status');
  await page.unroute('**/api/admin/audit?*');

  await page.goto(`${base}/storage`); await page.click('#storage-new');
  await page.selectOption('#ws-kind', 'folder'); await page.fill('#ws-label', 'Shared reception');
  await openAncestors(page.locator('#ws-id')); await page.fill('#ws-id', `${storageId}_folder`); await page.fill('#ws-directory', path.join(root, 'shared'));
  await fs.mkdir(path.join(root, 'shared'), { recursive: true });
  await layout('shared-folder-editor');
  let saved = page.waitForResponse((response) => response.url().endsWith('/api/workflows/storage') && response.request().method() === 'PUT');
  await page.locator('#workflow-save-storage button[type=submit]').click(); assert.equal((await saved).status(), 200);
  await page.waitForFunction(() => !document.querySelector('#storage-test').disabled);
  await page.click('#storage-test'); await page.getByText(/The server can read this shared folder/).waitFor();
  const request = await api('admin/links', { label: 'Peer connection fixture' });
  await api('workflows/storage', { storage: { ...disabled, id: `${storageId}_peer`, revision: 0, kind: 'votport', label: `Connected studio ${id}`, directory: '', prefix: '', endpoint: base, bucket: '', region: '', enabled: true }, credentials: { mode: 'votport', request_url: request.link.url } }, 'PUT');
  await page.reload();
  const peerCard = page.locator('#storage-list article').filter({ has: page.getByRole('heading', { name: `Connected studio ${id}`, exact: true }) });
  await peerCard.getByRole('button', { name: 'Disable receive-link connection', exact: true }).click(); await page.click('#confirm-ok');
  await peerCard.getByText('Disabled', { exact: true }).waitFor();
  assert.equal((await api('workflows/storage')).storage.find((item) => item.id === `${storageId}_peer`).enabled, false);
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

  await page.goto(`${base}/receive?search=${incoming.id}#link-${incoming.id}`);
  const actionCard = page.locator(`#link-${incoming.id}`);
  await actionCard.getByRole('button', { name: /^Deactivate receive link: / }).focus();
  await page.keyboard.press('Enter');
  const undo = page.locator('#toast-stack').getByRole('button', { name: /^Undo / });
  await undo.waitFor();
  assert.ok(await undo.evaluate((node) => node === document.activeElement), 'Keyboard row action must focus its Undo');
  await undo.hover(); await page.mouse.move(0, 0);
  await page.waitForTimeout(6200);
  assert.equal((await api('admin/links')).links.find((link) => link.id === incoming.id).active, true, 'Focused Undo pauses the server commit');
  await page.keyboard.press('Enter'); await undo.waitFor({ state: 'detached' });
  assert.ok(await page.locator('#links-action-status').evaluate((node) => node === document.activeElement), 'Undo returns focus to the request status');
  await page.route('**/api/admin/links?*', async (route) => {
    const response = await route.fetch();
    await actionCard.getByRole('button', { name: /^Copy receive link: / }).focus();
    await route.fulfill({ response });
  }, { times: 1 });
  await actionCard.getByRole('button', { name: /^Deactivate receive link: / }).focus();
  await page.keyboard.press('Enter'); await undo.waitFor();
  assert.ok(await page.locator('#links-action-status').evaluate((node) => node === document.activeElement), 'Undo must not steal the fallback of a newly focused row control');
  await undo.focus(); await page.keyboard.press('Enter'); await undo.waitFor({ state: 'detached' });

  for (const moveFocus of [false, true]) {
    await page.route(`**/api/admin/links/${incoming.id}`, async (route) => {
      await route.fetch();
      if (moveFocus) await page.locator('#links-query').focus();
      await route.fulfill({ status: 503, json: { error: 'Lost action response fixture' } });
    }, { times: 1 });
    await actionCard.getByRole('button', { name: /^Deactivate receive link: / }).focus();
    await page.keyboard.press('Enter'); await undo.waitFor();
    await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pagehide')));
    await page.getByRole('dialog', { name: 'Something went wrong', exact: true }).waitFor();
    assert.equal((await api('admin/links')).links.find((link) => link.id === incoming.id).active, false);
    if (!moveFocus) assert.equal(await page.locator('#links-action-status').textContent(), 'Action could not be confirmed.', 'A lost response must not claim that a committed action was undone');
    await page.locator('#confirm-cancel').press('Enter');
    assert.ok(await page.locator(moveFocus ? '#links-query' : '#links-action-status').evaluate((node) => node === document.activeElement), 'Closing the error preserves the current keyboard position');
    await api(`admin/links/${incoming.id}`, { active: true });
    await page.reload();
  }
  await actionCard.getByRole('button', { name: /^Legal hold: / }).focus();
  await page.keyboard.press('Enter');
  await page.getByText('Legal hold set.', { exact: true }).waitFor();
  assert.ok(await page.locator('#links-action-status').evaluate((node) => node === document.activeElement), 'Immediate row replacement retains keyboard position');
  await actionCard.getByRole('button', { name: /^Release hold: / }).focus();
  await page.keyboard.press('Enter'); await undo.waitFor();
  assert.ok(await undo.evaluate((node) => node === document.activeElement));
  await page.goto(`${base}/storage`);
  await page.waitForFunction(() => document.querySelector('#receiving-storage'));
  assert.equal((await api('admin/links')).links.find((link) => link.id === incoming.id).legal_hold, false, 'Pagehide commits even while Undo is focused');

  await page.goto(`${base}/receive?search=${incoming.id}#link-${incoming.id}`);
  await actionCard.waitFor();
  await page.route('**/api/admin/links?*', async (route) => {
    const response = await route.fetch();
    await page.locator('#links-query').focus();
    await route.fulfill({ response });
  }, { times: 1 });
  await actionCard.getByRole('button', { name: /^Deactivate receive link: / }).focus();
  await page.keyboard.press('Enter'); await undo.waitFor();
  assert.ok(await page.locator('#links-query').evaluate((node) => node === document.activeElement), 'A delayed refresh must not steal newly moved focus');
  await undo.hover(); await undo.focus(); await page.locator('#links-query').focus();
  await page.waitForTimeout(6200);
  assert.equal((await api('admin/links')).links.find((link) => link.id === incoming.id).active, true, 'Hover also pauses Undo');
  await page.mouse.move(0, 0);
  await undo.waitFor({ state: 'detached', timeout: 10000 });
  assert.equal((await api('admin/links')).links.find((link) => link.id === incoming.id).active, false, 'Leaving Undo resumes its unattended commit');
  assert.ok(await page.locator('#links-query').evaluate((node) => node === document.activeElement));
  await api(`admin/links/${incoming.id}`, { active: true });

  const fileRequest = (await api('admin/links', { label: `Files ${id}`, dest: `${id}-focus-files` })).link;
  await page.goto(fileRequest.url);
  await page.setInputFiles('#file-input', ['one.txt', 'two.txt'].map((name) => ({ name, mimeType: 'text/plain', buffer: Buffer.from(name) })));
  await page.click('#send'); await page.locator('#done-card:not([hidden])').waitFor({ timeout: 30000 });
  await page.goto(`${base}/receive?search=${fileRequest.id}#link-${fileRequest.id}`);
  const fileCard = page.locator(`#link-${fileRequest.id}`), clearRecord = fileCard.getByRole('button', { name: 'Clear record', exact: true, includeHidden: true });
  await fileCard.locator('.upload-history > summary').click();
  await clearRecord.waitFor();
  await clearRecord.focus(); await page.keyboard.press('Enter'); await undo.waitFor();
  assert.ok(await undo.evaluate((node) => node === document.activeElement), 'Clearing a transfer record focuses Undo');
  await page.keyboard.press('Enter'); await undo.waitFor({ state: 'detached' });
  await clearRecord.waitFor();
  assert.ok(await page.locator('#links-action-status').evaluate((node) => node === document.activeElement));
  await page.route('**/api/admin/links?*', (route) => route.fulfill({ status: 503 }), { times: 2 });
  await clearRecord.focus(); await page.keyboard.press('Enter'); await undo.waitFor();
  await page.keyboard.press('Enter'); await undo.waitFor({ state: 'detached' });
  assert.ok(await clearRecord.isEnabled(), 'Undo re-enables a retained button when list refreshes fail');
  await fileCard.getByRole('button', { name: 'Files and timeline', exact: true }).click();
  await page.locator('#timeline[open]').waitFor();
  await page.locator('#timeline-files .upload-file').first().waitFor();
  await page.evaluate(() => {
    const timeline = document.querySelector('#timeline');
    timeline.addEventListener('close', () => {
      timeline.showModal();
      window.__timelineStaleCloseReopened = true;
    }, { capture: true, once: true });
    timeline.addEventListener('close', () => { window.__timelineStaleCloseSeen = true; }, { once: true });
  });
  const timelineFilesBeforeStaleClose = await page.locator('#timeline-files .upload-file').count();
  await page.click('#timeline-close');
  await page.waitForFunction(() => window.__timelineStaleCloseSeen);
  assert.ok(await page.locator('#timeline').evaluate((node) => node.open && window.__timelineStaleCloseReopened), 'A stale close must leave a reopened timeline open');
  assert.equal(await page.locator('#timeline-files .upload-file').count(), timelineFilesBeforeStaleClose, 'A stale close must preserve loaded timeline files');
  const deleteFile = page.locator('#timeline-files').getByRole('button', { name: 'Delete file', exact: true }).first();
  await openAncestors(deleteFile); await deleteFile.focus(); await page.keyboard.press('Enter');
  await page.getByRole('dialog', { name: 'Delete file', exact: true }).waitFor();
  await page.locator('#confirm-ok').press('Enter');
  await page.waitForFunction(() => document.querySelector('#links-action-status').textContent.startsWith('Deleted "'));
  assert.ok(await page.locator('#timeline-range').evaluate((node) => node === document.activeElement), 'File deletion keeps focus inside the dialog');
  const deleteFiles = fileCard.getByRole('button', { name: 'Delete stored files', exact: true });
  await openAncestors(deleteFiles);
  const bulkHandle = await deleteFiles.elementHandle();
  await page.evaluate((bulk) => {
    const timeline = document.querySelector('#timeline');
    timeline.addEventListener('close', () => bulk.focus(), { capture: true, once: true });
    timeline.addEventListener('close', () => { window.__timelineCloseSeen = true; }, { once: true });
  }, bulkHandle);
  await page.click('#timeline-close');
  await page.waitForFunction(() => window.__timelineCloseSeen);
  assert.ok(await deleteFiles.evaluate((node) => node === document.activeElement), 'Native close preserves moved bulk focus');
  await page.keyboard.press('Enter');
  await page.getByRole('dialog', { name: 'Delete stored files', exact: true }).waitFor();
  await page.locator('#confirm-ok').press('Enter');
  await page.getByText('Stored-file deletion completed.', { exact: true }).waitFor();
  assert.ok(await page.locator('#links-action-status').evaluate((node) => node === document.activeElement), 'Batch file deletion retains keyboard position');

  const completeTimeline = await api(`admin/links/${fileRequest.id}/uploads`);
  const actualUpload = (await api(`admin/links/${fileRequest.id}/uploads/${completeTimeline.uploads[0].id}`)).upload;
  const actualFiles = (await api(`admin/links/${fileRequest.id}/uploads/${actualUpload.id}/files`)).files;
  const headers = Array.from({ length: 25 }, (_, index) => ({ ...actualUpload, id: `page-upload-${index}`, position: 25 - index, file_count: 201, total_bytes: 201 * actualFiles[0].bytes }));
  const names = Array.from({ length: 201 }, (_, index) => ({ ...actualFiles[0], file_index: index, exists: false,
    path: `file-${index}.txt`, stored_as: `folder/${index}-` + 'A long international production filename é '.repeat(4) + '.txt' }));
  let failFilePage = true, fileOffsets = [];
  const uploadPages = `**/api/admin/links/${fileRequest.id}/uploads**`;
  await page.route(uploadPages, (route) => {
    const url = new URL(route.request().url()), parts = url.pathname.split('/'), position = Number(url.searchParams.get('before_position') || 26);
    if (parts.at(-1) === 'uploads') {
      const remaining = headers.filter((upload) => upload.position < position), uploads = remaining.slice(0, 20);
      return route.fulfill({ json: { uploads, next_position: remaining.length > 20 ? uploads.at(-1).position : null } });
    }
    const upload = headers.find((upload) => parts.includes(upload.id));
    if (!upload) return route.continue();
    if (parts.at(-1) !== 'files') return route.fulfill({ json: { upload } });
    const offset = Number(url.searchParams.get('offset') || 0); fileOffsets.push(offset);
    if (offset === 100 && failFilePage) { failFilePage = false; return route.fulfill({ status: 503, json: { error: 'File page unavailable fixture' } }); }
    return route.fulfill({ json: { files: names.slice(offset, offset + 100), file_count: 201, next_offset: offset < 200 ? offset + 100 : null } });
  });
  await page.reload();
  assert.equal(await page.locator('#links .upload-file').count(), 0);
  await fileCard.locator('.upload-history > summary').click();
  await fileCard.getByText('Showing transfers 1 to 20, newest first.', { exact: true }).waitFor();
  assert.equal(await fileCard.locator('.uploads > li').count(), 20);
  await fileCard.getByRole('button', { name: 'Older transfers', exact: true }).focus(); await page.keyboard.press('Enter');
  await fileCard.getByText('Showing transfers 21 to 25, newest first.', { exact: true }).waitFor();
  assert.equal(await fileCard.locator('.uploads > li').count(), 5);
  assert.ok(await fileCard.locator('.upload-history [role=status]').evaluate((node) => node === document.activeElement));
  await fileCard.getByRole('button', { name: 'Files and timeline', exact: true }).first().click();
  await page.getByText('Showing files 1 to 100 of 201.', { exact: true }).waitFor();
  assert.equal(await page.locator('.upload-file').count(), 100);
  await layout('received-files-page');
  await page.locator('#timeline-next').focus(); await page.keyboard.press('Enter');
  await page.getByText('File page unavailable fixture', { exact: true }).waitFor();
  assert.equal(await page.locator('.upload-file').count(), 100);
  assert.equal(await page.locator('#timeline-range').textContent(), 'Showing files 1 to 100 of 201.');
  await page.click('#timeline-retry');
  await page.getByText('Showing files 101 to 200 of 201.', { exact: true }).waitFor();
  assert.deepEqual(fileOffsets, [0, 100, 100]);
  assert.equal(await page.locator('.upload-file').count(), 100);
  await page.locator('#timeline-next').focus(); await page.keyboard.press('Enter');
  await page.getByText('Showing files 201 to 201 of 201.', { exact: true }).waitFor();
  assert.equal(await page.locator('.upload-file').count(), 1);
  assert.ok(await page.locator('#timeline-range').evaluate((node) => node === document.activeElement));
  await page.locator('#timeline-previous').click();
  await page.getByText('Showing files 101 to 200 of 201.', { exact: true }).waitFor();
  await page.click('#timeline-close');
  await page.waitForFunction(() => document.querySelectorAll('.upload-file').length === 0);
  assert.equal(await page.locator('.upload-file').count(), 0, 'Closing the dialog releases its file nodes');
  await page.unroute(uploadPages);

  const summaries = Array.from({ length: 151 }, (_, index) => ({ ...incoming, id: `page-request-${index}`, label: `Page request ${index}`, upload_count: 0, upload_bytes: 0, url: `${base}/r/page-request-${index}`, created_at: Math.floor(Date.now() / 1000) - index }));
  let pageCursors = [], failThirdPage = true;
  await page.route('**/api/admin/links?*', (route) => {
    const query = new URL(route.request().url()).searchParams, before = query.get('before_id');
    const start = before ? Number(before.split('-').at(-1)) + 1 : 0; pageCursors.push(start);
    if (start === 100 && failThirdPage) { failThirdPage = false; return route.fulfill({ status: 503, json: { error: 'Request page unavailable fixture' } }); }
    const links = query.get('search') ? summaries.slice(0, 3) : summaries.slice(start, start + 50);
    return route.fulfill({ json: { links, receive_dir: root, next_cursor: !query.get('search') && start + 50 < summaries.length ? { id: links.at(-1).id, created_at: links.at(-1).created_at } : null } });
  });
  await page.goto(`${base}/receive`);
  await page.getByText('Showing requests 1 to 50.', { exact: true }).waitFor();
  const retainedEditor = page.locator('#link-page-request-0 .reception-workflow');
  await retainedEditor.locator('summary').click(); await retainedEditor.locator('input[data-metadata]').fill('Keep this request draft');
  await page.locator('#links-load-more').focus(); await page.keyboard.press('Enter');
  await page.getByText('Showing requests 1 to 100.', { exact: true }).waitFor();
  assert.equal(await retainedEditor.locator('input[data-metadata]').inputValue(), 'Keep this request draft');
  assert.ok(await page.locator('#links-load-more').evaluate((node) => node === document.activeElement));
  await page.click('#links-load-more'); await page.getByText('Request page unavailable fixture', { exact: true }).waitFor();
  assert.equal(await page.locator('#links-range').textContent(), 'Showing requests 1 to 100.');
  page.removeAllListeners('dialog'); page.once('dialog', (dialog) => dialog.dismiss());
  await page.click('#links-load-more'); await page.waitForFunction(() => !document.querySelector('#links-load-more').disabled);
  assert.equal(await retainedEditor.locator('input[data-metadata]').inputValue(), 'Keep this request draft');
  page.on('dialog', (dialog) => dialog.accept());
  await page.click('#links-load-more'); await page.getByText('Showing requests 51 to 150.', { exact: true }).waitFor();
  assert.equal(await page.locator('#links [data-link-id]').count(), 100);
  assert.deepEqual(pageCursors.slice(-3), [100, 100, 100], 'Errors and declined eviction preserve the cursor');
  await layout('receive-request-page');
  await page.locator('#links-load-more').focus(); await page.keyboard.press('Enter');
  await page.getByText('Showing requests 52 to 151.', { exact: true }).waitFor();
  assert.equal(await page.locator('#links [data-link-id]').count(), 100);
  assert.ok(await page.locator('#links-range').evaluate((node) => node === document.activeElement));
  await page.click('#links-refresh'); await page.getByText('Showing requests 1 to 50.', { exact: true }).waitFor();
  await page.fill('#links-query', 'matching request'); await page.locator('#links-filter button[type=submit]').click();
  await page.getByText('Showing requests 1 to 3.', { exact: true }).waitFor();
  assert.equal(await page.locator('#links [data-link-id]').count(), 3);
  await page.unroute('**/api/admin/links?*');

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
  await card.locator('.notification-details').evaluate((node) => { node.open = false; });
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
  assert.ok(await editor.locator('input[data-metadata]').evaluate((node) => node === document.activeElement), 'A retained dirty editor keeps its focused input');
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
  releasePatch(); await page.waitForFunction(() => document.querySelector('.reception-workflow > [role=status]').textContent.startsWith('Saved.'));
  assert.match(await editor.locator(':scope > [role=status]').textContent(), /^Saved\./);
  await pollStatus();
  await page.waitForFunction(() => !document.querySelector('.reception-workflow > [role=status]').textContent);
  assert.equal(listReads, 2, 'The deferred refresh runs after editing finishes');
  await page.unroute('**/api/admin/status?*'); await page.unroute('**/api/admin/links?*'); await page.unroute(`**/api/admin/links/${incoming.id}`);

  await editor.evaluate((node) => { node.open = true; });
  await editor.locator('input[data-metadata]').fill('Preserved by manual refresh');
  await page.click('#links-refresh'); await page.waitForLoadState('networkidle');
  assert.equal(await editor.locator('input[data-metadata]').inputValue(), 'Preserved by manual refresh');
  let releaseOld, oldStarted;
  const heldOld = new Promise((resolve) => releaseOld = resolve), oldPending = new Promise((resolve) => oldStarted = resolve);
  await page.route('**/api/admin/links?*', async (route) => { const response = await route.fetch(); oldStarted(); await heldOld; await route.fulfill({ response }); }, { times: 1 });
  await page.click('#links-refresh'); await oldPending;
  await editor.getByRole('button', { name: 'Save reception workflow' }).click();
  await page.waitForFunction(() => document.querySelector('.reception-workflow > [role=status]').textContent.startsWith('Saved.'));
  releaseOld(); await page.waitForLoadState('networkidle');
  assert.equal(await editor.locator('input[data-metadata]').inputValue(), 'Preserved by manual refresh', 'An older refresh cannot roll back a completed save');
  await editor.locator('input[data-metadata]').fill('Discard with request');
  await card.getByRole('button', { name: /^Delete receive link: / }).click();
  const extraDialogs = []; const onExtra = (dialog) => extraDialogs.push(dialog.message()); page.on('dialog', onExtra);
  await page.locator('#confirm-ok').click(); await card.waitFor({ state: 'detached' }); await page.waitForLoadState('networkidle');
  page.off('dialog', onExtra); assert.deepEqual(extraDialogs, [], 'Confirmed deletion removes the request draft without another discard prompt');
  assert.ok(await page.locator('#links-action-status').evaluate((node) => node === document.activeElement), 'Deleting the request keeps a keyboard focus target');

  // The status cache may return a fresh sample, an older sample, or no
  // expensive totals while the live activity count is still available. Keep
  // each response controlled so both pages exercise the real renderer and
  // poll error path without waiting on a wall-clock refresh interval.
  const statusTime = Math.floor(Date.now() / 1000);
  const statusFixture = (overrides = {}) => ({
    now: statusTime,
    sessions_active: 2,
    bytes_in_flight: 4096,
    receiving: [],
    today: { uploads: 12, bytes: 12 * 1024 },
    stored: { files: 3, bytes: 3 * 1024, missing_files: 0, missing_bytes: 0 },
    disk: { free_bytes: 8 * 1024 * 1024, total_bytes: 16 * 1024 * 1024 },
    outbound: {
      active: 8,
      open_grants: 6,
      deliveries: 11,
      disk: { free_bytes: 7 * 1024 * 1024, total_bytes: 16 * 1024 * 1024 },
    },
    sampled_at: statusTime,
    stale: false,
    stale_error: null,
    ...overrides,
  });
  let controlledStatus = statusFixture();
  let failControlledStatus = false;
  await page.route('**/api/admin/status?*', (route) => failControlledStatus
    ? route.fulfill({ status: 503, json: { error: 'Status fixture unavailable' } })
    : route.fulfill({ json: controlledStatus }));
  async function pollControlledStatus(next) {
    controlledStatus = next;
    failControlledStatus = false;
    const response = page.waitForResponse((candidate) => candidate.url().includes('/api/admin/status?'));
    await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
    assert.equal((await response).status(), 200);
  }
  async function failStatusPoll() {
    failControlledStatus = true;
    const response = page.waitForResponse((candidate) => candidate.url().includes('/api/admin/status?'));
    await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
    assert.equal((await response).status(), 503);
  }

  await page.goto(`${base}/receive`);
  await page.locator('#status-strip').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#stat-active').textContent(), '2', 'Receive renders the live active count for a fresh sample');
  assert.equal(await page.locator('#stat-today').textContent(), '12');
  assert.equal(await page.locator('#status-cache-note').textContent(), 'Totals refresh about once a minute. Transfer activity is live.');
  assert.doesNotMatch(await page.locator('#status-strip').textContent(), /warming up/i);
  await pollControlledStatus(statusFixture({
    sessions_active: 3,
    bytes_in_flight: 8192,
    today: { uploads: 13, bytes: 13 * 1024 },
    stored: { files: 4, bytes: 4 * 1024, missing_files: 0, missing_bytes: 0 },
    sampled_at: statusTime - 120,
    stale: true,
    stale_error: 'cached status is older than its refresh window',
  }));
  await page.waitForFunction(() => document.querySelector('#stat-active').textContent === '3' && document.querySelector('#status-cache-note').textContent.includes('may be out of date'));
  assert.equal(await page.locator('#stat-today').textContent(), '13', 'Receive keeps sampled totals visible when the sample is stale');
  assert.doesNotMatch(await page.locator('#status-strip').textContent(), /warming up/i);
  await pollControlledStatus(statusFixture({
    sessions_active: 4,
    bytes_in_flight: 16384,
    today: null,
    stored: null,
    disk: null,
    outbound: { active: 10, open_grants: null, deliveries: null, disk: null },
    sampled_at: null,
    stale: true,
    stale_error: 'status refresh unavailable',
  }));
  await page.waitForFunction(() => document.querySelector('#stat-active').textContent === '4' && document.querySelector('#stat-today').textContent === '–');
  assert.equal(await page.locator('#stat-stored').textContent(), '–');
  assert.equal(await page.locator('#status-cache-note').textContent(), 'Totals are temporarily unavailable.');
  assert.doesNotMatch(await page.locator('#status-strip').textContent(), /warming up/i);
  assert.notEqual(await page.locator('#stat-today').textContent(), '0');
  assert.notEqual(await page.locator('#stat-stored').textContent(), '0');
  await failStatusPoll();
  assert.equal(await page.locator('#stat-active').textContent(), '4', 'A failed poll preserves the last live Receive count');
  assert.doesNotMatch(await page.locator('#status-strip').textContent(), /warming up/i);

  controlledStatus = statusFixture();
  failControlledStatus = false;
  await page.goto(`${base}/deliver`);
  await page.locator('#status-strip').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#stat-active').textContent(), '8', 'Deliver renders the live active count for a fresh sample');
  assert.equal(await page.locator('#stat-open').textContent(), '6');
  assert.equal(await page.locator('#stat-deliveries').textContent(), '11');
  assert.equal(await page.locator('#status-cache-note').textContent(), 'Totals refresh about once a minute. Transfer activity is live.');
  assert.doesNotMatch(await page.locator('#status-strip').textContent(), /warming up/i);
  await pollControlledStatus(statusFixture({
    outbound: { active: 9, open_grants: 7, deliveries: 12, disk: { free_bytes: 7 * 1024 * 1024, total_bytes: 16 * 1024 * 1024 } },
    sampled_at: statusTime - 120,
    stale: true,
    stale_error: 'cached status is older than its refresh window',
  }));
  await page.waitForFunction(() => document.querySelector('#stat-active').textContent === '9' && document.querySelector('#status-cache-note').textContent.includes('may be out of date'));
  assert.equal(await page.locator('#stat-open').textContent(), '7', 'Deliver keeps sampled totals visible when the sample is stale');
  assert.doesNotMatch(await page.locator('#status-strip').textContent(), /warming up/i);
  await pollControlledStatus(statusFixture({
    sessions_active: 5,
    outbound: { active: 10, open_grants: null, deliveries: null, disk: null },
    today: null,
    stored: null,
    disk: null,
    sampled_at: null,
    stale: true,
    stale_error: 'status refresh unavailable',
  }));
  await page.waitForFunction(() => document.querySelector('#stat-active').textContent === '10' && document.querySelector('#stat-open').textContent === '–');
  assert.equal(await page.locator('#stat-deliveries').textContent(), '–');
  assert.equal(await page.locator('#status-cache-note').textContent(), 'Totals are temporarily unavailable.');
  assert.doesNotMatch(await page.locator('#status-strip').textContent(), /warming up/i);
  assert.notEqual(await page.locator('#stat-open').textContent(), '0');
  assert.notEqual(await page.locator('#stat-deliveries').textContent(), '0');
  await failStatusPoll();
  assert.equal(await page.locator('#stat-active').textContent(), '10', 'A failed poll preserves the last live Deliver count');
  assert.doesNotMatch(await page.locator('#status-strip').textContent(), /warming up/i);
  await page.unroute('**/api/admin/status?*');

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

  const held = (await api('workflows/jobs?limit=100')).jobs[0];
  held.job.state = 'suspended'; held.url = null;
  held.job.error = 'Held after restoring a backup. Create a new job to deliver these files.';
  held.job.project.destinations = ['restored-destination'];
  held.job.checks.route_revocations = { 'restored-destination': { state: 'pending' } };
  await page.route('**/api/workflows/jobs?*', (route) => route.fulfill({ json: { jobs: [held], next: null } }));
  await page.goto(`${base}/workflows`);
  const heldCard = page.locator(`#job-${held.job.id}`);
  await heldCard.getByText('Held after restore', { exact: true }).waitFor();
  assert.equal(await heldCard.getByRole('button', { name: /^(Retry|Approve delivery|Cancel delivery|Copy download link)$/ }).count(), 0);
  assert.equal(await heldCard.getByText(/Revocation awaiting/).count(), 0);
  assert.ok(await heldCard.getByText(/Create a new job to deliver/).isVisible());
  await page.selectOption('#workflow-filter-state', 'suspended');
  await heldCard.waitFor();
  await layout('restored-delivery');
  for (const [state, retiredFrom, sourceRevoked, saved, expected] of [
    ['retired', 'ready', null, null, false],
    ['retiring', 'ready', null, null, false],
    ['cancelled', 'ready', null, null, true],
    ['retired', 'cancelled', null, null, true],
    ['retired', 'ready', 1, null, true],
    ['retired', 'ready', null, { state: 'pending' }, true],
    ['suspended', 'cancelled', 1, { state: 'pending' }, false],
  ]) {
    held.job.state = state;
    held.job.checks.retired_from = retiredFrom;
    held.job.checks.source_revoked_at = sourceRevoked;
    held.job.checks.destinations = { 'restored-destination': { state: 'complete' } };
    held.job.checks.route_receipts = { 'restored-destination': {} };
    held.job.checks.route_revocations = saved ? { 'restored-destination': saved } : {};
    await page.goto(`${base}/workflows`);
    await heldCard.waitFor();
    assert.equal(await heldCard.getByText(/Revocation awaiting/).count(), expected ? 1 : 0, `${state}/${retiredFrom}: completed retirement must not imply revocation`);
  }
  await page.unroute('**/api/workflows/jobs?*');

  assert.deepEqual(errors, []);
  console.log('Responsive admin forms, project creation, lost-response recovery, automatic status refresh, policy invalidation, cumulative event export, private storage credentials and stale connection tests: passed');
} finally { await browser.close(); }
