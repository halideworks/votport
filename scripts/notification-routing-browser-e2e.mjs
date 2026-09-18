import { apiClient, chooseNotification as choose, openAncestors } from './browser-helpers.mjs';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import { chromium } from 'playwright';

const base = process.env.BASE_URL, root = process.env.WORKFLOW_TEST_ROOT;
if (!base || !root || !process.env.ADMIN_PASSWORD) throw new Error('Use an isolated instance with BASE_URL, WORKFLOW_TEST_ROOT and ADMIN_PASSWORD.');
const id = `notifications-${Date.now()}`, uploadLabel = `Routed upload ${id}`, downloadLabel = `Routed download ${id}`;
await fs.mkdir(path.join(root, 'library', id), { recursive: true });
await fs.writeFile(path.join(root, 'library', id, 'master.txt'), 'Notification workflow fixture\n');
await fs.writeFile(path.join(root, 'library', 'notification-clip.txt'), 'Notification download fixture\n');
const messages = [];
const sink = http.createServer(async (request, response) => {
  const chunks = []; for await (const chunk of request) chunks.push(chunk);
  messages.push({ path: request.url, payload: JSON.parse(Buffer.concat(chunks)) });
  if (request.url === '/slow') await new Promise((resolve) => setTimeout(resolve, 250));
  response.writeHead(request.url === '/blocked' ? 503 : 200); response.end('ok');
});
await new Promise((resolve) => sink.listen(0, process.env.NOTIFY_TEST_BIND || '127.0.0.1', resolve));
const endpoint = `http://${process.env.NOTIFY_TEST_HOST || '127.0.0.1'}:${sink.address().port}`;
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'reduce' });
const page = await context.newPage(), errors = [];
page.on('dialog', (dialog) => dialog.accept());
page.on('pageerror', (error) => errors.push(error.message));
const api = apiClient(context, base);
try {
  await api('admin/login', { password: process.env.ADMIN_PASSWORD });
  await api('notifications/defaults', { mode: 'off', rules: [] }, 'PUT');
  for (const destination of (await api('notifications')).destinations) await api(`notifications/${destination.id}`, { revision: destination.revision }, 'DELETE');
  await page.goto(`${base}/notifications`);
  assert.match(await page.locator('.info-banner').first().innerText(), /Choose events where notifications belong/);
  for (const [label, target] of [['Incoming', '#incoming'], ['Failures', '#operations']]) {
    await page.getByRole('button', { name: 'Add destination', exact: true }).click();
    await page.getByLabel('Destination name', { exact: true }).fill(label);
    await page.locator('#nd-target').fill(target);
    await page.locator('#nd-url').fill(`${endpoint}/${label.toLowerCase()}`);
    await page.getByRole('button', { name: 'Save destination', exact: true }).click();
    await page.locator('#notification-form').waitFor({ state: 'hidden' });
  }
  const catalog = await api('notifications');
  assert.equal(catalog.destinations.length, 2); assert.ok(!JSON.stringify(catalog).includes(endpoint));
  const incoming = catalog.destinations.find((d) => d.label === 'Incoming');
  const incomingCard = page.locator('#notification-destinations .card').filter({ has: page.getByRole('heading', { name: 'Incoming', exact: true }) });
  await incomingCard.getByRole('button', { name: 'Send test', exact: true }).click();
  await page.getByText('Test accepted for Incoming. Check that it appeared in #incoming.', { exact: true }).waitFor();
  assert.equal(messages.length, 1); assert.equal(messages[0].path, '/incoming');
  await incomingCard.getByRole('button', { name: 'Edit', exact: true }).click();
  assert.equal(await page.locator('#nd-url').inputValue(), '');
  await page.getByRole('button', { name: 'Save destination', exact: true }).click();
  await page.locator('#notification-form').waitFor({ state: 'hidden' });
  for (const service of ['teams', 'google_chat', 'discord']) {
    await page.click('#notification-new'); await page.fill('#nd-label', service); await page.selectOption('#nd-channel', service);
    await page.fill('#nd-target', `${service} test channel`); await page.fill('#nd-url', `${endpoint}/${service}`);
    await page.getByRole('button', { name: 'Save destination', exact: true }).click(); await page.locator('#notification-form').waitFor({ state: 'hidden' });
    const card = page.locator('#notification-destinations .card').filter({ has: page.getByRole('heading', { name: service, exact: true }) });
    const before = messages.length; await card.getByRole('button', { name: 'Send test', exact: true }).click();
    await page.getByText(`Test accepted for ${service}. Check that it appeared in ${service} test channel.`, { exact: true }).waitFor();
    assert.equal(messages.length, before + 1); assert.ok(messages.at(-1).path.startsWith(`/${service}`));
  }
  await api('notifications', { label: 'Slow', channel: 'webhook', target: 'Slow endpoint', enabled: true, url: `${endpoint}/slow` });
  await api('notifications', { label: 'Blocked', channel: 'webhook', target: 'Blocked endpoint', enabled: true, url: `${endpoint}/blocked` });
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  const slowCard = page.locator('#notification-destinations .card').filter({ has: page.getByRole('heading', { name: 'Slow', exact: true }) });
  const blockedCard = page.locator('#notification-destinations .card').filter({ has: page.getByRole('heading', { name: 'Blocked', exact: true }) });
  await slowCard.getByRole('button', { name: 'Send test', exact: true }).click();
  await page.waitForTimeout(30);
  await blockedCard.getByRole('button', { name: 'Send test', exact: true }).click();
  await page.getByText('Test failed for Blocked: ', { exact: false }).waitFor();
  await page.waitForTimeout(350);
  await page.getByText('Test failed for Blocked: ', { exact: false }).waitFor();
  await blockedCard.getByText(/^Last attempt [^]*?Failed(: |; )/, { exact: false }).waitFor();
  const removed = await context.request.post(`${base}/api/admin/notifications/test`, { headers: { 'X-Votport': '1' } });
  assert.equal(removed.status(), 404);
  const rejected = await context.request.put(`${base}/api/admin/settings`, { headers: { 'X-Votport': '1' }, data: { notify_slack: 'https://example.test/removed' } });
  assert.equal(rejected.status(), 422);
  await page.goto(`${base}/system`); assert.equal(await page.locator('[data-chat-channel], #notify-form, #smtp-to').count(), 0);
  await page.goto(`${base}/receive`);
  assert.equal(await page.locator('#create-notification-options').getAttribute('open'), '');
  const lifecycleCatalog = await api('notifications');
  const lifecycleReload = page.locator('#create-notifications').getByRole('button', { name: 'Refresh destinations', exact: true });
  const lifecycleStatus = page.locator('#create-notifications .notification-editor > p.field-help');
  let releaseOlder;
  let lifecycleRequests = 0;
  await page.route(`${base}/api/notifications`, async (route) => {
    lifecycleRequests++;
    if (lifecycleRequests === 1) {
      await new Promise((resolve) => { releaseOlder = resolve; });
      await route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: 'older refresh failed' }) });
    } else if (lifecycleRequests === 2) {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(lifecycleCatalog) });
    } else await route.continue();
  });
  try {
    await lifecycleReload.dispatchEvent('click');
    await lifecycleReload.dispatchEvent('click');
    await page.waitForFunction(() => !document.querySelector('#create-notifications .notification-editor')?.disabled, null, { timeout: 5000 });
    assert.equal(lifecycleRequests, 2);
    assert.equal(await lifecycleStatus.getAttribute('role'), null);
    releaseOlder();
    await page.waitForTimeout(100);
    assert.equal(await lifecycleStatus.getAttribute('role'), null);
  } finally {
    releaseOlder?.();
    await page.unroute(`${base}/api/notifications`);
  }
  let releaseDestroyed;
  let destroyRequests = 0;
  await page.route(`${base}/api/notifications`, async (route) => {
    destroyRequests++;
    if (destroyRequests === 1) {
      await new Promise((resolve) => { releaseDestroyed = resolve; });
      await route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: 'destroyed refresh failed' }) });
    } else await route.continue();
  });
  const discardedEditor = page.locator('#create-notifications .notification-editor');
  const discardedStatus = discardedEditor.locator(':scope > p.field-help');
  const discardedStatusHandle = await discardedStatus.elementHandle();
  assert.ok(discardedStatusHandle);
  try {
    await lifecycleReload.dispatchEvent('click');
    const discardedStatusBefore = await discardedStatusHandle.textContent();
    await page.locator('#create-label').fill(`Discarded stale ${id}`);
    await page.getByRole('button', { name: 'Create request link', exact: true }).click();
    await page.locator('#new-link').waitFor({ state: 'visible' });
    releaseDestroyed();
    await page.waitForTimeout(100);
    assert.equal(destroyRequests, 1);
    assert.equal(await discardedStatusHandle.textContent(), discardedStatusBefore);
    assert.equal(await discardedStatusHandle.getAttribute('role'), null);
  } finally {
    releaseDestroyed?.();
    await page.unroute(`${base}/api/notifications`);
  }
  await page.goto(`${base}/receive`);
  await page.locator('#create-label').fill(uploadLabel);
  await choose(page.locator('#create-notifications'), 'Incoming', 'Upload completed');
  const managePagePromise = page.waitForEvent('popup');
  await page.locator('#create-notifications').getByRole('link', { name: 'Add or manage destinations ↗', exact: true }).click();
  const managePage = await managePagePromise;
  await managePage.waitForLoadState('domcontentloaded');
  await api('notifications', { label: 'Added during setup', channel: 'webhook', target: 'Extra destination', enabled: true, url: `${endpoint}/extra` });
  await managePage.close();
  await page.bringToFront();
  // Headless Chromium keeps the opener visible while a popup is open. Fire the
  // same visible return event a real tab switch produces so this remains an
  // end-to-end check of the bounded catalog reload, without a Refresh click.
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
  await page.locator('#create-notifications .notification-add option').filter({ hasText: 'Added during setup' }).waitFor({ state: 'attached' });
  assert.ok(await page.locator('#create-notifications').getByRole('group', { name: 'Incoming', exact: true }).getByLabel('Upload completed', { exact: true }).isChecked());

  await page.getByRole('button', { name: 'Create request link', exact: true }).click();
  await page.locator('#new-link').waitFor({ state: 'visible' });
  let link = (await api('admin/links')).links.find((link) => link.label === uploadLabel);
  assert.deepEqual(link.notifications.rules, [{ destination_id: incoming.id, events: ['upload_complete'] }]);
  const requestCard = page.locator('#links .link-item').filter({ has: page.getByRole('heading', { name: uploadLabel, exact: true }) });
  await requestCard.locator('.notification-details > summary').click();
  await choose(requestCard.locator('.notification-details'), 'Failures', 'Upload failed');
  await page.locator('#links-refresh').click();
  assert.ok(await requestCard.getByRole('group', { name: 'Failures', exact: true }).getByLabel('Upload failed', { exact: true }).isChecked());
  await requestCard.getByRole('button', { name: 'Save notifications', exact: true }).click();
  await requestCard.getByText('Notification settings saved.', { exact: true }).waitFor();
  link = (await api('admin/links')).links.find((link) => link.label === uploadLabel); assert.equal(link.notifications.rules.length, 2);
  let notificationRequests = 0;
  await page.route(`${base}/api/notifications`, async (route) => { notificationRequests++; await route.continue(); });
  const removedManagePopup = page.waitForEvent('popup');
  await requestCard.locator('.notification-details').getByRole('link', { name: 'Add or manage destinations ↗', exact: true }).click();
  const removedManagePage = await removedManagePopup;
  await removedManagePage.waitForLoadState('domcontentloaded'); await removedManagePage.close(); await page.bringToFront();
  await page.locator('#links-query').fill(`no request named ${id}`);
  await page.locator('#links-refresh').click();
  await requestCard.waitFor({ state: 'detached' });
  const notificationRequestsBeforeReturn = notificationRequests;
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
  await page.waitForTimeout(100);
  assert.equal(notificationRequests, notificationRequestsBeforeReturn);
  await page.unroute(`${base}/api/notifications`);
  await page.goto(`${base}/deliver`);
  await page.locator('#library-files input[type=checkbox][value="notification-clip.txt"]').check();
  await page.locator('#deliver-label').fill(downloadLabel);
  await choose(page.locator('#deliver-notifications'), 'Incoming', 'First file requested');
  await page.getByRole('button', { name: 'Create delivery link', exact: true }).click();
  await page.getByRole('heading', { name: downloadLabel, exact: true }).waitFor();
  const grants = await api('admin/outbound-grants'); const grant = grants.grants.find((grant) => grant.label === downloadLabel);
  assert.deepEqual(grant.notifications.rules, [{ destination_id: incoming.id, events: ['outbound_download_started'] }]);
  await page.goto(`${base}/workflows#projects`);
  await page.click('#workflow-new-project');
  await page.fill('#wp-label', 'Notification workflow'); await openAncestors(page.locator('#wp-id'));  await page.fill('#wp-id', id); await page.fill('#wp-directory', id);
  await choose(page.locator('#project-notifications'), 'Failures', 'Workflow failed');
  await page.locator('#workflow-save-project button[type=submit]').click();
  await page.getByRole('dialog', { name: 'Save project rules' }).getByRole('button', { name: 'Save rules', exact: true }).click();
  await page.locator('#workflow-save-project').waitFor({ state: 'hidden' });
  await page.click('#workflow-new'); await page.selectOption('#workflow-project', id);
  await page.fill('#workflow-label', 'Routed workflow');
  assert.equal(await page.locator('#workflow-notifications .notification-mode').inputValue(), 'inherit');
  await openAncestors(page.locator('#workflow-notifications'));
  await page.locator('#workflow-notifications').getByText(/Workflow failed/).first().waitFor();
  const issued = page.waitForResponse((r) => r.url().endsWith('/api/workflows/jobs') && r.request().method() === 'POST');
  await page.locator('#workflow-create button[type=submit]').click();
  const job = (await (await issued).json()).job;
  const jobCard = page.locator(`#job-${job.id}`);
  await jobCard.locator('.notification-details > summary').click();
  assert.equal(await jobCard.locator('.notification-details .notification-mode').inputValue(), 'inherit');
  await choose(jobCard.locator('.notification-details'), 'Incoming', 'Every file requested');
  await jobCard.getByRole('button', { name: 'Save notifications', exact: true }).click();
  await jobCard.getByText('Notification settings saved.', { exact: true }).waitFor();
  let detail = await api(`workflows/jobs/${job.id}`);
  assert.deepEqual(detail.job.request, job.request);
  assert.deepEqual(detail.notifications_override.rules, [{ destination_id: incoming.id, events: ['outbound_delivery_complete'] }]);
  await page.reload(); await jobCard.locator('.notification-details > summary').click();
  assert.equal(await jobCard.locator('.notification-details .notification-mode').inputValue(), 'custom');
  await jobCard.locator('.notification-details .notification-mode').selectOption('inherit');
  await jobCard.getByRole('button', { name: 'Save notifications', exact: true }).click();
  await jobCard.getByText('Notification settings saved.', { exact: true }).waitFor();
  detail = await api(`workflows/jobs/${job.id}`); assert.equal(detail.notifications_override, null);
  assert.deepEqual(detail.job.request, job.request);
  await jobCard.locator('.notification-details .notification-mode').selectOption('off');
  await jobCard.getByRole('link', { name: 'Add or manage destinations ↗', exact: true }).evaluate((link) => {
    link.addEventListener('click', (event) => event.preventDefault(), { once: true });
    link.click();
  });
  const omitJob = async (route) => {
    const response = await route.fetch(), data = await response.json();
    data.jobs = data.jobs.filter((entry) => entry.job.id !== job.id);
    await route.fulfill({ response, json: data });
  };
  await page.route('**/api/workflows/jobs?*', omitJob);
  try {
    await page.click('#workflow-refresh');
    await jobCard.waitFor({ state: 'detached' });
    await page.waitForLoadState('networkidle');
    let reloads = 0;
    const countReloads = (request) => { if (new URL(request.url()).pathname === '/api/notifications') reloads++; };
    page.on('request', countReloads);
    try {
      await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
      await page.waitForTimeout(100);
      assert.equal(reloads, 0, 'A dirty workflow omitted by refresh releases its notification return listener');
    } finally { page.off('request', countReloads); }
  } finally { await page.unroute('**/api/workflows/jobs?*', omitJob); }
  await fs.mkdir(path.join(root, 'library', `${id}-off`), { recursive: true });
  await fs.writeFile(path.join(root, 'library', `${id}-off`, 'master.txt'), 'Silent workflow fixture\n');
  await api('workflows/projects', { id: `${id}-off`, label: 'No notification defaults', directory: `${id}-off` }, 'PUT');
  const silent = (await api('workflows/jobs', { operation_id: `${id}-off`, project_id: `${id}-off`, label: 'Silent workflow', expires_days: 1 })).job;
  await page.goto(`${base}/workflows#job-${silent.id}`);
  const silentCard = page.locator(`#job-${silent.id}`);
  await choose(silentCard.locator('.notification-details'), 'Incoming', 'Every file requested');
  await silentCard.getByRole('button', { name: 'Save notifications', exact: true }).click();
  await silentCard.getByText('Notification settings saved.', { exact: true }).waitFor();
  await silentCard.locator('.notification-details .notification-mode').selectOption('inherit');
  await silentCard.getByRole('button', { name: 'Save notifications', exact: true }).click();
  await silentCard.locator('.notification-details > summary').getByText('Notifications off · configure', { exact: true }).waitFor();
  await page.goto(`${base}/notifications`);
  await choose(page.locator('#notification-defaults'), 'Failures', 'Workflow failed');
  await page.getByRole('button', { name: 'Save defaults', exact: true }).click();
  await page.locator('#confirm-ok').click();
  await page.getByText('Tenant defaults saved.', { exact: true }).waitFor();
  const defaults = (await api('notifications')).defaults; assert.equal(defaults.rules[0].events[0], 'workflow_failed');
  await page.goto(`${base}/receive`);
  await openAncestors(page.locator('#create-notifications'));
  const receiveNotifications = page.locator('#create-notifications').getByRole('combobox', { name: 'Send notifications', exact: true });
  await receiveNotifications.waitFor();
  assert.equal(await receiveNotifications.inputValue(), 'off');
  await page.locator('#create-notifications').getByText('Tenant defaults are available.', { exact: false }).waitFor();
  await api('notifications/defaults', { mode: 'custom', rules: [{ destination_id: incoming.id, events: ['upload_complete'] }] }, 'PUT');
  await page.goto(`${base}/receive`);
  const configuredReceiveNotifications = page.locator('#create-notifications').getByRole('combobox', { name: 'Send notifications', exact: true });
  await configuredReceiveNotifications.waitFor();
  assert.equal(await configuredReceiveNotifications.inputValue(), 'default');
  await page.locator('#create-notifications').getByText('Incoming · #incoming: Upload completed', { exact: true }).waitFor();
  await configuredReceiveNotifications.selectOption('off');
  await page.locator('#create-notifications').getByText('Notifications are off for this item.', { exact: false }).waitFor();
  const offUploadLabel = `${uploadLabel} explicit off`;
  await page.locator('#create-label').fill(offUploadLabel);
  await page.getByRole('button', { name: 'Create request link', exact: true }).click();
  await page.locator('#new-link').waitFor({ state: 'visible' });
  const offLink = (await api('admin/links')).links.find((link) => link.label === offUploadLabel);
  assert.equal(offLink.notifications.mode, 'off');
  const resetReceiveNotifications = page.locator('#create-notifications').getByRole('combobox', { name: 'Send notifications', exact: true });
  await resetReceiveNotifications.waitFor();
  assert.equal(await resetReceiveNotifications.inputValue(), 'default');
  await page.goto(`${base}/deliver`);
  await openAncestors(page.locator('#deliver-notifications'));
  const configuredDeliverNotifications = page.locator('#deliver-notifications').getByRole('combobox', { name: 'Send notifications', exact: true });
  await configuredDeliverNotifications.waitFor();
  assert.equal(await configuredDeliverNotifications.inputValue(), 'off');
  await page.locator('#deliver-notifications').getByText('Tenant defaults are available.', { exact: false }).waitFor();
  await api('notifications/defaults', { mode: 'custom', rules: [{ destination_id: incoming.id, events: ['outbound_download_started'] }] }, 'PUT');
  await page.goto(`${base}/deliver`);
  await openAncestors(page.locator('#deliver-notifications'));
  const applicableDeliverNotifications = page.locator('#deliver-notifications').getByRole('combobox', { name: 'Send notifications', exact: true });
  await applicableDeliverNotifications.waitFor();
  assert.equal(await applicableDeliverNotifications.inputValue(), 'default');
  await page.locator('#deliver-notifications').getByText('Incoming · #incoming: First file requested', { exact: true }).waitFor();
  for (const width of [1440, 900, 640, 390, 320]) {
    await page.setViewportSize({ width, height: 1100 });
    await page.goto(`${base}/notifications`);
    await page.locator('#notification-defaults .notification-mode').waitFor();
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `Overflow at ${width}`);
    if (width === 1440 || width === 390) await page.screenshot({ path: path.join(root, `notification-routing-${width}.png`), fullPage: true });
  }
  assert.deepEqual(errors, []);
  console.log('Notification browser checks passed: multiple destinations, private secrets, scoped tests, request/delivery routing, workflow inheritance and job overrides, defaults, responsive layout.');
} finally {
  await browser.close(); await new Promise((resolve) => sink.close(resolve));
}
