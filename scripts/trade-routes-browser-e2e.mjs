import { chooseNotification, openAncestors } from './browser-helpers.mjs';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import { chromium } from 'playwright';

const base = process.env.BASE_URL, peer = process.env.TRADE_PEER_URL, root = process.env.WORKFLOW_TEST_ROOT;
if (!base || !peer || !root || !process.env.ADMIN_PASSWORD) throw new Error('Use two isolated ports with BASE_URL, TRADE_PEER_URL, WORKFLOW_TEST_ROOT and ADMIN_PASSWORD.');
const id = `trade${Date.now()}`, endpointName = `Masters ${id}`, routeName = `Route ${id}`, password = process.env.ADMIN_PASSWORD;
await fs.mkdir(path.join(root, 'library', id), { recursive: true });
await fs.writeFile(path.join(root, 'library', id, 'master.txt'), 'Two independent ports, one verified delivery.\n');
const notices = [];
const sink = http.createServer(async (request, response) => { for await (const chunk of request) { void chunk; } notices.push(request.url); response.end('ok'); });
await new Promise((resolve) => sink.listen(0, process.env.NOTIFY_TEST_BIND || '127.0.0.1', resolve));
const sinkUrl = `http://${process.env.NOTIFY_TEST_HOST || '127.0.0.1'}:${sink.address().port}`;
const browser = await chromium.launch(), errors = [];
const sender = await browser.newContext({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'reduce' });
const receiver = await browser.newContext({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'reduce' });
for (const context of [sender, receiver]) await context.addInitScript(() => {
  Object.defineProperty(navigator, 'clipboard', { value: { writeText: async (text) => { window.copiedText = String(text); } } });
});
const page = await sender.newPage(), receiving = await receiver.newPage();
for (const tab of [page, receiving]) tab.on('dialog', (dialog) => dialog.accept());
const failedResponses = [];
for (const tab of [page, receiving]) {
  tab.on('pageerror', (error) => errors.push(error.message));
  tab.on('response', (response) => {
    if (!response.ok()) failedResponses.push({ url: response.url(), status: response.status() });
  });
  tab.on('requestfailed', (request) => failedResponses.push({ url: request.url(), requestFailure: request.failure()?.errorText || 'unknown' }));
}
async function api(context, origin, route, data, method = data ? 'POST' : 'GET') {
  const response = await context.request.fetch(`${origin}/api/${route}`, { method, data, headers: { 'X-Votport': '1' } });
  assert.ok(response.ok(), `${route}: ${response.status()} ${await response.text()}`); return response.json();
}
const source = (route, data, method) => api(sender, base, route, data, method);
const destination = (route, data, method) => api(receiver, peer, route, data, method);
async function copyValue(tab, button, expected) {
  await openAncestors(button);
  const element = await button.elementHandle();
  await tab.evaluate(() => { window.copiedText = null; });
  await element.click();
  await tab.waitForFunction(() => window.copiedText !== null);
  assert.equal(await tab.evaluate(() => window.copiedText), expected);
  assert.equal(await element.textContent(), 'Copied');
  assert.deepEqual(errors, []);
}
async function until(read, predicate) { for (let n = 0; n < 80; n++) { const value = await read(); if (predicate(value)) return value; await new Promise((r) => setTimeout(r, 500)); } throw new Error('Expected state was not reached'); }
try {
  await source('admin/login', { password }); await destination('admin/login', { password });
  for (const request of [source, destination]) { const storage = await request('admin/receiving-storage'); if (!storage.ready) await request('admin/receiving-storage', { storage: storage.storage, enable: true, stable_acknowledgments: true, private_namespace: true }); }
  const receiverNotice = await destination('notifications', { id: '', revision: 0, label: `Received ${id}`, channel: 'webhook', target: 'Receiver only', url: `${sinkUrl}/receiver`, enabled: true });
  const senderNotice = await source('notifications', { id: '', revision: 0, label: `Sent ${id}`, channel: 'webhook', target: 'Sender only', url: `${sinkUrl}/sender`, enabled: true });
  await destination('trade-routes/port', { name: 'Receiver studio', address: process.env.TRADE_PEER_ADDRESS || peer }, 'PUT');
  await destination('workflows/projects', { id, label: 'Receiver approvals', directory: id, receive: true, require_approval: true }, 'PUT');
  const eligibleRequests = [];
  for (let index = 0; index < 52; index++) eligibleRequests.push((await destination('admin/links', { label: `${id}-page-${index}`, dest: `${id}/page-${index}` })).link);
  const excluded = (await destination('admin/links', { label: `${id}-excluded`, password: 'private request fixture' })).link;
  const firstRequests = await destination('admin/links?limit=50&route_eligible=true');
  assert.equal(firstRequests.links.length, 50);
  assert.ok(!firstRequests.links.some((request) => request.id === excluded.id));
  const olderRequest = eligibleRequests.find((request) => !firstRequests.links.some((entry) => entry.id === request.id));
  await receiving.goto(`${peer}/trade-routes`);
  const receiverPort = (await destination('trade-routes')).port;
  try {
    await receiving.waitForFunction(() => !!document.querySelector('#port-key')?.textContent);
  } catch (cause) {
    const state = await receiving.evaluate(() => ({
      url: location.href,
      readyState: document.readyState,
      tradeError: document.querySelector('#trade-error')?.textContent || '',
      tradeErrorHidden: document.querySelector('#trade-error')?.hidden ?? null,
      keyCount: document.querySelectorAll('#port-key').length,
      keyText: document.querySelector('#port-key')?.textContent || '',
    }));
    throw new Error(`Peer trade-routes bootstrap did not render port key: ${JSON.stringify({ state, pageErrors: errors, failedResponses })}; ${cause.message}`, { cause });
  }
  await copyValue(receiving, receiving.locator('#port-copy-address'), receiverPort.address);
  await copyValue(receiving, receiving.locator('#port-copy-key'), receiverPort.key);
  assert.ok(await receiving.locator('#trade-accept-form').isHidden());
  assert.ok(await receiving.locator('#trade-receive-setup').isHidden());
  await receiving.click('#trade-start-receive');
  assert.equal(await receiving.locator('#trade-request option').count(), 51);
  const selectedRequest = firstRequests.links[0].id;
  await receiving.selectOption('#trade-request', selectedRequest); await receiving.fill('#trade-endpoint-name', 'Keep route permission draft');
  let releaseSearch, searchStarted = false;
  const heldSearch = new Promise((resolve) => releaseSearch = resolve);
  const holdSearch = async (route) => { const response = await route.fetch(); searchStarted = true; await heldSearch; await route.fulfill({ response }); };
  await receiving.route('**/api/admin/links?*', holdSearch);
  try {
    await receiving.click('#trade-request-search'); await until(() => searchStarted, Boolean);
    const changedSelection = firstRequests.links[1].id;
    await receiving.selectOption('#trade-request', changedSelection);
    releaseSearch(); await receiving.waitForFunction(() => !document.querySelector('#trade-request-search').disabled);
    assert.equal(await receiving.locator('#trade-request').inputValue(), changedSelection, 'A delayed search must preserve a newer request selection');
  } finally { releaseSearch(); await receiving.unroute('**/api/admin/links?*', holdSearch); }
  await receiving.selectOption('#trade-request', selectedRequest);
  for (const width of [1440, 390]) {
    await receiving.setViewportSize({ width, height: 1000 });
    await receiving.locator('#trade-request-query').scrollIntoViewIfNeeded();
    assert.ok(await receiving.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `Trade receive setup fits at ${width}px`);
    await receiving.screenshot({ path: path.join(root, `trade-receive-setup-${width}.png`) });
  }
  await receiving.setViewportSize({ width: 1440, height: 1000 });
  await receiving.locator('#trade-request-more').focus(); await receiving.keyboard.press('Enter');
  await receiving.waitForFunction(() => document.querySelector('#trade-request-more').hidden);
  assert.equal(await receiving.locator('#trade-request').inputValue(), selectedRequest, 'Paging keeps the selected request');
  assert.equal(await receiving.locator('#trade-endpoint-name').inputValue(), 'Keep route permission draft');
  assert.ok(await receiving.locator('#trade-request-help').evaluate((node) => node === document.activeElement));
  assert.ok(await receiving.locator('#trade-request option').count() <= 4);
  await receiving.fill('#trade-request-query', olderRequest.id); await receiving.click('#trade-request-search');
  await receiving.waitForFunction((id) => [...document.querySelector('#trade-request').options].some((option) => option.value === id), olderRequest.id);
  await receiving.selectOption('#trade-request', olderRequest.id);
  await new Promise((resolve) => setTimeout(resolve, 1100));
  const idAlias = (await destination('admin/links', { label: `Alias for ${olderRequest.id}` })).link;
  assert.equal((await destination(`admin/links?limit=1&route_eligible=true&search=${olderRequest.id}`)).links[0].id, idAlias.id, 'General search is not an exact-ID lookup');
  await receiving.fill('#trade-request-query', 'No matching request fixture'); await receiving.locator('#trade-request-query').press('Enter');
  await receiving.waitForFunction(() => !document.querySelector('#trade-request-search').disabled && document.querySelector('#trade-request').options.length === 2);
  assert.equal(await receiving.locator('#trade-request').inputValue(), olderRequest.id, 'Search keeps the chosen request even outside its results');
  assert.equal(await receiving.locator('#trade-endpoint-name').inputValue(), 'Keep route permission draft');
  await receiving.goto(`${peer}/trade-routes?receive=${olderRequest.id}#receive`);
  await receiving.waitForFunction((id) => document.querySelector('#trade-request').value === id, olderRequest.id);
  assert.equal(await receiving.locator('#trade-request').inputValue(), olderRequest.id, 'Returning to an older request uses its exact tenant-scoped ID');
  await receiving.getByRole('link', { name: 'Create a request and return here →', exact: true }).click();
  await receiving.locator('#trade-return-guide').waitFor();
  assert.ok(await receiving.locator('#trade-return-guide').evaluate((node) => node === document.activeElement), 'Route handoff focuses its setup guide');
  assert.ok(await receiving.locator('#create-password').isHidden());
  const routeNotificationWrapper = receiving.locator('#create-notification-options').locator('xpath=..');
  assert.equal(await routeNotificationWrapper.locator('.hint-button').count(), 1);
  assert.ok(await routeNotificationWrapper.isHidden(), 'Trade route setup hides its notification help wrapper');
  await receiving.fill('#create-label', id);
  await receiving.locator('#create-workflow select').selectOption(id);
  await receiving.getByRole('button', { name: 'Continue to route permissions', exact: true }).click();
  await receiving.waitForURL(/\/trade-routes\?receive=/);
  await receiving.waitForFunction(() => !!document.querySelector('#trade-request').value);
  const receiveId = await receiving.locator('#trade-request').inputValue();
  assert.equal(new URL(receiving.url()).searchParams.get('receive'), receiveId);
  await receiving.selectOption('#trade-request', receiveId); await receiving.fill('#trade-endpoint-name', endpointName); await receiving.getByText('Forwarding and file information', { exact: true }).click(); await receiving.fill('#trade-metadata', 'episode');
  await receiving.getByText('Notifications for incoming routes', { exact: true }).click();
  await chooseNotification(receiving.locator('#trade-endpoint-notifications'), `Received ${id}`, 'Route received and verified');
  await receiving.locator('#trade-endpoint-form button[type=submit]').click(); await receiving.locator('#confirm-ok').click();
  await receiving.locator('#trade-endpoints').getByRole('heading', { name: endpointName }).waitFor();
  const endpointCard = receiving.locator('#trade-endpoints > .card').filter({ has: receiving.getByRole('heading', { name: endpointName, exact: true }) });
  await endpointCard.getByText('Invitation expiry and preapproval', { exact: true }).click();
  await endpointCard.getByLabel('Invitation expiry', { exact: true }).selectOption('3600');
  const refreshed = receiving.waitForResponse((response) => response.url().endsWith('/api/trade-routes'));
  await receiving.click('#trade-refresh'); await refreshed;
  await receiving.waitForLoadState('networkidle');
  assert.equal(await endpointCard.getByLabel('Invitation expiry', { exact: true }).inputValue(), '3600', 'Refresh preserves unfinished invitation options');
  await endpointCard.getByRole('button', { name: 'Create invitation', exact: true }).click();
  await receiving.locator('#trade-invitation-result').waitFor({ state: 'visible' });
  const invitation = await receiving.locator('#trade-issued-invitation').inputValue();
  await copyValue(receiving, receiving.locator('#trade-copy-invitation'), invitation);
  assert.ok(!JSON.stringify(JSON.parse(invitation).document.body.endpoint).includes('destination_id'));
  await page.goto(`${base}/trade-routes`);
  await page.screenshot({ path: path.join(root, 'trade-routes-start.png'), fullPage: true });
  await page.locator('#trade-start-send').focus(); await page.keyboard.press('Enter');
  assert.ok(await page.locator('#trade-accept-details').isHidden());
  await page.fill('#trade-invitation', 'https://not-an-invitation.example'); await page.click('#trade-inspect');
  await page.locator('#trade-error').getByText(/Paste the complete route invitation/).waitFor();
  for (const wrongShape of ['{}', 'null', '[]']) {
    await page.fill('#trade-invitation', wrongShape); await page.click('#trade-inspect');
    await page.locator('#trade-error').getByText(/Paste the complete route invitation/).waitFor();
    assert.ok(await page.locator('#trade-accept-details').isHidden());
    assert.ok(await page.locator('#trade-accept').isDisabled());
  }
  await page.route('**/api/trade-routes/inspect', (route) => route.fulfill({ status: 500, json: { error: 'Inspection unavailable fixture' } }), { times: 1 });
  await page.fill('#trade-invitation', invitation); await page.click('#trade-inspect');
  await page.locator('#trade-error').getByText('Inspection unavailable fixture', { exact: true }).waitFor();
  assert.ok(await page.locator('#trade-accept-details').isHidden());
  assert.ok(await page.locator('#trade-accept').isDisabled());
  let releasePreview, previewStarted;
  const heldPreview = new Promise((resolve) => { releasePreview = resolve; });
  const startedPreview = new Promise((resolve) => { previewStarted = resolve; });
  await page.route('**/api/trade-routes/inspect', async (route) => {
    const response = await route.fetch(); previewStarted(); await heldPreview; await route.fulfill({ response });
  }, { times: 1 });
  await page.fill('#trade-invitation', invitation); await page.click('#trade-inspect'); await startedPreview;
  await page.fill('#trade-invitation', 'Changed while checking'); releasePreview();
  await page.waitForFunction(() => !document.querySelector('#trade-inspect').disabled);
  assert.ok(await page.locator('#trade-accept-details').isHidden());
  assert.ok(await page.locator('#trade-accept').isDisabled());
  await page.fill('#trade-invitation', invitation); await page.click('#trade-inspect');
  await page.locator('#trade-preview').getByRole('heading', { name: 'Receiver studio' }).waitFor();
  const senderKey = await page.locator('#port-key').textContent(), receiverKey = await receiving.locator('#port-key').textContent(); assert.notEqual(senderKey, receiverKey);
  assert.ok((await page.locator('#trade-preview').innerText()).includes(receiverKey));
  await page.getByText('Notifications for this route', { exact: true }).click();
  await chooseNotification(page.locator('#trade-accept-notifications'), `Sent ${id}`, 'Route received and verified');
  await page.fill('#trade-name', routeName); await page.check('#trade-confirm'); await page.click('#trade-accept');
  await page.locator('#trade-connections').getByRole('heading', { name: routeName }).waitFor();
  let route = (await source('trade-routes')).routes.find((r) => r.name === routeName); assert.equal(route.state, 'pending_approval');
  const outgoingCard = page.locator('.trade-route').filter({ has: page.getByRole('heading', { name: routeName, exact: true }) });
  await copyValue(page, page.getByRole('button', { name: 'Copy peer fingerprint', exact: true, includeHidden: true }), receiverKey);
  await copyValue(page, outgoingCard.getByRole('button', { name: 'Copy local connection ID', exact: true, includeHidden: true }), route.id);
  await source(`trade-routes/${route.id}/test`, {});
  let incoming = (await destination('trade-routes')).routes.find((r) => r.peer_key === senderKey && r.endpoint === receiveId); assert.equal(incoming.state, 'pending_approval');
  assert.ok(!JSON.stringify(await source('trade-routes')).includes(JSON.parse(invitation).document.body.secret));
  await receiving.click('#trade-refresh');
  const incomingCard = receiving.locator('.trade-route').filter({ has: receiving.getByRole('heading', { name: endpointName, exact: true }) });
  await incomingCard.getByRole('button', { name: 'Approve incoming route', exact: true }).click();
  await receiving.locator('#confirm-ok').click();
  await until(() => destination('trade-routes'), (d) => d.routes.some((r) => r.id === incoming.id && r.state === 'active'));
  await source(`trade-routes/${route.id}/test`, {}); route = (await source('trade-routes')).routes.find((r) => r.id === route.id); assert.equal(route.state, 'active');
  await source(`trade-routes/${route.id}/rotate`, {}); await source(`trade-routes/${route.id}/test`, {});
  await source('workflows/projects', { id, label: 'Send masters', directory: id, destinations: [route.id] }, 'PUT');
  const issued = await source('workflows/jobs', { operation_id: id, project_id: id, label: 'Browser paired transfer', metadata: { episode: '42', private_note: 'keep local' }, expires_days: 1 });
  const job = await until(() => source(`workflows/jobs/${issued.job.id}`), (v) => v.job.state === 'ready');
  const receipt = job.job.checks.route_receipts[route.id]; assert.ok(receipt); assert.deepEqual(receipt.document.source.document.metadata, { episode: '42' }); assert.equal(receipt.document.source.document.permission.forwarding, false);
  const receivedJobs = await until(() => destination('workflows/jobs'), (v) => v.jobs.some((v) => v.job.received?.link_id === receiveId && v.job.state === 'awaiting_approval'));
  await source(`trade-routes/${route.id}/test`, {}); await page.click('#trade-refresh');
  await outgoingCard.getByText('Recent deliveries', { exact: true }).click(); await outgoingCard.getByText(/Received and verified · Held for approval/).waitFor();
  const receivedJob = receivedJobs.jobs.find((v) => v.job.received?.link_id === receiveId).job;
  await destination(`workflows/jobs/${receivedJob.id}`, { action: 'approve', manifest: receivedJob.manifest });
  await source(`trade-routes/${route.id}/test`, {}); await page.click('#trade-refresh'); await outgoingCard.getByText('Recent deliveries', { exact: true }).click(); await outgoingCard.getByText(/Received and verified · Released/).waitFor();
  for (const width of [320, 390, 768, 1440]) { await page.setViewportSize({ width, height: 1000 }); assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `No overflow at ${width}px`); }
  await page.screenshot({ path: path.join(root, 'trade-routes.png'), fullPage: true });
  await outgoingCard.getByText('Permissions and notifications', { exact: true }).click();
  await outgoingCard.getByLabel('Permission on this port', { exact: true }).selectOption('paused');
  const retainedEditor = await outgoingCard.locator('form[data-unsaved]').elementHandle();
  // Arm the return listener without opening another tab or changing browser focus.
  await outgoingCard.getByRole('link', { name: 'Add or manage destinations ↗', exact: true }).evaluate((link) => {
    link.addEventListener('click', (event) => event.preventDefault(), { once: true });
    link.click();
  });
  const oldCard = await outgoingCard.elementHandle();
  await page.click('#trade-refresh');
  await page.waitForFunction((card) => !card.isConnected, oldCard);
  assert.ok(await retainedEditor.evaluate((form) => form.isConnected), 'Refresh retains the dirty route editor');
  assert.equal(await outgoingCard.getByLabel('Permission on this port', { exact: true }).inputValue(), 'paused');
  const hideRoute = async (request) => {
    const response = await request.fetch(), data = await response.json();
    data.routes = data.routes.filter((entry) => entry.id !== route.id);
    await request.fulfill({ response, json: data });
  };
  await page.route('**/api/trade-routes', hideRoute);
  try {
    await page.click('#trade-refresh');
    await outgoingCard.waitFor({ state: 'detached' });
    await page.waitForLoadState('networkidle');
    let catalogRequests = 0;
    const countCatalog = (request) => { if (new URL(request.url()).pathname === '/api/notifications') catalogRequests++; };
    page.on('request', countCatalog);
    try {
      await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
      await page.waitForTimeout(100);
      assert.equal(catalogRequests, 0, 'Removing a retained route editor removes its notification return listener');
    } finally { page.off('request', countCatalog); }
  } finally { await page.unroute('**/api/trade-routes', hideRoute); }
  await page.click('#trade-refresh');
  await outgoingCard.waitFor();
  incoming = (await destination('trade-routes')).routes.find((r) => r.id === incoming.id);
  await destination(`trade-routes/${incoming.id}`, { revision: incoming.revision, state: 'revoked', cancel_active: false, notifications: incoming.notifications }, 'PUT');
  await source(`trade-routes/${route.id}/test`, {}); assert.equal((await source('trade-routes')).routes.find((r) => r.id === route.id).remote_state, 'revoked');
  await until(async () => notices, (v) => v.includes('/receiver') && v.includes('/sender'));
  assert.deepEqual(notices.sort(), ['/receiver', '/sender']);
  const pendingReason = 'Destination refused <revocation> & retry';
  const pendingRevocation = async (request) => {
    const response = await request.fetch(), data = await response.json();
    const entry = data.jobs.find((entry) => entry.job.id === issued.job.id);
    assert.ok(entry, 'The route delivery is present in the workflow list');
    entry.job.checks.route_revocations = { [route.id]: { state: 'pending', error: pendingReason } };
    await request.fulfill({ response, json: data });
  };
  await page.route('**/api/workflows/jobs?*', pendingRevocation);
  try {
    await page.goto(`${base}/workflows#job-${issued.job.id}`);
    await page.locator(`#job-${issued.job.id}`).getByText(pendingReason, { exact: false }).waitFor();
    assert.equal(await page.locator(`#job-${issued.job.id} revocation`).count(), 0, 'Remote failure text must not become markup');
    await source(`workflows/jobs/${issued.job.id}`, { action: 'cancel' });
    await until(() => source(`workflows/jobs/${issued.job.id}`), (entry) => entry.job.checks.route_revocations?.[route.id]?.state === 'acknowledged');
  } finally { await page.unroute('**/api/workflows/jobs?*', pendingRevocation); }
  await page.click('#workflow-refresh');
  await page.locator(`#job-${issued.job.id}`).getByText('Revocation acknowledged by the destination port.', { exact: true }).waitFor();
  assert.equal(await page.locator(`#job-${issued.job.id}`).getByText(pendingReason, { exact: false }).count(), 0, 'Acknowledgement clears the displayed failure reason');
  await receiving.route(`**/api/admin/links/${olderRequest.id}`, (route) => route.fulfill({ status: 503, json: { error: 'Returned request unavailable fixture' } }), { times: 1 });
  await receiving.goto(`${peer}/trade-routes?receive=${olderRequest.id}#receive`);
  await receiving.locator('#trade-request-help').getByText(/Returned request unavailable fixture/).waitFor();
  await receiving.locator(`#endpoint-${receiveId}`).waitFor();
  assert.equal(await receiving.locator('#trade-connections .trade-route').count(), 1, 'A failed returned-request lookup keeps the route catalog visible');
  await destination(`admin/links/${olderRequest.id}`, undefined, 'DELETE');
  for (let retry = 0; retry < 2; retry++) {
    await receiving.click('#trade-refresh');
    await receiving.locator('#trade-request-help').getByText(/Could not select the returned request/).waitFor();
    await receiving.waitForLoadState('networkidle');
    assert.equal(await receiving.locator('#trade-connections .trade-route').count(), 1);
    assert.equal(await receiving.locator(`#endpoint-${receiveId}`).count(), 1, 'A deleted return request does not erase existing receiving endpoints');
  }
  await new Promise((resolve) => setTimeout(resolve, 1100));
  for (let index = 0; index < 50; index++) await destination('admin/links', { label: `${id}-newer-${index}` });
  assert.ok(!(await destination('admin/links')).links.some((request) => request.id === receiveId), 'The endpoint request is outside the first Receive page');
  await receiving.locator(`#endpoint-${receiveId}`).getByRole('link', { name: 'Receiving folder, limits and project →', exact: true }).click();
  await receiving.locator(`#link-${receiveId}`).waitFor({ timeout: 5000 });
  assert.equal(new URL(receiving.url()).searchParams.get('search'), receiveId);
  assert.deepEqual(errors, []); console.log('Trade route browser acceptance passed: five clipboard actions, preview, independent keys, approval, rotation, transfer, metadata filtering, downstream hold, revocation, responsive UI.');
} finally { await browser.close(); await new Promise((resolve) => sink.close(resolve)); }
