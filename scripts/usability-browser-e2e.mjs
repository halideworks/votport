import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { chromium } from 'playwright';
import { apiClient, openAncestors } from './browser-helpers.mjs';

const base = process.env.BASE_URL, root = process.env.WORKFLOW_TEST_ROOT;
if (!base || !root || !process.env.ADMIN_PASSWORD) throw new Error('Use an isolated instance with BASE_URL, WORKFLOW_TEST_ROOT and ADMIN_PASSWORD.');
const id = `usability-${Date.now()}`;
await fs.mkdir(path.join(root, 'library', id), { recursive: true });
await fs.writeFile(path.join(root, 'library', id, 'cargo.txt'), 'Verified cargo\n');
const browser = await chromium.launch();
try {
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'reduce' });
  const page = await context.newPage(), errors = [], dialogs = [];
  await page.addInitScript(() => Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: async () => {} } }));
  let dismiss = false;
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('dialog', async (dialog) => { dialogs.push(dialog.type()); if (dismiss) await dialog.dismiss(); else await dialog.accept(); });
  const api = apiClient(context, base);
  async function checkCollapsedFormHints(rootSelector) {
    const wrappers = page.locator(`${rootSelector} .form-advanced-with-hint`);
    for (let index = 0; index < await wrappers.count(); index += 1) {
      const wrapper = wrappers.nth(index);
      const details = wrapper.locator(':scope > details');
      const summary = details.locator(':scope > summary');
      const hint = wrapper.locator(':scope > button[data-hint]');
      const tooltip = wrapper.locator(':scope > .field-hint');
      await details.evaluate((node) => { node.open = false; });
      assert.ok(await hint.isVisible(), `${rootSelector}: collapsed help stays visible`);
      await hint.click(); await tooltip.waitFor(); await page.keyboard.press('Escape');
      await summary.click();
      assert.ok(await details.evaluate((node) => node.open), `${rootSelector}: help summary opens details`);
      await summary.click();
      assert.equal(await details.evaluate((node) => node.open), false, `${rootSelector}: help summary closes details`);
      assert.ok(await hint.isVisible(), `${rootSelector}: help stays visible when collapsed`);
    }
  }
  await api('admin/login', { password: process.env.ADMIN_PASSWORD });
  await api('admin/login', { password: process.env.ADMIN_PASSWORD });
  await api('admin/login', { password: process.env.ADMIN_PASSWORD });
  const auditPageResponse = await page.goto(`${base}/audit`);
  await page.waitForLoadState('networkidle');
  assert.ok(auditPageResponse.headers()['content-security-policy'].includes("img-src 'self';"));
  assert.ok(!auditPageResponse.headers()['content-security-policy'].includes("img-src 'self' data:"));
  await page.fill('#audit-event', 'admin_login');
  await Promise.all([
    page.waitForResponse((response) => response.url().includes('/api/admin/audit?') && response.request().method() === 'GET'),
    page.getByRole('button', { name: 'Apply', exact: true }).click(),
  ]);
  const exportRows = async (href) => {
    const response = await context.request.fetch(new URL(href, base).toString(), { headers: { 'X-Votport': '1' } });
    assert.equal(response.status(), 200);
    return (await response.text()).trim().split('\n').filter(Boolean).map((line) => JSON.parse(line));
  };
  const newestHref = await page.locator('#export').getAttribute('href');
  assert.ok(newestHref);
  assert.match(newestHref, /(?:\?|&)limit=10000(?:&|$)/);
  assert.match(newestHref, /(?:\?|&)before_rowid=0(?:&|$)/);
  assert.match(newestHref, /(?:\?|&)event=admin_login(?:&|$)/);
  assert.equal(await page.locator('#export').textContent(), 'Export newest 10,000 rows');
  const newestRows = await exportRows(newestHref);
  assert.ok(newestRows.length >= 2);
  assert.ok(Number(newestRows[0].rowid) > Number(newestRows[1].rowid), 'newest export order');
  await Promise.all([
    page.waitForResponse((response) => response.url().includes('/api/admin/audit?') && response.request().method() === 'GET'),
    page.selectOption('#audit-order', 'oldest'),
  ]);
  const oldestHref = await page.locator('#export').getAttribute('href');
  assert.ok(oldestHref);
  assert.match(oldestHref, /(?:\?|&)limit=10000(?:&|$)/);
  assert.doesNotMatch(oldestHref, /(?:\?|&)(?:before_rowid|after_rowid|since)=/);
  assert.match(oldestHref, /(?:\?|&)event=admin_login(?:&|$)/);
  assert.equal(await page.locator('#export').textContent(), 'Export oldest 10,000 rows');
  const oldestRows = await exportRows(oldestHref);
  assert.ok(oldestRows.length >= 2);
  assert.ok(Number(oldestRows[0].rowid) < Number(oldestRows[1].rowid), 'oldest export order');
  await page.goto(`${base}/receive`); await page.locator('#create-password').waitFor({ state: 'attached' });
  await checkCollapsedFormHints('#create-form');
  assert.equal(await page.locator('#create-password').getAttribute('autocomplete'), 'new-password');
  await page.goto(`${base}/r/${id}`, { waitUntil: 'domcontentloaded' }); await page.locator('#link-password').waitFor({ state: 'attached' });
  assert.equal(await page.locator('#link-password').getAttribute('autocomplete'), 'current-password');
  const session = await api('admin/session');
  async function assertStorageNavigation(sessionOverride, expectedHint, managed) {
    await page.route(`${base}/storage`, async (route) => {
      const response = await route.fetch();
      const body = (await response.text()).replace(/(<script id="admin-session" type="application\/json">)[\s\S]*?(<\/script>)/, (_, start, end) => start + JSON.stringify(sessionOverride) + end);
      await route.fulfill({ response, body });
    }, { times: 1 });
    await page.goto(`${base}/storage`); await page.locator('#nav a[href="/storage"]').waitFor({ state: 'attached' });
    assert.equal(await page.locator('#nav a[href="/storage"]').getAttribute('data-hint'), expectedHint);
    assert.equal(await page.locator('#storage-new').isHidden(), !managed);
  }
  await assertStorageNavigation(session, 'Manage receiving storage, S3 buckets and shared folders.', true);
  await assertStorageNavigation({ ...session, role: 'admin', tenant: 'named-tenant' }, 'View available storage connections.', false);
  for (const route of ['receive', 'workflows', 'trade-routes', 'notifications', 'system']) {
    await page.goto(`${base}/${route}`); await page.waitForLoadState('networkidle');
    assert.equal(await page.locator('h2 button[data-hint], h3 button[data-hint], legend button[data-hint], summary button[data-hint]').count(), 0, `${route}: help controls stay outside semantic headings`);
    const labels = await page.locator('button[data-hint]').evaluateAll((buttons) => buttons.map((button) => button.getAttribute('aria-label')));
    assert.equal(new Set(labels).size, labels.length, `${route}: duplicate help controls`);
    assert.equal(await page.locator('#nav a[data-hint]').count(), 10);
    const styles = await page.locator('.field-hint').evaluateAll((hints) => hints.map((hint) => {
      const style = getComputedStyle(hint); return [style.textTransform, style.letterSpacing, style.fontWeight, style.fontSize];
    }));
    for (const style of styles) assert.deepEqual(style, ['none', 'normal', '400', '13.12px'], `${route}: tooltip typography`);
    for (const theme of ['dark', 'light']) {
      if (await page.evaluate(() => document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark')) !== theme) await page.click('#theme-toggle');
      for (const width of [390, 1440]) {
        await page.setViewportSize({ width, height: 1000 });
        assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `${route}: overflow at ${width}`);
        await page.screenshot({ path: path.join(root, `design-${route}-${theme}-${width}.png`) });
      }
    }
  }
  for (const reducedMotion of ['no-preference', 'reduce']) {
    await page.emulateMedia({ reducedMotion });
    await page.goto(`${base}/workflows`); await page.waitForLoadState('networkidle');
    await page.locator('#nav .nav-more > summary').click();
    await page.locator('.nav-panel').evaluate(async (panel) => { await Promise.all(panel.getAnimations().map((animation) => animation.finished)); });
    assert.ok(await page.getByRole('button', { name: 'Help about deliveries', exact: true }).evaluate((hint) => {
      const rect = hint.getBoundingClientRect();
      return !!document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2)?.closest('.nav-panel');
    }), `${reducedMotion}: navigation covers the page help button`);
    await page.screenshot({ path: path.join(root, `navigation-layering-${reducedMotion}.png`) });
    await page.keyboard.press('Escape');
  }
  await page.goto(`${base}/receive`);
  const workflowLink = page.locator('#nav a[href="/workflows"]');
  await workflowLink.focus(); await page.getByRole('tooltip').filter({ hasText: 'Prepare deliveries with reusable checks' }).waitFor();
  await page.keyboard.press('Enter'); await page.waitForURL(`${base}/workflows`);
  await page.getByRole('button', { name: 'Help about deliveries', exact: true }).click();
  await page.getByRole('tooltip').filter({ hasText: 'A project holds reusable rules.' }).waitFor();
  await page.keyboard.press('Escape');
  await page.locator('#nav a[href="/trade-routes"]').hover();
  await page.getByRole('tooltip').filter({ hasText: 'Connect ports to move files' }).waitFor();
  await page.locator('#nav a[href="/trade-routes"]').click(); await page.waitForURL(`${base}/trade-routes`);
  const touchContext = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  await touchContext.addCookies(await context.cookies()); const touch = await touchContext.newPage();
  await touch.goto(`${base}/trade-routes`); await touch.getByRole('button', { name: 'Help about trade routes', exact: true }).tap();
  await touch.getByRole('tooltip').filter({ hasText: 'The receiving team creates an invitation' }).waitFor();
  await touch.screenshot({ path: path.join(root, 'design-touch-hint.png') });
  await touch.locator('#nav a[href="/workflows"]').tap(); await touch.waitForURL(`${base}/workflows`);
  await touchContext.close();
  await page.goto(`${base}/receive`); await page.locator('#create-notifications .notification-mode').waitFor({ state: 'attached' });
  assert.equal(await page.locator('#nav .nav-primary a').count(), 4);
  for (const width of [320, 390, 640, 768, 1024, 1440, 2560]) {
    await page.setViewportSize({ width, height: 1000 });
    const menu = page.locator('#nav .nav-more');
    assert.equal(await menu.locator(':scope > summary').textContent(), 'Port settings');
    if (await menu.getAttribute('open') === null) await menu.locator(':scope > summary').click();
    assert.equal(await page.locator('#nav a:visible').count(), 10);
    for (const link of await page.locator('#nav a').all()) {
      const box = await link.boundingBox(); assert.ok(box.x >= 0 && box.x + box.width <= width, `Navigation clipped at ${width}`);
    }
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `Page overflow at ${width}`);
    if ([390, 1440].includes(width)) await page.screenshot({ path: path.join(root, `navigation-${width}.png`), fullPage: true });
    await page.keyboard.press('Escape'); assert.equal(await menu.getAttribute('open'), null);
  }
  await page.setViewportSize({ width: 390, height: 1000 });
  const hint = page.getByRole('button', { name: 'Help about requests', exact: true });
  await hint.focus(); await page.locator('.field-hint:popover-open').waitFor();
  await page.keyboard.press('Escape'); assert.equal(await page.locator('.field-hint:popover-open').count(), 0);
  await hint.click(); await page.locator('.field-hint:popover-open').waitFor(); await page.keyboard.press('Escape');
  await page.fill('#create-label', id); await page.fill('#create-dest', id);
  await openAncestors(page.locator('#create-password')); await page.fill('#create-password', 'never-store-this-password');
  const stored = await page.evaluate(() => Object.keys(sessionStorage).filter((key) => key.startsWith('votport-form:')).map((key) => sessionStorage.getItem(key)).join(''));
  assert.ok(stored.includes(id)); assert.ok(!stored.includes('never-store-this-password'));
  await page.reload(); await page.locator('.draft-note').waitFor();
  assert.equal(await page.inputValue('#create-label'), id); assert.equal(await page.inputValue('#create-password'), '');
  await page.route('**/api/admin/logout', (route) => route.fulfill({ status: 503, json: { error: 'Sign out refused fixture' } }), { times: 1 });
  await page.click('#logout'); await page.getByText('Sign out refused fixture', { exact: true }).waitFor();
  await page.locator('#confirm-cancel').click();
  dismiss = true; const leaving = page.waitForEvent('dialog');
  await page.evaluate(() => document.querySelector('#nav a[href="/workflows"]').click()); await leaving;
  assert.ok(page.url().endsWith('/receive')); dismiss = false;
  await page.route('**/api/admin/links', (route) => route.request().method() === 'POST' ? route.fulfill({ status: 422, json: { error: 'Save refused fixture' } }) : route.continue(), { times: 1 });
  await page.getByRole('button', { name: 'Create request link', exact: true }).click();
  await page.getByText('Save refused fixture', { exact: true }).waitFor();
  assert.equal(await page.inputValue('#create-label'), id);
  await page.getByRole('button', { name: 'Create request link', exact: true }).click(); await page.locator('#new-link').waitFor();
  const createdLink = (await api('admin/links')).links.find((link) => link.label === id);
  assert.ok(createdLink);
  const createdCard = page.locator(`#link-${createdLink.id}`);
  await createdCard.waitFor();
  const copyLink = createdCard.getByRole('button', { name: /^Copy request link: / });
  assert.equal(await copyLink.count(), 1);
  await copyLink.click();
  await createdCard.getByRole('button', { name: 'Copied', exact: true }).waitFor();
  await createdCard.getByRole('button', { name: /^Copy request link: / }).waitFor();
  assert.equal(await createdCard.getByRole('button', { name: /^Show QR code: / }).count(), 1);
  const before = dialogs.length; await page.goto(`${base}/workflows`); assert.equal(dialogs.length, before, 'Successful save clears the leave warning');

  await api('workflows/projects', { id, label: id, directory: id }, 'PUT');
  const issued = await api('workflows/jobs', { operation_id: id, project_id: id, label: `Cargo ${id}`, expires_days: 1 });
  await page.reload(); await page.click('#workflow-new');
  await page.locator('#workflow-create').waitFor();
  await checkCollapsedFormHints('#workflow-create');
  const recipientHelp = page.getByRole('button', { name: /Help about enrolled recipients/ });
  assert.equal(await recipientHelp.count(), 1);
  await page.selectOption('#workflow-project', '');
  assert.equal(await recipientHelp.count(), 1);
  await page.selectOption('#workflow-project', id);
  assert.equal(await recipientHelp.count(), 1);
  await recipientHelp.click();
  await page.getByRole('tooltip').filter({ hasText: 'An enrolled recipient proves access' }).waitFor();
  await page.keyboard.press('Escape'); await page.click('#workflow-close-create');
  await page.selectOption('#workflow-filter-project', id);
  await page.waitForFunction(() => !document.querySelector('#workflow-more').disabled);
  await page.locator(`#job-${issued.job.id}`).waitFor();
  assert.equal(await page.locator('.job-card').count(), 1);
  await page.fill('#workflow-query', 'no cargo matches'); await page.getByRole('button', { name: 'Filter deliveries', exact: true }).click();
  await page.getByRole('heading', { name: 'No deliveries match', exact: true }).waitFor();
  let release, started;
  const held = new Promise((resolve) => release = resolve), requested = new Promise((resolve) => started = resolve);
  await page.route('**/api/workflows/jobs?*', async (route) => { const response = await route.fetch(); started(); await held; await route.fulfill({ response }); }, { times: 1 });
  await page.fill('#workflow-query', id); await page.getByRole('button', { name: 'Filter deliveries', exact: true }).click(); await requested;
  assert.ok(await page.locator('#workflow-more').isDisabled()); assert.ok(await page.locator('#workflow-jobs').evaluate((node) => node.inert));
  await page.getByRole('link', { name: 'Projects', exact: true }).click();
  await page.getByRole('link', { name: 'Delivery jobs', exact: true }).click();
  await page.locator(`#job-${issued.job.id}`).waitFor(); const late = page.waitForResponse((response) => response.url().includes('/api/workflows/jobs?')); release(); await late;
  await page.waitForFunction(() => !document.querySelector('#workflow-more').disabled);
  assert.equal(await page.locator('.job-card').count(), 1);

  const jobEditor = page.locator(`#job-${issued.job.id} .notification-details`);
  await jobEditor.locator(':scope > summary').click(); await jobEditor.locator('.notification-mode').selectOption('off');
  await page.getByRole('link', { name: 'Projects', exact: true }).click();
  await page.locator('#workflow-project-list article').filter({ has: page.getByRole('heading', { name: id, exact: true }) }).getByRole('button', { name: 'Edit project', exact: true }).click();
  await page.locator('#workflow-save-project button[type=submit]').click();
  await page.locator('#confirm-ok').click(); await page.locator('#workflow-save-project').waitFor({ state: 'hidden' });
  await page.getByRole('link', { name: 'Delivery jobs', exact: true }).click();
  await jobEditor.locator('.notification-mode').waitFor();
  assert.equal(await jobEditor.locator('.notification-mode').inputValue(), 'off', 'Project save keeps the unsaved delivery notification editor');

  await page.goto(`${base}/system`); await page.waitForFunction(() => !document.querySelector('#smtp-form').inert);
  assert.equal(await page.locator('button[type=submit][aria-label^="Save "]').count(), 7, 'System save buttons identify their settings');
  await page.fill('#smtp-host', 'unsaved.example'); await page.fill('#smtp-password', 'unsaved-smtp-secret');
  await page.fill('#audit-retention-days', '40'); await page.locator('#retention-form button[type=submit]').click();
  await page.locator('#retention-note').getByText('Saved.', { exact: true }).waitFor();
  assert.equal(await page.inputValue('#smtp-host'), 'unsaved.example'); assert.equal(await page.inputValue('#smtp-password'), 'unsaved-smtp-secret');
  assert.equal(await page.locator('#audit-retention-source').textContent(), 'saved');
  assert.equal(await page.locator('[data-reset=audit_retention_days]').isVisible(), true);
  await page.fill('#audit-retention-days', '41'); await page.locator('[data-reset=audit_retention_days]').click();
  await page.locator('#retention-note').getByText('Using environment.', { exact: true }).waitFor();
  assert.notEqual(await page.inputValue('#audit-retention-days'), '41'); assert.equal(await page.inputValue('#smtp-host'), 'unsaved.example');
  assert.equal(await page.locator('#audit-retention-source').textContent(), 'from environment');
  assert.equal(await page.locator('[data-reset=audit_retention_days]').isVisible(), false);

  const clockPage = await context.newPage();
  const clockSettings = structuredClone(await api('admin/settings'));
  let clockPayload = { raw_wall_at: 1_700_000_000, held: true, capped: false };
  let clockAckResponse = 'ok';
  const clockAckBodies = [];
  await clockPage.route('**/api/admin/settings', async (route) => {
    const request = route.request();
    if (request.method() !== 'GET' || new URL(request.url()).pathname !== '/api/admin/settings') {
      await route.continue(); return;
    }
    const body = { ...clockSettings };
    delete body.retention_clock;
    if (clockPayload !== undefined) body.retention_clock = clockPayload;
    await route.fulfill({ json: body });
  });
  await clockPage.route('**/api/admin/settings/retention-clock/acknowledge', async (route) => {
    const request = route.request();
    if (request.method() !== 'POST') { await route.continue(); return; }
    clockAckBodies.push(request.postDataJSON());
    if (clockAckResponse === 'conflict') {
      await route.fulfill({ status: 409, json: { error: 'Clock changed fixture' } }); return;
    }
    clockPayload = { raw_wall_at: 1_700_000_000, held: false, capped: false };
    await route.fulfill({ json: { ...clockSettings, retention_clock: clockPayload } });
  });
  await clockPage.goto(`${base}/system`); await clockPage.waitForFunction(() => !document.querySelector('#smtp-form').inert);
  await clockPage.locator('#retention-clock-status').waitFor();
  assert.match(await clockPage.locator('#retention-clock-status').textContent(), /Cleanup based on file and record age is paused/);
  assert.equal(await clockPage.getByRole('button', { name: 'Confirm server time', exact: true }).isVisible(), true);
  const displayedAt = Number(await clockPage.locator('#retention-clock-ack').getAttribute('data-observed-at'));
  await new Promise((resolve) => setTimeout(resolve, 100));
  await clockPage.getByRole('button', { name: 'Confirm server time', exact: true }).click();
  await clockPage.getByText('Server time confirmed.', { exact: true }).waitFor();
  assert.deepEqual(clockAckBodies, [{ observed_at: displayedAt }], 'confirmation sends the displayed server observation');

  clockPayload = { raw_wall_at: 1_700_000_001, held: false, capped: true };
  await clockPage.reload(); await clockPage.locator('#retention-clock-status').waitFor();
  assert.match(await clockPage.locator('#retention-clock-status').textContent(), /Cleanup based on file and record age is limited/);
  assert.equal(await clockPage.getByRole('button', { name: 'Confirm server time', exact: true }).isVisible(), true);

  const ackCountBeforeEmpty = clockAckBodies.length;
  for (const emptyPayload of [undefined, {}]) {
    clockPayload = emptyPayload;
    await clockPage.reload();
    await clockPage.waitForFunction(() => document.querySelector('#retention-clock-status').textContent.includes('unavailable'));
    assert.equal(await clockPage.locator('#retention-clock-ack').isHidden(), true);
    await clockPage.evaluate(() => document.querySelector('#retention-clock-ack').click());
    assert.equal(await clockPage.locator('#retention-clock-note').textContent(), 'Refresh settings before confirming the server time.');
  }
  assert.equal(clockAckBodies.length, ackCountBeforeEmpty, 'empty clock data never sends a confirmation request');

  clockPayload = { raw_wall_at: 1_700_000_002, held: true, capped: false };
  clockAckResponse = 'conflict';
  await clockPage.reload(); await clockPage.locator('#retention-clock-status').waitFor();
  await clockPage.fill('#audit-retention-days', '73');
  clockPayload = { raw_wall_at: 1_700_000_003, held: false, capped: true };
  await clockPage.getByRole('button', { name: 'Confirm server time', exact: true }).click();
  await clockPage.getByText('Clock changed fixture', { exact: true }).waitFor();
  await clockPage.waitForFunction(() => document.querySelector('#retention-clock-status').textContent.includes('limited'));
  assert.equal(await clockPage.inputValue('#audit-retention-days'), '73', 'a refresh keeps the dirty retention setting');
  await clockPage.close();

  await api('admin/tenants', { key: id, label: id });
  await page.goto(`${base}/tenants`);
  const tenant = page.locator(`#tenants [data-tenant="${id}"]`);
  assert.equal(await tenant.locator('summary[aria-label^="Edit namespace: "]').count(), 1, 'Tenant edit control names its namespace');
  await tenant.getByText('Branding', { exact: true }).click();
  await page.waitForFunction((id) => !document.querySelector(`[data-tenant="${id}"]`).querySelectorAll('form')[1].inert, id);
  await tenant.getByLabel('Footer message', { exact: true }).fill('Unsaved tenant footer');
  await tenant.getByText('Edit namespace', { exact: true }).click();
  await tenant.getByLabel('Label', { exact: true }).fill('Updated namespace name');
  const patched = page.waitForResponse((response) => response.url().endsWith(`/api/admin/tenants/${id}`) && response.request().method() === 'PATCH');
  await tenant.getByRole('button', { name: 'Save', exact: true }).click(); await patched;
  await page.waitForFunction((id) => !document.querySelector(`[data-tenant="${id}"]`).querySelector('form').inert, id);
  assert.equal(await tenant.getByLabel('Footer message', { exact: true }).inputValue(), 'Unsaved tenant footer');
  assert.ok(await tenant.getByRole('button', { name: 'Save', exact: true }).isEnabled());

  await page.goto(`${base}/storage`); await page.click('#storage-new');
  assert.deepEqual(await page.locator('#ws-kind option').evaluateAll((options) => options.map((option) => option.value)), ['s3', 'folder']);
  await page.fill('#ws-label', 'Unsaved storage'); dismiss = true; await page.click('#storage-close');
  assert.ok(await page.locator('#workflow-save-storage').isVisible()); assert.equal(await page.inputValue('#ws-label'), 'Unsaved storage');
  dismiss = false; await page.click('#storage-close'); assert.ok(await page.locator('#workflow-save-storage').isHidden());

  await fs.writeFile(path.join(root, 'library', `${id}.txt`), 'Verified cargo\n');
  const download = await api('admin/outbound-grants', { paths: [`${id}.txt`], label: 'Cargo for review', expires_days: 1 });
  const recipient = await context.newPage(); recipient.on('pageerror', (error) => errors.push(error.message));
  await recipient.goto(download.url); await recipient.locator('#download-content').waitFor();
  assert.ok(await recipient.evaluate(() => !!(document.querySelector('#download-content').compareDocumentPosition(document.querySelector('#delivery-evidence')) & Node.DOCUMENT_POSITION_FOLLOWING)));
  await recipient.locator('#delivery-evidence > summary').click();
  await recipient.locator('#evidence-files').setInputFiles(path.join(root, 'library', `${id}.txt`));
  await recipient.click('#evidence-verify'); await recipient.getByRole('button', { name: 'Accept verified delivery', exact: true }).waitFor();
  recipient.on('dialog', (dialog) => dialog.accept()); await recipient.getByRole('button', { name: 'Accept verified delivery', exact: true }).click();
  await recipient.getByText(/Delivery accepted and reported to the sender/).waitFor();
  for (const width of [320, 390, 768, 1440]) { await recipient.setViewportSize({ width, height: 1000 }); assert.ok(await recipient.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `Recipient overflow at ${width}`); }
  await recipient.screenshot({ path: path.join(root, 'recipient-verification.png'), fullPage: true });
  assert.deepEqual(errors, []);
  console.log('Usability browser checks passed: grouped navigation at seven widths, accessible hints, private drafts, save/cancel protection, filter races, retention clock confirmation and refresh flows, one port setup path, and recipient verification/acceptance.');
} finally { await browser.close(); }
