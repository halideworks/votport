import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { chromium } from 'playwright';
import { openAncestors } from './browser-helpers.mjs';

const base = process.env.BASE_URL, root = process.env.WORKFLOW_TEST_ROOT;
if (!base || !root || !process.env.ADMIN_PASSWORD) throw new Error('Use an isolated instance with BASE_URL, WORKFLOW_TEST_ROOT and ADMIN_PASSWORD.');
const id = `usability-${Date.now()}`;
await fs.mkdir(path.join(root, 'library', id), { recursive: true });
await fs.writeFile(path.join(root, 'library', id, 'cargo.txt'), 'Verified cargo\n');
const browser = await chromium.launch();
try {
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'reduce' });
  const page = await context.newPage(), errors = [], dialogs = [];
  let dismiss = false;
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('dialog', async (dialog) => { dialogs.push(dialog.type()); if (dismiss) await dialog.dismiss(); else await dialog.accept(); });
  const api = async (route, data, method = data ? 'POST' : 'GET') => {
    const response = await context.request.fetch(`${base}/api/${route}`, { method, data, headers: { 'X-Votport': '1' } });
    assert.ok(response.ok(), `${route}: ${response.status()} ${await response.text()}`); return response.json();
  };
  await api('admin/login', { password: process.env.ADMIN_PASSWORD });
  for (const route of ['receive', 'workflows', 'trade-routes', 'notifications', 'system']) {
    await page.goto(`${base}/${route}`); await page.waitForLoadState('networkidle');
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
    assert.ok(await page.getByRole('button', { name: 'Help about workflows', exact: true }).evaluate((hint) => {
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
  await page.getByRole('button', { name: 'Help about workflows', exact: true }).click();
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
  const hint = page.getByRole('button', { name: 'Help about receive links', exact: true });
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
  await page.getByRole('button', { name: 'Create receive link', exact: true }).click();
  await page.getByText('Save refused fixture', { exact: true }).waitFor();
  assert.equal(await page.inputValue('#create-label'), id);
  await page.getByRole('button', { name: 'Create receive link', exact: true }).click(); await page.locator('#new-link').waitFor();
  const before = dialogs.length; await page.goto(`${base}/workflows`); assert.equal(dialogs.length, before, 'Successful save clears the leave warning');

  await api('workflows/projects', { id, label: id, directory: id }, 'PUT');
  const issued = await api('workflows/jobs', { operation_id: id, project_id: id, label: `Cargo ${id}`, expires_days: 1 });
  await page.reload(); await page.click('#workflow-new'); await page.selectOption('#workflow-project', id);
  await page.getByRole('button', { name: 'Help about enrolled recipients', exact: true }).click();
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
  await page.getByRole('link', { name: 'Deliveries', exact: true }).click();
  await page.locator(`#job-${issued.job.id}`).waitFor(); const late = page.waitForResponse((response) => response.url().includes('/api/workflows/jobs?')); release(); await late;
  await page.waitForFunction(() => !document.querySelector('#workflow-more').disabled);
  assert.equal(await page.locator('.job-card').count(), 1);

  const jobEditor = page.locator(`#job-${issued.job.id} .notification-details`);
  await jobEditor.locator(':scope > summary').click(); await jobEditor.locator('.notification-mode').selectOption('off');
  await page.getByRole('link', { name: 'Projects', exact: true }).click();
  await page.locator('#workflow-project-list article').filter({ has: page.getByRole('heading', { name: id, exact: true }) }).getByRole('button', { name: 'Edit project', exact: true }).click();
  await page.locator('#workflow-save-project button[type=submit]').click();
  await page.locator('#confirm-ok').click(); await page.locator('#workflow-save-project').waitFor({ state: 'hidden' });
  await page.getByRole('link', { name: 'Deliveries', exact: true }).click();
  await jobEditor.locator('.notification-mode').waitFor();
  assert.equal(await jobEditor.locator('.notification-mode').inputValue(), 'off', 'Project save keeps the unsaved delivery notification editor');

  await page.goto(`${base}/system`); await page.waitForFunction(() => !document.querySelector('#smtp-form').inert);
  await page.fill('#smtp-host', 'unsaved.example'); await page.fill('#smtp-password', 'unsaved-smtp-secret');
  await page.fill('#audit-retention-days', '40'); await page.locator('#retention-form button[type=submit]').click();
  await page.locator('#retention-note').getByText('Saved.', { exact: true }).waitFor();
  assert.equal(await page.inputValue('#smtp-host'), 'unsaved.example'); assert.equal(await page.inputValue('#smtp-password'), 'unsaved-smtp-secret');
  await page.fill('#audit-retention-days', '41'); await page.locator('[data-reset=audit_retention_days]').click();
  await page.locator('#retention-note').getByText('Using environment.', { exact: true }).waitFor();
  assert.notEqual(await page.inputValue('#audit-retention-days'), '41'); assert.equal(await page.inputValue('#smtp-host'), 'unsaved.example');

  await api('admin/tenants', { key: id, label: id });
  await page.goto(`${base}/tenants`);
  const tenant = page.locator(`#tenants [data-tenant="${id}"]`);
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
  console.log('Usability browser checks passed: grouped navigation at seven widths, accessible hints, private drafts, save/cancel protection, filter races, one port setup path, and recipient verification/acceptance.');
} finally { await browser.close(); }
