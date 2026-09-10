import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import { chromium } from 'playwright';

const base = process.env.BASE_URL, root = process.env.WORKFLOW_TEST_ROOT;
if (!base || !root || !process.env.ADMIN_PASSWORD) throw new Error('Use BASE_URL, WORKFLOW_TEST_ROOT and ADMIN_PASSWORD for an isolated instance.');
const messages = [];
let failTeams = false;
const sink = http.createServer(async (request, response) => {
  const chunks = []; for await (const chunk of request) chunks.push(chunk);
  const url = new URL(request.url, 'http://fixture');
  messages.push({ channel: url.pathname.slice(1), query: url.searchParams, body: JSON.parse(Buffer.concat(chunks)) });
  response.writeHead(failTeams && url.pathname === '/teams' ? 429 : 200); response.end('1');
});
await new Promise((resolve) => sink.listen(0, process.env.NOTIFY_TEST_BIND || '127.0.0.1', resolve));
const endpoint = `http://${process.env.NOTIFY_TEST_HOST || '127.0.0.1'}:${sink.address().port}`;
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'reduce' });
const page = await context.newPage(), errors = [];
let sessionReads = 0;
page.on('pageerror', (error) => errors.push(error.message));
page.on('request', (request) => { if (new URL(request.url()).pathname === '/api/admin/session') sessionReads++; });
const api = async (route, data, method = data ? 'POST' : 'GET') => {
  const response = await context.request.fetch(`${base}/api/${route}`, { method, data, headers: { 'X-Votport': '1' } });
  assert.ok(response.ok(), `${route}: ${response.status()} ${await response.text()}`); return response.json();
};
const card = (channel) => page.locator(`[data-chat-channel=${channel}]`);
async function saved(channel) {
  await card(channel).getByText('Connected', { exact: true }).waitFor();
  await page.waitForFunction((channel) => !document.querySelector(`[data-chat-channel=${channel}]`).inert, channel);
  assert.equal(await card(channel).locator('input').inputValue(), '');
  assert.ok(await card(channel).getByRole('button', { name: 'Send test', exact: true }).isEnabled());
}
async function save(channel) {
  await card(channel).getByRole('button', { name: 'Save connection', exact: true }).click(); await saved(channel);
}
try {
  await api('admin/login', { password: process.env.ADMIN_PASSWORD });
  await api('admin/settings', Object.fromEntries(['slack', 'teams', 'google_chat', 'discord'].map((c) => [`notify_${c}`, ''])), 'PUT');
  await page.goto(`${base}/system#notifications`);
  await page.waitForFunction(() => !document.querySelector('[data-chat-channel=slack]').inert);
  const html = await (await context.request.get(`${base}/system`)).text();
  assert.ok(html.includes('<a href="/system" class="active" aria-current="page">System</a>'));
  assert.ok(html.includes('id="admin-session"'));

  // Delaying an older response must not undo another card's newer state.
  let release, started;
  const held = new Promise((resolve) => release = resolve), entered = new Promise((resolve) => started = resolve);
  await page.route('**/api/admin/settings', async (route) => {
    const response = await route.fetch(); started(); await held; await route.fulfill({ response });
  }, { times: 1 });
  await card('slack').locator('input').fill(`${endpoint}/slack`);
  await card('slack').getByRole('button', { name: 'Save connection', exact: true }).click(); await entered;
  assert.ok(await card('slack').evaluate((form) => form.inert));
  await card('google_chat').locator('input').fill(`${endpoint}/google_chat`);
  await card('teams').locator('input').fill(`${endpoint}/teams`); await save('teams');
  release(); await saved('slack'); await saved('teams');
  assert.equal(await card('google_chat').locator('input').inputValue(), `${endpoint}/google_chat`);
  await save('google_chat');
  await card('discord').locator('input').fill(`${endpoint}/discord?wait=false`); await save('discord');

  for (const channel of ['slack', 'teams', 'google_chat', 'discord']) {
    const before = messages.length;
    await card(channel).getByRole('button', { name: 'Send test', exact: true }).click();
    await card(channel).getByText(/Test accepted by/).waitFor();
    assert.equal(messages.length, before + 1); assert.equal(messages.at(-1).channel, channel);
    assert.ok(JSON.stringify(messages.at(-1).body).includes('notification test'));
  }
  assert.equal(messages.find((m) => m.channel === 'slack').body.blocks[0].text.type, 'plain_text');
  assert.equal(messages.find((m) => m.channel === 'teams').body.attachments[0].content.type, 'AdaptiveCard');
  assert.deepEqual(messages.find((m) => m.channel === 'discord').body.allowed_mentions.parse, []);
  assert.deepEqual(messages.find((m) => m.channel === 'discord').query.getAll('wait'), ['true']);
  const settings = await api('admin/settings');
  assert.ok(!JSON.stringify(settings).includes(endpoint));
  for (const channel of ['slack', 'teams', 'google_chat', 'discord']) assert.equal(settings[`notify_${channel}_set`], true);
  failTeams = true;
  await page.click('#notify-test');
  await page.locator('#notify-test-error').waitFor();
  assert.equal(await page.locator('#notify-test').textContent(), 'Test all services');
  failTeams = false;
  await page.click('#notify-test');
  await page.getByText('Delivered 4 of 4 configured notification channels.', { exact: true }).waitFor();
  assert.equal(await page.locator('#notify-test').textContent(), 'Test all services');
  failTeams = true;
  await card('teams').getByRole('button', { name: 'Send test', exact: true }).click();
  await card('teams').getByRole('alert').waitFor();
  assert.ok(await card('teams').getByRole('button', { name: 'Send test', exact: true }).isEnabled());
  await card('teams').getByRole('button', { name: 'Disconnect', exact: true }).click();
  await card('teams').getByText('Not connected', { exact: true }).waitFor();
  assert.ok(await card('teams').getByRole('button', { name: 'Send test', exact: true }).isDisabled());

  await page.route('**/api/admin/settings', (route) => route.fulfill({ status: 503, json: { error: 'Save failed fixture' } }), { times: 1 });
  await card('slack').locator('input').fill(`${endpoint}/replacement`);
  await card('slack').getByRole('button', { name: 'Save connection', exact: true }).click();
  await card('slack').getByText('Save failed fixture', { exact: true }).waitFor();
  assert.equal(await card('slack').locator('input').inputValue(), `${endpoint}/replacement`);
  await page.reload(); await saved('slack');
  assert.ok(await card('teams').getByRole('button', { name: 'Send test', exact: true }).isDisabled());

  for (const width of [1440, 900, 640, 390, 320]) {
    await page.setViewportSize({ width, height: 1000 });
    await page.emulateMedia({ colorScheme: width < 640 ? 'light' : 'dark' });
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `Page overflow at ${width}`);
    const overlaps = await page.locator('#notifications').evaluate((section) => {
      const controls = [...section.querySelectorAll('input,button')].filter((node) => node.checkVisibility()).map((node) => ({ id: node.id || node.textContent.trim(), r: node.getBoundingClientRect() }));
      const overlaps = [];
      for (let i = 0; i < controls.length; i++) for (let j = i + 1; j < controls.length; j++) {
        const a = controls[i], b = controls[j];
        if (Math.min(a.r.right, b.r.right) - Math.max(a.r.left, b.r.left) > 1 && Math.min(a.r.bottom, b.r.bottom) - Math.max(a.r.top, b.r.top) > 1) overlaps.push(`${a.id} overlaps ${b.id}`);
      }
      return overlaps;
    });
    assert.deepEqual(overlaps, [], `Notifications at ${width}`);
    const alignment = await page.locator('#backup-enabled').evaluate((input) => {
      const a = input.getBoundingClientRect(), b = input.nextElementSibling.getBoundingClientRect(); return Math.abs((a.top + a.bottom - b.top - b.bottom) / 2);
    });
    assert.ok(alignment < 3, `Backup checkbox misaligned ${alignment}px at ${width}`);
    if (width === 1440 || width === 390) {
      await page.locator('#notifications').screenshot({ path: path.join(root, `notifications-${width}.png`) });
      await page.locator('#backup-form').screenshot({ path: path.join(root, `backups-${width}.png`) });
    }
  }
  await api('admin/automation-tokens', { label: 'Notification layout fixture', expires_days: 1, permissions: ['library:read'] });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  for (const destination of ['receive', 'deliver', 'workflows', 'storage', 'automation']) {
    await page.locator(`#nav a[href="/${destination}"]`).click();
    await page.locator(`#nav a[href="/${destination}"][aria-current=page]`).waitFor();
  }
  await page.locator('#automation-tokens .link-item').first().waitFor();
  assert.ok(await page.locator('#automation-tokens .link-item').first().evaluate((item) => item.querySelector('p.muted').getBoundingClientRect().top - item.querySelector('.head').getBoundingClientRect().bottom >= 10));
  await page.locator('#automation-tokens').screenshot({ path: path.join(root, 'agents-spacing.png') });
  await page.goBack(); await page.locator('#nav a[href="/storage"][aria-current=page]').waitFor();
  await page.goForward(); await page.locator('#nav a[href="/automation"][aria-current=page]').waitFor();
  assert.equal(sessionReads, 0, 'Admin navigation must not need a separate session request');
  assert.deepEqual(errors, []);
  await page.click('#logout'); await page.waitForURL(`${base}/`);
  const signedOut = await (await context.request.get(`${base}/system`)).text();
  assert.ok(!signedOut.includes('id="admin-session"'));
  console.log('Private chat settings, concurrent saves, isolated tests, failure recovery, responsive forms, checkbox/agent spacing, and navigation bootstrap: passed');
} finally {
  await browser.close();
  await new Promise((resolve) => sink.close(resolve));
}
