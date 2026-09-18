import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import { chromium } from 'playwright';

const run = promisify(execFile);
const base = process.env.BASE_URL;
const root = process.env.WORKFLOW_TEST_ROOT;
const scimToken = process.env.VOTPORT_SCIM_TOKEN;
const password = process.env.ADMIN_PASSWORD;
if (!base || !root || !scimToken || !password) {
  throw new Error('Use BASE_URL, WORKFLOW_TEST_ROOT, VOTPORT_SCIM_TOKEN and ADMIN_PASSWORD for an isolated instance.');
}

const id = `viewer-${Date.now()}`;
const subject = `${id}@example.test`;
const libraryPath = `${id}/viewer.txt`;
await fs.mkdir(path.join(root, 'library', id), { recursive: true, mode: 0o700 });
await fs.writeFile(path.join(root, 'library', libraryPath), 'Viewer browser fixture\n', { mode: 0o600 });
const tokenFile = path.join(root, 'viewer-admin-token');
const secretFile = path.join(root, 'data', 'secret');
let browser;

async function scim(method, route, body) {
  const response = await fetch(`${base}/scim/v2/${route}`, {
    method,
    headers: {
      Authorization: `Bearer ${scimToken}`,
      'Content-Type': 'application/scim+json',
    },
    body: JSON.stringify(body),
  });
  assert.equal(response.status, 201, `SCIM ${method} ${route}: ${response.status}`);
  return response.json();
}

try {
  await scim('POST', 'Users', {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
    userName: subject,
    active: true,
  });

  await run('rustup', [
    'run', '1.97.1', 'cargo',
    'test', '--locked', '--jobs', '4', '--manifest-path', 'server/Cargo.toml', '--test', 'viewer_token',
    '--', '--ignored', '--exact', 'issue_viewer_token',
  ], {
    cwd: path.resolve(import.meta.dirname, '..'),
    env: {
      ...process.env,
      VOTPORT_VIEWER_SECRET_FILE: secretFile,
      VOTPORT_VIEWER_TOKEN_FILE: tokenFile,
      VOTPORT_VIEWER_SUBJECT: subject,
      VOTPORT_ADMIN_PASSWORD: password,
      CARGO_TARGET_DIR: process.env.CARGO_TARGET_DIR || path.join(root, 'cargo-target'),
    },
    maxBuffer: 1024 * 1024,
    timeout: 15 * 60 * 1000,
  });
  const viewerToken = await fs.readFile(tokenFile, 'utf8');
  assert.match(viewerToken, /^[^.]+\.[^.]+\.[^.]+\.[^.]+$/);

  browser = await chromium.launch(process.env.PLAYWRIGHT_EXECUTABLE_PATH
    ? { executablePath: process.env.PLAYWRIGHT_EXECUTABLE_PATH }
    : undefined);
  const admin = await browser.newContext();
  const viewer = await browser.newContext({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'reduce' });
  const errors = [];
  const viewerPage = await viewer.newPage();
  viewerPage.on('pageerror', (error) => errors.push(error.message));

  async function request(context, route, data, method = data ? 'POST' : 'GET') {
    return context.request.fetch(`${base}/api/${route}`, {
      method,
      data,
      headers: { 'X-Votport': '1' },
    });
  }

  async function adminJson(route, data, method = data ? 'POST' : 'GET') {
    const response = await request(admin, route, data, method);
    assert.ok(response.ok(), `${route}: ${response.status()} ${await response.text()}`);
    return response.status() === 204 ? null : response.json();
  }

  await adminJson('admin/login', { password });
  const link = (await adminJson('admin/links', {
    label: `${id} receive`,
    dest: id,
    expires_days: 7,
  })).link;
  const grant = await adminJson('admin/outbound-grants', {
    paths: [libraryPath],
    label: `${id} download`,
    expires_days: 7,
  });
  const adminPage = await admin.newPage();
  adminPage.on('pageerror', (error) => errors.push(error.message));
  await adminPage.route('**/api/workflows/projects', (route) => route.fulfill({
    status: 503,
    contentType: 'application/json',
    body: JSON.stringify({ error: 'Project fixture unavailable' }),
  }));
  await adminPage.goto(`${base}/receive`);
  const adminCard = adminPage.locator(`#link-${link.id}`);
  await adminCard.waitFor();
  for (const name of [/^Deactivate request link: /, /^Legal hold: /, /^Delete request link: /]) {
    assert.equal(await adminCard.getByRole('button', { name }).count(), 1, `admin receive action is named ${name}`);
  }
  assert.ok(await adminPage.locator('#create-form').isVisible());
  assert.match(await adminPage.locator('#create-error').textContent(), /Could not load reception projects/);
  await adminPage.close();
  const uploader = await admin.newPage();
  await uploader.goto(link.url);
  await uploader.locator('#uploader:not([hidden])').waitFor({ timeout: 30000 });
  await uploader.setInputFiles('#file-input', [{
    name: 'received.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('Viewer receive fixture\n'),
  }]);
  await uploader.locator('#send:not([disabled])').waitFor({ timeout: 30000 });
  await uploader.click('#send');
  await uploader.locator('#done-card:not([hidden])').waitFor({ timeout: 30000 });
  await uploader.close();

  await viewer.addCookies([{ name: 'votport_admin', value: viewerToken, url: base }]);
  const sessionResponse = await request(viewer, 'admin/session');
  assert.equal(sessionResponse.status(), 200);
  const expectedSession = {
    ok: true,
    subject,
    tenant: '',
    grants: [{ incarnation: null, tenant: '', role: 'viewer' }],
    role: 'viewer',
    pages: ['receive', 'deliver', 'workflows', 'trade-routes', 'storage', 'automation', 'notifications', 'audit'],
  };
  assert.deepEqual(await sessionResponse.json(), expectedSession);

  const linksResponse = await request(viewer, 'admin/links');
  const grantsResponse = await request(viewer, 'admin/outbound-grants');
  assert.equal(linksResponse.status(), 200);
  assert.equal(grantsResponse.status(), 200);
  assert.ok((await linksResponse.json()).links.some((entry) => entry.id === link.id));
  assert.ok((await grantsResponse.json()).grants.some((entry) => entry.id === grant.grant.id));

  await viewerPage.goto(`${base}/receive`);
  await viewerPage.locator('#admin-session').waitFor({ state: 'attached' });
  await viewerPage.locator(`#link-${link.id}`).waitFor();
  assert.deepEqual(await viewerPage.locator('#admin-session').evaluate((node) => JSON.parse(node.textContent)), expectedSession);
  assert.ok(await viewerPage.locator('#create-form').isHidden());
  const receiveCard = viewerPage.locator(`#link-${link.id}`);
  for (const name of [/^Deactivate request link: /, /^Reactivate request link: /, /^Legal hold: /, /^Release hold: /, /^Delete request link: /]) {
    assert.equal(await receiveCard.getByRole('button', { name }).count(), 0, `viewer receive exposes ${name}`);
  }
  assert.equal(await receiveCard.getByRole('button', { name: /^Copy request link: / }).count(), 1);
  await receiveCard.getByRole('button', { name: /^Show QR code: / }).click();
  await receiveCard.locator('img[alt^="QR code"]').waitFor();
  await receiveCard.locator('.upload-history > summary').click();
  await receiveCard.locator('.upload-history .upload-head').waitFor();
  for (const name of ['Clear record', 'Delete stored files', 'Send', 'Delete file']) {
    assert.equal(await receiveCard.getByRole('button', { name, exact: true }).count(), 0, `viewer receive exposes ${name} after upload`);
  }
  await receiveCard.getByRole('button', { name: 'Files and timeline', exact: true }).click();
  await viewerPage.locator('#timeline[open] .upload-file').waitFor();
  for (const name of ['Send', 'Delete file']) {
    assert.equal(await viewerPage.locator('#timeline[open]').getByRole('button', { name, exact: true }).count(), 0, `viewer timeline exposes ${name}`);
  }

  await viewerPage.goto(`${base}/deliver`);
  await viewerPage.locator('#admin-session').waitFor({ state: 'attached' });
  assert.deepEqual(await viewerPage.locator('#admin-session').evaluate((node) => JSON.parse(node.textContent)), expectedSession);
  await viewerPage.locator(`#grant-${grant.grant.id}`).waitFor();
  assert.ok(await viewerPage.locator('#deliver-upload-form').evaluate((form) => form.inert));
  assert.ok(await viewerPage.locator('#deliver-form').evaluate((form) => form.inert));
  assert.equal(await viewerPage.locator('#deliver-submit').isDisabled(), true);
  assert.equal(await viewerPage.locator('#library-add-files').isDisabled(), true);
  assert.equal(await viewerPage.locator('#library-add-folder').isDisabled(), true);
  const grantCard = viewerPage.locator(`#grant-${grant.grant.id}`);
  for (const name of [/^New address: /, /^Extend 7 days: /, /^Revoke: /]) {
    assert.equal(await grantCard.getByRole('button', { name }).count(), 0, `viewer deliver exposes ${name}`);
  }
  await grantCard.getByRole('button', { name: 'Copy link', exact: true }).click();
  await viewerPage.locator('#library-refresh').click();
  const folder = viewerPage.getByRole('checkbox', { name: `Select folder ${id}`, exact: true });
  await folder.waitFor();
  assert.ok(await folder.isDisabled());
  await viewerPage.getByRole('button', { name: `Open folder ${id}`, exact: true }).click();
  const libraryFile = viewerPage.locator('#library-files .library-file').filter({ hasText: 'viewer.txt' });
  await libraryFile.waitFor();
  assert.ok(await libraryFile.getByRole('checkbox').isDisabled());
  assert.equal(await libraryFile.getByRole('button', { name: `Delete ${libraryPath}`, exact: true }).count(), 0);

  for (const [route, body] of [
    ['admin/links', { label: `${id} refused`, dest: id, expires_days: 7 }],
    ['admin/outbound-grants', { paths: [libraryPath], label: `${id} refused`, expires_days: 7 }],
  ]) {
    const response = await request(viewer, route, body);
    assert.equal(response.status(), 403, `viewer mutation ${route} must be refused`);
  }
  assert.deepEqual(errors, []);
  console.log('Real signed SCIM-provisioned viewer: SSR, read APIs, Receive and Deliver write controls, read controls and 403 mutations passed');
} finally {
  try { await browser?.close(); }
  finally { await fs.rm(tokenFile, { force: true }); }
}
