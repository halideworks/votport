import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

const receive = await readFile(new URL('../web/receive.html', import.meta.url), 'utf8');
const deliver = await readFile(new URL('../web/deliver.html', import.meta.url), 'utf8');
const audit = await readFile(new URL('../web/audit.html', import.meta.url), 'utf8');
const tenants = await readFile(new URL('../web/tenants.html', import.meta.url), 'utf8');
const system = await readFile(new URL('../web/system.html', import.meta.url), 'utf8');
const receiveScript = await readFile(new URL('../web/assets/page-receive.js', import.meta.url), 'utf8');
const deliverScript = await readFile(new URL('../web/assets/page-deliver.js', import.meta.url), 'utf8');
const tenantsScript = await readFile(new URL('../web/assets/page-tenants.js', import.meta.url), 'utf8');
const systemScript = await readFile(new URL('../web/assets/page-system.js', import.meta.url), 'utf8');
const commonScript = await readFile(new URL('../web/assets/admin-common.js', import.meta.url), 'utf8');
const brandingScript = await readFile(new URL('../web/assets/branding.js', import.meta.url), 'utf8');
const uploadScript = await readFile(new URL('../web/assets/upload.js', import.meta.url), 'utf8');
const outboundScript = await readFile(new URL('../web/assets/outbound.js', import.meta.url), 'utf8');
const style = await readFile(new URL('../web/assets/style.css', import.meta.url), 'utf8');

test('receive and deliver pages keep transfer concerns separate', () => {
  assert.match(receive, /page-receive\.js/);
  assert.match(receive, /create-notify-on-upload[^>]+name="notify_on_upload"[^>]+type="checkbox"/);
  assert.doesNotMatch(receive, /create-notify-on-upload[^>]+checked/);
  assert.doesNotMatch(receive, /library-input|automation-token-form/);
  assert.match(deliver, /page-deliver\.js/);
  assert.match(deliver, /deliver-notify-on-download[^>]+name="notify_on_download"[^>]+type="checkbox"/);
  assert.doesNotMatch(deliver, /deliver-notify-on-download[^>]+checked/);
  assert.match(receive, /Notify when an upload completes/);
  assert.match(deliver, /Notify on first download and delivery completion/);
  assert.doesNotMatch(deliver, /create-notify-on-upload|links-filter/);
  assert.match(commonScript, /\['receive', '\/receive', 'Receive'\]/);
  assert.match(commonScript, /\['deliver', '\/deliver', 'Deliver'\]/);
  assert.match(receiveScript, /notify_on_upload: \$\('create-notify-on-upload'\)\.checked/);
  assert.match(receiveScript, /method: 'PATCH'[\s\S]+notify_on_upload/);
  assert.match(receiveScript, /notifyInput\.disabled = true/);
  assert.match(deliverScript, /notify_on_download: \$\('deliver-notify-on-download'\)\.checked/);
  assert.match(deliverScript, /method: 'PATCH'[\s\S]+notify_on_download/);
  assert.match(deliverScript, /notifyInput\.disabled = true/);
});

test('issued request status filter uses the shared form control styling', () => {
  assert.match(receive, /<div class="grid">[\s\S]*id="links-status"/);
  assert.match(style, /input,\s*\.card select\s*\{[\s\S]*display: block;[\s\S]*width: 100%;[\s\S]*background: rgba\(255, 255, 255, 0\.03\);/);
  assert.match(style, /input:focus,\s*\.card select:focus\s*\{[\s\S]*border-color: var\(--border-active\);/);
  assert.doesNotMatch(style, /^select\s*\{/m);
});

test('admin navigation exposes the current page and tenant selector', () => {
  assert.match(commonScript, /link\.setAttribute\('aria-current', 'page'\)/);
  for (const page of [receive, deliver, audit, tenants, system]) {
    assert.match(page, /<select id="tenant-switcher" aria-label="Tenant" hidden>/);
  }
});

test('public pages apply tenant branding from their metadata', () => {
  assert.match(brandingScript, /export function applyBranding/);
  assert.match(brandingScript, /document\.createElement\('img'\)/);
  assert.doesNotMatch(brandingScript, /innerHTML/);
  assert.match(brandingScript, /setProperty\('--progress', branding\.color\)/);
  assert.ok(brandingScript.includes('/^#[0-9a-fA-F]{6}$/'));
  assert.match(brandingScript, /if \(!branding\) return;/);
  assert.match(uploadScript, /applyBranding\(info\.branding, `\/api\/r\/\$\{token\}\/logo`\)/);
  assert.match(outboundScript, /applyBranding\(body\.branding, `\/api\/s\/\$\{encodeURIComponent\(token\)\}\/logo`\)/);
  assert.match(style, /\.masthead \.brand-logo/);
});

test('admin pages expose the branding forms', () => {
  assert.match(system, /id="branding-form"/);
  assert.match(system, /id="branding-color"[^>]*\n?[^>]*type="color"/);
  assert.match(system, /id="branding-logo"/);
  assert.match(systemScript, /api\('\/api\/admin\/branding\/default'/);
  assert.match(systemScript, /'Content-Type': file\.type/);
  assert.match(tenantsScript, /api\(`\/api\/admin\/branding\/\$\{key\}`/);
  assert.match(tenantsScript, /api\(`\/api\/admin\/branding\/\$\{key\}\/logo`/);
  assert.match(tenantsScript, /colorInput\.type = 'color'/);
  assert.match(tenantsScript, /logoInput\.type = 'file'/);
});

test('tenant principals use a bounded searchable page', () => {
  assert.match(tenants, /id="principal-search"[^>]+maxlength="100"/);
  assert.match(tenants, /id="principal-load-more"[^>]+hidden/);
  assert.match(tenantsScript, /api\(`\/api\/admin\/principals\?\$\{params\}`\)/);
  assert.match(tenantsScript, /limit: String\(PRINCIPAL_PAGE_SIZE\)/);
  assert.match(tenantsScript, /setTimeout\([\s\S]*refreshPrincipals\(true\)[\s\S]*200/);
  assert.match(tenantsScript, /principalRows\.concat\(page\.principals\)/);
  assert.match(tenantsScript, /refreshPrincipals\(true\)/);
});

test('list actions announce their outcome and copy buttons confirm', () => {
  assert.match(receive, /id="links-action-status"[^>]+role="status"/);
  assert.match(deliver, /id="outbound-grants-status"[^>]+role="status"/);
  assert.match(receiveScript, /announce\('links-action-status'/);
  assert.match(deliverScript, /announce\('outbound-grants-status'/);
  assert.match(deliverScript, /confirmModal\('Extend download'/);
  // Every clipboard write goes through copyToClipboard so the button flips to Copied.
  assert.doesNotMatch(receiveScript, /navigator\.clipboard/);
  assert.doesNotMatch(deliverScript, /navigator\.clipboard/);
  assert.match(commonScript, /export async function copyToClipboard/);
});

test('no page repeats an element id', () => {
  for (const [name, html] of Object.entries({ receive, deliver, audit, tenants, system })) {
    const ids = [...html.matchAll(/\sid="([^"]+)"/g)].map((match) => match[1]);
    const seen = new Set();
    for (const id of ids) {
      assert.ok(!seen.has(id), `${name}.html repeats id="${id}"`);
      seen.add(id);
    }
  }
});

test('a stale sender tab reloads when the server reports a new web build', () => {
  assert.match(uploadScript, /webBuild = info\.web_build \|\| null/);
  assert.match(uploadScript, /info\.web_build !== webBuild[\s\S]{0,200}window\.location\.reload\(\)/);
  assert.match(uploadScript, /if \(!error\.cancelled\) await reloadIfServerUpdated\(\);/);
  assert.match(uploadScript, /if \(uploading && !reloading\) event\.preventDefault\(\);/);
  assert.match(uploadScript, /reloading = true;\s*window\.location\.reload\(\);/);
  // A finish refused as early is a 422; rebegin must key on that status.
  assert.match(uploadScript, /error\.status === 422 && \/not fully received\//);
});
