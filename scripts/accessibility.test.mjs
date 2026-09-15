import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

const request = await readFile(new URL('../web/request.html', import.meta.url), 'utf8');
const receive = await readFile(new URL('../web/receive.html', import.meta.url), 'utf8');
const deliver = await readFile(new URL('../web/deliver.html', import.meta.url), 'utf8');
const tenants = await readFile(new URL('../web/tenants.html', import.meta.url), 'utf8');
const audit = await readFile(new URL('../web/audit.html', import.meta.url), 'utf8');
const system = await readFile(new URL('../web/system.html', import.meta.url), 'utf8');
const verify = await readFile(new URL('../web/verify.html', import.meta.url), 'utf8');
const automation = await readFile(new URL('../web/automation.html', import.meta.url), 'utf8');
const uploadScript = await readFile(new URL('../web/assets/upload.js', import.meta.url), 'utf8');
const deliverScript = await readFile(new URL('../web/assets/page-deliver.js', import.meta.url), 'utf8');
const verifyScript = await readFile(new URL('../web/assets/verify.js', import.meta.url), 'utf8');
const commonScript = await readFile(new URL('../web/assets/admin-common.js', import.meta.url), 'utf8');
const automationScript = await readFile(new URL('../web/assets/page-automation.js', import.meta.url), 'utf8');
const objectCardScript = await readFile(new URL('../web/assets/object-card.js', import.meta.url), 'utf8');
const style = await readFile(new URL('../web/assets/style.css', import.meta.url), 'utf8');

test('drop zones are named and keyboard controls are not nested', () => {
  assert.match(request, /id="drop" class="drop">[\s\S]+id="pick"[^>]+>files<\/button>[\s\S]+id="pick-folder"[^>]+>a folder<\/button>/);
  assert.doesNotMatch(request, /id="drop"[^>]+(?:tabindex|role="button")/);
  assert.match(deliver, /id="library-drop" class="drop" role="group"/);
  assert.doesNotMatch(deliver, /id="library-drop"[^>]+(?:tabindex|role="button")/);
  assert.match(deliver, /id="library-add-files"[^>]+>files<\/button>[\s\S]+id="library-add-folder"[^>]+>a folder<\/button>/);
  assert.doesNotMatch(deliverScript, /libraryDrop\.addEventListener\('keydown'/);
  assert.match(deliverScript, /document\.addEventListener\('drop'/);
  assert.match(deliverScript, /if \(!carriesFiles\(event\)\) return/);
  assert.match(verify, /id="verify-drop"[^>]+role="button"[^>]+aria-label="Choose a file or receipt"/);
  assert.doesNotMatch(uploadScript, /drop\.addEventListener\('keydown'/);
  assert.match(uploadScript, /document\.addEventListener\('drop'/);
  assert.match(uploadScript, /!carriesFiles\(event\)[\s\S]+return/);
  assert.match(verifyScript, /dropZone\.addEventListener\('keydown',[\s\S]+e\.preventDefault\(\);[\s\S]+\$\('payload-input'\)\.click\(\)/);
});

test('upload progress exposes its current percentage', () => {
  assert.match(request, /id="meter" class="meter" role="progressbar"[\s\S]+aria-valuenow="0"/);
  assert.match(uploadScript, /const percent = Math\.min\(100, Math\.round\(fraction \* 100\)\);/);
  assert.match(uploadScript, /\$\('meter'\)\.setAttribute\('aria-valuenow', String\(percent\)\)/);
});

test('recipient pages identify their request and receipt contexts', () => {
  assert.match(request, /<title>VOTPort · Request files<\/title>/);
  assert.match(request, /<h1 id="title">Request files<\/h1>/);
  assert.match(verify, /<title>VOTPort · Verify a receipt<\/title>/);
  assert.match(uploadScript, /document\.title = `VOTPort · \$\{info\.label\}`/);
  assert.match(uploadScript, /showClosed\('Request not found'/);
  assert.match(uploadScript, /showClosed\('Request closed'\)/);
  assert.match(uploadScript, /document\.title = 'VOTPort · Request unavailable'/);
});

test('admin confirmation dialogs expose their shared title and detail', () => {
  for (const page of [receive, deliver, tenants, audit, system]) {
    const dialog = page.match(/<dialog id="confirm"[^>]*>/)?.[0];
    assert.ok(dialog, 'confirm dialog present');
    for (const [attribute, expectedId] of Object.entries({
      'aria-labelledby': 'confirm-title',
      'aria-describedby': 'confirm-detail',
    })) {
      const id = dialog.match(new RegExp(`${attribute}="([^"]+)"`))?.[1];
      assert.equal(id, expectedId, `${attribute} uses the shared ${expectedId} element`);
      assert.match(page, new RegExp(`id="${id}"`), `${attribute} reference resolves`);
    }
  }
  assert.match(commonScript, /document\.getElementById\('confirm-title'\)\.textContent = title/);
  assert.match(commonScript, /document\.getElementById\('confirm-detail'\)\.textContent = detail/);
  assert.match(commonScript, /document\.getElementById\('confirm-title'\)\.textContent = 'Something went wrong'/);
  assert.match(commonScript, /document\.getElementById\('confirm-detail'\)\.textContent = message/);
});

test('accessible controls keep names, focus cues, and quiet list updates', () => {
  assert.match(verify, /id="pick-payload"[^>]+aria-label="Browse for file"[^>]+aria-describedby="payload-name"/);
  assert.match(verify, /id="pick-sidecar"[^>]+aria-label="Browse for receipt"[^>]+aria-describedby="sidecar-name"/);
  assert.match(deliverScript, /row\.className = 'library-file'/);
  assert.match(deliverScript, /label\.className = 'library-file-name'/);
  assert.match(deliverScript, /label\.append\(checkbox, name\)/);
  assert.match(style, /input:focus-visible,[\s\S]+outline: 2px solid var\(--progress\)/);
  assert.match(style, /#tenant-switcher:focus-visible[\s\S]+outline: 2px solid var\(--progress\)/);
  assert.doesNotMatch(style.match(/label \.muted \{([^}]*)\}/)?.[1] ?? '', /opacity:/);
  assert.match(objectCardScript, /await navigator\.clipboard\.writeText\(identity\)/);
  assert.match(style, /\.file-id \{[\s\S]*overflow-wrap: anywhere;/);
  assert.match(commonScript, /undo\.setAttribute\('aria-label', `Undo \$\{text\}`\)/);
  assert.match(receive, /id="timeline-events"[^>]+aria-label="Transfer timeline"/);
  assert.doesNotMatch(deliver, /id="library-files"[^>]+aria-live=/);
  assert.match(automation, /id="automation-token-status"[^>]+role="status"[^>]+aria-live="polite"/);
  assert.doesNotMatch(automation, /id="automation-tokens"[^>]+aria-live=/);
  assert.match(automationScript, /automation-token-status.*automation token.*issued/s);
  assert.match(objectCardScript, /aria-label\", `Copied file hash: \$\{file\.name\}`/);
  assert.match(objectCardScript, /aria-label\", `Copy failed: \$\{file\.name\}`/);
  assert.match(objectCardScript, /catch \{[\s\S]+Copy failed/);
  assert.match(objectCardScript, /element\.dataset\.ariaLabel \?\?= element\.getAttribute\('aria-label'\)/);
  assert.match(objectCardScript, /element\.setAttribute\('aria-label', 'Copied'\)/);
  assert.match(objectCardScript, /if \(copyPending\) return/);
});
