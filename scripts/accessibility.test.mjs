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
const uploadScript = await readFile(new URL('../web/assets/upload.js', import.meta.url), 'utf8');
const deliverScript = await readFile(new URL('../web/assets/page-deliver.js', import.meta.url), 'utf8');
const verifyScript = await readFile(new URL('../web/assets/verify.js', import.meta.url), 'utf8');
const commonScript = await readFile(new URL('../web/assets/admin-common.js', import.meta.url), 'utf8');

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
