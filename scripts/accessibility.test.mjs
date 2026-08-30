import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

const request = await readFile(new URL('../web/request.html', import.meta.url), 'utf8');
const verify = await readFile(new URL('../web/verify.html', import.meta.url), 'utf8');
const uploadScript = await readFile(new URL('../web/assets/upload.js', import.meta.url), 'utf8');
const verifyScript = await readFile(new URL('../web/assets/verify.js', import.meta.url), 'utf8');

test('drop zones are named and keyboard-activatable', () => {
  assert.match(request, /id="drop" class="drop">[\s\S]+id="pick"[^>]+>files<\/button>[\s\S]+id="pick-folder"[^>]+>a folder<\/button>/);
  assert.doesNotMatch(request, /id="drop"[^>]+(?:tabindex|role="button")/);
  assert.match(verify, /id="verify-drop"[^>]+role="button"[^>]+aria-label="Choose a file or receipt"/);
  assert.doesNotMatch(uploadScript, /drop\.addEventListener\('keydown'/);
  assert.match(verifyScript, /dropZone\.addEventListener\('keydown',[\s\S]+e\.preventDefault\(\);[\s\S]+\$\('payload-input'\)\.click\(\)/);
});

test('upload progress exposes its current percentage', () => {
  assert.match(request, /id="meter" class="meter" role="progressbar"[\s\S]+aria-valuenow="0"/);
  assert.match(uploadScript, /const percent = Math\.min\(100, Math\.round\(fraction \* 100\)\);/);
  assert.match(uploadScript, /\$\('meter'\)\.setAttribute\('aria-valuenow', String\(percent\)\)/);
});
