import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

const receive = await readFile(new URL('../web/receive.html', import.meta.url), 'utf8');
const deliver = await readFile(new URL('../web/deliver.html', import.meta.url), 'utf8');
const receiveScript = await readFile(new URL('../web/assets/page-receive.js', import.meta.url), 'utf8');
const deliverScript = await readFile(new URL('../web/assets/page-deliver.js', import.meta.url), 'utf8');
const commonScript = await readFile(new URL('../web/assets/admin-common.js', import.meta.url), 'utf8');
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
