// Finding 444: the public receipt page says verify, like every page that
// links to it. "Check a receipt", "Check receipt" and friends are retired;
// the action is "Verify a receipt".
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const read = (p) => readFile(new URL(p, import.meta.url), 'utf8');

test('the verify page asks to verify a receipt in the heading and buttons', async () => {
  const page = await read('../web/verify.html');
  assert.match(page, /<h1>Verify a receipt<\/h1>/);
  assert.match(page, /<button type="submit" id="check" disabled>Verify receipt<\/button>/);
  assert.match(page, />Verify another<\/button>/);
});

test('verify.js copy verifies: progress, reset and verdict hints included', async () => {
  const script = await read('../web/assets/verify.js');
  assert.match(script, /'Verifying…' : 'Verify receipt'/);
  assert.match(script, /only a file and its receipt are verified\./);
  assert.match(script, /if you also want its bytes verified\./);
});

test('retired check wording is gone from the verify page', async () => {
  const files = ['../web/verify.html', '../web/assets/verify.js'];
  const sources = await Promise.all(files.map(read));
  for (const [i, src] of sources.entries()) {
    for (const retired of ['Check a receipt', 'Check receipt', 'Check another', "Checking…"]) {
      assert.ok(!src.includes(retired), `${files[i]} still says "${retired}"`);
    }
  }
});

test('the linking pages keep their verify wording', async () => {
  const request = await read('../web/request.html');
  assert.match(request, /<a class="button tiny" href="\/verify">Verify a receipt<\/a>/);
  const send = await read('../web/send.html');
  assert.match(send, /<a href="\/verify">Verify these receipts<\/a>/);
});
