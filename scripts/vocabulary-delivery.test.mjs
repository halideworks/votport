// Finding 440: one name per thing — the send-side shareable is a "delivery"
// with a "delivery link" (audit item 423). Controls: "Copy link",
// "Replace link", "Revoke delivery". Retired user text: "download link",
// "download address", "Outbound download", "issued downloads", "grant".
// The password-refusal sentinel is shared with the server, so its rename is
// asserted in lockstep on both sides.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const read = (p) => readFile(new URL(p, import.meta.url), 'utf8');
const files = [
  '../web/deliver.html',
  '../web/assets/page-deliver.js',
  '../web/assets/admin-common.js',
  '../web/assets/page-workflows.js',
  '../web/assets/page-system.js',
  '../web/assets/outbound.js',
];
const sources = await Promise.all(files.map(read));

test('deliver page issues delivery links with unified controls', async () => {
  const deliver = await read('../web/deliver.html');
  assert.match(deliver, /<button type="submit" id="deliver-submit">Create delivery link<\/button>/);
  assert.match(deliver, /Delivery link ready</);
  assert.match(deliver, /<button id="outbound-copy" type="button">Copy link<\/button>/);
  assert.match(deliver, /<h2>Delivery links<\/h2>/);
});

test('deliver actions use Replace link and Revoke delivery', async () => {
  const script = await read('../web/assets/page-deliver.js');
  assert.match(script, /button\('Replace link', 'tiny'/);
  assert.match(script, /'Replace delivery link',/);
  assert.match(script, /'Revoke delivery',/);
  assert.match(script, /'Delivery link replaced\.'/);
  assert.match(script, /'Delivery link ready\.'/);
});

test('retired delivery vocabulary is gone from web user text', () => {
  for (const [i, src] of sources.entries()) {
    for (const retired of [
      'download link', 'Download link', 'download address', 'Download address',
      'Copy address', 'New address', 'Rotate download', 'Revoke download',
      'Extend download', 'issued downloads', 'Issued downloads',
      'Outbound download', 'download grant', 'Copy destinations',
      'Copy receive link', 'receive address',
    ]) {
      assert.ok(!src.includes(retired), `${files[i]} still says "${retired}"`);
    }
  }
});

test('password refusal sentinel stays in lockstep with the server', async () => {
  const web = await read('../web/assets/outbound.js');
  const server = await read('../server/src/api/outbound.rs');
  const serverTests = await read('../server/src/api/outbound/tests.rs');
  assert.equal(web.split("'delivery password required'").length - 1, 3,
    'outbound.js must throw and match the server sentinel (metadata load and download refusal)');
  assert.match(web, /if \(error\.message === 'delivery password required'\) return;/);
  assert.equal(server.split('"delivery password required"').length - 1, 2,
    'outbound.rs: the two handlers');
  assert.equal(serverTests.split('"delivery password required"').length - 1, 1,
    'outbound tests: the integration test assertion');
  assert.ok(!server.includes('outbound grant password required'));
});
