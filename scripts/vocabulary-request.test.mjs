// Finding 439: one name per thing — the receive-side shareable is a "request"
// created from a "request link" (audit item 422). Retired user text:
// "receive link", "receive request", "transfer request", "upload link", "drop".
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const read = (p) => readFile(new URL(p, import.meta.url), 'utf8');
const files = [
  '../web/receive.html',
  '../web/trade-routes.html',
  '../web/assets/page-receive.js',
  '../web/assets/page-trade-routes.js',
  '../web/assets/upload.js',
];
const sources = await Promise.all(files.map(read));

test('receive page issues request links with the unified vocabulary', async () => {
  const receive = await read('../web/receive.html');
  assert.match(receive, /<h2>New request<\/h2>/);
  assert.match(receive, /aria-label="Help about requests"/);
  assert.match(receive, /Create request link</);
  assert.match(receive, /Request link ready</);
  assert.match(receive, /request link/);
});

test('trade routes reference requests, not receive requests', async () => {
  const trade = await read('../web/trade-routes.html');
  assert.match(trade, /A request holds your folder, file limits and optional project/);
  assert.match(trade, /Find a request</);
  assert.match(trade, /ordinary request link/);
});

test('retired request vocabulary is gone from web user text', () => {
  for (const [i, src] of sources.entries()) {
    for (const retired of [
      'receive link', 'Receive link', 'receive request', 'Receive request',
      'transfer request', 'Transfer request', 'upload link', 'Receive-link',
      'receive-link', 'a drop holds', '-file drop', 'no workflow',
    ]) {
      assert.ok(!src.includes(retired), `${files[i]} still says "${retired}"`);
    }
  }
});
