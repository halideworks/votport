// Finding 443: one instance, one name. A VOTPort deployment is a "port"
// when it is the peer; "server" only names the machine; "installation",
// "site" and "deployment" are retired as instance words in user copy.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const read = (p) => readFile(new URL(p, import.meta.url), 'utf8');

test('trade routes copy names the instance a port, never an installation or site', async () => {
  const page = await read('../web/trade-routes.html');
  assert.match(page, /a saved route on this port and is only needed by scripts or agents/);
  assert.match(page, /Move files between your ports or partner organizations\./);
  assert.match(page, /<option value="internal">Internal port<\/option>/);
  const script = await read('../web/assets/page-trade-routes.js');
  assert.equal(script.split('Internal port').length - 1, 3, 'endpoint cards, route cards and the invitation preview all say Internal port');
});

test('retired instance vocabulary is gone from web user text', async () => {
  const files = [
    '../web/trade-routes.html',
    '../web/storage.html',
    '../web/verify.html',
    '../web/assets/page-trade-routes.js',
    '../web/assets/admin-common.js',
    '../web/assets/upload.js',
  ];
  const sources = await Promise.all(files.map(read));
  for (const [i, src] of sources.entries()) {
    for (const retired of [
      'this installation', 'Internal site', 'your sites', "sender's site",
      'The site was updated', 'Folder on the server',
      "This server's receipt key",
    ]) {
      assert.ok(!src.includes(retired), `${files[i]} still says "${retired}"`);
    }
  }
});

test('the folder field matches the desktop shells: folder on the port', async () => {
  const storage = await read('../web/storage.html');
  assert.match(storage, /<label>Folder on the port<input id="ws-directory"/);
  // "server" stays only where it names the machine the folder lives on.
  assert.match(storage, /visible to this Votport server\./);
  const mac = await read('../client/macos/Votport/DeliverView.swift');
  assert.match(mac, /Folder on the port/);
  const win = await read('../client/windows/Votport/DeliverPage.xaml');
  assert.match(win, /Folder on the port/);
});

test('the verify page speaks of the port that issues receipts', async () => {
  const page = await read('../web/verify.html');
  assert.match(page, /<summary>This port's receipt key<\/summary>/);
  assert.match(page, /what the sender's port showed you, verifying below is proof/);
  const script = await read('../web/assets/verify.js');
  assert.match(script, /This receipt carries this port’s signature\./);
});

test('the trade routes nav hint drops the site word', async () => {
  const script = await read('../web/assets/admin-common.js');
  assert.match(script, /'Connect ports to move files between organizations\.'/);
});
