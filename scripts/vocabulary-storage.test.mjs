// Finding 442: one name per thing — a configured storage location is a
// "storage connection" (short "connection"); "destination" is reserved for
// notification targets (audit item 425). Trade-route peers are "the other
// port".
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const read = (p) => readFile(new URL(p, import.meta.url), 'utf8');

test('storage page manages storage connections', async () => {
  const page = await read('../web/storage.html');
  assert.match(page, /<button id="storage-new" type="button">Add storage connection<\/button>/);
  assert.match(page, /<h2 class="section-title">Storage connections<\/h2>/);
  assert.match(page, /Connection type</);
  assert.match(page, /Folder within the connection</);
});

test('storage page copy speaks of connections and projects', async () => {
  const script = await read('../web/assets/page-storage.js');
  assert.match(script, /'Add your first storage connection'/);
  assert.match(script, /'Votport connection'/);
  assert.match(script, /'Request-link connection/);
  assert.match(script, /'Disable request-link connection'/);
  assert.match(script, /using it in a project\./);
});

test('workflows page talks about storage connections', async () => {
  const page = await read('../web/workflows.html');
  assert.match(page, /<legend>Storage connections<\/legend>/);
  assert.match(page, /After all storage connections finish</);
  const script = await read('../web/assets/page-workflows.js');
  assert.match(script, /the selected connections\. Each connection reports/);
});

test('retired destination vocabulary is gone from web user text', async () => {
  const files = [
    '../web/storage.html',
    '../web/workflows.html',
    '../web/trade-routes.html',
    '../web/assets/page-storage.js',
    '../web/assets/page-workflows.js',
    '../web/assets/page-trade-routes.js',
  ];
  const sources = await Promise.all(files.map(read));
  for (const [i, src] of sources.entries()) {
    for (const retired of [
      'Copy destinations', 'Destination type', 'Add storage<', '>Add storage</button>',
      'Votport destination', 'receive-link destination',
      'Receive workflow settings', 'workflow’s destinations', "workflow's destinations",
      'Checking destination', 'remain at their destination', 'on the destination.',
    ]) {
      assert.ok(!src.includes(retired), `${files[i]} still says "${retired}"`);
    }
  }
});

test('trade-route peers are the other port', async () => {
  const script = await read('../web/assets/page-trade-routes.js');
  assert.match(script, /remain on the other port\./);
  assert.match(script, /'Checking the other port…'/);
});
