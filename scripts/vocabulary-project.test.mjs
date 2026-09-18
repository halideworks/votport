// Finding 441: one name per thing — reusable delivery rules are a "project"
// and a delivery job is a "delivery" (audit item 424). The /workflows URL and
// route are unchanged (copy-only rename); only visible labels moved.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const read = (p) => readFile(new URL(p, import.meta.url), 'utf8');

test('workflows page presents itself as Deliveries', async () => {
  const page = await read('../web/workflows.html');
  assert.match(page, /<title>VOTPort · Deliveries<\/title>/);
  assert.match(page, /<h1>Deliveries<\/h1>/);
  assert.match(page, /aria-label="Help about deliveries"/);
});

test('admin nav labels the page Deliveries while keeping the internal key', async () => {
  const nav = await read('../web/assets/admin-common.js');
  assert.match(nav, /\['workflows', '\/workflows', 'Deliveries', 'Prepare deliveries with reusable checks, approvals and storage connections\.'\]/);
  // URL kept: navigation still routes to /workflows (copy-only rename).
  assert.match(nav, /'\/workflows'/);
});

test('reception wording says project, not workflow', async () => {
  const receive = await read('../web/assets/page-receive.js');
  assert.match(receive, /'Reception project'/);
  assert.match(receive, /Keep files here; no project/);
  assert.ok(!receive.includes('Reception workflow'));
});

test('retired workflow vocabulary is gone from web user text', async () => {
  const files = [
    '../web/workflows.html',
    '../web/assets/admin-common.js',
    '../web/assets/page-workflows.js',
    '../web/assets/page-receive.js',
    '../web/assets/page-storage.js',
    '../web/assets/page-trade-routes.js',
    '../web/assets/outbound.js',
    '../web/assets/upload.js',
  ];
  const sources = await Promise.all(files.map(read));
  for (const [i, src] of sources.entries()) {
    for (const retired of [
      'Help about workflows', 'Workflow sections', 'Reception workflow',
      'a workflow', 'in a workflow', 'workflow project', 'workflow delivery',
      'workflow’s', 'workflow\'s', 'Use a project workflow',
    ]) {
      assert.ok(!src.includes(retired), `${files[i]} still says "${retired}"`);
    }
  }
});
