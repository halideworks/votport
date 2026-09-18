import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';

// Audit 430: the delivery status filter must offer exactly the card labels,
// one option per store state, so it never names a label no card shows nor a
// state the store cannot return.
const script = await readFile(new URL('../web/assets/page-workflows.js', import.meta.url), 'utf8');
const html = await readFile(new URL('../web/workflows.html', import.meta.url), 'utf8');

function pageEval(expression) {
  const stateLine = script.slice(
    script.indexOf('const stateNames'),
    script.indexOf('\n', script.indexOf('const stateNames')),
  );
  const filterLine = script.slice(
    script.indexOf('const stateFilterOptions'),
    script.indexOf('\n', script.indexOf('const stateFilterOptions')),
  );
  return runInNewContext(`${stateLine}\n${filterLine}\n${expression}`, {});
}

test('delivery status filter offers exactly the card labels', () => {
  // JSON round-trip drops the vm realm's prototypes so deepEqual compares
  // plain values.
  assert.deepEqual(pageEval('JSON.stringify(stateFilterOptions())'), JSON.stringify([
    { id: 'queued', label: 'Scheduled' },
    { id: 'preparing', label: 'Preparing files' },
    { id: 'awaiting_approval', label: 'Needs approval' },
    { id: 'exporting', label: 'Delivering copies' },
    { id: 'retrying', label: 'Retry scheduled' },
    { id: 'ready', label: 'Ready to share' },
    { id: 'failed', label: 'Needs attention' },
    { id: 'cancelled', label: 'Cancelled' },
    { id: 'retiring', label: 'Cleaning up' },
    { id: 'retired', label: 'Archived' },
    { id: 'suspended', label: 'Held after restore' },
  ]));
  assert.ok(
    script.includes("options($('workflow-filter-state'), stateFilterOptions(), 'All deliveries')"),
    'the status select is fed from the card labels',
  );
});

test('the status select hardcodes no filter options', () => {
  const select = html.match(/<select id="workflow-filter-state">([\s\S]*?)<\/select>/);
  assert.ok(select, 'workflows.html keeps the status select');
  const hardcoded = [...select[1].matchAll(/<option/g)].length;
  assert.equal(hardcoded, 1, 'only the empty placeholder lives in the HTML');
});
