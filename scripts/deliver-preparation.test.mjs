import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { preparationProgress, pollDeliverPreparation } from '../web/assets/deliver-progress.js';

const deliver = await readFile(new URL('../web/deliver.html', import.meta.url), 'utf8');
const deliverScript = await readFile(new URL('../web/assets/page-deliver.js', import.meta.url), 'utf8');
const style = await readFile(new URL('../web/assets/style.css', import.meta.url), 'utf8');

test('before totals arrive the bar is indeterminate with file-so-far text', () => {
  const view = preparationProgress({ status: 'preparing', files_done: 2 });
  assert.equal(view.indeterminate, true);
  assert.match(view.text, /Hashing file 2 so far/);
  assert.equal(view.percent, undefined);
});

test('once totals are known the bar is determinate in files and bytes', () => {
  const view = preparationProgress({
    status: 'preparing',
    files_done: 3,
    files_total: 12,
    bytes_done: 1_000_000,
    bytes_total: 4_000_000,
  });
  assert.equal(view.indeterminate, false);
  assert.equal(view.percent, 25);
  assert.match(view.text, /file 3 of 12/);
  assert.match(view.text, /1\.0 MB of 4\.0 MB/);
});

test('a zero-byte selection counts as fully hashed, not division by zero', () => {
  const view = preparationProgress({
    status: 'preparing',
    files_done: 2,
    files_total: 2,
    bytes_done: 0,
    bytes_total: 0,
  });
  assert.equal(view.indeterminate, false);
  assert.equal(view.percent, 100);
});

test('a completed preparation reads as done with the ready line', () => {
  const view = preparationProgress({ status: 'complete' });
  assert.equal(view.done, true);
  assert.equal(view.failed, undefined);
  assert.match(view.text, /Delivery link ready\./);
});

test('a failed preparation carries the server error for the page to show', () => {
  const view = preparationProgress({ status: 'failed', error: 'library file vanished' });
  assert.equal(view.done, true);
  assert.equal(view.failed, true);
  assert.equal(view.text, 'library file vanished');
});

test('preparation polling renders in-flight snapshots and returns either terminal state', async (t) => {
  t.mock.method(globalThis, 'setTimeout', (done) => { done(); });
  for (const status of ['complete', 'failed']) {
    const snapshots = [{ status: 'preparing', files_done: 1 }, { status, error: status === 'failed' ? 'unavailable' : undefined }];
    const rendered = [];
    let requests = 0;
    const result = await pollDeliverPreparation('id/with space', (snapshot) => rendered.push(snapshot), async (url) => {
      assert.equal(url, '/api/admin/outbound-grants/preparations/id%2Fwith%20space');
      return snapshots[requests++];
    });
    assert.equal(result, snapshots[1]);
    assert.deepEqual(rendered, [snapshots[0]]);
    assert.equal(requests, 2);
  }
});

test('a folder tick shows optimistic selecting text before reconciliation', () => {
  assert.match(deliverScript, /Selecting folder \$\{directory\.slice\(directory\.lastIndexOf\('\/'\) \+ 1\)\}…`/);
  assert.match(deliverScript, /librarySelectionsPending \+= 1/);
  assert.match(deliverScript, /librarySelectionsPending -= 1/);
});

test('the shimmer runs only when the bar is indeterminate and motion is allowed', () => {
  assert.match(style, /\.deliver-progress-bar\.indeterminate \.deliver-progress-fill \{ width: 40%; animation: deliver-shimmer/);
  assert.match(style, /@media \(prefers-reduced-motion: reduce\)[\s\S]*?\.deliver-progress-bar\.indeterminate \.deliver-progress-fill \{ width: 100%; \}/);
});
