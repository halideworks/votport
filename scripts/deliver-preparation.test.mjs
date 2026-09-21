import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { preparationProgress } from '../web/assets/deliver-progress.js';

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

test('the page polls 202 preparations and renders each snapshot', () => {
  assert.match(deliverScript, /api\('\/api\/admin\/outbound-grants\/preparations'/);
  assert.match(deliverScript, /response\.preparation_id/);
  assert.match(deliverScript, /pollDeliverPreparation\(response\.preparation_id, renderDeliverProgress\)/);
  assert.match(deliverScript, /preparations\/\$\{encodeURIComponent\(id\)\}/);
  assert.match(deliverScript, /preparationProgress\(snapshot\)/);
  // aria-busy on the form and the role="status" progress line stay live.
  assert.match(deliverScript, /form\.setAttribute\('aria-busy', 'true'\)/);
  assert.match(deliver, /id="deliver-progress" class="muted" role="status"/);
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
