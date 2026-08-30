import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  dedupeFilenames,
  runWorkerPool,
  sanitizeFilename,
  summarizeFailures,
} from '../web/assets/outbound-download.js';

test('sanitizes flattened unsafe and reserved filenames', () => {
  assert.equal(sanitizeFilename('nested\\report?.txt'), 'report_.txt');
  assert.equal(sanitizeFilename('CON.txt'), '_CON.txt');
  assert.equal(sanitizeFilename('../'), 'download');
});

test('deduplicates case-insensitive names before extensions', () => {
  assert.deepEqual(
    dedupeFilenames(['dir/report.txt', 'report.txt', 'REPORT.TXT', 'report (2).txt']),
    ['report.txt', 'report (2).txt', 'REPORT (3).TXT', 'report (2) (2).txt'],
  );
});

test('caps failure summaries', () => {
  assert.equal(
    summarizeFailures(['a: failed', 'b: failed', 'c: failed', 'd: failed', 'e: failed']),
    'a: failed; b: failed; c: failed; and 2 more',
  );
});

test('runs at most four workers and keeps result order', async () => {
  let active = 0;
  let peak = 0;
  const result = await runWorkerPool([1, 2, 3, 4, 5, 6], async (value) => {
    active += 1;
    peak = Math.max(peak, active);
    await new Promise((resolve) => setTimeout(resolve, value === 1 ? 5 : 0));
    active -= 1;
    return value * 2;
  });
  assert.equal(peak, 4);
  assert.deepEqual(result, [2, 4, 6, 8, 10, 12]);
});
