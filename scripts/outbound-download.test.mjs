import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import {
  anchorDownloadsAllowed,
  dedupeFilenames,
  MAX_ANCHOR_DOWNLOADS,
  runWorkerPool,
  sanitizeFilename,
  summarizeFailures,
} from '../web/assets/outbound-download.js';

const outboundScript = await readFile(new URL('../web/assets/outbound.js', import.meta.url), 'utf8');

test('anchor download fallback is capped at the supported browser threshold', () => {
  assert.equal(MAX_ANCHOR_DOWNLOADS, 10);
  assert.equal(anchorDownloadsAllowed(MAX_ANCHOR_DOWNLOADS), true);
  assert.equal(anchorDownloadsAllowed(MAX_ANCHOR_DOWNLOADS + 1), false);
});

test('anchor fallback copy explains the large-link limit', () => {
  assert.match(outboundScript, /Requested \$\{files\.length\} downloads/);
  assert.match(outboundScript, /Use Download everything or Chrome\/Edge folder selection/);
});

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
