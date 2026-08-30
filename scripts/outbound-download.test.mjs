import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import {
  anchorDownloadsAllowed,
  appendMetadataPage,
  dedupeFilenames,
  FILE_RENDER_BATCH_SIZE,
  metadataMoreAvailable,
  MAX_ANCHOR_DOWNLOADS,
  publicMetadataPageUrl,
  runWorkerPool,
  sanitizeFilename,
  summarizeFailures,
  nextFileBatch,
} from '../web/assets/outbound-download.js';

const outboundScript = await readFile(new URL('../web/assets/outbound.js', import.meta.url), 'utf8');
const sendPage = await readFile(new URL('../web/send.html', import.meta.url), 'utf8');

test('anchor download fallback is capped at the supported browser threshold', () => {
  assert.equal(MAX_ANCHOR_DOWNLOADS, 10);
  assert.equal(anchorDownloadsAllowed(MAX_ANCHOR_DOWNLOADS), true);
  assert.equal(anchorDownloadsAllowed(MAX_ANCHOR_DOWNLOADS + 1), false);
});

test('anchor fallback copy explains the large-link limit', () => {
  assert.match(outboundScript, /Requested \$\{files\.length\} downloads/);
  assert.match(outboundScript, /Use Download everything or Chrome\/Edge folder selection/);
});

test('file batches are fixed and bounded at both ends', () => {
  const files = Array.from({ length: 205 }, (_, index) => index);
  assert.equal(FILE_RENDER_BATCH_SIZE, 100);
  assert.deepEqual(nextFileBatch(files, 0), files.slice(0, 100));
  assert.deepEqual(nextFileBatch(files, 100), files.slice(100, 200));
  assert.deepEqual(nextFileBatch(files, 200), files.slice(200));
  assert.deepEqual(nextFileBatch(files, 300), []);
});

test('show more remains available for loaded or pending metadata', () => {
  for (const [rendered, loaded, hasMore, expected] of [
    [0, 100, false, true],
    [100, 100, true, true],
    [100, 100, false, false],
    [100, 500, false, true],
  ]) {
    assert.equal(metadataMoreAvailable(rendered, loaded, hasMore), expected);
  }
});

test('public metadata pages append only contiguous stable ranges', () => {
  const file = (index) => ({
    name: `file-${index}.bin`,
    suite: 'blake3',
    root: `root-${index}`,
    bytes: index,
    download_url: `/api/s/token/files/${index}`,
    receipt_url: `/api/s/token/receipts/${index}`,
  });
  const first = appendMetadataPage(
    { files: [], total: null },
    { files_total: 3, offset: 0, limit: 2, has_more: true, files: [file(0), file(1)] },
  );
  assert.equal(first.files.length, 2);
  assert.equal(first.hasMore, true);
  const last = appendMetadataPage(
    first,
    { files_total: 3, offset: 2, limit: 2, has_more: false, files: [file(2)] },
  );
  assert.equal(last.files.length, 3);
  assert.throws(
    () => appendMetadataPage(first, {
      files_total: 3, offset: 1, limit: 2, has_more: true, files: [file(2)],
    }),
    /offset changed/,
  );
  assert.throws(
    () => appendMetadataPage(first, {
      files_total: 4, offset: 2, limit: 2, has_more: true, files: [file(2), file(1)],
    }),
    /total changed|duplicate/,
  );
  assert.throws(
    () => appendMetadataPage(first, {
      files_total: 3, offset: 2, limit: 2, has_more: 'false', files: [file(2)],
    }),
    /incomplete/,
  );
  const legacy = appendMetadataPage(
    { files: [], total: null },
    {
      files_total: 501,
      offset: 0,
      limit: 501,
      has_more: false,
      files: Array.from({ length: 501 }, (_, index) => file(index)),
    },
  );
  assert.equal(legacy.files.length, 501);
  assert.equal(legacy.hasMore, false);
});

test('public metadata starts with the bounded page and picker precedes fetch', () => {
  assert.equal(publicMetadataPageUrl('a/b', 0), '/api/s/a%2Fb?offset=0&limit=100');
  assert.match(outboundScript, /publicMetadataPageUrl\(token, offset, limit\)/);
  assert.match(outboundScript, /appendMetadataPageAt\(metadataFiles\.length\)/);
  assert.match(outboundScript, /metadataMoreAvailable\(renderedFileCount, metadataFiles\.length, metadataHasMore\)/);
  assert.match(outboundScript, /renderedFileCount >= metadataFiles\.length && metadataHasMore/);
  assert.match(outboundScript, /appendMetadataPageAt\(metadataFiles\.length, 500\)/);
  assert.match(
    outboundScript,
    /showDirectoryPicker\(\{ mode: 'readwrite' \}\)[\s\S]+loadRemainingMetadata\(\)/,
  );
});

test('public page wires an accessible bounded file list', () => {
  assert.match(sendPage, /id="file-list-controls" hidden/);
  assert.match(sendPage, /<button type="button" id="show-more-files" class="tiny ghost">Show more files<\/button>/);
  assert.match(sendPage, /id="file-list-status" class="muted" aria-live="polite"/);
  assert.match(outboundScript, /nextFileBatch\(metadataFiles, renderedFileCount\)/);
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
