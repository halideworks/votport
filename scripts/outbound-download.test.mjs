import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import {
  anchorDownloadsAllowed,
  appendMetadataPage,
  batchDownloadEligible,
  BATCH_LARGE_FILE_BYTES,
  dedupeFilenames,
  FILE_RENDER_BATCH_SIZE,
  metadataMoreAvailable,
  MAX_ANCHOR_DOWNLOADS,
  publicMetadataPageUrl,
  runWorkerPool,
  saveBatchFiles,
  BatchDownloadUnsupportedError,
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
  assert.match(outboundScript, /Use Download as ZIP or Chrome\/Edge folder selection/);
});

test('recipient page makes individual files primary and ZIP secondary', () => {
  assert.ok(sendPage.indexOf('id="separate-download"') < sendPage.indexOf('id="bundle-download"'));
  assert.match(sendPage, /<h2>Download all files<\/h2>/);
  assert.match(sendPage, />Download all files<\/button>/);
  assert.match(sendPage, /Chrome or Edge.*individually.*No ZIP or receipt files/s);
  assert.match(sendPage, /<h2>Download as ZIP<\/h2>/);
  assert.match(sendPage, /id="bundle-download-button"[\s\S]*class="ghost"[\s\S]*>Download as ZIP<\/button>/);
  assert.doesNotMatch(sendPage, /Download everything/);
});

test('file batches are fixed and bounded at both ends', () => {
  const files = Array.from({ length: 205 }, (_, index) => index);
  assert.equal(FILE_RENDER_BATCH_SIZE, 100);
  assert.deepEqual(nextFileBatch(files, 0), files.slice(0, 100));
  assert.deepEqual(nextFileBatch(files, 100), files.slice(100, 200));
  assert.deepEqual(nextFileBatch(files, 200), files.slice(200));
  assert.deepEqual(nextFileBatch(files, 300), []);
});

test('uses batch transport for multi-file selections with a large file', () => {
  assert.equal(batchDownloadEligible(Array.from({ length: 99 }, () => ({ bytes: 1 }))), false);
  assert.equal(batchDownloadEligible([{ bytes: BATCH_LARGE_FILE_BYTES }, { bytes: 1 }]), true);
  assert.equal(batchDownloadEligible([{ bytes: BATCH_LARGE_FILE_BYTES }]), false);
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
  assert.match(outboundScript, /batchUrl = body\.batch_url/);
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

function responseInChunks(chunks, status = 200, contentType = 'application/vnd.votport.batch; charset=binary') {
  return {
    status,
    headers: new Headers({ 'content-type': contentType }),
    body: new ReadableStream({
      start(controller) {
        for (const chunk of chunks) controller.enqueue(chunk);
        controller.close();
      },
    }),
  };
}

function fakeDirectory({ failWrite = false } = {}) {
  const files = new Map();
  const aborted = [];
  return {
    files,
    aborted,
    async getFileHandle(name) {
      return {
        async createWritable() {
          const chunks = [];
          return {
            async write(chunk) {
              if (failWrite) throw new Error('write failed');
              chunks.push(new Uint8Array(chunk));
            },
            async close() { files.set(name, new TextDecoder().decode(join(...chunks))); },
            async abort() { aborted.push(name); },
          };
        },
      };
    },
  };
}

function join(...parts) {
  const output = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
}

test('streams concatenated batch payloads by trusted metadata lengths', async () => {
  const directory = fakeDirectory();
  const response = responseInChunks([
    new TextEncoder().encode('fi'), new TextEncoder().encode('rstse'),
    new TextEncoder().encode('cond'),
  ]);
  const progress = [];
  await saveBatchFiles(response, directory, [{ bytes: 5 }, { bytes: 6 }], ['first.bin', 'second.bin'],
    (completed, total) => progress.push([completed, total]));
  assert.deepEqual([...directory.files], [['first.bin', 'first'], ['second.bin', 'second']]);
  assert.deepEqual(progress, [[1, 2], [2, 2]]);
});

test('rejects truncation and trailing bytes without direct fallback', async () => {
  const truncated = fakeDirectory();
  await assert.rejects(
    saveBatchFiles(responseInChunks([new TextEncoder().encode('first')]), truncated, [{ bytes: 5 }, { bytes: 6 }], ['one', 'two']),
    /truncated/,
  );
  assert.deepEqual(truncated.aborted, ['two']);
  await assert.rejects(
    saveBatchFiles(responseInChunks([new TextEncoder().encode('first!')]), fakeDirectory(), [{ bytes: 5 }], ['one']),
    /trailing bytes/,
  );
});

test('aborts a failed writer and validates all metadata before writing', async () => {
  const failed = fakeDirectory({ failWrite: true });
  await assert.rejects(saveBatchFiles(responseInChunks([new TextEncoder().encode('first')]), failed, [{ bytes: 5 }], ['one']), /write failed/);
  assert.deepEqual(failed.aborted, ['one']);
  await assert.rejects(
    saveBatchFiles(responseInChunks([]), fakeDirectory(), [{ bytes: 1 }, { bytes: Number.MAX_SAFE_INTEGER + 1 }], ['one', 'two']),
    /invalid file size/,
  );
});

test('only an empty batch response raises the fallback classification', async () => {
  await assert.rejects(saveBatchFiles({ status: 413 }, fakeDirectory(), [{ bytes: 1 }], ['one']), BatchDownloadUnsupportedError);
  await assert.rejects(
    saveBatchFiles(responseInChunks([new TextEncoder().encode('first')], 200, 'application/octet-stream'), fakeDirectory(), [{ bytes: 5 }], ['one']),
    BatchDownloadUnsupportedError,
  );
});
