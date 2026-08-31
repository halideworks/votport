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
  saveStoredZipFiles,
  StoredZipUnsupportedError,
  sanitizeFilename,
  summarizeFailures,
  nextFileBatch,
} from '../web/assets/outbound-download.js';

const outboundScript = await readFile(new URL('../web/assets/outbound.js', import.meta.url), 'utf8');
const sendPage = await readFile(new URL('../web/send.html', import.meta.url), 'utf8');

function u16(value) {
  const bytes = new Uint8Array(2);
  new DataView(bytes.buffer).setUint16(0, value, true);
  return bytes;
}

function u32(value) {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, true);
  return bytes;
}

function u64(value) {
  const bytes = new Uint8Array(8);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, Number(BigInt(value) & 0xffffffffn), true);
  view.setUint32(4, Number(BigInt(value) >> 32n), true);
  return bytes;
}

function join(...parts) {
  const output = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function storedZip(entries, { zip64 = false, zip64End = false, method = 0, flags = 0 } = {}) {
  const local = [];
  const central = [];
  let offset = 0;
  for (const { name, data } of entries) {
    const nameBytes = new TextEncoder().encode(name);
    const extra = zip64 ? join(u16(1), u16(16), u64(data.length), u64(data.length)) : new Uint8Array();
    const size = zip64 ? 0xffffffff : data.length;
    const header = join(
      u32(0x04034b50), u16(20), u16(flags), u16(method), u16(0), u16(0),
      u32(0), u32(size), u32(size), u16(nameBytes.length), u16(extra.length),
      nameBytes, extra, data,
    );
    local.push(header);
    central.push(join(
      u32(0x02014b50), u16(20), u16(20), u16(flags), u16(method), u16(0), u16(0),
      u32(0), u32(size), u32(size), u16(nameBytes.length), u16(extra.length), u16(0),
      u16(0), u16(0), u32(0), u32(offset), nameBytes, extra,
    ));
    offset += header.length;
  }
  const centralBytes = join(...central);
  if (!zip64End) return join(
    ...local, centralBytes,
    join(u32(0x06054b50), u16(0), u16(0), u16(entries.length), u16(entries.length),
      u32(centralBytes.length), u32(offset), u16(0)),
  );
  const zip64Offset = offset + centralBytes.length;
  const zip64Record = join(
    u32(0x06064b50), u64(44), u16(45), u16(45), u32(0), u32(0),
    u64(entries.length), u64(entries.length), u64(centralBytes.length), u64(offset),
  );
  return join(
    ...local, centralBytes, zip64Record,
    join(u32(0x07064b50), u32(0), u64(zip64Offset), u32(1)),
    join(u32(0x06054b50), u16(0), u16(0), u16(0xffff), u16(0xffff),
      u32(0xffffffff), u32(0xffffffff), u16(0)),
  );
}

function responseInChunks(bytes, chunkSize = 1, status = 200) {
  return {
    status,
    body: new ReadableStream({
      start(controller) {
        for (let offset = 0; offset < bytes.length; offset += chunkSize) {
          controller.enqueue(bytes.slice(offset, offset + chunkSize));
        }
        controller.close();
      },
    }),
  };
}

function fakeDirectory() {
  const files = new Map();
  return {
    files,
    async getFileHandle(name) {
      return {
        async createWritable() {
          const chunks = [];
          return {
            async write(chunk) { chunks.push(new Uint8Array(chunk)); },
            async close() { files.set(name, join(...chunks)); },
            async abort() { chunks.length = 0; },
          };
        },
      };
    },
  };
}

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

test('streams a stored ZIP into individual files across adversarial chunks', async () => {
  const bytes = storedZip([
    { name: 'ignored/first.bin', data: new TextEncoder().encode('first') },
    { name: 'ignored/second.bin', data: new TextEncoder().encode('second') },
  ]);
  const directory = fakeDirectory();
  const progress = [];
  await saveStoredZipFiles(
    responseInChunks(bytes, 7),
    directory,
    [{ bytes: 5 }, { bytes: 6 }],
    ['first.bin', 'second.bin'],
    (completed, total) => progress.push([completed, total]),
  );
  assert.deepEqual([...directory.files].map(([name, value]) => [name, new TextDecoder().decode(value)]), [
    ['first.bin', 'first'],
    ['second.bin', 'second'],
  ]);
  assert.deepEqual(progress, [[1, 2], [2, 2]]);
});

test('accepts ZIP64 entry sizes without trusting archive names', async () => {
  const bytes = storedZip([{ name: 'safe.bin', data: new Uint8Array() }], { zip64: true });
  const directory = fakeDirectory();
  await saveStoredZipFiles(responseInChunks(bytes, 3), directory, [{ bytes: 0 }], ['renamed.bin']);
  assert.ok(directory.files.has('renamed.bin'));
});

test('accepts ZIP64 central-directory counts', async () => {
  const bytes = storedZip([
    { name: 'one.bin', data: new Uint8Array([1]) },
    { name: 'two.bin', data: new Uint8Array([2]) },
  ], { zip64End: true });
  const directory = fakeDirectory();
  await saveStoredZipFiles(responseInChunks(bytes, 11), directory, [{ bytes: 1 }, { bytes: 1 }], ['one.bin', 'two.bin']);
  assert.equal(directory.files.size, 2);
});

test('rejects unsupported ZIP shapes for caller fallback', async () => {
  const directory = fakeDirectory();
  await assert.rejects(
    saveStoredZipFiles(
      responseInChunks(storedZip([{ name: 'safe.bin', data: new Uint8Array([1]) }], { method: 8 }), 2),
      directory,
      [{ bytes: 1 }],
      ['safe.bin'],
    ),
    StoredZipUnsupportedError,
  );
  await assert.rejects(
    saveStoredZipFiles(
      responseInChunks(storedZip([{ name: '../escape.bin', data: new Uint8Array([1]) }]), 2),
      fakeDirectory(),
      [{ bytes: 1 }],
      ['safe.bin'],
    ),
    /unsafe ZIP filename/,
  );
  await assert.rejects(
    saveStoredZipFiles(responseInChunks(new Uint8Array()), fakeDirectory(), [{ bytes: 1 }], ['safe.bin']),
    StoredZipUnsupportedError,
  );
});

test('does not classify a post-write archive failure as a safe fallback', async () => {
  const data = new Uint8Array([1]);
  const bytes = storedZip([{ name: 'safe.bin', data }]);
  const centralOffset = 30 + 'safe.bin'.length + data.length;
  new DataView(bytes.buffer).setUint32(centralOffset + 20, 2, true);
  await assert.rejects(
    saveStoredZipFiles(responseInChunks(bytes, 5), fakeDirectory(), [{ bytes: 1 }], ['safe.bin']),
    (error) => error instanceof StoredZipUnsupportedError && error.filesWritten === 1,
  );
});
