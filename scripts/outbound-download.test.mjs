import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import {
  appendMetadataPage,
  batchDownloadEligible,
  BATCH_LARGE_FILE_BYTES,
  dedupeFilenames,
  FILE_RENDER_BATCH_SIZE,
  metadataMoreAvailable,
  publicMetadataPageUrl,
  runWorkerPool,
  saveBatchFiles,
  BatchDownloadUnsupportedError,
  sanitizeFilename,
  streamToWritable,
  summarizeFailures,
  nextFileBatch,
} from '../web/assets/outbound-download.js';

const outboundScript = await readFile(new URL('../web/assets/outbound.js', import.meta.url), 'utf8');
const sendPage = await readFile(new URL('../web/send.html', import.meta.url), 'utf8');

test('VOTPort imposes no anchor fallback file-count cap; Chromium batches permission after 10', () => {
  assert.doesNotMatch(outboundScript, /MAX_ANCHOR_DOWNLOADS|anchorDownloadsAllowed/);
  assert.match(outboundScript, /prepareAnchorDownloads\(\)[\s\S]+loadRemainingMetadata\(\)/);
  assert.match(outboundScript, /startAnchorDownloads\(\)[\s\S]+triggerSeparateDownloads\(pending\.files, pending\.names\)/);
  assert.match(outboundScript, /const link = document\.createElement\('a'\);[\s\S]+await new Promise\(\(resolve\) => setTimeout\(resolve, 100\)\)/);
  assert.doesNotMatch(outboundScript, /cannot request more than|Chrome\/Edge/);
});

test('anchor fallback copy explains multiple downloads', () => {
  assert.match(outboundScript, /Requested \$\{pending\.files\.length\} downloads/);
  assert.match(outboundScript, /Your browser may ask you to allow multiple downloads; accept that prompt to receive every file\./);
  assert.doesNotMatch(outboundScript, /Safari may ask|If Safari asks/);
  assert.match(sendPage, /id="separate-download-confirm" class="modal"/);
  assert.match(sendPage, /id="separate-download-confirm-detail"/);
  assert.match(sendPage, /aria-describedby="separate-download-confirm-detail"/);
  assert.match(sendPage, />Start downloads<\/button>/);
});

test('recipient page has one primary action with ZIP as a secondary link', () => {
  // The primary button sits in the hero block; ZIP is a text-style link after it.
  assert.match(sendPage, /id="separate-download" class="hero-action"/);
  assert.ok(sendPage.indexOf('id="separate-download-button"') < sendPage.indexOf('id="bundle-download-button"'));
  assert.match(sendPage, /id="separate-download-button"[^>]*>Download all files<\/button>/);
  assert.match(sendPage, /id="bundle-download-button" class="link"[^>]*>Download as ZIP<\/button>/);
  assert.doesNotMatch(sendPage, /<h2>Download all files<\/h2>|<h2>Download as ZIP<\/h2>/);
  // The manifest is the file list; the availability line lives in the masthead.
  assert.match(sendPage, /<h2>Manifest<\/h2>/);
  assert.doesNotMatch(sendPage, /id="expires"/);
  assert.match(outboundScript, /available until \$\{when\(body\.expires_at\)\}/);
  // A finished save is "landed", never "verified": the browser checks nothing.
  assert.match(outboundScript, /badge\.textContent = 'landed'/);
  assert.doesNotMatch(outboundScript, /verified on this device/);
  // The anchor-fallback path still carries the multiple-downloads advice.
  assert.match(outboundScript, /prepareAnchorDownloads\(\)/);
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

test('deduplicates repeated names across folders and existing numbered names', () => {
  assert.deepEqual(
    dedupeFilenames(['a/frame.exr', 'frame (2).exr', 'b/frame.exr', 'FRAME.EXR',
      'frame (3).exr', 'frame.exr', 'CON', '_con']),
    ['frame.exr', 'frame (2).exr', 'frame (3).exr', 'FRAME (4).EXR',
      'frame (3) (2).exr', 'frame (5).exr', '_CON', '_con (2)'],
  );
  const names = dedupeFilenames(Array(20000).fill('nested/frame.exr'));
  assert.equal(new Set(names).size, 20000);
  assert.equal(names.at(-1), 'frame (20000).exr');
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

function fakeWritable() {
  return {
    chunks: [],
    truncated: 0,
    async write(bytes) { this.chunks.push(bytes); },
    async truncate(size) { this.truncated += 1; this.chunks = []; assert.equal(size, 0); },
    written() { return this.chunks.reduce((total, chunk) => total + chunk.byteLength, 0); },
  };
}

function bodyOf(chunks, { failAfter = Infinity } = {}) {
  let index = 0;
  let delivered = 0;
  return {
    getReader() {
      return {
        async read() {
          if (delivered >= failAfter) throw new TypeError('network dropped');
          if (index >= chunks.length) return { done: true };
          delivered += 1;
          return { value: chunks[index++], done: false };
        },
        async cancel() {},
        releaseLock() {},
      };
    },
  };
}

const bytes = (count, fill) => new Uint8Array(count).fill(fill);
const noSleep = { sleep: async () => {} };

test('streamToWritable resumes a dropped stream with a byte range', async () => {
  const requests = [];
  const responses = [
    { ok: true, status: 200, body: bodyOf([bytes(4, 1), bytes(4, 2)], { failAfter: 1 }) },
    { ok: true, status: 206, headers: new Headers({ 'content-range': 'bytes 4-7/8' }), body: bodyOf([bytes(4, 2)]) },
  ];
  const fetchFn = async (url, options) => { requests.push(options.headers); return responses.shift(); };
  const writable = fakeWritable();
  const total = await streamToWritable(fetchFn, writable, { download_url: '/f/0', bytes: 8 }, noSleep);
  assert.equal(total, 8);
  assert.equal(writable.written(), 8);
  assert.deepEqual(requests, [{}, { Range: 'bytes=4-' }]);
  assert.equal(writable.truncated, 0);
});

test('streamToWritable restarts from zero when a resume is answered with 200', async () => {
  const responses = [
    { ok: true, status: 200, body: bodyOf([bytes(4, 1)], { failAfter: 1 }) },
    { ok: true, status: 200, body: bodyOf([bytes(4, 1), bytes(4, 2)]) },
  ];
  const writable = fakeWritable();
  const total = await streamToWritable(async () => responses.shift(), writable, { download_url: '/f/0', bytes: 8 }, noSleep);
  assert.equal(total, 8);
  assert.equal(writable.truncated, 1);
  assert.equal(writable.written(), 8);
});

test('streamToWritable keeps resuming for the waiting budget, not a fixed count', async () => {
  let clock = 0;
  const sleep = async (ms) => { clock += ms; };
  let calls = 0;
  const responses = [];
  for (let i = 0; i < 40; i += 1) responses.push({ ok: false, status: 503, body: null });
  responses.push({ ok: true, status: 200, body: bodyOf([bytes(8, 2)]) });
  const fetchFn = async () => { calls += 1; return responses.shift(); };
  const writable = fakeWritable();
  // Forty 503s at the 8 s cap is nearly five minutes of waiting; the ten
  // minute budget covers it, a five-attempt limit would not.
  const total = await streamToWritable(fetchFn, writable, { download_url: '/f/0', bytes: 8 }, { sleep });
  assert.equal(calls, 41);
  assert.ok(clock > 4 * 60 * 1000 && clock < 10 * 60 * 1000, `waited ${clock} ms`);
  assert.equal(total, 8);
  await assert.rejects(
    streamToWritable(async () => ({ ok: false, status: 503, body: null }), fakeWritable(),
      { download_url: '/f/0', bytes: 8 }, { sleep, retryBudgetMs: 20000 }),
    /server returned 503/,
  );
});

test('streamToWritable does not charge streaming time against the budget', async () => {
  // A body that takes far longer than the budget to deliver, then drops:
  // the resume must still happen, since only backoff sleeps are budgeted.
  const slowBody = {
    getReader() {
      let delivered = 0;
      return {
        async read() {
          if (delivered === 0) {
            delivered += 1;
            await new Promise((resolve) => setTimeout(resolve, 600));
            return { value: bytes(4, 1), done: false };
          }
          throw new TypeError('network dropped after a long stream');
        },
        async cancel() {},
        releaseLock() {},
      };
    },
  };
  const responses = [
    { ok: true, status: 200, body: slowBody },
    { ok: true, status: 206, headers: new Headers({ 'content-range': 'bytes 4-7/8' }), body: bodyOf([bytes(4, 2)]) },
  ];
  const requests = [];
  const fetchFn = async (url, options) => { requests.push(options.headers); return responses.shift(); };
  const writable = fakeWritable();
  // The stream took longer than the budget; wall-clock accounting would
  // give up here, backoff accounting retries.
  const total = await streamToWritable(fetchFn, writable, { download_url: '/f/0', bytes: 8 }, { ...noSleep, retryBudgetMs: 500 });
  assert.equal(total, 8);
  assert.deepEqual(requests, [{}, { Range: 'bytes=4-' }]);

  // The boundary: a sleep that would overrun the budget is not taken.
  const slept = [];
  await assert.rejects(
    streamToWritable(async () => ({ ok: false, status: 503, body: null }), fakeWritable(),
      { download_url: '/f/0', bytes: 8 }, { sleep: async (ms) => { slept.push(ms); }, retryBudgetMs: 3000 }),
    /server returned 503/,
  );
  assert.deepEqual(slept, [500, 1000]);
});

test('streamToWritable re-authorizes on 401 and resumes from its offset', async () => {
  const requests = [];
  const responses = [
    { ok: true, status: 200, body: bodyOf([bytes(4, 1), bytes(4, 2)], { failAfter: 1 }) },
    { ok: false, status: 401, body: null },
    { ok: true, status: 206, headers: new Headers({ 'content-range': 'bytes 4-7/8' }), body: bodyOf([bytes(4, 2)]) },
  ];
  const fetchFn = async (url, options) => { requests.push(options.headers); return responses.shift(); };
  let asked = 0;
  const writable = fakeWritable();
  const total = await streamToWritable(fetchFn, writable, { download_url: '/f/0', bytes: 8 }, {
    ...noSleep,
    onAuthLost: async () => { asked += 1; return true; },
  });
  assert.equal(total, 8);
  assert.equal(asked, 1);
  assert.deepEqual(requests, [{}, { Range: 'bytes=4-' }, { Range: 'bytes=4-' }]);
  assert.equal(writable.truncated, 0);
  // A gate that cannot re-authorize, or no gate at all, is a hard failure.
  await assert.rejects(
    streamToWritable(async () => ({ ok: false, status: 401, body: null }), fakeWritable(),
      { download_url: '/f/0', bytes: 8 }, { ...noSleep, onAuthLost: async () => false }),
    /server returned 401/,
  );
  await assert.rejects(
    streamToWritable(async () => ({ ok: false, status: 403, body: null }), fakeWritable(),
      { download_url: '/f/0', bytes: 8 }, noSleep),
    /server returned 403/,
  );
});

test('streamToWritable gives up after the retry limit and on non-transient statuses', async () => {
  let calls = 0;
  await assert.rejects(
    streamToWritable(async () => { calls += 1; return { ok: true, status: 200, body: bodyOf([], { failAfter: 0 }) }; },
      fakeWritable(), { download_url: '/f/0', bytes: 8 }, { retries: 3, ...noSleep }),
    TypeError,
  );
  assert.equal(calls, 3);
  await assert.rejects(
    streamToWritable(async () => ({ ok: false, status: 404 }), fakeWritable(), { download_url: '/f/0', bytes: 8 }, noSleep),
    /server returned 404/,
  );
});

test('streamToWritable rejects invalid sizes before fetching or writing', async () => {
  for (const size of [undefined, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '8']) {
    await assert.rejects(streamToWritable(
      async () => assert.fail('must not fetch'), fakeWritable(),
      { download_url: '/f/0', bytes: size }, noSleep,
    ), /invalid file size/);
  }
});

test('streamToWritable rejects mismatched resumed ranges before appending bytes', async () => {
  for (const range of [null, 'garbage', 'bytes 0-7/8', 'bytes 5-7/8', 'bytes 4-6/8',
    'bytes 4-7/9', 'bytes 4-7/*']) {
    let calls = 0;
    let cancelled = false;
    const writable = fakeWritable();
    await assert.rejects(streamToWritable(async () => {
      calls += 1;
      if (calls === 1) return { ok: true, status: 200, body: bodyOf([bytes(4, 1)], { failAfter: 1 }) };
      assert.equal(calls, 2);
      return new Response(new ReadableStream({
        start(controller) { controller.enqueue(bytes(4, 2)); controller.close(); },
        cancel() { cancelled = true; },
      }), { status: 206, headers: range === null ? {} : { 'content-range': range } });
    }, writable, { download_url: '/f/0', bytes: 8 }, noSleep), /invalid byte range/);
    assert.equal(writable.written(), 4);
    assert.equal(cancelled, true);
  }
});

test('streamToWritable resumes clean truncation and refuses excess bytes', async () => {
  const requests = [];
  const responses = [
    new Response(bytes(4, 1)),
    new Response(bytes(4, 2), { status: 206, headers: { 'content-range': 'bytes 4-7/8' } }),
  ];
  const writable = fakeWritable();
  assert.equal(await streamToWritable(async (_url, options) => {
    requests.push(options.headers);
    return responses.shift();
  }, writable, { download_url: '/f/0', bytes: 8 }, noSleep), 8);
  assert.deepEqual(requests, [{}, { Range: 'bytes=4-' }]);
  assert.deepEqual(join(...writable.chunks), join(bytes(4, 1), bytes(4, 2)));

  let cancelled = false;
  const oversized = fakeWritable();
  await assert.rejects(streamToWritable(async () => new Response(new ReadableStream({
    start(controller) {
      controller.enqueue(bytes(9, 1));
      controller.enqueue(bytes(1, 1));
      controller.close();
    },
    cancel() { cancelled = true; },
  })), oversized, { download_url: '/f/0', bytes: 8 }, noSleep), /exceeds the file size/);
  assert.equal(oversized.written(), 0);
  assert.equal(cancelled, true);

  await assert.rejects(streamToWritable(async () => new Response(bytes(0)), fakeWritable(),
    { download_url: '/f/0', bytes: 8 }, { ...noSleep, retries: 2 }), /truncated/);
  assert.equal(await streamToWritable(async () => new Response(bytes(0)), fakeWritable(),
    { download_url: '/f/0', bytes: 0 }, noSleep), 0);
});

test('streamToWritable rejects unexpected successful statuses', async () => {
  await assert.rejects(streamToWritable(async () => new Response(bytes(8), { status: 202 }),
    fakeWritable(), { download_url: '/f/0', bytes: 8 }, noSleep), /unexpected download status 202/);
});

test('streamToWritable cancels error bodies before retrying or asking for authorization', async () => {
  for (const status of [429, 503, 401, 403, 404]) {
    let cancelled = false;
    let calls = 0;
    const saving = streamToWritable(async () => {
      calls += 1;
      if (calls > 1) {
        assert.equal(cancelled, true);
        return new Response(bytes(8));
      }
      return new Response(new ReadableStream({
        start(controller) { controller.enqueue(bytes(16)); controller.close(); },
        cancel() { cancelled = true; },
      }), { status });
    }, fakeWritable(), { download_url: '/f/0', bytes: 8 }, {
      retries: 2,
      sleep: async () => { assert.equal(cancelled, true); },
      onAuthLost: async () => { assert.equal(cancelled, true); return true; },
    });
    if (status === 404) await assert.rejects(saving, /server returned 404/);
    else assert.equal(await saving, 8);
    assert.equal(cancelled, true);
  }
});
