import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import {
  appendMetadataPage,
  batchDownloadEligible,
  BATCH_LARGE_FILE_BYTES,
  dedupeFilenames,
  FILE_RENDER_BATCH_SIZE,
  METADATA_PAGE_SIZE,
  metadataMoreAvailable,
  publicMetadataPageUrl,
  runWorkerPool,
  saveBatchFiles,
  BatchDownloadUnsupportedError,
  sanitizeFilename,
  streamToWritable,
  saveFile,
  createDownloadFile,
  triggerDownload,
  triggerSeparateDownloads,
  summarizeFailures,
  nextFileBatch,
} from '../web/assets/outbound-download.js';

const outboundScript = await readFile(new URL('../web/assets/outbound.js', import.meta.url), 'utf8');
const sendPage = await readFile(new URL('../web/send.html', import.meta.url), 'utf8');

function downloadDocument(t, clicked) {
  const previous = globalThis.document;
  globalThis.document = {
    body: { append() {} },
    createElement() { return { click() { clicked(this); }, remove() {} }; },
  };
  t.after(() => { globalThis.document = previous; });
}

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

test('metadata accepts absent receipts while validating receipt URLs when present', () => {
  for (const receipt of [null, '/api/s/token/receipts/0', '/api/s/token/receipts/1', '', 7, undefined]) {
    const page = { files_total: 1, offset: 0, limit: 1, has_more: false,
      files: [{ download_url: '/api/s/token/files/0', receipt_url: receipt }] };
    if (receipt === null || receipt === '/api/s/token/receipts/0') {
      assert.equal(appendMetadataPage({ files: [], total: null }, page).files.length, 1);
    } else {
      assert.throws(() => appendMetadataPage({ files: [], total: null }, page), /invalid/);
    }
  }
});

test('sanitizes flattened unsafe and reserved filenames', () => {
  assert.equal(sanitizeFilename('nested\\report?.txt'), 'report_.txt');
  assert.equal(sanitizeFilename('CON.txt'), '_CON.txt');
  assert.equal(sanitizeFilename('../'), 'download');
});

test('the batch save shares the uploader refusal set (audit finding 509)', async () => {
  // Zero-width, bidi and byte-order marks cannot be sent through the
  // uploader; the batch save must not write them verbatim either.
  assert.equal(sanitizeFilename('report\u202e.txt'), 'report_.txt');
  assert.equal(sanitizeFilename('re\u200cport\u2066x\u2069.txt'), 're_port_x_.txt');
  assert.equal(sanitizeFilename('rec\ufefford.mov'), 'rec_ord.mov');
  const uploader = await readFile(new URL('../web/assets/upload.js', import.meta.url), 'utf8');
  assert.match(
    uploader,
    /import \{ nameHasForbiddenCharacter \} from '\/assets\/outbound-download\.js';/,
  );
  assert.doesNotMatch(uploader, /const FORBIDDEN = new RegExp/);
  const download = await readFile(
    new URL('../web/assets/outbound-download.js', import.meta.url),
    'utf8',
  );
  assert.match(download, /const FORBIDDEN_SOURCE =/);
});

test('deduplicates case-insensitive names before extensions', () => {
  assert.deepEqual(
    dedupeFilenames(['dir/report.txt', 'report.txt', 'REPORT.TXT', 'report (2).txt']),
    ['report.txt', 'report (2).txt', 'REPORT (3).TXT', 'report (2) (2).txt'],
  );
});

test('deduplicates canonically equivalent Unicode names and suffixes', () => {
  assert.deepEqual(
    dedupeFilenames(['one/Café.mov', 'two/Cafe\u0301.mov', 'CAFÉ.MOV', 'Cafe\u0301 (2).mov']),
    ['Café.mov', 'Cafe\u0301 (2).mov', 'CAFÉ (3).MOV', 'Cafe\u0301 (2) (2).mov'],
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

function fakeDirectory({ failWrite = false, initialFiles = [], directories = [] } = {}) {
  const files = new Map(initialFiles);
  const aborted = [];
  return {
    files,
    aborted,
    async getFileHandle(name, { create = false } = {}) {
      if (directories.includes(name)) throw new DOMException('entry is a directory', 'TypeMismatchError');
      if (!files.has(name)) {
        if (!create) throw new DOMException('entry missing', 'NotFoundError');
        files.set(name, '');
      }
      return {
        name,
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

test('parallel individual saves and interrupted batch fallback retain earlier files', async (t) => {
  t.mock.method(globalThis, 'fetch', async (url) => new Response(url));
  const individualSave = (directory, file, name) => saveFile(directory, { ...file, download_url: file.content }, name);
  const directory = fakeDirectory({ initialFiles: [['chart.txt', 'keep']] });
  await Promise.all([
    individualSave(directory, { content: 'one', bytes: 3 }, 'chart.txt'),
    individualSave(directory, { content: 'two', bytes: 3 }, 'chart (2).txt'),
  ]);
  assert.equal(directory.files.get('chart.txt'), 'keep');
  assert.deepEqual([...directory.files.values()].sort(), ['keep', 'one', 'two']);
  let completed = 0;
  await assert.rejects(saveBatchFiles(responseInChunks([new TextEncoder().encode('firstcut')]), directory,
    [{ bytes: 5 }, { bytes: 9 }], ['first', 'second'], (count) => { completed = count; }), /truncated/);
  assert.equal(completed, 1);
  await individualSave(directory, { content: 'remaining', bytes: 9 }, 'second');
  assert.equal(directory.files.get('first'), 'first');
  assert.equal(directory.files.get('second'), '');
  assert.equal(directory.files.get('second (2)'), 'remaining');
});

test('name allocation propagates permission, cancellation and invalid-name failures without poisoning the queue', async () => {
  for (const name of ['NotAllowedError', 'AbortError', 'TypeError', 'QuotaExceededError']) {
    const failure = new DOMException('Cannot use this filename', name);
    let probes = 0;
    await assert.rejects(createDownloadFile({
      async getFileHandle() { probes += 1; throw failure; },
    }, 'chart.txt'), (error) => error === failure);
    assert.equal(probes, 1);
    const directory = fakeDirectory();
    await createDownloadFile(directory, 'chart.txt');
    assert.deepEqual([...directory.files], [['chart.txt', '']]);
  }
});

test('name allocation bounds collisions and handles a directory appearing during creation', async () => {
  let probes = 0;
  await assert.rejects(createDownloadFile({
    async getFileHandle(_name, options) {
      assert.equal(options, undefined);
      probes += 1;
      if (probes > 1000) throw new Error('fixture observed excess name probes');
      return {};
    },
  }, 'chart.txt'), /after 1,000 attempts/);
  assert.equal(probes, 1000);
  const directory = fakeDirectory();
  const getFileHandle = directory.getFileHandle;
  directory.getFileHandle = async (name, options) => {
    if (name === 'chart.txt') {
      throw new DOMException('directory appeared', options?.create ? 'TypeMismatchError' : 'NotFoundError');
    }
    return getFileHandle(name, options);
  };
  await createDownloadFile(directory, 'chart.txt');
  assert.deepEqual([...directory.files], [['chart (2).txt', '']]);
});

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
    (completed, total, name) => progress.push([completed, total, name]));
  assert.deepEqual([...directory.files], [['first.bin', 'first'], ['second.bin', 'second']]);
  assert.deepEqual(progress, [[1, 2, 'first.bin'], [2, 2, 'second.bin']]);
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

test('streamToWritable retries on the redirected final URL that carries the lease', async () => {
  const calls = [];
  const responses = [
    {
      ok: true,
      status: 200,
      url: '/api/s/t/files/0?download_lease=abcdef0123456789.0123456789abcdef',
      body: bodyOf([bytes(4, 1)], { failAfter: 1 }),
    },
    { ok: true, status: 206, headers: new Headers({ 'content-range': 'bytes 4-7/8' }), body: bodyOf([bytes(4, 2)]) },
  ];
  const fetchFn = async (url, options) => { calls.push([url, options.headers]); return responses.shift(); };
  const writable = fakeWritable();
  const total = await streamToWritable(
    fetchFn, writable, { download_url: '/api/s/t/files/0', bytes: 8 }, noSleep,
  );
  assert.equal(total, 8);
  assert.deepEqual(calls[0], ['/api/s/t/files/0', {}]);
  assert.deepEqual(
    calls[1],
    ['/api/s/t/files/0?download_lease=abcdef0123456789.0123456789abcdef', { Range: 'bytes=4-' }],
  );
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
