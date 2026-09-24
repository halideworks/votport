import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { entryFiles, runUploadBatch, uploadLibraryFile, libraryFileIdentity } from '../web/assets/upload-entries.js';

const deliver = await readFile(new URL('../web/deliver.html', import.meta.url), 'utf8');
const deliverScript = await readFile(new URL('../web/assets/page-deliver.js', import.meta.url), 'utf8');

test('dropped entries drain directory readers and preserve relative paths', async () => {
  const file = (path) => ({
    isFile: true,
    fullPath: `/${path}`,
    file(resolve) { resolve({ name: path.split('/').pop() }); },
  });
  const children = [file('project/a.txt'), file('project/nested/b.txt')];
  let readCount = 0;
  const directory = {
    isDirectory: true,
    createReader: () => ({
      readEntries(resolve) {
        resolve(readCount++ === 0 ? children : []);
      },
    }),
  };
  assert.deepEqual(
    (await entryFiles(directory)).map(({ path }) => path),
    ['project/a.txt', 'project/nested/b.txt'],
  );
  assert.match(deliverScript, /file\.webkitRelativePath \|\| file\.name/);
  assert.match(deliverScript, /project \? `\$\{project\}\/\$\{relative\}` : relative/);
  assert.match(deliverScript, /entryFiles\)\)\)\.flat\(\)/);
});

test('library upload attempts isolate same-metadata files and keep the id through retries', async (t) => {
  const stages = new Map();
  const requests = [];
  let loseReply = true;
  t.mock.method(globalThis, 'fetch', async (_url, request) => {
    const id = request.headers['X-Votport-Upload-Id'];
    const range = /^bytes (\d+)-(\d+)\/(\d+)$/.exec(request.headers['Content-Range']);
    const start = Number(range[1]);
    const end = Number(range[2]) + 1;
    requests.push({ id, start });
    const chunks = stages.get(id) || [];
    const offset = chunks.reduce((size, chunk) => size + chunk.length, 0);
    if (offset === Number(range[3])) return Response.json({ offset });
    if (offset !== start) return Response.json({ offset }, { status: 409 });
    chunks.push(new Uint8Array(await request.body.arrayBuffer()));
    stages.set(id, chunks);
    if (loseReply) { loseReply = false; throw new TypeError('reply lost'); }
    return Response.json({ offset: end });
  });
  const metadata = { lastModified: 123456789 };
  const first = new File(['old bytes'], 'same.bin', metadata);
  const second = new File(['new bytes'], 'same.bin', metadata);
  await uploadLibraryFile(first, 'same.bin');
  await uploadLibraryFile(second, 'same.bin');
  assert.equal(requests.length, 3);
  assert.match(requests[0].id, /^[a-f0-9]{64}$/);
  assert.equal(requests[0].id, requests[1].id);
  assert.notEqual(requests[0].id, requests[2].id);
  assert.equal(requests[2].start, 0);
  assert.equal(new TextDecoder().decode(stages.get(requests[2].id)[0]), 'new bytes');
});

test('library upload recovery rejects unchanged and unpublished completion offsets', async (t) => {
  t.mock.method(globalThis, 'setTimeout', (done) => { queueMicrotask(done); });
  for (const offset of [0, 1, 2, -1]) {
    let requests = 0;
    t.mock.method(globalThis, 'fetch', async () => {
      assert.ok(++requests <= 8, 'upload must stop retrying an invalid checkpoint');
      return Response.json({ offset }, { status: 409 });
    });
    const result = assert.rejects(uploadLibraryFile(new File(['x'], 'x'), 'x'), /invalid upload offset/);
    await result;
    assert.equal(requests, 4);
  }
});

test('library uploads recover a lost stage but bound repeated rewinds across successful chunks', async (t) => {
  t.mock.method(globalThis, 'setTimeout', (done) => { queueMicrotask(done); });
  const file = new File([new Uint8Array(8 * 1024 * 1024 + 1)], 'two-chunks.bin');
  for (const lostStages of [1, 4]) {
    let losses = 0;
    let requests = 0;
    t.mock.method(globalThis, 'fetch', async (_url, request) => {
      assert.ok(++requests <= 20, 'upload must stop a rewind cycle');
      const [, start, end] = /^bytes (\d+)-(\d+)\/\d+$/.exec(request.headers['Content-Range']);
      if (Number(start) > 0 && losses++ < lostStages) return Response.json({ offset: 0 }, { status: 409 });
      return Response.json({ offset: Number(end) + 1 });
    });
    const upload = uploadLibraryFile(file, file.name);
    const result = lostStages === 1 ? upload : assert.rejects(upload, /repeatedly lost upload progress/);
    await result;
    assert.equal(requests, lostStages === 1 ? 4 : 8);
  }
});

test('upload batches cap concurrency and wait for running work after failure', async () => {
  const deferred = new Map();
  for (const item of [0, 2, 3, 4, 5, 6, 7]) {
    let resolve;
    const promise = new Promise((finish) => { resolve = finish; });
    deferred.set(item, { promise, resolve });
  }
  let active = 0;
  let maximum = 0;
  const started = [];
  const batch = runUploadBatch([...Array(12).keys()], async (item) => {
    started.push(item);
    active += 1;
    maximum = Math.max(maximum, active);
    if (item === 1) {
      active -= 1;
      throw undefined;
    }
    await deferred.get(item).promise;
    active -= 1;
  });
  let settled = false;
  const result = batch.catch((error) => {
    settled = true;
    throw error;
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(started, [0, 1, 2, 3, 4, 5, 6, 7]);
  assert.ok(maximum <= 8);
  assert.equal(active, 7);
  assert.equal(settled, false);
  for (const { resolve } of deferred.values()) resolve();
  await assert.rejects(result, (error) => error === undefined);
  assert.equal(active, 0);
});

test('library uploads resume acknowledged chunks after reselection and clear completed checkpoints', async (t) => {
  const saved = new Map();
  const previous = globalThis.sessionStorage;
  globalThis.sessionStorage = { getItem: (key) => saved.get(key) ?? null, setItem: (key, value) => saved.set(key, value), removeItem: (key) => saved.delete(key) };
  t.after(() => { if (previous === undefined) delete globalThis.sessionStorage; else globalThis.sessionStorage = previous; });
  t.mock.method(globalThis, 'setTimeout', (done) => { queueMicrotask(done); });
  const bytes = new Uint8Array(8 * 1024 * 1024 + 1);
  bytes[bytes.length - 1] = 19;
  let offline = true;
  const requests = [];
  t.mock.method(globalThis, 'fetch', async (_url, request) => {
    const [, start, end] = /^bytes (\d+)-(\d+)\/\d+$/.exec(request.headers['Content-Range']);
    requests.push([Number(start), request.headers['X-Votport-Upload-Id']]);
    if (Number(start) > 0 && offline) throw new TypeError('offline');
    return Response.json({ offset: Number(end) + 1 });
  });
  await assert.rejects(uploadLibraryFile(new File([bytes], 'large.bin', { lastModified: 1 }), 'large.bin'), /offline/);
  assert.deepEqual([...saved.values()], [String(8 * 1024 * 1024)]);
  offline = false;
  await uploadLibraryFile(new File([bytes], 'large.bin', { lastModified: 2 }), 'large.bin');
  assert.equal(requests.at(-1)[0], 8 * 1024 * 1024);
  assert.equal(requests.at(-1)[1], requests[0][1]);
  assert.equal(saved.size, 0);
});

test('library identities bind contents and reject short reads', async () => {
  const original = new File(['same contents'], 'first');
  assert.equal(await libraryFileIdentity(original), await libraryFileIdentity(new File(['same contents'], 'renamed')));
  assert.notEqual(await libraryFileIdentity(original), await libraryFileIdentity(new File(['Same contents'], 'first')));
  await assert.rejects(libraryFileIdentity({ size: 2, slice: () => new Blob(['x']) }), /could not be read completely/);
});
