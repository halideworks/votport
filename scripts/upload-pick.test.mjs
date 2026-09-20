// Regression pins for the chunked pick admission: the first preview slice
// paints before the whole pick admits, and a mid-batch refusal still leaves
// the selection, its rows and the collision keys exactly as they began.
// The page wiring in upload.js is pinned by source shape, the way
// deliver-upload.test.mjs does.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

import { PICK_FIRST_SLICE, PICK_SLICE, admitPickBatch } from '../web/assets/upload-pick.js';

const uploadScript = await readFile(new URL('../web/assets/upload.js', import.meta.url), 'utf8');

const pair = (path, mark = path) => ({
  path,
  file: { name: path.split('/').pop(), size: 1, marker: mark },
});

test('the first preview slice paints before the whole pick admits', async () => {
  const pairs = Array.from({ length: 10_000 }, (_, i) => pair(`pick-${String(i).padStart(5, '0')}.dpx`));
  const picked = new Map();
  const deliveredPaths = new Set();
  const keys = new Map();
  const renders = [];
  let slices = 0;
  const done = admitPickBatch(pairs, {
    picked,
    deliveredPaths,
    keys,
    validate: () => null,
    keyOf: (path) => path.toLowerCase(),
    render: (settled) => renders.push({ settled, size: picked.size }),
    fail: () => assert.fail('no refusal expected'),
    slice: async () => { slices += 1; },
  });
  // The synchronous prefix ends at the first slice boundary: 200 entries
  // admitted and one unsettled render, before any await runs.
  assert.deepEqual(renders, [{ settled: false, size: PICK_FIRST_SLICE }]);
  assert.equal(picked.size, PICK_FIRST_SLICE);
  assert.deepEqual(await done, true);
  assert.equal(picked.size, pairs.length);
  assert.equal(keys.size, pairs.length);
  assert.equal(renders.at(-1).settled, true);
  assert.ok(slices >= Math.ceil((pairs.length - PICK_FIRST_SLICE) / PICK_SLICE));
});

test('a mid-batch refusal rolls the whole batch back', async () => {
  const seed = new Map([['keep.txt', pair('keep.txt').file], ['delivered.txt', pair('delivered.txt').file]]);
  const picked = new Map(seed);
  const deliveredPaths = new Set(['delivered.txt']);
  const keys = new Map([['keep.txt', 'keep.txt'], ['delivered.txt', 'delivered.txt']]);
  const refusals = [];
  let settledRenders = 0;
  const bad = Array.from({ length: 3_000 }, (_, i) => pair(`new-${String(i).padStart(5, '0')}.txt`));
  bad[2_500] = pair('bad?.txt');
  const done = admitPickBatch(bad, {
    picked,
    deliveredPaths,
    keys,
    validate: (component) => (component.includes('?') ? 'name has a forbidden character' : null),
    keyOf: (path) => path.toLowerCase(),
    render: (settled) => { if (settled) settledRenders += 1; },
    fail: (message) => refusals.push(message),
  });
  assert.equal(await done, false);
  assert.deepEqual(refusals, ['"bad?.txt": name has a forbidden character']);
  assert.equal(settledRenders, 1);
  assert.deepEqual([...picked], [...seed]);
  assert.deepEqual([...deliveredPaths], ['delivered.txt']);
});

test('a refusal after re-picking a delivered file restores it', async () => {
  const first = pair('a.txt', 'old');
  const picked = new Map([['a.txt', first.file]]);
  const deliveredPaths = new Set(['a.txt']);
  const keys = new Map([['a.txt', 'a.txt']]);
  let refusal = '';
  const done = admitPickBatch([pair('a.txt', 'new'), pair('z.txt'), pair('b?d.txt')], {
    picked,
    deliveredPaths,
    keys,
    validate: (component) => (component.includes('?') ? 'no' : null),
    keyOf: (path) => path.toLowerCase(),
    render: () => {},
    fail: (message) => { refusal = message; },
  });
  assert.equal(await done, false);
  assert.match(refusal, /"b\?d\.txt"/);
  assert.equal(picked.get('a.txt'), first.file);
  assert.ok(deliveredPaths.has('a.txt'));
  assert.equal(picked.size, 1);
});

test('two names that fold together inside one batch refuse and roll back', async () => {
  const picked = new Map();
  const deliveredPaths = new Set();
  const keys = new Map();
  let refusal = '';
  const done = admitPickBatch([pair('Reports/Q1.txt'), pair('reports/q1.txt')], {
    picked,
    deliveredPaths,
    keys,
    validate: () => null,
    keyOf: (path, components) => (components ?? path.split('/')).join('/').toLowerCase(),
    render: () => {},
    fail: (message) => { refusal = message; },
  });
  assert.equal(await done, false);
  assert.match(refusal, /"Reports\/Q1\.txt" and "reports\/q1\.txt" collide once case is folded/);
  assert.equal(picked.size, 0);
});

test('upload.js admits picks in slices and holds send until the batch settles', () => {
  assert.match(uploadScript, /import \{ admitPickBatch \} from '\/assets\/upload-pick\.js';/);
  // The page hands the seam a clone of the render's collision keys, the
  // memoized fold (finding 537), and an unsettled render that holds send.
  assert.match(uploadScript, /keys: new Map\(pickedKeys\),/);
  assert.match(uploadScript, /const key = pathKeyString\(components\);\s*\n\s*pathKeyMemo\.set\(path, key\);/);
  assert.match(uploadScript, /if \(!settled\) \$\('send'\)\.disabled = true;/);
  // A running batch retires on clear-files via the generation.
  assert.match(
    uploadScript,
    /clear-files'\)\.addEventListener\('click', \(\) => \{\s*\n\s*if \(uploading\) return;\s*\n\s*\/\/ Retire any pick batch still admitting[\s\S]{0,120}pickGeneration \+= 1;/,
  );
  assert.match(uploadScript, /aborted: \(\) => uploading \|\| pickGeneration !== batchGeneration,/);
});
