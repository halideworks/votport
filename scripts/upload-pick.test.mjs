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

