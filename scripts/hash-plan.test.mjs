import assert from 'node:assert/strict';
import { test } from 'node:test';

import { segments } from '../web/assets/hash-plan.js';

const LEAF = 65536;
const MIN = 16 * 1024 * 1024;

test('small files and a single worker hash in one piece', () => {
  assert.deepEqual(segments(5000, LEAF, 4, MIN), [[0, 5000]]);
  assert.deepEqual(segments(2 * MIN - 1, LEAF, 4, MIN), [[0, 2 * MIN - 1]]);
  assert.deepEqual(segments(1 << 30, LEAF, 1, MIN), [[0, 1 << 30]]);
  assert.deepEqual(segments(0, LEAF, 4, MIN), []);
});

test('segments are leaf aligned, contiguous, cover the file, and only the tail is short', () => {
  for (const [size, workers] of [[2 * MIN, 4], [1000 * LEAF + 1234, 4], [(1 << 30) + 7, 8], [3 * MIN + 5, 2]]) {
    const plan = segments(size, LEAF, workers, MIN);
    assert.ok(plan.length >= 2 && plan.length <= workers, `${size}/${workers}: ${plan.length} segments`);
    assert.equal(plan[0][0], 0);
    assert.equal(plan[plan.length - 1][1], size);
    for (let i = 0; i < plan.length; i += 1) {
      const [start, end] = plan[i];
      assert.equal(start % LEAF, 0, 'aligned start');
      assert.ok(end > start);
      if (i > 0) assert.equal(start, plan[i - 1][1], 'contiguous');
      if (i < plan.length - 1) assert.equal((end - start) % LEAF, 0, 'whole leaves before the tail');
    }
  }
});

test('the number of segments never exceeds what minSegment allows', () => {
  assert.equal(segments(3 * MIN, LEAF, 8, MIN).length, 3);
  assert.equal(segments(64 * MIN, LEAF, 8, MIN).length, 8);
});
