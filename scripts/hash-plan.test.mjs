import assert from 'node:assert/strict';
import { test } from 'node:test';

import { segments } from '../web/assets/hash-plan.js';

const LEAF = 65536;
const MIN = 16 * 1024 * 1024;

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

