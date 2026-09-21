import assert from 'node:assert/strict';
import { test } from 'node:test';
import { expandBeginEntries } from '../web/assets/upload-entries.js';

test('a compact begin reply fills absent entries with admitted-as-requested defaults', () => {
  const entries = expandBeginEntries({
    total: 3,
    entries: [{ index: 1, stored_as: 'beta-1.bin' }, { index: 2, complete: true }],
  }, 3);
  assert.equal(entries.length, 3);
  assert.deepEqual(entries[0], { index: 0, complete: false, covered_bytes: 0 });
  assert.equal(entries[1].stored_as, 'beta-1.bin');
  assert.equal(entries[1].complete, false);
  assert.equal(entries[2].complete, true);
});

test('a compact begin reply sizes itself from the total, not the exception list', () => {
  const entries = expandBeginEntries({ total: 20000, entries: [] }, 20000);
  assert.equal(entries.length, 20000);
  assert.equal(entries.at(-1).index, 19999);
});

test('a dense legacy begin reply (no total) passes through unchanged', () => {
  const reply = {
    entries: [
      { index: 0, path: 'alpha.bin', stored_as: 'alpha.bin', bytes: 7, complete: true, covered_bytes: 7 },
      { index: 1, path: 'beta.bin', stored_as: 'beta.bin', bytes: 7, complete: false, covered_bytes: 4096 },
    ],
  };
  const entries = expandBeginEntries(reply, 2);
  assert.equal(entries.length, 2);
  assert.equal(entries[0].complete, true);
  assert.equal(entries[0].covered_bytes, 7);
  assert.equal(entries[1].covered_bytes, 4096);
  assert.equal(entries[1].path, 'beta.bin');
});
