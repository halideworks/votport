import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

import { deleteStoredFiles } from '../web/assets/delete-stored-files.js';

const receive = await readFile(new URL('../web/assets/page-receive.js', import.meta.url), 'utf8');

// Two pages of two files; `exists` files get deleted, the rest are skipped.
function page(next_offset, exists = true) {
  return {
    file_count: 4,
    next_offset,
    files: [
      { file_index: 0, exists },
      { file_index: 1, exists },
    ],
  };
}

test('pages through the file list, deletes stored files, and reports progress', async () => {
  const deleted = [];
  const progress = [];
  const pages = [page(100), page(null)];
  const result = await deleteStoredFiles({
    upload: { file_count: 4 },
    fetchPage: (offset) => {
      assert.equal(offset, deleted.length < 2 ? 0 : 100);
      return pages.shift();
    },
    deleteFile: (index) => deleted.push(index),
    onProgress: (done, total) => progress.push([done, total]),
  });
  assert.deepEqual(deleted, [0, 1, 0, 1]);
  assert.deepEqual(progress, [[1, 4], [2, 4], [3, 4], [4, 4]]);
  assert.deepEqual(result, { stopped: false, done: 4 });
});

test('a stop request halts between requests and reports the count', async () => {
  let stop = false;
  const deleted = [];
  // A first page with a follow-up, then the end of the list, so a mutant
  // that ignores the stop runs to completion instead of looping forever.
  const pages = [page(100), page(null)];
  const result = await deleteStoredFiles({
    upload: { file_count: 4 },
    fetchPage: () => pages.shift() ?? page(null),
    deleteFile: (index) => {
      deleted.push(index);
      stop = true;
    },
    shouldStop: () => stop,
  });
  // The in-flight DELETE completes; nothing else runs.
  assert.deepEqual(deleted, [0]);
  assert.deepEqual(result, { stopped: true, done: 1 });
});

test('a changed file count refuses to delete', async () => {
  await assert.rejects(
    deleteStoredFiles({
      upload: { file_count: 5 },
      fetchPage: () => page(null),
      deleteFile: () => assert.fail('must not delete'),
    }),
    /Transfer history changed/,
  );
});

