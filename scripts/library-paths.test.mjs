import assert from 'node:assert/strict';
import { test } from 'node:test';
import { projectDirectoryPrefixes } from '../web/assets/library-paths.js';

test('derives nested directory prefixes', () => {
  assert.deepEqual(
    projectDirectoryPrefixes([{ path: 'client/alex/report.pdf' }]),
    ['client', 'client/alex'],
  );
});

test('deduplicates and sorts directory prefixes', () => {
  assert.deepEqual(
    projectDirectoryPrefixes([
      { path: 'z/file.txt' },
      { path: 'a/b/file.txt' },
      { path: 'a/c/file.txt' },
      { path: 'a/b/other.txt' },
    ]),
    ['a', 'a/b', 'a/c', 'z'],
  );
});

test('skips unsafe path components', () => {
  assert.deepEqual(
    projectDirectoryPrefixes([
      { path: '../escape/file.txt' },
      { path: 'project/../escape/file.txt' },
      { path: 'project/./escape/file.txt' },
      { path: 'project\\escape\\file.txt' },
      { path: '/absolute/file.txt' },
      { path: 'safe/file.txt' },
    ]),
    ['safe'],
  );
});
