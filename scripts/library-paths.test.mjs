import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseLibraryPath } from '../web/assets/library-paths.js';

test('parses only safe relative paths', () => {
  assert.deepEqual(parseLibraryPath('client/alex/report.pdf'), ['client', 'alex', 'report.pdf']);
  for (const path of ['', '/absolute/file', 'client\\file', 'client//file', './file', '../file']) {
    assert.equal(parseLibraryPath(path), null);
  }
});
