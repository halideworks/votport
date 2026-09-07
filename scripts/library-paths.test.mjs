import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseLibraryPath, retainLibraryProjectSuggestions } from '../web/assets/library-paths.js';

test('parses only safe relative paths', () => {
  assert.deepEqual(parseLibraryPath('client/alex/report.pdf'), ['client', 'alex', 'report.pdf']);
  for (const path of ['', '/absolute/file', 'client\\file', 'client//file', './file', '../file']) {
    assert.equal(parseLibraryPath(path), null);
  }
});

test('project suggestions retain the current path within the cap', () => {
  const suggestions = new Set(['old-1', 'old-2']);
  const directories = Array.from({ length: 201 }, (_, index) => `new-${index}`);
  retainLibraryProjectSuggestions(suggestions, directories, 'old-1', 200);
  assert.equal(suggestions.size, 200);
  assert.ok(suggestions.has('old-1'));
  assert.ok(!suggestions.has('old-2'));
});

test('project suggestions preserve small lists without an empty current path', () => {
  const suggestions = new Set(['first', 'second']);
  retainLibraryProjectSuggestions(suggestions, ['third'], '', 200);
  assert.deepEqual([...suggestions], ['first', 'second', 'third']);
  assert.ok(!suggestions.has(''));
});
