import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  buildLibraryTree,
  filterLibraryFiles,
  libraryFilesIn,
  libraryTreeNode,
  parseLibraryPath,
  projectDirectoryPrefixes,
  selectedLibraryStats,
  toggleFolderSelection,
} from '../web/assets/library-paths.js';

test('parses only safe relative paths', () => {
  assert.deepEqual(parseLibraryPath('client/alex/report.pdf'), ['client', 'alex', 'report.pdf']);
  for (const path of ['', '/absolute/file', 'client\\file', 'client//file', './file', '../file']) {
    assert.equal(parseLibraryPath(path), null);
  }
});

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

test('builds immediate child folders and finds their files recursively', () => {
  const files = [
    { path: 'project/root.txt', bytes: 1 },
    { path: 'project/render/a.txt', bytes: 2 },
    { path: 'project/render/deep/b.txt', bytes: 3 },
  ];
  const tree = buildLibraryTree(files);
  const project = libraryTreeNode(tree, 'project');
  assert.deepEqual([...tree.children.keys()], ['project']);
  assert.deepEqual([...project.children.keys()], ['render']);
  assert.deepEqual(libraryFilesIn(project).map((file) => file.path), [
    'project/root.txt',
    'project/render/a.txt',
    'project/render/deep/b.txt',
  ]);
});

test('filters matching files without changing the source list', () => {
  const files = [{ path: 'a/report.pdf' }, { path: 'b/photo.jpg' }];
  assert.deepEqual(filterLibraryFiles(files, 'REPORT'), [{ path: 'a/report.pdf' }]);
  assert.deepEqual(files, [{ path: 'a/report.pdf' }, { path: 'b/photo.jpg' }]);
});

test('selects and deselects a folder recursively without exceeding the limit', () => {
  const paths = ['project/a.txt', 'project/nested/b.txt'];
  const selected = toggleFolderSelection(new Set(), paths);
  assert.deepEqual([...selected], paths);
  assert.deepEqual([...toggleFolderSelection(selected, paths)], []);
  assert.equal(toggleFolderSelection(new Set(['other.txt']), paths, 2), null);
});

test('counts selected files and bytes', () => {
  assert.deepEqual(
    selectedLibraryStats(
      [{ path: 'a', bytes: 4 }, { path: 'b', bytes: 6 }],
      new Set(['b']),
    ),
    { count: 1, bytes: 6 },
  );
});
