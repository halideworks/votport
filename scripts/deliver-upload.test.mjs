import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { entryFiles } from '../web/assets/upload-entries.js';

const deliver = await readFile(new URL('../web/deliver.html', import.meta.url), 'utf8');
const deliverScript = await readFile(new URL('../web/assets/page-deliver.js', import.meta.url), 'utf8');

test('Deliver exposes file and folder pickers with an accessible drop zone', () => {
  assert.match(deliver, /id="library-drop" class="drop" role="group"/);
  assert.doesNotMatch(deliver, /id="library-drop"[^>]+(?:tabindex|role="button")/);
  assert.match(deliver, /aria-label="Add files or a folder to the library"/);
  assert.match(deliver, /id="library-add-files"[^>]*>files<\/button>/);
  assert.match(deliver, /id="library-add-folder"[^>]*>a folder<\/button>/);
  assert.match(deliver, /id="library-folder-input" type="file" webkitdirectory[^>]*hidden/);
  assert.doesNotMatch(deliverScript, /libraryDrop\.addEventListener\('keydown'/);
  assert.match(deliverScript, /libraryDrop\.addEventListener\('drop'/);
  assert.match(deliverScript, /libraryDrop\.setAttribute\('aria-busy', 'true'\)/);
  assert.match(deliverScript, /An upload is already in progress\./);
});

test('dropped entries drain directory readers and preserve relative paths', async () => {
  const file = (path) => ({
    isFile: true,
    fullPath: `/${path}`,
    file(resolve) { resolve({ name: path.split('/').pop() }); },
  });
  const children = [file('project/a.txt'), file('project/nested/b.txt')];
  let readCount = 0;
  const directory = {
    isDirectory: true,
    createReader: () => ({
      readEntries(resolve) {
        resolve(readCount++ === 0 ? children : []);
      },
    }),
  };
  assert.deepEqual(
    (await entryFiles(directory)).map(({ path }) => path),
    ['project/a.txt', 'project/nested/b.txt'],
  );
  assert.match(deliverScript, /file\.webkitRelativePath \|\| file\.name/);
  assert.match(deliverScript, /project \? `\$\{project\}\/\$\{relative\}` : relative/);
  assert.match(deliverScript, /entryFiles\)\)\)\.flat\(\)/);
});

test('one upload batch validates paths and reports per-file progress', () => {
  assert.match(deliverScript, /async function uploadLibraryFiles\(pairs\)/);
  assert.match(deliverScript, /parseLibraryPath\(path\)/);
  assert.match(deliverScript, /await uploadLibraryFile\(file, path, \(offset\)/);
  assert.match(deliverScript, /Uploading \$\{file\.name\}: \$\{percent\}%/);
  assert.match(deliverScript, /await refreshLibrary\(\)/);
});
