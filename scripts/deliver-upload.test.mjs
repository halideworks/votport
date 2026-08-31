import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { entryFiles, runUploadBatch } from '../web/assets/upload-entries.js';

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
  assert.match(deliverScript, /document\.addEventListener\('drop'/);
  assert.match(deliverScript, /carriesFiles\(event\)/);
  assert.match(deliverScript, /item\.getAsEntry\?\.\(\) \|\| item\.webkitGetAsEntry\?\.\(\)/);
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
  assert.match(deliverScript, /runUploadBatch\(/);
  assert.match(deliverScript, /uploadLibraryFile\(file, path, progress\)/);
  assert.match(deliverScript, /Uploading \$\{file\.name\}: \$\{percent\}%/);
  assert.match(deliverScript, /files complete/);
  assert.match(deliverScript, /if \(completedUploads > 0\) \{\s+await refreshLibrary\(\)/);
  assert.match(deliverScript, /\$\{error\.message\} \$\{completedUploads\} of \$\{uploads\.length\} files added\./);
  assert.match(deliverScript, /await refreshLibrary\(\);\s+\$\('library-status'\)\.textContent = `\$\{uploads\.length\}/);
});

test('upload batches cap concurrency and wait for running work after failure', async () => {
  const deferred = new Map();
  for (const item of [0, 2, 3, 4, 5, 6, 7]) {
    let resolve;
    const promise = new Promise((finish) => { resolve = finish; });
    deferred.set(item, { promise, resolve });
  }
  let active = 0;
  let maximum = 0;
  const started = [];
  const batch = runUploadBatch([...Array(12).keys()], async (item) => {
    started.push(item);
    active += 1;
    maximum = Math.max(maximum, active);
    if (item === 1) {
      active -= 1;
      throw undefined;
    }
    await deferred.get(item).promise;
    active -= 1;
  });
  let settled = false;
  const result = batch.catch((error) => {
    settled = true;
    throw error;
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(started, [0, 1, 2, 3, 4, 5, 6, 7]);
  assert.ok(maximum <= 8);
  assert.equal(active, 7);
  assert.equal(settled, false);
  for (const { resolve } of deferred.values()) resolve();
  await assert.rejects(result, (error) => error === undefined);
  assert.equal(active, 0);
});
