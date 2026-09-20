// Regression pins for the search debounce floor: a keystroke fires one run
// ~60ms after the last key, every keystroke restarts that wait and drops
// the pending run, and cancel retires it without firing. The three call
// sites (library, global header, tenant principals) are pinned by source
// shape, the way deliver-upload.test.mjs does.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

import { searchDebounce } from '../web/assets/search-debounce.js';

const read = async (path) => readFile(new URL(`../${path}`, import.meta.url), 'utf8');
const deliverScript = await read('web/assets/page-deliver.js');
const tenantsScript = await read('web/assets/page-tenants.js');
const commonScript = await read('web/assets/admin-common.js');

test('a keystroke fires one run ~60ms after the last key', (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let runs = 0;
  const schedule = searchDebounce(60, () => { runs += 1; });
  schedule();
  t.mock.timers.tick(50);
  assert.equal(runs, 0);
  t.mock.timers.tick(20);
  assert.equal(runs, 1);
});

test('every keystroke restarts the wait and drops the pending run', (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let runs = 0;
  const schedule = searchDebounce(60, () => { runs += 1; });
  schedule();
  t.mock.timers.tick(50);
  schedule();
  t.mock.timers.tick(50);
  assert.equal(runs, 0);
  t.mock.timers.tick(20);
  assert.equal(runs, 1);
});

test('cancel retires a pending run without firing it', (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let runs = 0;
  const schedule = searchDebounce(60, () => { runs += 1; });
  schedule();
  schedule.cancel();
  t.mock.timers.tick(1_000);
  assert.equal(runs, 0);
});

test('library search schedules at the reduced floor and cancels on browse', () => {
  assert.match(deliverScript, /const scheduleLibrarySearch = searchDebounce\(60, \(\) => refreshLibrary\(\)\);/);
  assert.match(deliverScript, /scheduleLibrarySearch\(\);/);
  assert.match(deliverScript, /async function browseLibrary\(directory\) \{\s*\n\s*scheduleLibrarySearch\.cancel\(\);/);
  // Keystrokes still retire in-flight library requests.
  assert.match(
    deliverScript,
    /library-search'\)\.addEventListener\('input', \(\) => \{\s*\n\s*libraryRequestGeneration \+= 1;/,
  );
});

test('the global header search schedules at the reduced floor', () => {
  assert.match(commonScript, /const scheduleSearch = searchDebounce\(60, run\);/);
  assert.match(commonScript, /scheduleSearch\(\);/);
  // Closing the panel still retires the pending run with the request ticket.
  assert.match(commonScript, /const close = \(\) => \{\s*\n\s*scheduleSearch\.cancel\(\);\s*\n\s*latest \+= 1;/);
});

test('tenant principal search schedules at the reduced floor and skips stale replies', () => {
  assert.match(tenantsScript, /searchDebounce\(60, \(\) =>\s*\n\s*refreshPrincipals\(true\)/);
  // Keystrokes retire any principal request in flight; its response must
  // not paint rows for a query that is already gone.
  assert.match(
    tenantsScript,
    /principal-search'\)\.addEventListener\('input', \(\) => \{[\s\S]{0,200}?principalRequestGeneration \+= 1;/,
  );
  assert.match(tenantsScript, /if \(generation !== principalRequestGeneration\) return;/);
});
