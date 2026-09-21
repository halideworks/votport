import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

const receive = await readFile(new URL('../web/receive.html', import.meta.url), 'utf8');
const receiveScript = await readFile(new URL('../web/assets/page-receive.js', import.meta.url), 'utf8');

test('the request form offers the three verification levels with a hint', () => {
  assert.match(receive, /id="create-verification"/);
  assert.match(
    receive,
    /<select data-draft-field id="create-verification">[\s\S]*?<option value="default">Automatic<\/option>[\s\S]*?<option value="balanced">Balanced rehash<\/option>[\s\S]*?<option value="strict">Strict rehash<\/option>[\s\S]*?<\/select>/,
  );
  // The hint names the constraint the server enforces: strict is refused
  // for network storage destinations.
  assert.match(receive, /strict needs local storage/);
});

test('creating a request sends the chosen verification level', () => {
  assert.match(
    receiveScript,
    /retention_days: Number\.isFinite\(retention\) \? retention : null,\s*verification: \$\('create-verification'\)\.value,/,
  );
});

test('created and listed requests show the verification level', () => {
  assert.match(receiveScript, /verificationNames = \{ default: 'Automatic', balanced: 'Balanced rehash', strict: 'Strict rehash' \}/);
  // The created card names the level even when it is Automatic.
  assert.match(receiveScript, /Verification: \$\{verificationNames\[link\.verification\] \|\| verificationNames\.default\}/);
  // Listed cards flag only the levels that deviate from Automatic.
  assert.match(receiveScript, /link\.verification !== 'default'/);
});

test('a refused level renders as the form error, not a silent downgrade', () => {
  // The submit handler already routes api errors into #create-error; assert
  // the refusal path stays wired there.
  assert.match(receiveScript, /createError\.show\(error\.message\)/);
});
