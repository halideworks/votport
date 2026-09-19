// Copy register regression tests (audit items 447, 448, 449, 450).
// 447: em and en dashes are banned from public text; unknown stats read
// "not measured" instead of a dash glyph.
// 448: attestation checkboxes speak in the first person.
// 449: the Tenants page uses the same plain register as the rest of the UI.
// 450: confirms state outcomes, not key-separator implementation details.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const read = (p) => readFile(new URL(p, import.meta.url), 'utf8');

test('public page text contains no em or en dashes (447)', async () => {
  for (const file of [
    '../web/verify.html',
    '../web/deliver.html',
    '../web/receive.html',
    '../web/assets/verify.js',
    '../web/assets/page-receive.js',
    '../web/assets/page-deliver.js',
  ]) {
    const source = await read(file);
    const text = source
      .split('\n')
      .filter((line) => !/^\s*\/\//.test(line))
      .join('\n');
    assert.doesNotMatch(text, /—|–|&mdash;|&ndash;/, `${file} uses a dash in public text`);
  }
});

test('unknown stats read "not measured" instead of a dash glyph (447)', async () => {
  const receive = await read('../web/assets/page-receive.js');
  assert.match(receive, /summary\.duration === null \? 'not measured'/);
  assert.match(receive, /summary\.average === null \? 'not measured'/);
  assert.match(receive, /today \? String\(today\.uploads\) : 'not measured'/);
  assert.match(receive, /stored \? formatBytes\(stored\.bytes\) : 'not measured'/);
  assert.match(receive, /status\.disk \? formatBytes\(status\.disk\.free_bytes\) : 'not measured'/);
  const deliver = await read('../web/assets/page-deliver.js');
  assert.match(deliver, /active === null \? 'not measured'/);
  assert.match(deliver, /outbound\.open_grants \?\? 'not measured'/);
  assert.match(deliver, /outbound\.deliveries \?\? 'not measured'/);
  assert.match(deliver, /outbound\.disk \? formatBytes\(outbound\.disk\.free_bytes\) : 'not measured'/);
  assert.doesNotMatch(await read('../web/receive.html'), /&ndash;/);
  assert.doesNotMatch(await read('../web/deliver.html'), /&ndash;/);
});

test('attestation checkboxes speak in the first person (448)', async () => {
  const storage = await read('../web/storage.html');
  assert.match(storage, /I confirm that the server keeps acknowledged writes/);
  assert.match(storage, /I confirm that server permissions make/);
  const trade = await read('../web/trade-routes.html');
  assert.match(trade, /id="trade-confirm"[^>]*\/> I recognize this destination/);
});

test('tenants page uses plain register, no colloquialisms (449)', async () => {
  const page = await read('../web/tenants.html');
  const script = await read('../web/assets/page-tenants.js');
  assert.match(page, /Revoke ends current sessions and refuses/);
  assert.match(script, /They can sign in with SSO again\. Open sessions end\./);
  assert.match(script, /Ends current sessions and refuses SSO until unblocked; remove the IdP group for a lasting revoke\./);
  for (const source of [page, script]) {
    assert.doesNotMatch(source, /\bkicks\b|stay dead|make it stick/i, 'colloquial copy survives');
  }
});

test('delete-tenant confirm states the outcome, not key-separator internals (450)', async () => {
  const script = await read('../web/assets/page-tenants.js');
  assert.match(
    script,
    /`Delete "\$\{tenant\.key\}"\? Refused while its links still exist\. No files are deleted\.`/,
  );
  assert.doesNotMatch(script, /separator/);
});
