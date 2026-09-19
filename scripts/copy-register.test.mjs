// Copy register regression tests (audit items 447, 448, 449, 450, 451, 452,
// 453, 454).
// 447: em and en dashes are banned from public text; unknown stats read
// "not measured" instead of a dash glyph.
// 448: attestation checkboxes speak in the first person.
// 449: the Tenants page uses the same plain register as the rest of the UI.
// 450: confirms state outcomes, not key-separator implementation details.
// 451: one spelling, "acknowledgement", across web and server copy.
// 452: one expiry term, "Expires after", on every surface.
// 453: the VOT fetch block stays a plain purpose sentence plus limitation.
// 454: the 64-character hash reads "Delivery fingerprint", with an
// explanation, never "Manifest".
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

test('one spelling: acknowledgement (451)', async () => {
  for (const file of [
    '../web/workflows.html',
    '../web/assets/page-workflows.js',
    '../server/src/api/admin.rs',
  ]) {
    const source = (await read(file)).replace(/stable_acknowledgments/g, '');
    assert.doesNotMatch(source, /acknowledgment/i, `${file} still uses the acknowledgment spelling`);
  }
  const script = await read('../web/assets/page-workflows.js');
  assert.match(script, /Revocation awaiting destination acknowledgement\./);
  assert.match(script, /recipient acknowledgements/);
});

test('one expiry term: Expires after (452)', async () => {
  const workflows = await read('../web/workflows.html');
  assert.match(workflows, /<label>Expires after \(days\)</);
  assert.doesNotMatch(workflows, /Link expires after|Closes after|Invitation expiry/);
  for (const file of [
    '../web/receive.html',
    '../web/deliver.html',
    '../web/automation.html',
  ]) {
    const page = await read(file);
    assert.match(page, /Expires after/, `${file} drops the shared expiry term`);
    assert.doesNotMatch(page, /Closes after|Invitation expiry|Link expires/);
  }
  const linksPage = await read('../client/windows/Votport/LinksPage.xaml');
  assert.match(linksPage, /Expires after \(days\)/);
  assert.doesNotMatch(linksPage, /Closes after/);
  const links = await read('../client/macos/Votport/LinksView.swift');
  assert.match(links, /NumberField\("Expires after"/);
  assert.doesNotMatch(links, /Closes after/);
  const trade = await read('../web/assets/page-trade-routes.js');
  assert.match(trade, /field\('Expires after', expiry\)/);
  assert.doesNotMatch(trade, /Invitation expiry/);
});

test('VOT fetch block reads as purpose plus a plain limitation (453)', async () => {
  const send = await read('../web/send.html');
  const block = send.match(/<details id="vot-fetch"[\s\S]*?<\/details>/)[0];
  assert.match(block, /<summary>Fetch with the VOT client<\/summary>/);
  assert.match(block, /Faster on long or lossy links/);
  assert.match(block, /cannot be opened as regular files yet/);
  assert.doesNotMatch(
    block,
    /key pair|mint a one-hour|bundle directory|objects by root|package receipt/,
    'the fetch copy still leans on unexplained terms',
  );
});

test('the 64-character hash reads Delivery fingerprint, with an explanation (454)', async () => {
  const evidence = await read('../web/assets/delivery-evidence.js');
  assert.match(evidence, /`Delivery fingerprint \$\{record\.evidence\.authorization\.challenge\.manifest\}`/);
  assert.match(evidence, /64-character hash of the exact files/);
  assert.match(evidence, /Signed delivery fingerprint/);
  assert.doesNotMatch(evidence, /textContent = `Manifest |very large manifest/);
  const script = await read('../web/assets/page-workflows.js');
  assert.match(script, /`Delivery fingerprint: \$\{job\.manifest\}`/);
  assert.match(script, /with delivery fingerprint \$\{job\.manifest\} \(a 64-character hash of the files\)\?/);
  assert.doesNotMatch(script, /`Manifest: |with manifest /);
  const swift = await read('../client/macos/Votport/WorkflowsView.swift');
  assert.match(swift, /Delivery fingerprint: \\\(manifest\)/);
  assert.match(swift, /Delivery fingerprint: \\\(record\.manifest\)/);
  assert.match(swift, /Approve this delivery/);
  assert.match(swift, /Confirm you reviewed the files and \\\(action\.action\) this delivery \(fingerprint/);
  assert.doesNotMatch(swift, /Manifest:|Approve this manifest|\(action\.action\) manifest/);
});
