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
// 455: the pause or revoke control speaks of "Transfers already under way"
// with plain choices and a discard hint, never "admitted".
// 456: operator copy avoids "custody evidence", "custody ancestry" and
// "allowlist"; route evidence and accepted metadata fields instead.
// 457: reserved-name refusals stay plain on both ends and never name server
// internals (tenant storage, instance lease, staging files).
// 458: uploader failures speak to the sender, never about proofs and ranges.
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

test('pause or revoke control offers plain choices for transfers under way (455)', async () => {
  const page = await read('../web/assets/page-trade-routes.js');
  assert.match(page, /field\('Transfers already under way', active\)/);
  assert.match(page, /\['finish', 'Let them finish'\]/);
  assert.match(page, /\['cancel', 'Cancel them'\]/);
  assert.match(page, /Cancelling discards transfers that have not finished; no partial data is published\./);
  assert.doesNotMatch(page, /admitted/i, 'the admitted wording survives');
});

test('operator copy avoids custody and allowlist jargon (456)', async () => {
  const receive = await read('../web/assets/page-receive.js');
  const workflows = await read('../web/assets/page-workflows.js');
  assert.match(receive, /Could not load route evidence/);
  assert.doesNotMatch(receive, /custody evidence/i);
  assert.match(workflows, /Download route evidence/);
  assert.doesNotMatch(workflows, /custody evidence/i);
  const routes = await read('../server/src/api/outbound/workflows/routes.rs');
  assert.match(routes, /accepted metadata fields are missing; submit a new delivery/);
  assert.match(routes, /a receipt from an earlier port carries metadata fields this route does not accept; forwarding held/);
  assert.doesNotMatch(routes, /custody ancestry|allowlist/, 'custody and allowlist jargon survives in route copy');
  const trade = await read('../server/src/store/trade.rs');
  assert.match(trade, /invalid endpoint name, category or accepted metadata fields/);
  assert.doesNotMatch(trade, /metadata allowlist/);
});

test('reserved-name refusals stay plain on both ends (457)', async () => {
  const paths = await read('../protocol/paths.rs');
  assert.match(paths, /name is reserved for the port's own files/);
  assert.doesNotMatch(
    paths,
    /reserved for tenant storage|reserved for the instance lease|reserved for votport staging files/,
    'a refusal still names server internals',
  );
  const upload = await read('../web/assets/upload.js');
  assert.match(upload, /this name is reserved for the port's own files/);
  assert.doesNotMatch(upload, /reserved for the server/);
});

test('uploader failures speak to the sender, not about proofs and ranges (458)', async () => {
  const upload = await read('../web/assets/upload.js');
  assert.match(upload, /failed an upload check; retry the upload/);
  assert.doesNotMatch(upload, /unexpected range/, 'the internal range wording survives');
});

test('504: the browser refuses the same reserved list before hashing', async () => {
  const upload = await read('../web/assets/upload.js');
  // protocol/paths.rs folds the component to lowercase once and matches
  // the reserved shapes against that (finding 542); the sender mirrors the
  // list so the refusal costs nothing hashed (finding 543).
  assert.ok(upload.includes('/^\\.votport-(lease|workflows)$/.test(lower)'), 'lease and workflows');
  assert.ok(upload.includes('/^\\.vot-stage$/.test(lower)'), 'vot-stage');
  assert.ok(upload.includes('/^\\.vot-tenants\\.stage$/.test(lower)'), 'tenant storage');
  assert.ok(
    upload.includes('/^\\.vot-push-[0-9a-f]{32}$/.test(lower)'),
    'push staging',
  );
  assert.ok(
    upload.includes('/^\\.vot-.*\\.(stage|journal)$/.test(lower)'),
    'staging suffixes',
  );
  // The fold happens once, before the reserved matches.
  assert.ok(upload.includes('const lower = component.toLowerCase()'), 'lowercase once');
});
