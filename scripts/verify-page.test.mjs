import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

// The verify page must decide in-tab: the receipt sidecar's Ed25519 signature
// is checked here against the key fetched from /api/receipt-key, and a
// payload only passes when its locally hashed root equals the signed root.
// A server answer (the old POST /api/verify) must never be the verdict.
const verifyScript = await readFile(new URL('../web/assets/verify.js', import.meta.url), 'utf8');

test('the verify page verifies the receipt signature in-tab with the vendored wasm', () => {
  assert.match(
    verifyScript,
    /import init, \{\s*ErrorCode,\s*SubjectKind,\s*verifyReceiptEd25519,\s*\} from '\/assets\/vendor\/vot_wasm\.js';/,
  );
  assert.match(verifyScript, /wasmReady \?\?= init\(\);/);
  assert.match(
    verifyScript,
    /receipt = verifyReceiptEd25519\(\s*new Uint8Array\(await sidecarFile\.arrayBuffer\(\)\),\s*key,\s*\);/,
  );
});

test('the verify verdict needs the signature and the locally hashed root, never a server answer', () => {
  assert.match(verifyScript, /const signedRoot = toHex\(subject\.root\);/);
  assert.match(verifyScript, /const match = subject\.suite === done\.suite && signedRoot === root && signedLength === length;/);
  assert.match(verifyScript, /title: match \? 'Verified' : 'Does not match'/);
  // The old flow took its verdict from POST /api/verify; that must not return.
  assert.doesNotMatch(verifyScript, /\/api\/verify/);
});

test('signature failure, key fetch failure and root mismatch each get their own message', () => {
  assert.match(verifyScript, /This is not a vot-receipt\./);
  assert.match(
    verifyScript,
    /This receipt was not signed by the receipt key this port publishes\./,
  );
  assert.match(
    verifyScript,
    /This port’s receipt key is unavailable\. Reload the page and try again\./,
  );
  assert.match(verifyScript, /This file is not the object in the receipt\./);
});

test('the result card renders the receipt authoritative observed_at labelled UTC', () => {
  // Audit finding 404: the receipt carries the one authoritative timestamp
  // and the wasm receipt exposes it, but the page never showed it.
  assert.match(verifyScript, /observedAt: receipt\.observedAt/);
  assert.match(verifyScript, /\$\('verify-observed'\)/);
  assert.match(verifyScript, /Observed \$\{observedAt\} \(UTC\)/);
  assert.match(verifyScript, /observed\.hidden = !observedAt;/);
});
