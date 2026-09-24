import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

// The verify page must decide in-tab: the receipt sidecar's Ed25519 signature
// is checked here against the key fetched from /api/receipt-key, and a
// payload only passes when its locally hashed root equals the signed root.
// A server answer (the old POST /api/verify) must never be the verdict.
const verifyScript = await readFile(new URL('../web/assets/verify.js', import.meta.url), 'utf8');

test('the verify verdict needs the signature and the locally hashed root, never a server answer', () => {
  assert.match(verifyScript, /const signedRoot = toHex\(subject\.root\);/);
  assert.match(verifyScript, /const match = subject\.suite === done\.suite && signedRoot === root && signedLength === length;/);
  assert.match(verifyScript, /title: match \? 'Verified' : 'Does not match'/);
  // The old flow took its verdict from POST /api/verify; that must not return.
  assert.doesNotMatch(verifyScript, /\/api\/verify/);
});

