// The sender's segment plan must follow the wasm's proof leaf size, not a
// copied literal. Pin both ends: the vendored export exists and keeps its
// value, and upload.js reads it after init instead of hardcoding bytes.
// VOTPORT PROPRIETARY LICENSE.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// The vendored wasm is a build artifact absent from fresh checkouts (CI's
// unit job runs before the image builds it); the pin runs wherever it exists.
const vendorUrl = new URL('../web/assets/vendor/vot_wasm_bg.wasm', import.meta.url);
if (!existsSync(vendorUrl)) {
  console.log('skipping: web/assets/vendor is not built (run scripts/build-wasm.sh)');
  process.exit(0);
}
// Node cannot fetch the wasm the way the browser does; answer the glue's
// fetch from disk so the real module and binary load here.
const bytes = readFileSync(vendorUrl);
const realFetch = globalThis.fetch;
globalThis.fetch = async () =>
  new Response(bytes, { headers: { 'content-type': 'application/wasm' } });
const { default: init, proofLeafSize } = await import(
  '../web/assets/vendor/vot_wasm.js'
);

test('the vendored wasm exports the proof leaf size the plan follows', async () => {
  await init();
  // Init is cached after the first call; the patch can go now.
  globalThis.fetch = realFetch;
  assert.equal(proofLeafSize(), 65536n);
});

test('the sender takes the leaf size from the wasm export, not a literal', () => {
  const source = readFileSync(
    new URL('../web/assets/upload.js', import.meta.url),
    'utf8',
  );
  assert.match(source, /proofLeafSize/);
  assert.match(source, /proofLeafBytes\s*=\s*Number\(proofLeafSize\(\)\)/);
  assert.doesNotMatch(source, /=\s*65536/);
});
