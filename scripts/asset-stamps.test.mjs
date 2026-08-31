import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

// Stamped asset URLs (?v=<first 16 hex of sha256>) are served immutable by
// the server, so a stale stamp means browsers keep an old font or image
// forever. The assertion messages carry the expected value; paste it in.

const root = new URL('../', import.meta.url);

const referencingFiles = [
  'web/assets/fonts.css',
  'web/assets/style.css',
  'web/audit.html',
  'web/deliver.html',
  'web/index.html',
  'web/receive.html',
  'web/request.html',
  'web/send.html',
  'web/system.html',
  'web/tenants.html',
  'web/verify.html',
];

const mustBeStamped = [
  'fonts/InstrumentSerif-400-italic.woff2',
  'fonts/InstrumentSerif-400.woff2',
  'fonts/JetBrainsMono-400.woff2',
  'fonts/JetBrainsMono-500.woff2',
  'fonts/PlusJakartaSans-300.woff2',
  'fonts/PlusJakartaSans-400.woff2',
  'fonts/PlusJakartaSans-500.woff2',
  'fonts/PlusJakartaSans-600.woff2',
  'fonts/PlusJakartaSans-700.woff2',
  'pommern_painting.jpg',
  'pommern_ship_white.png',
];

async function hash16(path) {
  const bytes = await readFile(new URL(path, root));
  return createHash('sha256').update(bytes).digest('hex').slice(0, 16);
}

test('every ?v= stamp matches the content of the asset it references', async () => {
  const stamped = new Set();
  for (const file of referencingFiles) {
    const text = await readFile(new URL(file, root), 'utf8');
    for (const [, asset, stamp] of text.matchAll(/\/assets\/([\w./-]+)\?v=([0-9a-f]{16})/g)) {
      stamped.add(asset);
      assert.equal(stamp, await hash16(`web/assets/${asset}`), `stale stamp for /assets/${asset} in ${file}`);
    }
  }
  for (const asset of mustBeStamped) {
    assert.ok(stamped.has(asset), `/assets/${asset} lost its ?v= stamp`);
  }
});

test('the built wasm loader stamps its wasm binary', async (t) => {
  if (!existsSync(new URL('web/assets/vendor/vot_wasm.js', root))) {
    t.skip('web/assets/vendor not built');
    return;
  }
  const loader = await readFile(new URL('web/assets/vendor/vot_wasm.js', root), 'utf8');
  const match = loader.match(/vot_wasm_bg\.wasm\?v=([0-9a-f]{16})/);
  assert.ok(match, 'vot_wasm.js has no ?v= stamp; rerun scripts/build-wasm.sh');
  assert.equal(match[1], await hash16('web/assets/vendor/vot_wasm_bg.wasm'), 'stale wasm stamp; rerun scripts/build-wasm.sh');
});
