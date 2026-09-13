import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

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
  'fonts/LibreCaslonDisplay-400.woff2',
  'fonts/JetBrainsMono-400.woff2',
  'fonts/PlusJakartaSans-300.woff2',
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

test('the shared wasm stamp helper follows binary bytes and refuses incomplete output', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'votport-wasm-stamp-'));
  const vendor = join(directory, 'vendor output');
  const wasm = join(vendor, 'vot_wasm_bg.wasm');
  const loader = join(vendor, 'vot_wasm.js');
  const original = "const module = new URL('vot_wasm_bg.wasm', import.meta.url);\n";
  const helper = fileURLToPath(new URL('scripts/stamp-wasm.sh', root));
  const stamp = (env = process.env) => {
    const result = spawnSync('sh', [helper, vendor], { encoding: 'utf8', env });
    assert.ifError(result.error);
    return result;
  };
  try {
    await mkdir(vendor);
    await writeFile(loader, original);
    for (const bytes of [Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]), Buffer.from('changed wasm')]) {
      await writeFile(wasm, bytes);
      const result = stamp();
      assert.equal(result.status, 0, result.stderr);
      const expected = createHash('sha256').update(bytes).digest('hex').slice(0, 16);
      assert.equal(await readFile(loader, 'utf8'), original.replace('vot_wasm_bg.wasm', `vot_wasm_bg.wasm?v=${expected}`));
    }

    await writeFile(loader, 'export const missingReference = true;\n');
    assert.notEqual(stamp().status, 0, 'a missing wasm reference must fail');
    assert.equal(await readFile(loader, 'utf8'), 'export const missingReference = true;\n');
    await writeFile(loader, original);
    await rm(wasm);
    assert.notEqual(stamp().status, 0, 'a missing wasm binary must fail');
    assert.equal(await readFile(loader, 'utf8'), original);
    await writeFile(wasm, 'wasm');
    const bin = join(directory, 'bin');
    await mkdir(bin);
    for (const [output, status] of [['0123456789abcdef', 1], ['invalid', 0], ['abcdef', 0]]) {
      await writeFile(join(bin, 'sha256sum'), `#!/bin/sh\nprintf '%s\\n' '${output}'\nexit ${status}\n`);
      await chmod(join(bin, 'sha256sum'), 0o755);
      assert.notEqual(stamp({ ...process.env, PATH: `${bin}:${process.env.PATH}` }).status, 0, 'failed or invalid hashes must fail');
      assert.equal(await readFile(loader, 'utf8'), original);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
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
