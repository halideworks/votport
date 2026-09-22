import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';

test('hash worker selects the receipt suite while uploads retain the default', async () => {
  const source = await readFile(new URL('../web/assets/hash-worker.js', import.meta.url), 'utf8');
  const built = [];
  const replies = [];
  const self = {};
  runInNewContext(source.slice(source.indexOf('const HASH_READ_BYTES')), {
    self, init: async () => {}, postMessage: (reply) => replies.push(reply),
    Suite: { Blake3Bao64: 0, Sha256Bep52: 1 },
    ObjectBuilder: class {
      constructor(suite) { built.push(suite); }
      finish() { return { objectId: { suite: built.at(-1), root: new Uint8Array(32), length: 0n } }; }
    },
  });
  for (const suite of [undefined, 0, 1, 'unknown']) {
    await self.onmessage({ data: { op: 'hash', req: 1, key: 'file', file: { size: 0 }, suite } });
  }
  assert.deepEqual(built, [0, 0, 1]);
  assert.equal(replies.length, 4);
  assert.equal(replies[2].done.suite, 1);
  assert.match(replies[3].error, /unsupported hash suite/);
});
