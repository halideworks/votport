import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import vm from 'node:vm';

const source = (await readFile(new URL('../web/assets/hash-worker.js', import.meta.url), 'utf8'))
  .replace(/import init,\s*\{[\s\S]*?\} from '[^']+';/, '');

test('hash and parallel leaf reads reject short or empty file slices', async () => {
  for (const op of ['hash', 'leaves']) {
    for (const returned of [0, 1, 3, 4]) {
      const messages = [];
      let reads = 0;
      class ObjectBuilder {
        update() {}
        finish() { return { objectId: { suite: 1, root: 'root', length: 4n } }; }
      }
      const self = {};
      const context = vm.createContext({
        self, init: async () => {}, ObjectBuilder, PreparedObject: {},
        Suite: { Blake3Bao64: 1, Sha256Bep52: 2 },
        proofLeavesAt: () => new Uint8Array([1]),
        postMessage: (message) => messages.push(message), Uint8Array,
      });
      vm.runInContext(source, context);
      const file = { size: 4, slice() { return { async arrayBuffer() {
        if (++reads > 4) throw new Error('reader did not advance');
        return new Uint8Array(returned).buffer;
      } }; } };
      await self.onmessage({ data: { op, req: 1, key: 'file', file, start: 0, end: 4 } });
      if (returned === 4) {
        assert.equal(reads, 1);
        assert.ok(messages.at(-1).done);
      } else {
        assert.equal(reads, 1);
        assert.match(messages.at(-1).error, /File changed or could not be read completely/);
        assert.equal(messages.some((message) => message.done), false);
      }
    }
  }
});
