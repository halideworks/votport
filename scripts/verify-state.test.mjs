import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';

test('receipt checks retain selection, bound input and match the signed suite', { timeout: 2000 }, async () => {
  const source = await readFile(new URL('../web/assets/verify.js', import.meta.url), 'utf8');
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, {
      hidden: false, disabled: false, value: '',
      classList: { add() {}, remove() {}, toggle() {} },
      querySelectorAll: () => [element('pick-payload'), element('check')],
      replaceChildren() {},
    });
    return elements.get(id);
  };
  let releaseRead;
  let reads = 0;
  let displayed;
  let subjectKind = 0;
  let hashedSuite = 1;
  const receipt = { name: 'original.vot-receipt', size: 65536, arrayBuffer: async () => {
    reads += 1;
    return new Promise((resolve) => { releaseRead = resolve; });
  } };
  const payload = { name: 'original.txt', size: 1 };
  const controller = runInNewContext(`${source.slice(source.indexOf('let payloadFile'), source.indexOf("$('pick-payload').addEventListener"))}
    ({ select(payload, receipt) { payloadFile = payload; sidecarFile = receipt; }, check, takeFiles })`, {
    $: element, formatBytes: String,
    appendObjectCard: (_list, file) => { displayed = file; },
    fetch: async () => ({ ok: true, json: async () => ({ receipt_key: '01'.repeat(32) }) }),
    init: async () => {}, ErrorCode: { Malformed: 1 }, SubjectKind: { Object: 0, Package: 1 },
    verifyReceiptEd25519: () => ({ subjectKind, subjectId: { suite: 1, root: new Uint8Array([1]), length: 1n } }),
    Worker: class {
      postMessage(message) {
        assert.equal(message.file, payload);
        assert.equal(message.suite, 1);
        this.onmessage({ data: { done: { suite: hashedSuite, root: new Uint8Array([1]), length: 1n } } });
      }
      terminate() {}
    },
  });
  controller.select(payload, receipt);
  const pending = controller.check();
  await new Promise(setImmediate);
  await controller.check();
  assert.equal(reads, 1);
  assert.equal(element('pick-payload').disabled, true);
  assert.equal(element('verify-result').hidden, true);
  assert.equal(controller.takeFiles([{ name: 'replacement.txt' }]), 0);
  controller.select(null, null);
  releaseRead(new ArrayBuffer(0));
  await pending;
  assert.equal(displayed.name, 'original.txt');
  assert.equal(displayed.suite, 'sha256');
  assert.equal(element('verify-title').textContent, 'Verified');
  assert.equal(element('pick-payload').disabled, false);
  assert.equal(element('check').disabled, true);
  controller.select(payload, { ...receipt, size: 65537 });
  await controller.check();
  assert.equal(reads, 1);
  assert.equal(element('verify-result').hidden, true);
  assert.match(element('verify-error').textContent, /64 KiB/);
  controller.select(payload, receipt);
  subjectKind = 1;
  const packageCheck = controller.check();
  await new Promise(setImmediate);
  releaseRead(new ArrayBuffer(0));
  await packageCheck;
  assert.match(element('verify-error').textContent, /describes a package/);
  subjectKind = 0;
  hashedSuite = 0;
  const wrongSuite = controller.check();
  await new Promise(setImmediate);
  releaseRead(new ArrayBuffer(0));
  await wrongSuite;
  assert.equal(element('verify-title').textContent, 'Does not match');
  assert.equal(displayed.suite, 'blake3');
});
