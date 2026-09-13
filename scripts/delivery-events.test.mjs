import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, createHmac, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { Readable } from 'node:stream';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { canonical, verifyEvent, verifyWebhook, verifyChain, verifyExport } from '../examples/delivery-event-receiver.mjs';

test('MAM receiver verifies pinned event keys, HMAC bytes, timestamps and chain continuity', () => {
  const key = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 1)]), format: 'der', type: 'pkcs8' });
  const issuer = createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
  const document = { id: 1, tenant: '', grant_id: 'job', kind: 'delivery_ready', created_at: 100, payload: { '2': 'b', '10': 'a' }, previous_hash: '', issuer };
  assert.equal(canonical(document.payload), '{"10":"a","2":"b"}');
  const signature = sign(null, Buffer.from(`votport-delivery-event-v1\0${canonical(document)}`), key).toString('hex');
  const hash = createHash('sha256').update(canonical({ document, signature })).digest('hex');
  const event = { ...document, hash, signature };
  const body = Buffer.from(JSON.stringify(event));
  const headers = { 'x-votport-timestamp': '100', 'x-votport-event-id': '1', 'x-votport-signature': 'sha256=' + createHmac('sha256', 'secret').update('100.').update(body).digest('hex') };
  assert.equal(verifyEvent(event, issuer), true);
  assert.equal(verifyWebhook(body, headers, 'secret', issuer, 100), true);
  assert.equal(verifyWebhook(body, headers, 'wrong', issuer, 100), false);
  assert.equal(verifyWebhook(body, headers, 'secret', issuer, 401), false);
  assert.equal(verifyWebhook(body, { ...headers, 'x-votport-event-id': '2' }, 'secret', issuer, 100), false);
  assert.equal(verifyEvent({ ...event, kind: 'accepted' }, issuer), false);
  assert.equal(verifyEvent(event, '0'.repeat(64)), false);
  const start = { id: 0, hash: '' }, terminal = { id: event.id, hash };
  assert.deepEqual(verifyChain([event], issuer, '', start, terminal), terminal);
  assert.throws(() => verifyChain([event], issuer, '', { id: 0, hash: 'missing-predecessor' }, terminal));
  assert.throws(() => verifyChain([event], issuer, 'different-tenant', start, terminal));
  assert.throws(() => verifyChain([], issuer, '', start, terminal));
});

test('paged export pins the endpoint and rejects missing, reordered and oversized pages', async () => {
  const key = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 1)]), format: 'der', type: 'pkcs8' });
  const issuer = createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
  const events = [];
  for (const id of [1, 3, 6]) {
    const document = { id, tenant: 'tenant', grant_id: 'job', kind: 'delivery_ready', created_at: 100, payload: {}, previous_hash: events.at(-1)?.hash || '', issuer };
    const signature = sign(null, Buffer.from(`votport-delivery-event-v1\0${canonical(document)}`), key).toString('hex');
    events.push({ ...document, signature, hash: createHash('sha256').update(canonical({ document, signature })).digest('hex') });
  }
  const point = (event) => ({ id: event.id, hash: event.hash });
  const start = { id: 0, hash: '' }, terminal = point(events[2]);
  const pages = events.map((event, index) => ({ format: 'votport-delivery-events-v1', issuer, tenant: 'tenant', start: index ? point(events[index - 1]) : start, end: point(event), terminal, complete: index === 2, events: [event] }));
  const stream = (values) => Readable.from(values.map((value) => Buffer.from(JSON.stringify(value) + '\n')));
  const verify = (values, trusted = terminal) => verifyExport(stream(values), issuer, 'tenant', start, trusted);
  assert.deepEqual(await verify(pages), terminal);
  assert.deepEqual(await verifyExport(stream(pages.slice(1)), issuer, 'tenant', point(events[0]), terminal), terminal);
  for (const values of [[], pages.slice(0, 2), [pages[0], pages[2]], [pages[1], pages[0], pages[2]], [...pages, pages[2]]]) await assert.rejects(verify(values));
  await assert.rejects(verify(pages, { ...terminal, hash: '0'.repeat(64) }));
  await assert.rejects(verify(pages.map((page) => ({ ...page, tenant: 'other' }))));
  await assert.rejects(verify([{ ...pages[0], events: [{ ...events[0], payload: { changed: true } }] }, ...pages.slice(1)]));
  await assert.rejects(verifyExport(stream(pages), '0'.repeat(64), 'tenant', start, terminal));
  const truncated = pages.slice(0, 2).map((page, index) => ({ ...page, terminal: point(events[1]), complete: index === 1 }));
  await assert.rejects(verify(truncated));
  const empty = { ...pages[0], start, end: start, terminal: start, complete: true, events: [] };
  assert.deepEqual(await verify([empty], start), start);
  await assert.rejects(verify([empty]));
  const encoded = Buffer.from(pages.map((page) => JSON.stringify(page)).join('\n'));
  assert.deepEqual(await verifyExport(Readable.from(Array.from({ length: Math.ceil(encoded.length / 7) }, (_, index) => encoded.subarray(index * 7, (index + 1) * 7))), issuer, 'tenant', start, terminal), terminal);
  const directory = mkdtempSync(join(tmpdir(), 'votport-event-export-'));
  try {
    const file = join(directory, 'pages.ndjson');
    const run = () => spawnSync(process.execPath, ['examples/delivery-event-receiver.mjs', 'verify', file, 'tenant', String(terminal.id), terminal.hash], { encoding: 'utf8', timeout: 5000, env: { ...process.env, VOTPORT_EVENT_ISSUER: issuer } });
    writeFileSync(file, encoded);
    const accepted = run();
    assert.ifError(accepted.error);
    assert.equal(accepted.status, 0, accepted.stderr);
    assert.deepEqual(JSON.parse(accepted.stdout), terminal);
    writeFileSync(file, JSON.stringify(pages[0]) + '\n');
    const refused = run();
    assert.ifError(refused.error);
    assert.notEqual(refused.status, 0);
    assert.match(refused.stderr, /Expected terminal event checkpoint was not reached/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
  async function* tooLarge() { for (let i = 0; i < 257; i++) yield Buffer.alloc(64 * 1024, 32); }
  await assert.rejects(verifyExport(tooLarge(), issuer, 'tenant', start, terminal), /exceeds 16 MiB/);
});
