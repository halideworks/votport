import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, createHmac, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { canonical, verifyEvent, verifyWebhook, verifyChain } from '../examples/delivery-event-receiver.mjs';

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
  assert.equal(verifyChain([event], issuer), hash);
  assert.throws(() => verifyChain([event], issuer, 'missing-predecessor'));
});
