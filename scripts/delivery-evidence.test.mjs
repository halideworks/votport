import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';

globalThis.crypto ||= webcrypto;
const source = (await readFile(new URL('../web/assets/delivery-evidence.js', import.meta.url), 'utf8'))
  .replace(/^import .*$/gm, '');
const { authorization, manifestDigest, message } = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);

test('browser evidence uses the same ordered manifest and signed bytes as the Rust protocol', async () => {
  const manifest = await manifestDigest([{ name: 'file', suite: 'blake3', root: 'abcd', bytes: 7 }]);
  assert.equal(manifest, 'e3177fb9094c6dc5112fe278bf01979847f154d451961e035489847baba8c5f0');
  assert.notEqual(await manifestDigest([{ name: 'renamed', suite: 'blake3', root: 'abcd', bytes: 7 }]), manifest);
  const challenge = { origin: 'https://drop.example', grant_id: 'delivery-1', manifest,
    holder: '8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394', nonce: 'nonce-1', issued_at: 1, expires_at: 2 };
  const auth = authorization({ signature: '848bbbbd34ecef86faa736d49a731a9e09f77a18ee8cdb418ba3057811e74738d6e395af5cbf79d199b6da8dbdec910b75e72057af8ce1ad5df97128b2c4f10c', issuer: '8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c',
    challenge: Object.fromEntries(Object.entries(challenge).reverse()) });
  const server = await crypto.subtle.importKey('raw', Buffer.from(auth.issuer, 'hex'), 'Ed25519', false, ['verify']);
  assert.equal(await crypto.subtle.verify('Ed25519', server, Buffer.from(auth.signature, 'hex'), message('votport-evidence-challenge-v1\0', auth.challenge)), true);
  const device = await crypto.subtle.importKey('raw', Buffer.from(challenge.holder, 'hex'), 'Ed25519', false, ['verify']);
  const signature = Buffer.from('5f50ff0e9bf768b9ab3a33645c7397f443d59ecb39e07413385084a86f7a4d8725607fd0256d036fb3ed1352d91bae6c244e61bd02727354c0d299f2049d1c0c', 'hex');
  assert.equal(await crypto.subtle.verify('Ed25519', device, signature, message('votport-evidence-statement-v1\0', [auth, 'verified'])), true);
  assert.equal(await crypto.subtle.verify('Ed25519', device, signature, message('votport-evidence-statement-v1\0', [auth, 'accepted'])), false);
});
