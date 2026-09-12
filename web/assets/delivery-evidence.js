/* global crypto, indexedDB, DataView, AbortSignal */
import { dedupeFilenames } from '/assets/outbound-download.js';
import { copyToClipboard } from '/assets/object-card.js';

const encode = new TextEncoder();
const hex = (bytes) => [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
const unhex = (value) => {
  if (typeof value !== 'string' || value.length % 2 || !/^[0-9a-f]+$/.test(value)) throw new Error('Invalid signature or key.');
  return Uint8Array.from(value.match(/../g), (byte) => parseInt(byte, 16));
};
const message = (domain, value) => encode.encode(domain + JSON.stringify(value));
let database, devicePromise;

function db() {
  database ||= new Promise((resolve, reject) => {
    const request = indexedDB.open('votport-delivery-evidence', 1);
    request.onupgradeneeded = () => request.result.createObjectStore('records');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  return database;
}

async function stored(key, value, add = false) {
  const database = await db();
  return new Promise((resolve, reject) => {
    const write = value !== undefined;
    const transaction = database.transaction('records', write ? 'readwrite' : 'readonly', { durability: 'strict' });
    const store = transaction.objectStore('records');
    const request = write ? store[add ? 'add' : 'put'](value, key) : store.get(key);
    transaction.oncomplete = () => resolve(request.result);
    transaction.onabort = () => reject(transaction.error || request.error);
    transaction.onerror = () => {};
  });
}

async function device() {
  devicePromise ||= (async () => {
    let key = await stored('device');
    if (!key) {
      const generated = await crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify']);
      try { await stored('device', generated, true); }
      catch (error) { if (error.name !== 'ConstraintError') throw error; }
      key = await stored('device');
    }
    return { key, holder: hex(await crypto.subtle.exportKey('raw', key.publicKey)) };
  })();
  return devicePromise;
}

function authorization(value) {
  if (!value?.challenge) throw new Error('Delivery authorization is unavailable. Reload the download page.');
  const { origin, grant_id, manifest, holder, nonce, issued_at, expires_at } = value.challenge;
  return { challenge: { origin, grant_id, manifest, holder, nonce, issued_at, expires_at }, issuer: value.issuer, signature: value.signature };
}

async function verifyAuthorization(value, issuer) {
  const auth = authorization(value), local = await device();
  const key = await crypto.subtle.importKey('raw', unhex(issuer), 'Ed25519', false, ['verify']);
  if (auth.issuer !== issuer || auth.challenge.origin !== window.location.origin || auth.challenge.holder !== local.holder ||
      !Number.isSafeInteger(auth.challenge.expires_at) || auth.challenge.expires_at <= Date.now() / 1000 ||
      !(await crypto.subtle.verify('Ed25519', key, unhex(auth.signature), message('votport-evidence-challenge-v1\0', auth.challenge)))) {
    throw new Error('Delivery authorization is invalid or expired. Reload the download page.');
  }
  return auth;
}

export async function deliveryMetadata(url, token) {
  const local = await device().catch(() => null);
  const options = { credentials: 'same-origin', headers: local ? { 'X-Votport-Device': local.holder } : {} };
  let response = await fetch(url, options);
  if (response.status !== 403 || !local) return response;
  const error = await response.clone().json().catch(() => null);
  if (error?.code !== 'recipient_required') return response;
  const requested = await fetch(`/api/s/${token}/recipient-challenge`, {
    method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-Votport': '1' }, body: JSON.stringify({ holder: local.holder }),
  });
  const challenge = await requested.json();
  if (!requested.ok) throw new Error(challenge.error || 'Ask the sender to enroll this browser device key.');
  const auth = await verifyAuthorization(challenge, challenge.issuer);
  const signature = hex(await crypto.subtle.sign('Ed25519', local.key.privateKey, message('votport-recipient-access-v1\0', auth)));
  const verified = await fetch(`/api/s/${token}/recipient-verify`, {
    method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-Votport': '1' }, body: JSON.stringify({ authorization: auth, signature }),
  });
  if (!verified.ok) throw new Error('This browser device could not be authorized. Ask the sender to check enrollment.');
  response = await fetch(url, options);
  return response;
}

async function manifestDigest(files) {
  const parts = [encode.encode('votport-delivery-files-v1\0')];
  const integer = (value) => { const bytes = new Uint8Array(8); new DataView(bytes.buffer).setBigUint64(0, BigInt(value)); return bytes; };
  for (const file of files) {
    for (const value of [file.name, file.suite, file.root]) { const bytes = encode.encode(value); parts.push(integer(bytes.length), bytes); }
    if (!Number.isSafeInteger(file.bytes) || file.bytes < 0) throw new Error('Invalid file size.');
    parts.push(integer(file.bytes));
  }
  parts.push(integer(files.length));
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  if (length > 64 * 1024 * 1024) throw new Error('Use the desktop app to acknowledge this very large manifest.');
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) { bytes.set(part, offset); offset += part.length; }
  return hex(await crypto.subtle.digest('SHA-256', bytes));
}

async function statement(auth, kind) {
  const local = await device();
  const signature = hex(await crypto.subtle.sign('Ed25519', local.key.privateKey, message('votport-evidence-statement-v1\0', [auth, kind])));
  const evidence = { authorization: auth, kind, signature };
  const id = hex(await crypto.subtle.digest('SHA-256', message('votport-evidence-id-v1\0', evidence)));
  const record = { id, evidence, status: 'pending' };
  await stored(`evidence:${id}`, record);
  return record;
}

async function submit(record) {
  if (record.status === 'recorded') return record;
  const response = await fetch('/api/evidence', { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(5000),
    headers: { 'Content-Type': 'application/json', 'X-Votport': '1' }, body: JSON.stringify(record.evidence) });
  if (response.status === 401 && record.evidence.authorization.challenge.expires_at <= Date.now() / 1000) {
    record.status = 'expired'; await stored(`evidence:${record.id}`, record); return record;
  }
  const result = await response.json();
  if (!response.ok || result.id !== record.id || result.recorded !== true) throw new Error('Verification report remains queued; retry when the server is available.');
  record.status = 'recorded'; await stored(`evidence:${record.id}`, record); return record;
}

async function allRecords() {
  const database = await db();
  return new Promise((resolve, reject) => {
    const request = database.transaction('records').objectStore('records').getAll();
    request.onsuccess = () => resolve(request.result.filter((record) => record?.evidence));
    request.onerror = () => reject(request.error);
  });
}

function hashFile(file) {
  return new Promise((resolve, reject) => {
    const worker = new Worker('/assets/hash-worker.js', { type: 'module' });
    worker.onmessage = ({ data }) => {
      if (data.error || data.done) {
        worker.terminate();
        if (data.error) reject(new Error(data.error)); else resolve({ root: hex(data.done.root), bytes: Number(data.done.length) });
      }
    };
    worker.onerror = () => { worker.terminate(); reject(new Error('File verification worker failed.')); };
    worker.postMessage({ op: 'hash', req: 1, key: 'delivery', file });
  });
}

export function initDeliveryEvidence(getMetadata) {
  const $ = (id) => document.getElementById(id);
  const token = window.location.pathname.split('/').filter(Boolean).pop();
  const status = $('evidence-status');
  let busy = false;
  async function run(action) {
    if (busy) return;
    busy = true;
    try { await action(); } catch (error) { status.textContent = error.message; }
    finally { busy = false; }
  }
  async function show() {
    const records = (await allRecords()).filter((record) => record.evidence.authorization.challenge.grant_id === $('evidence-records').dataset.grant);
    $('evidence-records').replaceChildren();
    for (const record of records.filter((record) => record.evidence.kind === 'verified')) {
      const accepted = records.find((item) => item.evidence.kind === 'accepted' && item.evidence.authorization.signature === record.evidence.authorization.signature);
      const row = document.createElement('div'); row.className = 'verification-record';
      const manifest = document.createElement('span'); manifest.className = 'mono';
      manifest.textContent = `Manifest ${record.evidence.authorization.challenge.manifest}`;
      const result = document.createElement('p'); result.textContent = `Files verified on this device. ${record.status === 'recorded' ? 'Verification reported to the sender.' : 'Verification report: ' + record.status + '.'} ${accepted ? (accepted.status === 'recorded' ? 'Delivery accepted and reported to the sender.' : 'Delivery accepted on this device; report: ' + accepted.status + '.') : 'Ready for your acceptance.'}`;
      const detail = document.createElement('details'), caption = document.createElement('summary'); caption.textContent = 'Signed delivery fingerprint'; detail.append(caption, manifest); row.append(result, detail);
      if (!accepted) {
        const button = document.createElement('button'); button.type = 'button'; button.textContent = 'Accept verified delivery';
        button.onclick = () => run(async () => {
          if (!window.confirm('Accept this verified delivery? This records your acceptance of the exact files shown here and sends a signed report to the sender.')) return;
          const auth = await verifyAuthorization(record.evidence.authorization, record.evidence.authorization.issuer);
          const acceptance = await statement(auth, 'accepted');
          await show();
          try { await submit(record); await submit(acceptance); } finally { await show(); }
        });
        row.append(button);
      }
      $('evidence-records').append(row);
    }
    if (records.some((record) => record.status === 'pending')) status.textContent = 'Signed reports are waiting to reach the sender. Use Retry pending reports if needed.';
    else if (records.length) status.textContent = records.some((record) => record.status === 'expired') ? 'Some reports expired before reaching the sender. Review the verification records below.' : 'Signed reports recorded by the sending port.';
    if (!$('evidence-records').children.length) { const empty = document.createElement('p'); empty.className = 'field-help'; empty.textContent = 'No verification record yet. Verify your saved files above to make acceptance available.'; $('evidence-records').append(empty); }
  }
  $('evidence-copy-key').onclick = () => run(async () => {
    const local = await device(); await copyToClipboard($('evidence-copy-key'), local.holder); status.textContent = 'Device public key copied. Give it to the sender for enrollment.';
  });
  $('evidence-retry').onclick = () => run(async () => {
    const records = (await allRecords()).filter((record) => record.status === 'pending');
    records.sort((a, b) => a.evidence.kind === b.evidence.kind ? a.id.localeCompare(b.id) : a.evidence.kind === 'verified' ? -1 : 1);
    for (const record of records) { try { await submit(record); } catch { /* Continue with the other queued reports after an unavailable request. */ } }
    status.textContent = 'Pending reports retried.'; await show();
  });
  $('evidence-verify').onclick = () => run(async () => {
    const selected = [...$('evidence-files').files];
    if (!selected.length) throw new Error('Choose the saved files first.');
    const metadata = await getMetadata();
    if (!metadata?.grant_id) throw new Error('Load the delivery before verifying files.');
    const auth = await verifyAuthorization(metadata.evidence_authorization, metadata.receipt_key);
    if (auth.challenge.grant_id !== metadata.grant_id || auth.challenge.manifest !== await manifestDigest(metadata.files)) throw new Error('The delivery manifest does not match its authorization.');
    const names = dedupeFilenames(metadata.files.map((file) => file.name));
    const selectedByName = new Map();
    for (const file of selected) { if (selectedByName.has(file.name)) throw new Error('Choose files with distinct saved filenames.'); selectedByName.set(file.name, file); }
    for (const [index, expected] of metadata.files.entries()) {
      const file = selectedByName.get(names[index]);
      if (!file || file.size !== expected.bytes || expected.suite !== 'blake3') throw new Error(`Missing or wrong-sized file: ${names[index]}`);
      status.textContent = `Verifying saved files: ${index + 1} of ${metadata.files.length}`;
      const actual = await hashFile(file);
      if (actual.root !== expected.root || actual.bytes !== expected.bytes) throw new Error(`Verification failed: ${names[index]}`);
    }
    const record = await statement(auth, 'verified');
    await stored(`delivery:${token}`, metadata.grant_id);
    $('evidence-records').dataset.grant = metadata.grant_id;
    status.textContent = 'Saved files verified. Signed report queued.';
    await show();
    submit(record).then(show).catch(() => {});
  });
  // This is an explicit post-download check; browser anchor clicks cannot attest to saved bytes.
  $('evidence-refresh').onclick = () => run(async () => {
    const metadata = await getMetadata().catch(() => null);
    $('evidence-records').dataset.grant = metadata?.grant_id || await stored(`delivery:${token}`) || '';
    await show();
  });
  $('evidence-open-app').href = `votport://s/${encodeURIComponent(token)}?base=${encodeURIComponent(window.location.origin)}`;
}

export { authorization, manifestDigest, message };
