// Persist authenticated delivery events before acknowledging them to Votport.
import { createHash, createHmac, createPublicKey, randomUUID, timingSafeEqual, verify } from 'node:crypto';
import { createServer } from 'node:http';
import { createReadStream } from 'node:fs';
import { open, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)))
      .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  if (typeof value === 'number' && !Number.isSafeInteger(value)) throw new Error('Unsafe event number');
  return JSON.stringify(value);
}

export function verifyEvent(event, issuer) {
  if (!/^[0-9a-f]{64}$/.test(issuer) || event.issuer !== issuer || !/^[0-9a-f]{128}$/.test(event.signature)) return false;
  const { id, tenant, grant_id, kind, created_at, payload, previous_hash } = event;
  const document = { id, tenant, grant_id, kind, created_at, payload, previous_hash, issuer };
  const publicKey = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(issuer, 'hex')]), format: 'der', type: 'spki' });
  const signed = Buffer.from(`votport-delivery-event-v1\0${canonical(document)}`);
  return verify(null, signed, publicKey, Buffer.from(event.signature, 'hex'))
    && createHash('sha256').update(canonical({ document, signature: event.signature })).digest('hex') === event.hash;
}

export function verifyWebhook(body, headers, secret, issuer, now = Math.floor(Date.now() / 1000)) {
  const timestamp = headers['x-votport-timestamp'];
  const supplied = headers['x-votport-signature'];
  if (!/^\d{1,16}$/.test(timestamp || '') || Math.abs(now - Number(timestamp)) > 300 || !/^sha256=[0-9a-f]{64}$/.test(supplied || '')) return false;
  const expected = createHmac('sha256', secret).update(`${timestamp}.`).update(body).digest();
  if (!timingSafeEqual(expected, Buffer.from(supplied.slice(7), 'hex'))) return false;
  const event = JSON.parse(body);
  return String(event.id) === headers['x-votport-event-id'] && verifyEvent(event, issuer);
}

function checkpoint(value) {
  if (!value || !Number.isSafeInteger(value.id) || value.id < 0 || (value.id === 0 ? value.hash !== '' : !/^[0-9a-f]{64}$/.test(value.hash))) throw new Error('Invalid event checkpoint');
  return value;
}

function sameCheckpoint(left, right) {
  return left.id === right.id && left.hash === right.hash;
}

export function verifyChain(events, issuer, tenant, start, terminal) {
  checkpoint(start); checkpoint(terminal);
  if (!/^[0-9a-f]{64}$/.test(issuer) || !Array.isArray(events) || events.length > 100 || typeof tenant !== 'string') throw new Error('Invalid event page');
  let previous = start;
  for (const event of events) {
    if (!Number.isSafeInteger(event.id) || event.id <= previous.id || event.tenant !== tenant || !verifyEvent(event, issuer) || event.previous_hash !== previous.hash) throw new Error(`Invalid or incomplete event chain at ${event.id}`);
    previous = { id: event.id, hash: event.hash };
  }
  if (!sameCheckpoint(previous, terminal)) throw new Error('Expected terminal event checkpoint was not reached');
  return previous;
}

export async function verifyExport(source, issuer, tenant, start, terminal) {
  checkpoint(start); checkpoint(terminal);
  if (!/^[0-9a-f]{64}$/.test(issuer) || typeof tenant !== 'string' || start.id > terminal.id) throw new Error('Invalid export trust parameters');
  let previous = start, complete = false, pages = 0, parts = [], length = 0;
  function page(bytes) {
    const value = JSON.parse(bytes.toString('utf8'));
    if (complete || value.format !== 'votport-delivery-events-v1' || value.issuer !== issuer || value.tenant !== tenant || !sameCheckpoint(checkpoint(value.start), previous) || !sameCheckpoint(checkpoint(value.terminal), terminal)) throw new Error('Event export page does not match the expected checkpoints');
    previous = verifyChain(value.events, issuer, tenant, previous, value.end);
    if (previous.id > terminal.id || value.complete !== sameCheckpoint(previous, terminal) || (!value.complete && value.events.length === 0)) throw new Error('Invalid event export completion');
    complete = value.complete;
    pages++;
  }
  for await (const chunk of source) {
    const bytes = Buffer.from(chunk);
    let start = 0;
    while (start < bytes.length) {
      const newline = bytes.indexOf(10, start);
      const end = newline < 0 ? bytes.length : newline;
      const part = bytes.subarray(start, end);
      length += part.length;
      if (length > 16 * 1024 * 1024) throw new Error('Event export page exceeds 16 MiB');
      parts.push(part);
      if (newline >= 0) {
        page(Buffer.concat(parts, length));
        parts = []; length = 0;
      }
      start = end + 1;
    }
  }
  if (length) page(Buffer.concat(parts, length));
  if (!pages || !complete || !sameCheckpoint(previous, terminal)) throw new Error('Expected terminal event checkpoint was not reached');
  return previous;
}

async function main() {
  const issuer = process.env.VOTPORT_EVENT_ISSUER;
  if (process.argv[2] === 'verify') {
    const args = process.argv.slice(3);
    if (args.length !== 4 && args.length !== 6) throw new Error('verify requires <pages.ndjson> <tenant> <terminal-id> <terminal-hash> [<start-id> <start-hash>]');
    const [file, tenant, id, hash, startId = '0', startHash = ''] = args;
    const result = await verifyExport(createReadStream(file, { highWaterMark: 64 * 1024 }), issuer, tenant, { id: Number(startId), hash: startHash }, { id: Number(id), hash });
    console.log(JSON.stringify(result));
    return;
  }
  const secret = process.env.VOTPORT_WEBHOOK_SECRET;
  const directory = process.env.VOTPORT_EVENT_DIRECTORY;
  if (!secret || !directory || !/^[0-9a-f]{64}$/.test(issuer || '')) throw new Error('Set VOTPORT_WEBHOOK_SECRET, VOTPORT_EVENT_ISSUER and VOTPORT_EVENT_DIRECTORY');
  const prepared = await open(directory, 'r');
  await prepared.close();
  const server = createServer(async (request, response) => {
    try {
      if (request.method !== 'POST' || request.url !== '/events') { response.writeHead(404).end(); return; }
      const parts = []; let length = 0;
      for await (const part of request) {
        length += part.length;
        if (length > 1024 * 1024) { response.writeHead(413).end(); return; }
        parts.push(part);
      }
      const body = Buffer.concat(parts);
      if (!verifyWebhook(body, request.headers, secret, issuer)) { response.writeHead(401).end(); return; }
      const event = JSON.parse(body);
      const target = path.join(directory, `${event.hash}.json`);
      const temporary = path.join(directory, `.${randomUUID()}.tmp`);
      try {
        const file = await open(temporary, 'wx', 0o600);
        try { await file.writeFile(body); await file.sync(); } finally { await file.close(); }
        await rename(temporary, target);
      } finally { await rm(temporary, { force: true }); }
      const parent = await open(directory, 'r');
      try { await parent.sync(); } finally { await parent.close(); }
      response.writeHead(204).end();
    } catch { response.writeHead(503).end(); }
  });
  server.requestTimeout = 10000;
  server.listen(Number(process.env.PORT || 8090), '127.0.0.1');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
