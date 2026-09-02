import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

const page = await readFile(new URL('../web/request.html', import.meta.url), 'utf8');
const script = await readFile(new URL('../web/assets/upload.js', import.meta.url), 'utf8');

test('a held transfer leads the sender page as a card with a discard action', () => {
  assert.match(page, /id="resume-note" class="card ok resume-card" hidden/);
  assert.ok(page.indexOf('id="resume-note"') < page.indexOf('id="drop"'));
  assert.match(page, /id="resume-discard" class="link"/);
  assert.match(script, /\$\('resume-discard'\)\.addEventListener\('click'[\s\S]{0,80}clearResume\(\)/);
});

test('each staged file carries a state badge and a meter while sending', () => {
  assert.match(script, /item\.dataset\.state = state/);
  assert.match(script, /const state = done \? 'verified'/);
  assert.match(script, /meter\.className = 'row-meter'/);
  assert.match(script, /item\.file\.size \? fileSent \/ item\.file\.size : 1/);
  assert.match(script, /files verified`\)/);
});

test('the shipped card carries proof the sender can copy', () => {
  assert.match(page, /id="done-summary"/);
  assert.match(page, /id="copy-proof" class="tiny"/);
  assert.match(script, /delivered to \$\{window\.location\.host\}, verified on receipt/);
  assert.match(script, /copyToClipboard\(copy, proof\)/);
  // One package per file: no single "package root" is claimed for the shipment.
  assert.doesNotMatch(script, /packageRootHex/);
  // The done list keeps the shape the browser e2e reads.
  assert.match(script, /status: formatBytes\(file\.bytes\) \+ \(file\.receipt \? ' · receipt ✓' : ''\)/);
});

test('a large file is hashed as leaf-aligned segments across the pool and assembled on its owner', async () => {
  const worker = await readFile(new URL('../web/assets/hash-worker.js', import.meta.url), 'utf8');
  assert.match(script, /segments\(file\.size, PROOF_LEAF_BYTES, hashWorkers\.length, MIN_SEGMENT_BYTES\)/);
  assert.match(script, /op: 'leaves'/);
  assert.match(script, /op: 'assemble'/);
  assert.match(worker, /proofLeavesAt\(Suite\.Blake3Bao64, BigInt\(offset\), bytes, BigInt\(file\.size\)\)/);
  assert.match(worker, /PreparedObject\.fromProofLeaves\(/);
  assert.match(script, /const MAX_WORKERS = 8;/);
  assert.match(script, /if \(pending\.op === 'prove'\) error\.paused = true;/);
  assert.match(script, /&& !parallelHashing/);
});
