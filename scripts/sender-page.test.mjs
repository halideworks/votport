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
  assert.match(script, /meter\.setAttribute\('role', 'progressbar'\)/);
  assert.match(script, /meter\.setAttribute\('aria-label', `\$\{path\} upload progress`\)/);
  assert.match(script, /meter\.setAttribute\('aria-valuemin', '0'\)/);
  assert.match(script, /meter\.setAttribute\('aria-valuemax', '100'\)/);
  assert.match(script, /const percent = Math\.max\(0, Math\.min\(100, Math\.round\(fraction \* 100\)\)\);/);
  assert.match(script, /meter\.setAttribute\('aria-valuenow', String\(percent\)\)/);
  assert.match(script, /item\.file\.size \? fileSent \/ item\.file\.size : 1/);
  assert.match(script, /files verified`\)/);
});

test('the progress note keeps ticking between progress callbacks', () => {
  // renderNote drops stale rate clauses itself, but only when it runs: a
  // tick bounded to the transfer keeps it honest through quiet stretches,
  // and the submit handler's finally is the single clear on every end path.
  assert.match(script, /const noteTick = setInterval\(renderNote, 1000\);/);
  assert.match(script, /finally \{\s*\n\s*clearInterval\(noteTick\);/);
  assert.match(script, /clearInterval\(noteTick\);[\s\S]{0,120}releaseWakeLock\(\);/);
});

test('a rebegin keeps delivered marks for rows past the visible limit', () => {
  // Rows past MAX_VISIBLE_FILE_ROWS have no element, so the delivered check
  // reads the set, not the row's class.
  assert.match(
    script,
    /if \(!deliveredPaths\.has\(item\.path\)\) \{\s*\n\s*setStatus\(item\.path, 'Continuing'\);/,
  );
  assert.doesNotMatch(script, /rows\.get\(item\.path\)\?\.classList/);
});

test('the shipped card carries proof the sender can copy', () => {
  assert.match(page, /id="done-summary"/);
  assert.match(page, /id="copy-proof" class="tiny"/);
  assert.match(script, /delivered to \$\{window\.location\.host\}, verified on receipt/);
  assert.match(script, /copyToClipboard\(copy, proof\)/);
  // One package per drop: the selection is announced as one session, the
  // resume record is keyed on that package root alone, and every entry is
  // addressed by its manifest index.
  assert.match(script, /buildPackage\(items\)/);
  assert.doesNotMatch(script, /buildPackage\(\[item\]\)/);
  assert.match(script, /saved && saved\.root === rootHex \? saved : null/);
  assert.match(script, /const item = items\[entry\.index\]/);
  assert.match(script, /hidden names \(starting with a dot\) are not accepted here/);
  assert.match(script, /maxEntries = info\.max_entries \|\| maxEntries/);
  assert.match(script, /collide once case is folded; rename one/);
  assert.match(script, /workerByPath\.delete\(item\.path\)/);
  assert.match(script, /if \(!workerByPath\.has\(item\.path\)\) await hashOne\(/);
  assert.match(script, /await abortSession\(sessionId\)/);
  assert.match(script, /signal: globalThis\.AbortSignal\?\.timeout\?\.\(5000\)/);
  // The done list keeps the shape the browser e2e reads.
  assert.match(script, /status: formatBytes\(file\.bytes\) \+ \(file\.receipt \? ' · receipt ✓' : ''\)/);
});

test('543: the pick-time reserved list folds case exactly like the server', () => {
  // The server lowercases once before matching the reserved shapes
  // (finding 542); the mirror here must agree or a casing variant is
  // admitted, hashed, and only refused by begin (finding 543).
  assert.match(script, /const lower = component\.toLowerCase\(\);/);
  assert.match(script, /\^\\\.votport-\(lease\|workflows\)\$\/\.test\(lower\)/);
  assert.match(script, /\^\\\.vot-stage\$\/\.test\(lower\)/);
  assert.match(script, /\^\\\.vot-tenants\\\.stage\$\/\.test\(lower\)/);
  assert.match(script, /\^\\\.vot-push-\[0-9a-f\]\{32\}\$\/\.test\(lower\)/);
  assert.match(script, /\^\\\.vot-\.\*\\\.\(stage\|journal\)\$\/\.test\(lower\)/);
  // No exact-case reserved match may remain against the raw component.
  assert.doesNotMatch(script, /test\(component\)\s*\{\s*\n\s*return "this name is reserved/);
});

test('503: the plan collision check folds full Unicode, not per character', () => {
  // toLowerCase alone leaves the final sigma, the long s and sharp s
  // distinct while macOS, SMB3 and NTFS collapse them; the shared fold
  // applies the CaseFolding remainder before both plan checks.
  assert.match(script, /FOLDS_FULL\.get\(character\.codePointAt\(0\)\)/);
  assert.match(script, /\[0x3c2, \[0x3c3\]\]/, 'final sigma folds to sigma');
  assert.match(script, /\[0x17f, \[0x73\]\]/, 'long s folds to s');
  assert.match(script, /\[0xdf, \[0x73, 0x73\]\]/, 'sharp s folds to ss');
  // The pick-time check and the package plan both key on the folded form.
  assert.match(script, /const key = pathKeyString\(components\);/);
  assert.match(script, /key: pathKeyBytes\(components\)/);
});

test('picking folds each selected path once, not once per add', () => {
  // renderPicked rebuilds the list and its collision keys on every add; the
  // memoized keys keep the 20,000th add from refolding the 19,999 paths
  // before it (finding 537).
  assert.match(script, /function pickedPathKey\(path\) \{/);
  assert.match(script, /pathKeyMemo\.set\(path, key\);/, 'the batch check seeds the memo with the key it already folded');
  assert.match(script, /pickedKeys\.set\(pickedPathKey\(path\), path\);/);
  assert.doesNotMatch(script, /pickedKeys\.set\(pathKeyString\(/);
  // Clearing the selection must not leave stale keys for reused paths.
  assert.match(script, /picked\.clear\(\);\s*\n\s*pathKeyMemo\.clear\(\);/);
});

test('a recovery round skips rows already showing its state', () => {
  // Every re-begin sweeps all rows with the same words; the shown-state memo
  // turns the repeat sweeps into no-ops instead of full-page DOM rewrites
  // (finding 538).
  assert.match(script, /const shownState = new Map\(\);/);
  assert.match(
    script,
    /if \(shown && shown\.text === text && shown\.done === done && shown\.state === state && shown\.fraction === fraction\) return;/,
  );
  // Rebuilt row elements must not inherit what the old ones showed.
  assert.match(script, /rows = new Map\(\);\s*\n\s*\/\/ Fresh row elements know nothing of what the old ones showed\.\s*\n\s*shownState\.clear\(\);/);
  // The sweep itself keeps its delivered-mark authority.
  assert.match(
    script,
    /if \(!deliveredPaths\.has\(item\.path\)\) \{\s*\n\s*setStatus\(item\.path, 'Continuing'\);/,
  );
});

test('a large file is hashed as leaf-aligned segments across the pool and assembled on its owner', async () => {
  const worker = await readFile(new URL('../web/assets/hash-worker.js', import.meta.url), 'utf8');
  assert.match(script, /segments\(file\.size, proofLeafBytes, hashWorkers\.length, MIN_SEGMENT_BYTES\)/);
  assert.match(script, /op: 'leaves'/);
  assert.match(script, /op: 'assemble'/);
  assert.match(worker, /proofLeavesAt\(Suite\.Blake3Bao64, BigInt\(offset\), bytes, BigInt\(file\.size\)\)/);
  assert.match(worker, /PreparedObject\.fromProofLeaves\(/);
  assert.match(script, /const MAX_WORKERS = 8;/);
  assert.match(script, /if \(pending\.op === 'prove'\) error\.paused = true;/);
  assert.match(script, /&& !parallelHashing/);
});
