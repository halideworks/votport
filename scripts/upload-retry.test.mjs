import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

import {
  RETRY_ATTEMPTS,
  RETRY_BUDGET_MS,
  expireForeignResumes,
  finishMayBeComplete,
  loadResumeRecord,
  resumeDropId,
  retryDecision,
  saveResumeRecord,
  sessionUnknown,
} from '../web/assets/upload-retry.js';

const upload = await readFile(new URL('../web/assets/upload.js', import.meta.url), 'utf8');

// A minimal Storage stand-in with the length/key(i) API the expiry scan uses.
function storage() {
  const map = new Map();
  return {
    get length() { return map.size; },
    key: (index) => [...map.keys()][index] ?? null,
    getItem: (key) => (map.has(key) ? map.get(key) : null),
    setItem: (key, value) => map.set(key, String(value)),
    removeItem: (key) => map.delete(key),
  };
}

test('a 503 honors Retry-After within the remaining budget', () => {
  assert.deepEqual(
    retryDecision({ attempt: 0, status: 503, retryAfterMs: 4000 }),
    { retry: true, delayMs: 4000 },
  );
  assert.equal(
    retryDecision({ attempt: 0, status: 503, retryAfterMs: RETRY_BUDGET_MS * 10 }).delayMs,
    RETRY_BUDGET_MS,
  );
});

test('retries stop at the attempt cap and the time budget', () => {
  assert.deepEqual(
    retryDecision({ attempt: RETRY_ATTEMPTS, status: 503 }),
    { retry: false },
  );
  assert.deepEqual(
    retryDecision({ attempt: 0, elapsedMs: RETRY_BUDGET_MS, status: 503 }),
    { retry: false },
  );
});

test('the server envelope can refuse a retry even in the 5xx class', () => {
  assert.deepEqual(
    retryDecision({ attempt: 0, status: 503, body: { error: 'x', retryable: false } }),
    { retry: false },
  );
});

test('named admission refusals stop with the server sentence', () => {
  const address = retryDecision({
    attempt: 0,
    status: 429,
    body: { error: 'too many uploads started from your address; try again in 600 seconds' },
  });
  assert.equal(address.retry, false);
  assert.equal(address.message, 'too many uploads started from your address; try again in 600 seconds');
  const tenant = retryDecision({
    attempt: 0,
    status: 429,
    body: { error: 'too many concurrent uploads for this tenant' },
  });
  assert.equal(tenant.retry, false);
  assert.equal(tenant.message, 'too many concurrent uploads for this tenant');
  const draining = retryDecision({
    attempt: 0,
    status: 503,
    body: { error: 'the server is draining for maintenance; your upload will resume shortly' },
  });
  assert.equal(draining.retry, false);
  assert.equal(draining.message, 'the server is draining for maintenance; your upload will resume shortly');
});

test('a plain 503 body still retries, and markers match exactly', () => {
  assert.equal(
    retryDecision({ attempt: 0, status: 503, body: { error: 'internal error' } }).retry,
    true,
  );
  assert.equal(
    retryDecision({
      attempt: 0,
      status: 503,
      body: { error: 'the server is draining for maintenance; your upload will resume SOON' },
    }).retry,
    true,
  );
  assert.equal(
    retryDecision({
      attempt: 0,
      status: 429,
      body: { error: 'Too many concurrent uploads for this tenant' },
    }).retry,
    true,
  );
});

test('a finish refused after the session is gone may still have completed', () => {
  for (const error of [
    { status: 404, message: 'unknown or expired session' },
    { status: 410, message: 'upload session ended' },
    { message: 'unknown or expired session' },
    { status: 409, message: 'nothing to finish in this state' },
    { paused: true, message: 'request failed (503)' },
  ]) {
    assert.equal(finishMayBeComplete(error), true, JSON.stringify(error));
  }
  for (const error of [
    { status: 422, message: '0 is not fully received yet' },
    { status: 409, message: 'seal was already provided' },
    { status: 500, message: 'internal error' },
  ]) {
    assert.equal(finishMayBeComplete(error), false, JSON.stringify(error));
  }
});

test('two drops on the same link hold distinct resume records', () => {
  const local = storage();
  const tabA = storage();
  const tabB = storage();
  globalThis.localStorage = local;
  globalThis.sessionStorage = tabA;
  saveResumeRecord('link', { session: 's-a', root: 'root-a', files: 2, size: 10, chunk: 4096 });
  const dropA = resumeDropId('link');
  globalThis.sessionStorage = tabB;
  saveResumeRecord('link', { session: 's-b', root: 'root-b', files: 1, size: 5, chunk: 4096 });
  const dropB = resumeDropId('link');
  assert.notEqual(dropA, dropB);
  assert.match(dropA, /^[0-9a-f]{32}$/);
  // Each record kept its own session: neither tab overwrote the other.
  globalThis.sessionStorage = tabA;
  assert.equal(loadResumeRecord('link', dropA).session, 's-a');
  assert.equal(loadResumeRecord('link', dropB).session, 's-b');
  const record = loadResumeRecord('link', dropA);
  assert.equal(record.drop, dropA);
  assert.equal(typeof record.at, 'number');
});

test('records not owned by this tab expire once stale', () => {
  const local = storage();
  const own = storage();
  globalThis.localStorage = local;
  globalThis.sessionStorage = own;
  saveResumeRecord('link', { session: 's-own', root: 'r', files: 1, size: 1, chunk: 1 });
  const ownKey = `votport-resume-link-${resumeDropId('link')}`;
  const freshForeign = 'votport-resume-link-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  const staleForeign = 'votport-resume-link-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
  local.setItem(freshForeign, JSON.stringify({ session: 's-fresh', at: Date.now() - 1000 }));
  local.setItem(staleForeign, JSON.stringify({ session: 's-stale', at: Date.now() - 2 * 60 * 60 * 1000 }));
  local.setItem('votport-resume-other-link', JSON.stringify({ session: 's-other' }));
  expireForeignResumes('link');
  assert.notEqual(local.getItem(ownKey), null);
  assert.notEqual(local.getItem(freshForeign), null, 'a fresh foreign record may be a live sender');
  assert.equal(local.getItem(staleForeign), null);
  assert.notEqual(local.getItem('votport-resume-other-link'), null);
});

test('a restarted server\'s unknown-session 404 restarts, not fails, the send', () => {
  // Only the server's own unknown-session sentence on a 404 counts: a bare
  // 404, a closed link (410), or a transient failure must not restart.
  assert.equal(sessionUnknown({ status: 404, message: 'unknown or expired session' }), true);
  assert.equal(sessionUnknown({ status: 404, message: 'request failed (404)' }), false);
  assert.equal(sessionUnknown({ status: 410, message: 'this link is no longer accepting uploads' }), false);
  assert.equal(sessionUnknown({ status: 500, message: 'unknown or expired session' }), false);
  assert.equal(sessionUnknown({ message: 'unknown or expired session' }), false);
  // Wiring, per the established source-assertion style: the single-shot
  // manifest phases mark the unknown-session refusal for a restart instead
  // of fatal, and the fresh session's begin does the same.
  assert.match(upload, /singleShot && sessionUnknown\(failure\)/);
  assert.match(upload, /if \(sessionUnknown\(error\)\) \{\n\s+\/\/ The server restarted between the last page and begin/);
  assert.match(upload, /error\.restart = true;\n\s+\}\n\s+throw error;/);
});

