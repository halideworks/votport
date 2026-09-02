import assert from 'node:assert/strict';
import { test } from 'node:test';

import { narrate, summarize, timelineJson } from '../web/assets/timeline.js';

const upload = {
  id: 'up1',
  started_at: 1000,
  completed_at: 1708,
  total_bytes: 3 * 1024 * 1024 * 1024,
  replayed_chunks: 17,
  rejected_chunks: 0,
  transport: 'http',
  files: [{ path: 'a.mov', bytes: 1, suite: 'blake3', root: 'r', receipt: true }, { path: 'b.mov', bytes: 2, suite: 'blake3', root: 's', receipt: true }],
  log: [
    { at: 1000, kind: 'opened' },
    { at: 1003, kind: 'published', path: 'a.mov', bytes: 412 * 1024 * 1024, secs: 3 },
    { at: 1160, kind: 'quiet', secs: 160 },
    { at: 1400, kind: 'reattached', count: 1 },
    { at: 1700, kind: 'published', path: 'b.mov', bytes: 398 * 1024 * 1024, secs: 4 },
    { at: 1708, kind: 'finished', count: 17 },
  ],
};

test('summarize reads duration, rates, pauses, restarts, and outcome from the record', () => {
  const summary = summarize(upload);
  assert.equal(summary.duration, 708);
  assert.equal(summary.average, Math.round((3 * 1024 * 1024 * 1024) / 708));
  assert.equal(summary.peak, Math.round((412 * 1024 * 1024) / 3));
  assert.equal(summary.pauses, 160);
  assert.equal(summary.restarts, 1);
  assert.equal(summary.resent, 17);
  assert.equal(summary.outcome, 'finished');
  assert.equal(summary.files, 2);
});

test('a record without a log or timing has null rates and a partial outcome', () => {
  const summary = summarize({ id: 'x', completed_at: 5, total_bytes: 10, partial: true, files: [] });
  assert.equal(summary.duration, null);
  assert.equal(summary.average, null);
  assert.equal(summary.peak, null);
  assert.equal(summary.pauses, 0);
  assert.equal(summary.outcome, 'partial');
});

test('narrate turns each event kind into a sentence with its facts', () => {
  assert.equal(narrate(upload.log[0]).text, 'Session opened, manifest verified');
  const published = narrate(upload.log[1]);
  assert.equal(published.text, 'a.mov published with its receipt');
  assert.match(published.detail, /412 MiB in 3s · 137 MiB\/s/);
  assert.equal(narrate(upload.log[2]).text, 'Sender went quiet for 2m 40s');
  assert.match(narrate(upload.log[3]).detail, /1 file already published/);
  assert.equal(narrate(upload.log[5]).detail, '17 re-sent chunks');
  assert.equal(narrate({ kind: 'elided', count: 30 }).text, '30 more events not kept');
  assert.equal(narrate({ kind: 'weird' }).text, 'weird');
});

test('timelineJson carries the request, the record, the summary, and every event', () => {
  const doc = JSON.parse(timelineJson({ id: 'l', label: 'L', dest: 'd' }, upload));
  assert.equal(doc.request.label, 'L');
  assert.equal(doc.upload.files.length, 2);
  assert.equal(doc.summary.resent, 17);
  assert.equal(doc.events.length, 6);
});
