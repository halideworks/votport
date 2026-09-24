import assert from 'node:assert/strict';
import { test } from 'node:test';

import { narrate, summarize } from '../web/assets/timeline.js';

const upload = {
  id: 'up1',
  started_at: 1000,
  completed_at: 1708,
  total_bytes: 3 * 1024 * 1024 * 1024,
  replayed_chunks: 17,
  rejected_chunks: 0,
  transport: 'http',
  file_count: 2,
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

