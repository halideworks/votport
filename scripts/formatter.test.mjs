// Formatting regressions: one decimal size and one duration formatter per
// language, minute rollover, and relative stamps with the absolute secondless.
// The formatter assertions run the real shared helpers.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

import { formatAgo, formatBytes, formatDuration, formatWhen } from '../web/assets/object-card.js';

const read = (path) => readFile(new URL(`../${path}`, import.meta.url), 'utf8');

test('461: one decimal size formatter and one duration formatter per language', async () => {
  // The shared web helper speaks decimal KB like the Rust human_bytes.
  assert.equal(formatBytes(0), '0 bytes');
  assert.equal(formatBytes(1), '1 byte');
  assert.equal(formatBytes(999), '999 bytes');
  assert.equal(formatBytes(1_000), '1.0 KB');
  assert.equal(formatBytes(99_950), '100 KB');
  assert.equal(formatBytes(999_499), '999 KB');
  assert.equal(formatBytes(999_500), '1.0 MB');
  assert.equal(formatBytes(1_536_000), '1.5 MB');
  assert.equal(formatBytes(412 * 1024 * 1024), '432 MB');
  assert.equal(formatBytes(250_000_000_000), '250 GB');
  assert.doesNotMatch(formatBytes(2 * 1024 * 1024), /KiB|MiB/);
  // Rates quote the same vocabulary; upload.js reuses the helper.
  const upload = await read('web/assets/upload.js');
  assert.doesNotMatch(upload, /function formatRate\(|function formatDuration\(/);
  assert.match(upload, /formatBytes\(Math\.round\(lastHashBps\)\)\}\/s/);
  assert.match(upload, /formatDuration\(remaining \/ lastSendBps\)\} left/);
  // Notifications show human sizes instead of bare bytes.
  const notify = await read('server/src/notify.rs');
  assert.match(notify, /human_bytes\(total\)/);
  assert.match(notify, /human_bytes\(total_bytes\)/);
  assert.match(notify, /human_bytes\(event\.received_bytes\)/);
  assert.doesNotMatch(notify, /\{total\} bytes/);
  // One duration formatter: whole seconds, fractional input rounds.
  assert.equal(formatDuration(45), '45s');
  assert.equal(formatDuration(160), '2m 40s');
  assert.equal(formatDuration(3900), '1h 5m');
  assert.equal(formatDuration(45.7), '46s');
});

test('506: the one duration formatter never rolls minutes over at 60', () => {
  // The retired per-call rounding printed 60m at 3599s and 1h 60m at 7199s.
  assert.equal(formatDuration(3599), '59m 59s');
  assert.equal(formatDuration(7199), '1h 59m');
  assert.equal(formatDuration(86399), '23h 59m');
});

test('462: stamps drop seconds and relative ages carry the absolute nearby', async () => {
  assert.match(formatWhen(0), /UTC/);
  assert.equal(formatWhen(0), formatWhen(59));
  assert.notEqual(formatWhen(0), formatWhen(60));
  const fixed = 1_700_000_460;
  assert.equal(formatAgo(fixed, fixed), 'just now');
  assert.equal(formatAgo(fixed - 45, fixed), 'just now');
  assert.equal(formatAgo(fixed - 180, fixed), '3 min ago');
  assert.equal(formatAgo(fixed - 2 * 3600, fixed), '2 h ago');
  assert.equal(formatAgo(fixed - 3 * 86400, fixed), '3 d ago');
  assert.equal(formatAgo(fixed + 300, fixed), 'in 5 min');
  const audit = await read('web/assets/page-audit.js');
  assert.match(audit, /formatAgo\(row\.at\)/);
  assert.match(audit, /when\.title = formatWhen\(row\.at\)/);
  const receive = await read('web/assets/page-receive.js');
  assert.match(receive, /node\('span', formatAgo\(event\.at\), 'when mono'\);\n\s*when\.title = formatWhen\(event\.at\);/);
  assert.match(receive, /when\.title = formatWhen\(upload\.completed_at\)/);
  assert.doesNotMatch(receive, /toLocaleTimeString\(\)/);
});
