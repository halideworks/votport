// Regression pins for the formatting findings 459, 460, 461, 462, 513 and
// 515: guarded plurals everywhere, one decimal size and one duration
// formatter per language, and relative stamps with the absolute secondless.
// The formatter assertions run the real shared helpers; the page-level pins
// hold the source shape the way copy-register.test.mjs does.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

import { formatAgo, formatBytes, formatDuration } from '../web/assets/object-card.js';

const read = (path) => readFile(new URL(`../${path}`, import.meta.url), 'utf8');

test('459: counts pluralise with the shared guard instead of file(s)', async () => {
  const upload = await read('web/assets/upload.js');
  assert.match(upload, /\$\{picked\.size\} file\$\{picked\.size === 1 \? '' : 's'\}, \$\{formatBytes\(total\)\} total/);
  assert.doesNotMatch(upload, /file\(s\)/);
  const cli = await read('client/cli/src/main.rs');
  assert.ok(cli.includes('if files == 1 { "file" } else { "files" }'), 'push output pluralises');
  assert.ok(cli.includes('if link.drops == 1 { "drop" } else { "drops" }'), 'request line pluralises drops');
  assert.doesNotMatch(cli, /\(s\)/);
  const notify = await read('server/src/notify.rs');
  assert.ok(notify.includes('if count == 1 { "file" } else { "files" }'), 'upload body pluralises');
  assert.ok(notify.includes('if file_count == 1 { "file" } else { "files" }'), 'outbound body pluralises');
  assert.doesNotMatch(notify, /file\(s\)/);
});

test('460: the three unguarded plurals carry a singular branch', async () => {
  const audit = await read('web/assets/page-audit.js');
  assert.match(audit, /retained === 1\s*\n\s*\? 'Showing row 1\.'/);
  const workflows = await read('web/assets/page-workflows.js');
  assert.match(workflows, /enrolled recipient\$\{project\.recipients\.length === 1 \? '' : 's'\}/);
  assert.match(workflows, /required field\$\{project\.required_metadata\.length === 1 \? '' : 's'\}/);
  const trade = await read('web/assets/page-trade-routes.js');
  assert.match(trade, /recent \$\{failures === 1 \? 'delivery' : 'deliveries'\}/);
});

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

test('513: live rates carry at 999.5 instead of printing 1000 KB/s', async () => {
  // The retired formatRate printed the division raw (audit finding 513);
  // the shared formatter carries into the next unit like human_bytes does.
  assert.equal(formatBytes(999_499), '999 KB');
  assert.equal(formatBytes(999_500), '1.0 MB');
  assert.equal(formatBytes(999_950), '1.0 MB');
  const upload = await read('web/assets/upload.js');
  assert.doesNotMatch(upload, /function formatRate\(/);
  assert.match(upload, /formatBytes\(Math\.round\(lastSendBps\)\)\}\/s/);
});

test('515: fractional durations round to the shown second', () => {
  // formatDuration is documented for whole seconds; a fractional estimate
  // from a live rate must never print raw (audit finding 515, 0.4s).
  assert.equal(formatDuration(0.4), '0s');
  assert.equal(formatDuration(0.5), '1s');
  assert.equal(formatDuration(45.7), '46s');
});

test('506: the one duration formatter never rolls minutes over at 60', () => {
  // The retired per-call rounding printed 60m at 3599s and 1h 60m at 7199s.
  assert.equal(formatDuration(3599), '59m 59s');
  assert.equal(formatDuration(7199), '1h 59m');
  assert.equal(formatDuration(86399), '23h 59m');
});

test('462: stamps drop seconds and relative ages carry the absolute nearby', async () => {
  const common = await read('web/assets/admin-common.js');
  assert.match(common, /month: 'short',/);
  assert.doesNotMatch(common, /second: '2-digit'/);
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
  assert.match(receive, /when\.textContent = formatAgo\(event\.at\);\n\s*when\.title = formatWhen\(event\.at\);/);
  assert.match(receive, /when\.title = formatWhen\(upload\.completed_at\)/);
  assert.doesNotMatch(receive, /toLocaleTimeString\(\)/);
});
