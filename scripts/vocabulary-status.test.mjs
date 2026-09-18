// Finding 446: object classes print mapped labels, not raw wire values. The
// three lowercase-badge classes (request link, delivery link, automation
// token) join the mapped ones, "Closed" in the receive filter names a real
// card badge, and incomplete sessions plus webhook attempts reuse the
// timeline's prose instead of wire strings.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const read = (p) => readFile(new URL(p, import.meta.url), 'utf8');

test('request link badges come from one mapped table that the Closed filter matches', async () => {
  const script = await read('../web/assets/page-receive.js');
  assert.match(script, /const linkStatusNames = \{ open: 'Open', closed: 'Closed', expired: 'Expired' \};/);
  assert.match(script, /linkStatusNames\[link\.usable \? 'open' : link\.active \? 'expired' : 'closed'\]/);
  const page = await read('../web/receive.html');
  assert.match(page, /<option value="closed">Closed<\/option>/);
  assert.doesNotMatch(script, /badge\.textContent = link\.usable/);
});

test('delivery link and token badges print mapped Sentence-case labels', async () => {
  const deliver = await read('../web/assets/page-deliver.js');
  assert.match(deliver, /const grantStatusNames = \{ active: 'Active', used: 'Used up', expired: 'Expired', revoked: 'Revoked' \};/);
  assert.match(deliver, /badge\.textContent = grantStatusNames\[status\];/);
  const automation = await read('../web/assets/page-automation.js');
  assert.match(automation, /const tokenStatusNames = \{ active: 'Active', expired: 'Expired', revoked: 'Revoked' \};/);
  assert.match(automation, /badge\.textContent = tokenStatusNames\[status\];/);
});

test('incomplete sessions reuse the timeline outcome words', async () => {
  const timeline = await read('../web/assets/timeline.js');
  assert.match(timeline, /export const outcomeWords = \{/);
  assert.match(timeline, /cancelled: 'Cancelled by the sender'/);
  assert.match(timeline, /interrupted: 'Session went idle and expired'/);
  assert.match(timeline, /rejected: 'Refused before the first file arrived'/);
  assert.match(timeline, /return \{ text: outcomeWords\[event\.kind\] \};/);
  const receive = await read('../web/assets/page-receive.js');
  assert.match(receive, /import \{ narrate, outcomeWords, summarize \} from '\/assets\/timeline\.js';/);
  assert.match(receive, /outcomeWords\[event\.outcome\] \?\? event\.outcome/);
  assert.doesNotMatch(receive, /· \$\{event\.outcome\}`/);
});

test('webhook attempt rows print mapped status labels', async () => {
  const script = await read('../web/assets/page-workflows.js');
  assert.match(script, /const attemptStatusNames = \{/);
  assert.match(script, /pending: 'Pending'/);
  assert.match(script, /delivered: 'Delivered'/);
  assert.match(script, /dead: 'Failed; retries exhausted'/);
  assert.match(script, /superseded: 'Superseded'/);
  assert.match(script, /attemptStatusNames\[attempt\.status\] \?\? attempt\.status/);
  assert.doesNotMatch(script, /Event \$\{attempt\.event_id\} · \$\{attempt\.status\}`/);
});
