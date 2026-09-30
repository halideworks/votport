import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';

const source = (await readFile(new URL('../web/assets/notifications.js', import.meta.url), 'utf8'))
  .replace(/^import .*\n/gm, '').replace(/^export /gm, '');

test('older notification failures retain newer cached refreshes and current failures permit retry', async () => {
  for (const completeNewerFirst of [false, true]) {
    const requests = [];
    const load = runInNewContext(`${source}\nloadNotificationSettings`, {
      api: () => new Promise((resolve, reject) => requests.push({ resolve, reject })),
    });
    const older = load(), rejected = assert.rejects(older, /older failed/);
    const newer = load(true), catalog = { destinations: [] };
    if (completeNewerFirst) { requests[1].resolve(catalog); await newer; }
    requests[0].reject(new Error('older failed')); await rejected;
    assert.equal(load(), newer);
    assert.equal(requests.length, 2);
    if (!completeNewerFirst) requests[1].resolve(catalog);
    assert.equal(await newer, catalog);
    const failed = load(true), currentRejected = assert.rejects(failed, /current failed/);
    requests[2].reject(new Error('current failed')); await currentRejected;
    const retry = load(); assert.equal(requests.length, 4);
    requests[3].resolve(catalog); assert.equal(await retry, catalog);
  }
});
