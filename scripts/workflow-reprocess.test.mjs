import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canReprocess } from '../web/assets/deliver-progress.js';
const project = { id: 'project', receive: true, revision: 2 };
const job = { received: {}, manifest: 'frozen', project: { id: 'project', revision: 1 }, state: 'failed' };

test('reprocess is offered only for inactive prepared receptions under changed rules', () => {
  for (const state of ['failed', 'retrying', 'awaiting_approval', 'ready']) assert.ok(canReprocess({ ...job, state }, project));
  for (const state of ['queued', 'preparing', 'exporting', 'cancelled', 'retiring', 'retired', 'suspended']) assert.equal(canReprocess({ ...job, state }, project), false);
  for (const change of [{ received: null }, { manifest: null }, { reprocessed_as: 'new' }]) assert.equal(canReprocess({ ...job, ...change }, project), false);
  assert.equal(canReprocess(job, { ...project, receive: false }), false);
  assert.equal(canReprocess(job, { ...project, revision: 1 }), false);
  assert.equal(canReprocess(job, undefined), false);
});
