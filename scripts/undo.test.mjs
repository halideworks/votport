import assert from 'node:assert/strict';
import { test } from 'node:test';

import { createUndoQueue } from '../web/assets/undo.js';

function fakeTimers() {
  const timers = new Map();
  let next = 1;
  return {
    setTimer: (fn, ms) => { const id = next++; timers.set(id, { fn, ms }); return id; },
    clearTimer: (id) => timers.delete(id),
    fire: () => { for (const [id, { fn }] of [...timers]) { timers.delete(id); fn(); } },
    get armed() { return timers.size; },
  };
}

test('undo inside the window restores and never commits', async () => {
  const clock = fakeTimers();
  const calls = [];
  const queue = createUndoQueue({ ...clock, delayMs: 100 });
  const handle = queue.add({ commit: () => calls.push('commit'), restore: () => calls.push('restore') });
  assert.equal(queue.size, 1);
  await handle.undo();
  clock.fire();
  await handle.undo();
  assert.deepEqual(calls, ['restore']);
  assert.equal(queue.size, 0);
  assert.equal(clock.armed, 0);
});

test('the window closing commits once and reports settled', async () => {
  const clock = fakeTimers();
  const calls = [];
  const settled = [];
  const queue = createUndoQueue({ ...clock, delayMs: 100 });
  const handle = queue.add({
    commit: async () => { calls.push('commit'); },
    restore: () => calls.push('restore'),
    onSettled: (committed) => settled.push(committed),
  });
  clock.fire();
  await new Promise((resolve) => setImmediate(resolve));
  await handle.undo();
  assert.deepEqual(calls, ['commit']);
  assert.deepEqual(settled, [true]);
});

test('flush commits everything still waiting, for page unload', async () => {
  const clock = fakeTimers();
  const calls = [];
  const queue = createUndoQueue({ ...clock, delayMs: 100 });
  queue.add({ commit: () => calls.push('a') });
  const second = queue.add({ commit: () => calls.push('b') });
  await second.undo();
  await queue.flush();
  assert.deepEqual(calls, ['a']);
  assert.equal(queue.size, 0);
  assert.equal(clock.armed, 0);
});

test('a failing commit still reports settled', async () => {
  const clock = fakeTimers();
  const settled = [];
  const queue = createUndoQueue({ ...clock, delayMs: 100 });
  const handle = queue.add({
    commit: async () => { throw new Error('offline'); },
    onSettled: (committed) => settled.push(committed),
  });
  await assert.rejects(handle.commitNow(), /offline/);
  assert.deepEqual(settled, [true]);
});
