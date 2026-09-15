import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';

const script = await readFile(new URL('../web/assets/page-workflows.js', import.meta.url), 'utf8');
const source = script.slice(script.indexOf('function canReprocess('), script.indexOf('function form('));
const project = { id: 'project', label: 'Incoming', receive: true, revision: 2, members: { sender: 'sender', observer: 'viewer' } };
const job = { id: 'old', received: {}, manifest: 'frozen', project: { id: 'project', revision: 1 }, state: 'failed' };

function setup(overrides = {}) {
  const requests = [], confirmations = [];
  const context = {
    admin: false, session: { subject: 'sender' }, projects: [project], window: { location: {} },
    button: (label, style, click) => ({ label, click }), guard: (action) => action(),
    refreshProjects: async () => {}, notice: () => {},
    confirmModal: async (...args) => { confirmations.push(args); return true; },
    api: async (...args) => { requests.push(args); return { job: { id: 'new' } }; },
    ...overrides,
  };
  const action = runInNewContext(`${source}\nreprocessAction`, context);
  return { action, context, requests, confirmations };
}

test('reprocess is offered only for inactive prepared receptions under changed rules', () => {
  const { action } = setup();
  for (const state of ['failed', 'retrying', 'awaiting_approval', 'ready']) assert.ok(action({ ...job, state }, project, true));
  for (const state of ['queued', 'preparing', 'exporting', 'cancelled', 'retiring', 'retired', 'suspended']) assert.equal(action({ ...job, state }, project, true), null);
  for (const change of [{ received: null }, { manifest: null }, { reprocessed_as: 'new' }]) assert.equal(action({ ...job, ...change }, project, true), null);
  assert.equal(action(job, { ...project, receive: false }, true), null);
  assert.equal(action(job, { ...project, revision: 1 }, true), null);
  assert.equal(action(job, undefined, true), null);
  assert.equal(setup({ session: { subject: 'observer' } }).action(job, project, false), null);
  assert.ok(setup({ admin: true, session: { subject: 'administrator' } }).action(job, project, true));
});

test('reprocess confirms new copies and binds the refreshed revision and frozen manifest', async () => {
  const state = setup();
  state.context.refreshProjects = async () => { state.context.projects = [{ ...project, revision: 3 }]; };
  await state.action(job, project, true).click();
  assert.equal(state.requests.length, 1);
  assert.equal(state.requests[0][0], '/api/workflows/jobs/old/reprocess');
  assert.deepEqual(JSON.parse(state.requests[0][1].body), { manifest: 'frozen', project_revision: 3 });
  assert.match(state.confirmations[0][1], /revision 3/);
  assert.match(state.confirmations[0][1], /may create new copies/);
  assert.equal(state.context.window.location.hash, '#job-new');
  const cancelled = setup({ confirmModal: async () => false });
  await cancelled.action(job, project, true).click();
  assert.equal(cancelled.requests.length, 0);
});
