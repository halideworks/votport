import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import vm from 'node:vm';

const source = await readFile(new URL('../web/assets/page-workflows.js', import.meta.url), 'utf8');
const helpers = source.slice(source.indexOf('let pendingRequest;'), source.indexOf('const initialFilters'));
const valid = { operation_id: 'operation', project_id: 'project', label: 'Delivery', expires_days: 7,
  metadata: { version: 'one' }, recipients: ['recipient'], not_before: null, deadline: null };

function load(storage) {
  const context = vm.createContext({ sessionStorage: storage, draftKey: 'draft' });
  vm.runInContext(helpers, context);
  return context;
}

test('blocked storage preserves the pending workflow operation in memory', () => {
  const context = load({ getItem() { throw new Error('blocked'); }, setItem() { throw new Error('quota'); }, removeItem() { throw new Error('blocked'); } });
  assert.equal(context.readRequestDraft(), null);
  context.writeRequestDraft(valid);
  assert.equal(context.readRequestDraft(), valid);
  context.writeRequestDraft(null);
  assert.equal(context.readRequestDraft(), null);
});

test('corrupt or invalid workflow drafts are discarded without breaking creation', () => {
  for (const value of ['broken json', JSON.stringify({ ...valid, recipients: [1] }), JSON.stringify({ ...valid, metadata: [] }), JSON.stringify({ ...valid, deadline: 1e20 }), JSON.stringify({ ...valid, operation_id: '' })]) {
    let removed = 0;
    const context = load({ getItem() { return value; }, removeItem() { removed++; } });
    assert.equal(context.readRequestDraft(), null);
    assert.equal(removed, 1);
  }
  const context = load({ getItem() { return JSON.stringify(valid); } });
  assert.equal(JSON.stringify(context.readRequestDraft()), JSON.stringify(valid));
});
