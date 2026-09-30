import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import vm from 'node:vm';

const trade = await readFile(new URL('../web/assets/page-trade-routes.js', import.meta.url), 'utf8');
const picker = trade.slice(trade.indexOf('function showRequests('), trade.indexOf('async function loadRequests('));
const receive = await readFile(new URL('../web/assets/page-receive.js', import.meta.url), 'utf8');
const refresh = receive.slice(receive.indexOf('const key = status.receiving'), receive.indexOf(';', receive.indexOf('const key = status.receiving')) + 1);

test('request pagination keeps previous choices and appends without duplicates', () => {
  const select = { value: '', children: [],
    get options() { return this.children; },
    get selectedOptions() { return this.children.filter((option) => option.value === this.value); },
    replaceChildren() { this.children = []; },
    append(option) { this.children = this.children.filter((child) => child !== option); this.children.push(option); },
  };
  const elements = new Map([['trade-request', select], ['trade-request-more', {}], ['trade-request-help', {}]]);
  const context = vm.createContext({ $: (id) => elements.get(id),
    node: (_, textContent) => ({ textContent, value: '', dataset: {} }), requestCursor: null, requestSelected() {},
  });
  vm.runInContext(picker, context);
  const request = (id) => ({ id, label: id, dest: '' });
  context.showRequests({ links: [request('a'), request('b')], next_cursor: 'next' });
  select.value = 'a';
  context.showRequests({ links: [request('c'), request('a')], next_cursor: null }, '', true);
  assert.deepEqual(new Set(select.options.map((option) => option.value)), new Set(['', 'a', 'b', 'c']));
  assert.equal(select.options.length, 4);
  assert.equal(select.value, 'a');
  context.showRequests({ links: [], next_cursor: null }, '', true);
  assert.doesNotMatch(elements.get('trade-request-help').textContent, /No eligible/);
  assert.equal(elements.get('trade-request-more').hidden, true);
  select.value = '';
  context.showRequests({ links: [request('new')], next_cursor: null });
  assert.deepEqual(select.options.map((option) => option.value), ['', 'new']);
});

test('one of two uploads finishing on the same link changes the refresh key', () => {
  const transfer = { id: 'first', link_id: 'request', transport: 'http', started_at: 10, total: 100 };
  const key = (receiving) => vm.runInNewContext(`${refresh}\nkey`, { status: { receiving } });
  assert.notEqual(key([transfer, transfer]), key([transfer]));
  assert.notEqual(key([transfer]), key([{ ...transfer, id: 'replacement' }]));
  assert.notEqual(key([transfer]), key([]));
  const other = { ...transfer, id: 'other', link_id: 'other' };
  assert.equal(key([transfer, other]), key([other, transfer]));
});
