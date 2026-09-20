// The pages share one $ lookup and one node builder from object-card.js;
// this pin keeps the copy-pasted definitions from coming back. The appLink
// builder keeps its own pin in app-link.test.mjs.
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { $, node } from '../web/assets/object-card.js';

const read = (name) => readFile(new URL(`../web/assets/${name}`, import.meta.url), 'utf8');

const dollarPages = [
  'delivery-evidence.js', 'login.js', 'outbound.js', 'page-audit.js',
  'page-automation.js', 'page-deliver.js', 'page-notifications.js',
  'page-receive.js', 'page-storage.js', 'page-system.js', 'page-tenants.js',
  'page-trade-routes.js', 'page-workflows.js', 'upload.js', 'verify.js',
];
const nodePages = [
  'notifications.js', 'page-notifications.js', 'page-storage.js',
  'page-trade-routes.js', 'page-workflows.js',
];

test('the shared $ lookup and node builder come from object-card.js', async () => {
  assert.equal(typeof $, 'function');
  assert.equal(typeof node, 'function');
  for (const name of dollarPages) {
    const script = await read(name);
    assert.match(script, /import \{[^}]*\$[^}]*\} from '\/assets\/object-card\.js';/, `${name} imports $ from object-card.js`);
    assert.doesNotMatch(script, /const \$ = \(id\) => document/, `${name} must not redefine $`);
  }
  for (const name of nodePages) {
    const script = await read(name);
    assert.match(script, /import \{[^}]*node[^}]*\} from '\/assets\/object-card\.js';/, `${name} imports node from object-card.js`);
    assert.doesNotMatch(script, /const node = /, `${name} must not redefine node`);
    assert.doesNotMatch(script, /^function node\(/m, `${name} must not redefine node`);
  }
});
