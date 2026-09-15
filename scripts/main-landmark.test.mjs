import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

const pages = [
  'audit', 'automation', 'deliver', 'index', 'notifications', 'receive',
  'request', 'send', 'storage', 'system', 'tenants', 'trade-routes',
  'verify', 'workflows',
];

test('every web page has an early skip link and one main landmark', async () => {
  for (const page of pages) {
    const html = await readFile(new URL(`../web/${page}.html`, import.meta.url), 'utf8');
    const body = html.slice(html.indexOf('<body'), html.indexOf('</body>'));
    const skip = '<a class="skip-link" href="#main-content">Skip to content</a>';
    assert.equal((body.match(/<a class="skip-link"/g) || []).length, 1, `${page}: one skip link`);
    assert.equal((body.match(/<main\b/g) || []).length, 1, `${page}: one main landmark`);
    assert.match(body, /<main id="main-content" tabindex="-1">/);
    assert.ok(body.indexOf(skip) >= 0, `${page}: skip link is present`);
    assert.doesNotMatch(body.slice(0, body.indexOf(skip)), /<(?:a|button|input|select|textarea|summary|details)\b/,
      `${page}: skip link is first focusable element`);
  }
});
