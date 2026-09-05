// The public pages offer the desktop app the same link, hidden until the
// page decides the visitor is on a desktop.
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import assert from 'node:assert/strict';

const request = await readFile(new URL('../web/request.html', import.meta.url), 'utf8');
const send = await readFile(new URL('../web/send.html', import.meta.url), 'utf8');
const upload = await readFile(new URL('../web/assets/upload.js', import.meta.url), 'utf8');
const outbound = await readFile(new URL('../web/assets/outbound.js', import.meta.url), 'utf8');

test('both pages carry a hidden Open in the app link', () => {
  assert.match(request, /<p class="muted" id="open-in-app" hidden><a id="open-in-app-link"[^>]*>Open in the votport app<\/a>/);
  assert.match(send, /<a id="open-in-app-link"[^>]*hidden>Open in the votport app<\/a>/);
});

test('each page builds the votport: link with its own origin and the token', () => {
  for (const [script, kind] of [[upload, 'r'], [outbound, 's']]) {
    assert.match(script, /function offerApp\(kind\)/);
    assert.match(script, /votport:\/\/\$\{kind\}\/\$\{encodeURIComponent\(token\)\}\?base=\$\{encodeURIComponent\(window\.location\.origin\)\}/);
    assert.match(script, new RegExp(`offerApp\\('${kind}'\\)`));
  }
});
