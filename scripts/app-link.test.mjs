// The public pages offer the desktop app the same link, hidden until the
// page decides the visitor is on a desktop.
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import assert from 'node:assert/strict';

const request = await readFile(new URL('../web/request.html', import.meta.url), 'utf8');
const send = await readFile(new URL('../web/send.html', import.meta.url), 'utf8');
const upload = await readFile(new URL('../web/assets/upload.js', import.meta.url), 'utf8');
const outbound = await readFile(new URL('../web/assets/outbound.js', import.meta.url), 'utf8');
const evidence = await readFile(new URL('../web/assets/delivery-evidence.js', import.meta.url), 'utf8');
const objectCard = await readFile(new URL('../web/assets/object-card.js', import.meta.url), 'utf8');

test('both pages carry a hidden Open in the app link', () => {
  assert.match(request, /<p class="muted" id="open-in-app" hidden><a id="open-in-app-link"[^>]*>Open in the votport app<\/a>/);
  assert.match(send, /<a id="open-in-app-link"[^>]*hidden>Open in the votport app<\/a>/);
});

test('every app link comes from the shared builder with its own origin and token', () => {
  assert.match(objectCard, /export function appLink\(kind, token\)/);
  assert.match(objectCard, /votport:\/\/\$\{kind\}\/\$\{encodeURIComponent\(token\)\}\?base=\$\{encodeURIComponent\(window\.location\.origin\)\}/);
  for (const [script, kind] of [[upload, 'r'], [outbound, 's']]) {
    assert.match(script, /function offerApp\(kind\)/);
    assert.match(script, /link\.href = appLink\(kind, token\)/);
    assert.match(script, new RegExp(`offerApp\\('${kind}'\\)`));
  }
  assert.match(evidence, /appLink\('s', token\)/);
});
