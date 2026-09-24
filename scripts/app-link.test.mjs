// The public pages offer the desktop app the same link, hidden until the
// page decides the visitor is on a desktop.
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { appLink, offerApp } from '../web/assets/object-card.js';

const request = await readFile(new URL('../web/request.html', import.meta.url), 'utf8');
const send = await readFile(new URL('../web/send.html', import.meta.url), 'utf8');
const upload = await readFile(new URL('../web/assets/upload.js', import.meta.url), 'utf8');
const outbound = await readFile(new URL('../web/assets/outbound.js', import.meta.url), 'utf8');
const evidence = await readFile(new URL('../web/assets/delivery-evidence.js', import.meta.url), 'utf8');

test('desktop offers reveal the encoded link and mobile offers stay hidden', (t) => {
  const link = { hidden: true }, holder = { hidden: true };
  const context = {
    navigator: { userAgent: 'Desktop' },
    window: { location: { origin: 'https://port.example' } },
    document: { getElementById: (id) => id === 'open-in-app-link' ? link : holder },
  };
  for (const [key, value] of Object.entries(context)) {
    const original = Object.getOwnPropertyDescriptor(globalThis, key);
    Object.defineProperty(globalThis, key, { configurable: true, value });
    t.after(() => original ? Object.defineProperty(globalThis, key, original) : delete globalThis[key]);
  }
  assert.equal(appLink('r', 'a/b'), 'votport://r/a%2Fb?base=https%3A%2F%2Fport.example');
  offerApp('r', 'a/b');
  assert.equal(link.href, 'votport://r/a%2Fb?base=https%3A%2F%2Fport.example');
  assert.equal(link.hidden, false);
  assert.equal(holder.hidden, false);
  for (const userAgent of ['Android', 'iPhone', 'iPad', 'iPod', 'Mobile']) {
    context.navigator.userAgent = userAgent;
    link.hidden = holder.hidden = true;
    offerApp('s', 'token');
    assert.equal(link.hidden, true);
    assert.equal(holder.hidden, true);
  }
  context.navigator.userAgent = 'Desktop';
  context.document.getElementById = () => null;
  assert.doesNotThrow(() => offerApp('s', 'token'));
  context.document.getElementById = (id) => id === 'open-in-app-link' ? link : null;
  offerApp('s', 'token');
  assert.equal(link.hidden, false);
  assert.equal(link.href, 'votport://s/token?base=https%3A%2F%2Fport.example');
});
