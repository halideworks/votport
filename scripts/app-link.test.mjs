// The public pages offer the desktop app the same link, hidden until the
// page decides the visitor is on a desktop.
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';

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
    assert.match(script, /import \{[^}]*offerApp[^}]*\} from '\/assets\/object-card\.js'/);
    assert.match(script, new RegExp(`offerApp\\('${kind}', token\\)`));
  }
  assert.match(evidence, /appLink\('s', token\)/);
});

test('desktop offers reveal the encoded link and mobile offers stay hidden', () => {
  const link = { hidden: true }, holder = { hidden: true };
  const context = vm.createContext({
    navigator: { userAgent: 'Desktop' },
    window: { location: { origin: 'https://port.example' } },
    document: { getElementById: (id) => id === 'open-in-app-link' ? link : holder },
  });
  vm.runInContext(objectCard.replaceAll('export ', ''), context);
  vm.runInContext("offerApp('r', 'a/b')", context);
  assert.equal(link.href, 'votport://r/a%2Fb?base=https%3A%2F%2Fport.example');
  assert.equal(link.hidden, false);
  assert.equal(holder.hidden, false);
  for (const userAgent of ['Android', 'iPhone', 'iPad', 'iPod', 'Mobile']) {
    context.navigator.userAgent = userAgent;
    link.hidden = holder.hidden = true;
    vm.runInContext("offerApp('s', 'token')", context);
    assert.equal(link.hidden, true);
    assert.equal(holder.hidden, true);
  }
  context.navigator.userAgent = 'Desktop';
  context.document.getElementById = () => null;
  assert.doesNotThrow(() => vm.runInContext("offerApp('s', 'token')", context));
  context.document.getElementById = (id) => id === 'open-in-app-link' ? link : null;
  vm.runInContext("offerApp('s', 'token')", context);
  assert.equal(link.hidden, false);
  assert.equal(link.href, 'votport://s/token?base=https%3A%2F%2Fport.example');
});
