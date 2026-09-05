// The committed token files are exactly what the stylesheet generates, so
// the apps and the web cannot drift.
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { render, parseColor, OUTPUTS } from './design-tokens.mjs';

const root = new URL('../', import.meta.url);
const out = render(await readFile(new URL('web/assets/style.css', root), 'utf8'));

test('every generated token file matches the stylesheet', async () => {
  for (const [kind, path] of Object.entries(OUTPUTS)) {
    assert.equal(await readFile(new URL(path, root), 'utf8'), out[kind], `${path} is stale; run npm run design:tokens`);
  }
});

test('colours parse from hex and rgba', () => {
  assert.deepEqual(parseColor('#38bdf8'), [56, 189, 248, 1]);
  assert.deepEqual(parseColor('rgba(255, 255, 255, 0.025)'), [255, 255, 255, 0.025]);
  assert.throws(() => parseColor('rgb(0 0 0 / 60%)'));
});

test('the shells get both blocks', () => {
  assert.match(out.swift, /static let progress = dynamic\(dark: \(56, 189, 248, 1\), light: \(3, 105, 161, 1\)\)/);
  assert.match(out.xaml, /<ResourceDictionary x:Key="Light">[\s\S]*<Color x:Key="VotProgress">#FF0369A1<\/Color>/);
});
