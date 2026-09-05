#!/usr/bin/env node
// Generates client/design/tokens.json from the :root and light blocks of
// web/assets/style.css, so the web and the apps read one set of colours.
// Run from the repo root: node scripts/design-tokens.mjs
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";

const css = readFileSync("web/assets/style.css", "utf8");

function block(selector) {
  const start = css.indexOf(`${selector} {`);
  if (start < 0) throw new Error(`no ${selector} block in style.css`);
  const body = css.slice(start, css.indexOf("\n}", start));
  const tokens = {};
  for (const [, name, value] of body.matchAll(/^\s*--([a-z0-9-]+):\s*([^;]+);/gm)) {
    tokens[name] = value.trim();
  }
  return tokens;
}

const dark = block(":root");
const light = { ...dark, ...block(':root[data-theme="light"]') };
const tokens = {
  generated: "scripts/design-tokens.mjs from web/assets/style.css",
  fonts: {
    text: "Plus Jakarta Sans",
    mono: "JetBrains Mono",
    wordmark: "Libre Caslon Display",
  },
  dark,
  light,
};
mkdirSync("client/design", { recursive: true });
writeFileSync("client/design/tokens.json", `${JSON.stringify(tokens, null, 2)}\n`);
console.log(`client/design/tokens.json: ${Object.keys(dark).length} dark, ${Object.keys(light).length} light tokens`);
