import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

const receive = await readFile(new URL('../web/receive.html', import.meta.url), 'utf8');
const deliver = await readFile(new URL('../web/deliver.html', import.meta.url), 'utf8');
const audit = await readFile(new URL('../web/audit.html', import.meta.url), 'utf8');
const tenants = await readFile(new URL('../web/tenants.html', import.meta.url), 'utf8');
const system = await readFile(new URL('../web/system.html', import.meta.url), 'utf8');
const workflows = await readFile(new URL('../web/workflows.html', import.meta.url), 'utf8');
const storage = await readFile(new URL('../web/storage.html', import.meta.url), 'utf8');
const tradeRoutes = await readFile(new URL('../web/trade-routes.html', import.meta.url), 'utf8');
const notifications = await readFile(new URL('../web/notifications.html', import.meta.url), 'utf8');
const automation = await readFile(new URL('../web/automation.html', import.meta.url), 'utf8');
const send = await readFile(new URL('../web/send.html', import.meta.url), 'utf8');
const request = await readFile(new URL('../web/request.html', import.meta.url), 'utf8');
const receiveScript = await readFile(new URL('../web/assets/page-receive.js', import.meta.url), 'utf8');
const deliverScript = await readFile(new URL('../web/assets/page-deliver.js', import.meta.url), 'utf8');
const tenantsScript = await readFile(new URL('../web/assets/page-tenants.js', import.meta.url), 'utf8');
const workflowsScript = await readFile(new URL('../web/assets/page-workflows.js', import.meta.url), 'utf8');
const systemScript = await readFile(new URL('../web/assets/page-system.js', import.meta.url), 'utf8');
const commonScript = await readFile(new URL('../web/assets/admin-common.js', import.meta.url), 'utf8');
const brandingScript = await readFile(new URL('../web/assets/branding.js', import.meta.url), 'utf8');
const uploadScript = await readFile(new URL('../web/assets/upload.js', import.meta.url), 'utf8');
const outboundScript = await readFile(new URL('../web/assets/outbound.js', import.meta.url), 'utf8');
const style = await readFile(new URL('../web/assets/style.css', import.meta.url), 'utf8');

const verify = await readFile(new URL('../web/verify.html', import.meta.url), 'utf8');

test('no page repeats an element id', () => {
  for (const [name, html] of Object.entries({ receive, deliver, workflows, storage, automation, audit, tenants, system, send, request, verify })) {
    const ids = [...html.matchAll(/\sid="([^"]+)"/g)].map((match) => match[1]);
    const seen = new Set();
    for (const id of ids) {
      assert.ok(!seen.has(id), `${name}.html repeats id="${id}"`);
      seen.add(id);
    }
  }
});

test('a stale sender tab reloads when the server reports a new web build', () => {
  assert.match(uploadScript, /webBuild = info\.web_build \|\| null/);
  assert.match(uploadScript, /info\.web_build !== webBuild[\s\S]{0,200}window\.location\.reload\(\)/);
  assert.match(uploadScript, /if \(!error\.cancelled\) await reloadIfServerUpdated\(\);/);
  assert.match(uploadScript, /if \(uploading && !reloading\) event\.preventDefault\(\);/);
  assert.match(uploadScript, /reloading = true;\s*window\.location\.reload\(\);/);
  // A finish refused as early is a 422; rebegin must key on that status.
  assert.match(uploadScript, /error\.status === 422 && \/not fully received\//);
});

test('every page applies the saved theme before paint and admin pages carry the toggle', async () => {
  for (const name of ['index', 'receive', 'deliver', 'workflows', 'storage', 'automation', 'tenants', 'audit', 'system', 'send', 'request', 'verify']) {
    const html = await readFile(new URL(`../web/${name}.html`, import.meta.url), 'utf8');
    assert.match(html, /<script src="\/assets\/theme\.js"><\/script>/, `${name} loads theme.js`);
  }
  for (const html of [receive, deliver, workflows, storage, automation, tenants, audit, system]) {
    assert.match(html, /id="theme-toggle"/);
  }
  const css = await readFile(new URL('../web/assets/style.css', import.meta.url), 'utf8');
  assert.match(css, /:root\[data-theme="light"\]/);
  assert.match(css, /prefers-color-scheme: light/);
  // The forced block and the system-preference block must carry the same
  // tokens, or a theme edit drifts between the two ways of reaching light.
  const forcedBlock = css.match(/:root\[data-theme="light"\] \{([^}]*)\}/)[1];
  const systemBlock = css.match(/:root:not\(\[data-theme="dark"\]\) \{([^}]*)\}/)[1];
  const tokens = (block) => block.split('\n').map((line) => line.trim()).filter(Boolean).join('\n');
  assert.equal(tokens(forcedBlock), tokens(systemBlock));
  // Fills, rules, and shadows read tokens; only the painting keeps raw black.
  const afterTokens = css.slice(css.indexOf('::selection'));
  assert.doesNotMatch(afterTokens, /rgba\(255, 255, 255, 0\.(02|03|05|06|08|1|12|25)\)/);
  assert.doesNotMatch(afterTokens, /rgba\(0, 0, 0, 0\.(3|45)\)/);
});

test('admin pages preload their module graph and fetch data alongside the session check', async () => {
  // The preload list must be the page's whole import graph, or the browser
  // discovers the missing module one round trip late.
  const graph = async (entry) => {
    const seen = new Set();
    const walk = async (file) => {
      if (seen.has(file)) return;
      seen.add(file);
      const source = await readFile(new URL(`../web/assets/${file}`, import.meta.url), 'utf8');
      for (const [, dep] of source.matchAll(/from '(?:\/assets\/|\.\/)([\w-]+\.js)'/g)) await walk(dep);
    };
    await walk(entry);
    return [...seen].sort();
  };
  for (const [name, html] of [['receive', receive], ['deliver', deliver], ['workflows', workflows], ['storage', storage], ['automation', automation], ['notifications', notifications], ['trade-routes', tradeRoutes], ['tenants', tenants], ['audit', audit], ['system', system]]) {
    const preloads = [...html.matchAll(/rel="modulepreload" href="\/assets\/([\w-]+\.js)"/g)].map((m) => m[1]).sort();
    assert.deepEqual(preloads, await graph(`page-${name}.js`), `${name} preloads its import graph`);
  }
  assert.match(receiveScript, /Promise\.all\(\[sessionReady, refreshLinksSafe\(\)\]\)/);
  assert.match(deliverScript, /Promise\.all\(\[sessionReady, refreshGrants\(\)/);
});

