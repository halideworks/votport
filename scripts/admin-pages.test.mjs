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

test('receive and deliver pages keep transfer concerns separate', () => {
  assert.match(receive, /page-receive\.js/);
  assert.match(receive, /id="create-notifications"/);
  assert.doesNotMatch(receive, /library-input|automation-token-form/);
  assert.match(deliver, /page-deliver\.js/);
  assert.match(deliver, /id="deliver-notifications"/);
  assert.match(receiveScript, /notifications: (?:creatingRoute \?[^\n]+: )?createNotifications\.read\(\)/);
  assert.match(deliverScript, /notifications: (?:creatingRoute \?[^\n]+: )?createNotifications\.read\(\)/);
  assert.match(receiveScript, /notificationDetails\([\s\S]+events: uploadEvents/);
  assert.match(deliverScript, /notificationDetails\([\s\S]+events: downloadEvents/);
  assert.match(receiveScript, /notification-details\[open\]/);
});

test('loading more requests scans the page once for unsaved forms', () => {
  // Refresh used to run a querySelectorAll inside a walk over every card on
  // screen, so each Load more redid the whole page per click (finding 536).
  assert.match(
    receiveScript,
    /for \(const editor of container\.querySelectorAll\('\[data-unsaved\]'\)\) \{[\s\S]+?editor\.closest\('\[data-link-id\]'\)/,
  );
  assert.doesNotMatch(receiveScript, /map\(\(card\) => \[card\.dataset\.linkId, \[\.\.\.card\.querySelectorAll/);
  // The omitted-edit decision reads membership sets, not a rescan per entry.
  assert.match(receiveScript, /append \? evictedIds\.has\(id\) : !listedIds\.has\(id\)/);
  assert.doesNotMatch(receiveScript, /evicted\.some\(\(card\) => card\.dataset\.linkId === id\)/);
});

test('issued request status filter uses the shared form control styling', () => {
  assert.match(receive, /<div class="grid">[\s\S]*id="links-status"/);
  assert.match(style, /input,\s*textarea,\s*\.card select\s*\{[\s\S]*display: block;[\s\S]*width: 100%;[\s\S]*background: var\(--ink-3\);/);
  assert.match(style, /input:focus,\s*textarea:focus,\s*\.card select:focus\s*\{[\s\S]*border-color: var\(--border-active\);/);
  assert.doesNotMatch(style, /^select\s*\{/m);
});

test('admin navigation exposes the current page and tenant selector', () => {
  assert.match(commonScript, /link\.setAttribute\('aria-current', 'page'\)/);
  for (const page of [receive, deliver, workflows, storage, automation, audit, tenants, system]) {
    assert.match(page, /<select id="tenant-switcher" aria-label="Tenant" hidden>/);
  }
});

test('public pages apply tenant branding from their metadata', () => {
  assert.match(brandingScript, /export function applyBranding/);
  assert.match(brandingScript, /document\.createElement\('img'\)/);
  assert.doesNotMatch(brandingScript, /innerHTML/);
  assert.match(brandingScript, /setProperty\('--progress', branding\.color\)/);
  assert.ok(brandingScript.includes('/^#[0-9a-fA-F]{6}$/'));
  assert.match(brandingScript, /if \(!branding\) return;/);
  assert.match(uploadScript, /applyBranding\(info\.branding, `\/api\/r\/\$\{token\}\/logo`\)/);
  assert.match(outboundScript, /applyBranding\(body\.branding, `\/api\/s\/\$\{encodeURIComponent\(token\)\}\/logo`\)/);
  assert.match(style, /\.masthead \.brand-logo/);
});

test('admin pages expose the branding forms', () => {
  assert.match(system, /id="branding-form"/);
  assert.match(system, /id="branding-color"[^>]*\n?[^>]*type="color"/);
  assert.match(system, /id="branding-logo"/);
  assert.match(systemScript, /api\('\/api\/admin\/branding\/default'/);
  assert.match(systemScript, /'Content-Type': file\.type/);
  assert.match(tenantsScript, /api\(`\/api\/admin\/branding\/\$\{key\}`/);
  assert.match(tenantsScript, /api\(`\/api\/admin\/branding\/\$\{key\}\/logo`/);
  assert.match(tenantsScript, /colorInput\.type = 'color'/);
  assert.match(tenantsScript, /logoInput\.type = 'file'/);
});

test('tenant admins get a self-branding page without platform controls', () => {
  assert.match(tenants, /id="self-branding" class="card" hidden/);
  assert.match(tenants, /id="platform-tenant-management" hidden/);
  assert.match(tenantsScript, /const session = await requireSession\(\);/);
  assert.match(tenantsScript, /session\.tenant/);
  assert.doesNotMatch(tenantsScript, /Promise\.all\(\[requireSession\(\), refreshTenants/);
  assert.match(commonScript, /selfBranding \? 'Branding'/);
});

test('tenant principals use a bounded searchable page', () => {
  assert.match(tenants, /id="principal-search"[^>]+maxlength="100"/);
  assert.match(tenants, /id="principal-load-more"[^>]+hidden/);
  assert.match(tenantsScript, /api\(`\/api\/admin\/principals\?\$\{params\}`\)/);
  assert.match(tenantsScript, /limit: String\(PRINCIPAL_PAGE_SIZE\)/);
  assert.match(tenantsScript, /setTimeout\([\s\S]*refreshPrincipals\(true\)[\s\S]*200/);
  assert.match(tenantsScript, /principalRows\.concat\(page\.principals\)/);
  assert.match(tenantsScript, /refreshPrincipals\(true\)/);
});

test('list actions announce their outcome and copy buttons confirm', () => {
  assert.match(receive, /id="links-action-status"[^>]+role="status"/);
  assert.match(deliver, /id="outbound-grants-status"[^>]+role="status"/);
  assert.match(receiveScript, /announce\('links-action-status'/);
  assert.match(deliverScript, /announce\('outbound-grants-status'/);
  assert.match(deliverScript, /confirmModal\('Extend delivery'/);
  // Every clipboard write goes through copyToClipboard so the button flips to Copied.
  assert.doesNotMatch(receiveScript, /navigator\.clipboard/);
  assert.doesNotMatch(deliverScript, /navigator\.clipboard/);
  assert.match(commonScript, /export \{ copyToClipboard \}/);
});

test('repeated actions and help controls carry their context', () => {
  const pages = { receive, deliver, workflows, storage, automation, tenants, system, send, request, notifications };
  assert.equal(Object.values(pages).reduce((count, page) => count + (page.match(/class="hint-button"/g) || []).length, 0), 28);
  assert.equal([receive, deliver, storage, workflows].reduce((count, page) => count + (page.match(/class="form-advanced-with-hint"/g) || []).length, 0), 6);
  for (const [name, page] of Object.entries(pages)) {
    for (const heading of page.matchAll(/<(h2|h3|legend|summary)\b[^>]*>[\s\S]*?<\/\1>/g)) {
      assert.doesNotMatch(heading[0], /class="hint-button"/, `${name}: help control remains inside ${heading[1]}`);
    }
  }
  assert.match(receiveScript, /copy\.setAttribute\('aria-label', `Copy request link: \$\{link\.label\}`\)/);
  assert.match(receiveScript, /qrButton\.setAttribute\('aria-label', `Show QR code: \$\{link\.label\}`\)/);
  assert.match(receiveScript, /qrButton\.setAttribute\('aria-label', `\$\{qr\.hidden \? 'Show' : 'Hide'\} QR code: \$\{link\.label\}`\)/);
  assert.match(receiveScript, /activeButton\.setAttribute\('aria-label', `\$\{link\.active \? 'Deactivate' : 'Reactivate'\} request link: \$\{link\.label\}`\)/);
  assert.match(receiveScript, /holdButton\.setAttribute\('aria-label', `\$\{link\.legal_hold \? 'Release hold' : 'Legal hold'\}: \$\{link\.label\}`\)/);
  assert.match(receiveScript, /\$\('create-notification-options'\)\.closest\('\.form-advanced-with-hint'\)\.hidden = true/);
  assert.match(deliverScript, /newAddress\.setAttribute\('aria-label', `Replace link: \$\{grant\.label \|\| grant\.name\}`\)/);
  assert.match(deliverScript, /extend\.setAttribute\('aria-label', `Extend 7 days: \$\{grant\.label \|\| grant\.name\}`\)/);
  assert.match(deliverScript, /revoke\.setAttribute\('aria-label', `Revoke: \$\{grant\.label \|\| grant\.name\}`\)/);
  assert.equal((system.match(/<button[^>]*aria-label="Save [^"]+"[^>]*>Save<\/button>/g) || []).length, 7);
  assert.match(workflowsScript, /row\.querySelector\(`\[data-key="\$\{subjectKey\}"\]`\)\.addEventListener\('input', updateRemoveName\)/);
  assert.match(tenantsScript, /summary\.setAttribute\('aria-label', `Edit namespace: \$\{tenant\.key\}`\)/);
});

test('setting a legal hold confirms and describes the retention pause', () => {
  assert.match(receiveScript, /holdButton = button\(link\.legal_hold \? 'Release hold' : 'Legal hold', 'tiny ghost', async \(control\) => \{[\s\S]*?if \(!\(await confirmModal\(\s*'Set legal hold',[\s\S]*?the retention sweep is suspended until the hold is released\.[\s\S]*?'Set hold',[\s\S]*?\)\)\) return;/);
  assert.match(receiveScript, /Legal hold blocks manual deletion and suspends the retention sweep until released\./);
  assert.match(receiveScript, /Manual deletion of stored files and transfer history is disabled and the retention sweep is suspended while this request is under legal hold\./);
});

test('the hidden files deployment value carries the dot-name hint', () => {
  assert.match(system, /<dt>Hidden files<button type="button" class="hint-button" aria-label="Help about hidden files" data-hint="A hidden file is one whose name starts with a dot\. When blocked, an upload that contains one is refused\."><\/button><\/dt>/);
});

test('connection and project ID help each state the name and audience once', () => {
  assert.doesNotMatch(storage, /This local ID is filled from the name/);
  assert.match(storage, /<summary>Connection ID<\/summary>[\s\S]*?Filled from the connection name\. People choose the connection by name; scripts and agents use this ID\.<\/p>/);
  assert.doesNotMatch(storage, /Connection ID for scripts and agents/);
  assert.match(workflows, /<summary>Project ID<\/summary>[\s\S]*?Filled from the name\. Scripts and agents use this ID\./);
  assert.doesNotMatch(workflows, /agents and integrations/);
});

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

test('receive page carries the status strip and polls the status endpoint', async () => {
  for (const id of ['status-strip', 'stat-active', 'stat-today', 'stat-stored', 'stat-disk']) {
    assert.match(receive, new RegExp(`id="${id}"`), `${id} present`);
  }
  for (const id of ['status-strip', 'stat-active', 'stat-open', 'stat-deliveries', 'stat-disk']) {
    assert.match(deliver, new RegExp(`id="${id}"`), `deliver ${id} present`);
  }
  assert.doesNotMatch(receive, /stat-drain|stat-health/);
  assert.match(receiveScript, /startStatusPoll\(/);
  assert.match(deliverScript, /startStatusPoll\(/);
  const poll = await readFile(new URL('../web/assets/status-strip.js', import.meta.url), 'utf8');
  assert.match(poll, /\/api\/admin\/status\?since=/);
  assert.match(poll, /visibilitychange/);
  assert.match(receiveScript, /receiving-now/);
  assert.match(receiveScript, /How receiving works/);
  assert.match(deliverScript, /How delivering works/);
});

test('every admin page mounts the masthead search and results deep-link into their lists', () => {
  for (const [name, html] of [['receive', receive], ['deliver', deliver], ['workflows', workflows], ['storage', storage], ['automation', automation], ['audit', audit], ['tenants', tenants], ['system', system]]) {
    assert.match(html, /id="global-search-input"/, `${name} has the search box`);
    assert.match(html, /id="global-search-results"/, `${name} has the results panel`);
  }
  assert.match(receiveScript, /card\.id = `link-\$\{link\.id\}`/);
  assert.match(deliverScript, /card\.id = `grant-\$\{grant\.id\}`/);
  assert.match(receiveScript, /revealHash\(\)/);
  assert.match(deliverScript, /revealHash\(\)/);
});

test('non-destructive receive actions use undo toasts, destructive ones keep the modal', () => {
  const clearRecord = receiveScript.slice(receiveScript.indexOf("button('Clear record'"), receiveScript.indexOf("button('Delete stored files'"));
  assert.match(clearRecord, /deferred\(/);
  assert.match(receiveScript, /await undoable\(/);
  assert.doesNotMatch(clearRecord, /confirmModal\(/);
  // The deletion modal lives in the card handler (finding 533 moved the loop
  // into delete-stored-files.js); the destructive action keeps its confirm.
  const deleteFiles = receiveScript.slice(receiveScript.indexOf('async function deleteStoredFilesFromCard'), receiveScript.indexOf('function renderUpload'));
  assert.match(deleteFiles, /confirmModal\(/);
  assert.match(receiveScript, /keepalive: true/);
  assert.match(commonScript, /pagehide/);
  assert.match(commonScript, /createUndoQueue\(/);
});

test('each transfer opens a timeline dialog built from the record', () => {
  for (const id of ['timeline', 'timeline-stats', 'timeline-events', 'timeline-download', 'timeline-audit']) {
    assert.match(receive, new RegExp(`id="${id}"`), `${id} present`);
  }
  assert.match(receiveScript, /button\('Files and timeline'/);
  assert.match(receiveScript, /from '\/assets\/timeline\.js'/);
  assert.doesNotMatch(receiveScript, /transfer-log/);
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

test('the audit log can be read oldest first, the theme switch is a quiet link, and settings sections are not outlined', async () => {
  assert.match(audit, /id="audit-order"/);
  const auditScript = await readFile(new URL('../web/assets/page-audit.js', import.meta.url), 'utf8');
  assert.match(auditScript, /after_rowid/);
  assert.match(receive, /id="theme-toggle" class="link theme-toggle"/);
  assert.match(commonScript, /\^\(link\|grant\|job\|route\)-/);
  assert.match(system, /Reset to default/);
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

test('status strip banners a failed health probe or a draining instance', async () => {
  const statusStrip = await readFile(new URL('../web/assets/status-strip.js', import.meta.url), 'utf8');
  // The banner renders from the shared poll, so both pages inherit it.
  assert.match(statusStrip, /id = 'status-health-banner'/);
  assert.match(statusStrip, /status\?\.health === false/);
  assert.match(statusStrip, /status\?\.draining === true/);
  assert.match(statusStrip, /setAttribute\('role', 'alert'\)/);
  assert.match(statusStrip, /banner\?\.remove\(\)/);
  assert.match(statusStrip, /renderHealth\(status\)/);
  assert.match(style, /\.status-health-banner/);
});

test('admin timestamps carry the UTC zone name, matching logs, receipts and the audit export', () => {
  // Audit finding 405: formatWhen was a bare toLocaleString, so every admin
  // timestamp rendered in an unlabelled browser-local zone while the server's
  // logs, receipts and audit export all speak UTC.
  assert.match(commonScript, /export function formatWhen\(unixSeconds\) \{/);
  assert.match(
    commonScript,
    /\.toLocaleString\(\[\], \{\s*timeZone: 'UTC',\s*timeZoneName: 'short',\s*year: 'numeric',\s*month: 'short',\s*day: 'numeric',\s*hour: '2-digit',\s*minute: '2-digit',\s*\}\);/,
  );
});

test('the receive-link transfer limit is decimal GB on the web like the desktops', () => {
  assert.match(receive, /Transfer limit <span class="muted">GB, optional<\/span>/);
  // The cap is created in decimal GB and read back the same way; the binary
  // formatBytes stays for the file sizes beside it.
  assert.match(receiveScript, /max_bytes: Number\.isFinite\(maxGb\) \? maxGb \* 1000 \*\* 3 : null/);
  assert.doesNotMatch(receiveScript, /1024 \*\* 3/);
  assert.match(receiveScript, /function formatLimit\(bytes\) \{[\s\S]*?bytes \/ 1000 \*\* 3[\s\S]*? GB`/);
  assert.match(receiveScript, /limit \$\{formatLimit\(link\.max_bytes\)\}/);
});
