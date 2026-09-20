// Phase 1 interaction-latency measurement harness (measurement only, no speed
// assertions). Like the other browser suites, this script does NOT start a
// server: point BASE_URL, WORKFLOW_TEST_ROOT and ADMIN_PASSWORD at an isolated
// instance (suites.sh conventions), then run:
//   node scripts/interaction-latency-e2e.mjs
// Seeds realistic data (a 50k-file transfer through the real upload flow,
// library folders, links, grants, jobs, tenants, principals, audit rows),
// then measures every named user interaction with one warm-up plus N runs of
// act -> waitForFunction(expected DOM/state change) and writes a median/p95
// table to stdout and to LATENCY_REPORT as JSON.
// VOTPORT PROPRIETARY LICENSE.
import fs from 'node:fs/promises';
import http from 'node:http';
import { apiClient } from './browser-helpers.mjs';
import { chromium } from 'playwright';

const base = process.env.BASE_URL, root = process.env.WORKFLOW_TEST_ROOT;
if (!base || !root || !process.env.ADMIN_PASSWORD) throw new Error('Use an isolated instance with BASE_URL, WORKFLOW_TEST_ROOT and ADMIN_PASSWORD.');
const RUNS = Number(process.env.LATENCY_RUNS || 7);
const REPORT = process.env.LATENCY_REPORT || './latency-baseline.json';

// Scale knobs: one "realistic afternoon" of data, not a toy instance.
const LINKS = 120, GRANTS = 120, JOBS = 120, TENANTS = 60, AUDIT_CYCLES = 400;
const PRINCIPALS = process.env.VOTPORT_SCIM_TOKEN ? 400 : 0;
const BIG_FILES = 50_000, PICK_FILES = 10_000;
const TICK_FOLDERS = 24, TICK_FILES = 250, PAGE_FILES = 1500;
const SEARCH_TOKEN = 'search-150', SEARCH_MATCHES = 150;

const stamp = `lat${Date.now().toString(36)}`;
const bigLabel = `${stamp}-big-transfer`;

async function pooled(count, worker, width = 8) {
  let next = 0, failed = null;
  const attempt = async (index) => {
    for (let tries = 0; ; tries += 1) {
      try {
        await worker(index);
        return;
      } catch (error) {
        // Seeding bursts trip per-route rate limits; back off and retry.
        if (tries < 12 && /429/.test(String(error.message))) {
          await new Promise((resolve) => setTimeout(resolve, 1500));
        } else { throw error; }
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(width, count) }, async () => {
    while (next < count && !failed) {
      const index = next++;
      try { await attempt(index); } catch (error) { failed ??= error; }
    }
  }));
  if (failed) throw failed;
}

// Local webhook sink so the notification "Send test" round-trip can succeed.
const sinkHits = [];
const sink = http.createServer((request, response) => {
  request.resume();
  sinkHits.push(Date.now());
  response.end('ok');
});
await new Promise((resolve) => sink.listen(0, '127.0.0.1', resolve));
const sinkPort = sink.address().port;

const browser = await chromium.launch();
try {
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'reduce' });
  await context.addInitScript(() => Object.defineProperty(navigator, 'clipboard', {
    configurable: true, value: { writeText: async () => {} },
  }));
  const page = await context.newPage();
  const api2 = apiClient(context, base);
  await api2('admin/login', { password: process.env.ADMIN_PASSWORD });

  // ---------------------------------------------------------------- seed
  const seedLog = [];
  console.log(`Seeding: ${TENANTS} tenants…`);
  await pooled(TENANTS, (i) => api2('admin/tenants', { key: `${stamp}-t${String(i).padStart(2, '0')}`, label: `Latency tenant ${i}` }));
  seedLog.push(['tenants', TENANTS]);

  if (PRINCIPALS) {
    console.log(`Seeding: ${PRINCIPALS} principals via SCIM…`);
    await pooled(PRINCIPALS, async (i) => {
      const response = await fetch(`${base}/scim/v2/Users`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${process.env.VOTPORT_SCIM_TOKEN}`, 'Content-Type': 'application/scim+json' },
        body: JSON.stringify({ schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'], userName: `${stamp}-p${String(i).padStart(3, '0')}@example.test`, active: true }),
      });
      if (response.status !== 201) throw new Error(`SCIM create ${response.status}`);
    });
    seedLog.push(['principals', PRINCIPALS]);
  }

  console.log('Seeding: projects, jobs, links…');
  await api2('workflows/projects', { id: `${stamp}-proj`, label: `Latency project ${stamp}`, directory: `${stamp}-proj` }, 'PUT');
  await pooled(JOBS, (i) => api2('workflows/jobs', {
    operation_id: `${stamp}-op${i}`, project_id: `${stamp}-proj`,
    label: `Latency job ${String(i).padStart(3, '0')}${i === 7 ? ' LATQ7' : ''}`, expires_days: 30,
  }));
  seedLog.push(['delivery jobs', JOBS]);
  const linkBody = (label, dest) => ({
    label, dest, password: null, expires_days: null, max_bytes: null,
    retention_days: null, notifications: { mode: 'off', rules: [] }, workflow: null,
  });
  await pooled(LINKS, (i) => api2('admin/links', linkBody(`${stamp} request ${String(i).padStart(3, '0')}`, `${stamp}-in${i}`)));
  seedLog.push(['request links', LINKS]);

  console.log('Seeding: library folders and files…');
  const libraryPaths = [];
  for (let folder = 0; folder < TICK_FOLDERS; folder += 1) {
    for (let file = 0; file < TICK_FILES; file += 1) libraryPaths.push(`tick-${String(folder).padStart(2, '0')}/asset-${String(file).padStart(4, '0')}.dat`);
  }
  for (let folder = 0; folder < 2; folder += 1) {
    for (let file = 0; file < PAGE_FILES; file += 1) libraryPaths.push(`zpage-${folder}/asset-${String(file).padStart(4, '0')}.dat`);
  }
  for (let file = 0; file < SEARCH_MATCHES; file += 1) libraryPaths.push(`${SEARCH_TOKEN}/match-${String(file).padStart(4, '0')}.dat`);
  await pooled(libraryPaths.length, async (i) => {
    const response = await context.request.fetch(`${base}/api/admin/outbound-files?path=${encodeURIComponent(libraryPaths[i])}`, {
      method: 'POST', headers: { 'X-Votport': '1', 'Content-Type': 'application/octet-stream' }, data: 'x',
    });
    if (!response.ok()) throw new Error(`library upload ${response.status()}`);
  });
  seedLog.push(['library files', libraryPaths.length]);

  console.log('Seeding: delivery links…');
  await pooled(GRANTS, (i) => api2('admin/outbound-grants', {
    paths: [libraryPaths[i]], label: `${stamp} delivery ${String(i).padStart(3, '0')}`,
    expires_days: 30, password: null, max_downloads: null, notifications: { mode: 'off', rules: [] },
  }));
  seedLog.push(['outbound grants', GRANTS]);

  console.log(`Seeding: ${AUDIT_CYCLES} link create/delete cycles for the audit trail…`);
  await pooled(AUDIT_CYCLES, async (i) => {
    const { link: created } = await api2('admin/links', linkBody(`${stamp} audit ${i}`, `${stamp}-audit${i}`));
    await api2(`admin/links/${created.id}`, undefined, 'DELETE');
  }, 4);
  seedLog.push(['audit rows (approx)', AUDIT_CYCLES * 2 + LINKS + GRANTS + JOBS + TENANTS + PRINCIPALS]);

  const sinkDestination = await api2('notifications', {
    label: `${stamp} sink`, channel: 'webhook', target: 'Latency sink', enabled: true,
    url: `http://127.0.0.1:${sinkPort}/hook`,
  });

  // The big transfer ships through the real uploader, so records, sidecars
  // and stored files are exactly what production writes.
  console.log(`Seeding: one request link receiving ${BIG_FILES} stored files (real upload flow)…`);
  const { link: bigLink } = await api2('admin/links', linkBody(bigLabel, `${stamp}-big`));
  const bigName = (i) => `scan-batch-${String(i).padStart(5, '0')}-scene-comp-render-final-v003-approved-${String((i * 7919) % 100000).padStart(5, '0')}.exr`.padEnd(242, 'a');
  await page.goto(bigLink.url);
  await page.waitForSelector('#uploader:not([hidden])');
  await page.setInputFiles('#file-input', Array.from({ length: BIG_FILES }, (_, i) => ({
    name: bigName(i), mimeType: 'application/octet-stream', buffer: Buffer.from('x'),
  })), { timeout: 300000 });
  await page.click('#send');
  await page.waitForFunction(() => {
    const done = document.getElementById('done-card');
    return done && !done.hidden;
  }, undefined, { timeout: 900000, polling: 500 });
  seedLog.push(['stored files on big link', BIG_FILES]);

  const { link: pickLink } = await api2('admin/links', linkBody(`${stamp}-pick-link`, `${stamp}-pick`));
  console.log('Seeding done:', seedLog.map(([k, v]) => `${k}=${v}`).join(' '), `notification=${sinkDestination?.id ?? '?'}`);

  // ----------------------------------------------------------- harness core
  // Same-URL goto would be a same-document navigation and keep stale page
  // state (e.g. an applied workflow filter), so reload in that case.
  const open = async (path, ready, timeout = 30000) => {
    const url = `${base}${path}`;
    // A previous interaction (tenant switch) may leave a reload in flight.
    await page.waitForLoadState('load', { timeout: 30000 }).catch(() => {});
    if (page.url() === url) await page.reload({ waitUntil: 'domcontentloaded' });
    else await page.goto(url, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(new Function(`return ${ready}`), undefined, { timeout, polling: 100 });
  };
  // In-page act sources run as one evaluation: t0 and the user gesture land in
  // the same task, so no CDP round trip sits inside the measured window.
  const actSource = (source) => page.evaluate(new Function(`window.__t0 = performance.now();\n${source}`));

  const rows = [];
  const specContext = {};
  async function measure(spec) {
    const row = { name: spec.name, page: spec.page, runs: RUNS, samples_ms: [] };
    if (spec.skip) {
      row.skipped = spec.skip;
      rows.push(row);
      console.log(`  SKIP ${spec.name}: ${spec.skip}`);
      return;
    }
    try {
      for (let i = 0; i <= RUNS; i += 1) {
        if (i === 0 && spec.prepare) await spec.prepare();
        await spec.setup();
        const expectSrc = typeof spec.expect === 'function' ? spec.expect() : spec.expect;
        const started = spec.nodeTimed ? Date.now() : null;
        if (typeof spec.act === 'string') await actSource(spec.act);
        else {
          if (!spec.nodeTimed) await page.evaluate(() => { window.__t0 = performance.now(); });
          await spec.act();
        }
        await page.waitForFunction(new Function(`return ${expectSrc}`), undefined, { timeout: spec.timeout || 20000, polling: spec.polling || 'raf' });
        if (i > 0) row.samples_ms.push(spec.nodeTimed ? Date.now() - started : await page.evaluate(() => performance.now() - window.__t0));
        if (spec.then) await spec.then();
      }
      const sorted = [...row.samples_ms].sort((a, b) => a - b);
      const mid = sorted.length >> 1;
      row.median_ms = Math.round((sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2) * 10) / 10;
      row.p95_ms = Math.round(sorted[Math.ceil(sorted.length * 0.95) - 1] * 10) / 10;
    } catch (error) {
      row.error = String(error.message || error).split('\n')[0];
      row.runs = row.samples_ms.length;
    }
    rows.push(row);
    console.log(`  ${row.error ? 'ERROR' : 'ok'} ${spec.name}: ${row.error ?? `median ${row.median_ms}ms p95 ${row.p95_ms}ms`}`);
  }

  // ----------------------------------------------------------- interactions
  const card = page.locator(`#link-${bigLink.id}`);
  const receiveReady = `document.querySelectorAll('#links [data-link-id]').length >= 50`;
  const libraryRootReady = `document.querySelectorAll('#library-files .library-folder input').length >= 20`;
  const jobsReady = `document.querySelectorAll('.job-card').length === 50`;
  const tenantsReady = `document.querySelectorAll('#tenants [data-tenant]').length === 50`;
  // 'Files and timeline' and 'Delete stored files' render inside the upload
  // history accordion entries, so the accordion must be opened first.
  const uploadHead = card.locator('.upload-history .uploads > li, .upload-history .uploads > *').first();
  const openHistory = async () => {
    await open('/receive', receiveReady);
    await card.locator('.upload-history > summary').click();
    await page.waitForFunction(new Function(`return (() => { const list = document.querySelector('#link-${bigLink.id} .upload-history .uploads'); return list && list.childElementCount === 1; })()`), undefined, { timeout: 30000, polling: 100 });
  };
  const openTimelineFromHistory = async () => {
    await openHistory();
    await uploadHead.getByRole('button', { name: 'Files and timeline', exact: true }).click();
    await page.waitForFunction(() => document.querySelectorAll('#timeline-files .object-card').length === 100, undefined, { polling: 100 });
  };
  const timelineReady = `document.querySelector('#timeline').open && document.querySelectorAll('#timeline-files .object-card').length === 100`;

  const interactionGroups = [
    {
      page: '/receive', list: [
        {
          name: 'receive: request list load-more click', page: '/receive',
          setup: () => open('/receive', receiveReady),
          act: `document.getElementById('links-load-more').click();`,
          expect: `document.querySelectorAll('#links [data-link-id]').length >= 100`,
        },
        {
          name: 'receive: request search keystroke-to-results', page: '/receive',
          setup: () => open('/receive', receiveReady),
          act: `
            const input = document.getElementById('links-query');
            input.focus();
            input.value = '${bigLabel}';
            document.getElementById('links-filter').requestSubmit();`,
          expect: `document.querySelectorAll('#links [data-link-id]').length === 1`,
        },
        {
          name: 'receive: transfer history accordion open (fetches page)', page: '/receive',
          setup: () => open('/receive', receiveReady),
          act: () => card.locator('.upload-history > summary').click(),
          expect: `(() => { const details = document.querySelector('#link-${bigLink.id} .upload-history'); const list = details && details.querySelector('.uploads'); return details.open && list && list.childElementCount === 1 && details.querySelector('p.muted').textContent.startsWith('Showing transfers 1 to 1'); })()`,
          timeout: 30000,
        },
        {
          name: 'receive: upload retention accordion toggle', page: '/receive',
          setup: () => open('/receive', receiveReady),
          act: () => card.locator('details[data-unsaved] > summary').first().click(),
          expect: `!!document.querySelector('#link-${bigLink.id} details[data-unsaved][open] input')`,
        },
        {
          name: 'receive: files & timeline modal open (100-file page)', page: '/receive',
          setup: openHistory,
          act: () => uploadHead.getByRole('button', { name: 'Files and timeline', exact: true }).click(),
          expect: timelineReady,
          timeout: 30000,
        },
        {
          name: 'receive: timeline next page (files 101-200)', page: '/receive',
          setup: openTimelineFromHistory,
          act: `document.getElementById('timeline-next').click();`,
          expect: `document.getElementById('timeline-range').textContent.includes('files 101 to 200 of')`,
          timeout: 30000,
        },
        {
          name: 'receive: copy file-hash identity line', page: '/receive',
          setup: openTimelineFromHistory,
          act: () => page.locator('#timeline-files .file-id').first().click(),
          expect: `document.querySelector('#timeline-files .file-id').textContent === 'Copied'`,
        },
        {
          name: 'receive: delete stored files first click (confirm modal only)', page: '/receive',
          setup: openHistory,
          act: () => uploadHead.getByRole('button', { name: 'Delete stored files', exact: true }).click(),
          expect: `document.querySelector('#confirm').open && document.getElementById('confirm-title').textContent === 'Delete stored files'`,
          then: () => page.locator('#confirm-cancel').click(),
        },
        {
          name: 'receive: confirm modal cancel close', page: '/receive',
          setup: async () => {
            await openHistory();
            await uploadHead.getByRole('button', { name: 'Delete stored files', exact: true }).click();
            await page.waitForFunction(() => document.querySelector('#confirm').open, undefined, { polling: 100 });
          },
          act: `document.getElementById('confirm-cancel').click();`,
          expect: `!document.querySelector('#confirm').open`,
        },
        {
          name: 'global: header search keystroke-to-options', page: '/receive',
          setup: async () => {
            await open('/receive', receiveReady);
            await page.evaluate(() => { document.getElementById('global-search-input').value = ''; document.getElementById('global-search-results').replaceChildren(); });
          },
          act: `
            const input = document.getElementById('global-search-input');
            input.focus();
            input.value = '${stamp}-big';
            input.dispatchEvent(new Event('input', { bubbles: true }));`,
          expect: `document.querySelectorAll('#global-search-results [role="option"]').length >= 1`,
        },
        {
          name: 'nav: tenant switcher select (POST + reload + list paint)', page: '/receive',
          // The switch reloads the page; the reload races the switched session
          // cookie, so the reloaded page can settle in either scope (found
          // app-level race, see audit report). The sample waits for the
          // post-reload document and its first settled list state.
          nodeTimed: true,
          setup: async () => {
            await api2('admin/tenant', { tenant: '' });
            await open('/receive', receiveReady);
            specContext.timeOrigin0 = await page.evaluate(() => performance.timeOrigin);
          },
          act: `
            const select = document.getElementById('tenant-switcher');
            select.value = '${stamp}-t00';
            select.dispatchEvent(new Event('change', { bubbles: true }));`,
          expect: () => `performance.timeOrigin !== ${specContext.timeOrigin0} && document.readyState === 'complete' && (() => { const range = document.getElementById('links-range'); const cards = document.querySelectorAll('#links [data-link-id]').length; return range && (range.textContent === 'No requests.' || cards >= 50); })()`,
          timeout: 30000,
          then: async () => {
            await page.waitForLoadState('load', { timeout: 30000 }).catch(() => {});
            await page.waitForTimeout(400);
            await api2('admin/tenant', { tenant: '' });
          },
        },
      ],
    },
    {
      page: '/deliver', list: [
        {
          name: 'deliver: library folder tick (whole folder, 250 files)', page: '/deliver',
          setup: async () => {
            await open('/deliver', libraryRootReady);
            await page.evaluate(() => {
              const box = document.querySelector('input[aria-label="Select folder tick-00"]');
              if (box.checked) box.click();
            });
          },
          act: () => page.locator('input[aria-label="Select folder tick-00"]').click(),
          expect: `document.getElementById('library-selection-status').textContent.startsWith('250 files selected')`,
        },
        {
          name: 'deliver: library search keystroke-to-results', page: '/deliver',
          setup: () => open('/deliver', libraryRootReady),
          act: `
            const input = document.getElementById('library-search');
            input.focus();
            input.value = '${SEARCH_TOKEN}';
            input.dispatchEvent(new Event('input', { bubbles: true }));`,
          expect: `document.querySelectorAll('#library-files .library-file:not(.library-folder)').length === ${SEARCH_MATCHES}`,
          timeout: 30000,
        },
        {
          name: 'deliver: library pagination next page', page: '/deliver',
          setup: async () => {
            await open('/deliver', libraryRootReady);
            await page.locator('button[aria-label="Open folder zpage-0"]').first().click();
            await page.waitForFunction(() => document.querySelectorAll('#library-files .library-file').length === 1000, undefined, { polling: 100 });
          },
          act: `document.getElementById('library-pagination-next').click();`,
          expect: `document.querySelectorAll('#library-files .library-file').length === ${PAGE_FILES - 1000} && !document.getElementById('library-pagination-previous').hidden`,
        },
        {
          name: 'deliver: deliveries list load-more click', page: '/deliver',
          setup: () => open('/deliver', `document.querySelectorAll('#outbound-grants .link-item').length === 50`),
          act: `document.getElementById('outbound-grants-load-more').click();`,
          expect: `document.querySelectorAll('#outbound-grants .link-item').length === 100`,
        },
      ],
    },
    {
      page: '/r/<token>', list: [
        {
          name: `request: upload picker add ${PICK_FILES} files (pick-to-preview only)`, page: '/r/<token>',
          setup: async () => {
            await page.goto(pickLink.url, { waitUntil: 'domcontentloaded' });
            await page.waitForSelector('#uploader:not([hidden])');
            // The 10k File objects are built outside the timed window: they
            // stand in for what the OS file dialog hands the page for free.
            // Playwright's setInputFiles transport (a temp-file write plus
            // CDP per file) costs ~1s at this size and dominated the phase-1
            // baseline row, while the page's own admission for all 10k files
            // brackets at ~50-60ms. The timed window starts at the same
            // in-page boundary as every other row: input.files assignment
            // plus the change dispatch.
            await page.evaluate((count) => {
              window.__pickTransfer = new DataTransfer();
              for (let i = 0; i < count; i += 1) {
                window.__pickTransfer.items.add(new File(['x'], `pick-${String(i).padStart(5, '0')}.dpx`, { type: 'application/octet-stream' }));
              }
            }, PICK_FILES);
          },
          act: `
            const input = document.getElementById('file-input');
            input.files = window.__pickTransfer.files;
            input.dispatchEvent(new Event('change', { bubbles: true }));`,
          expect: `document.querySelectorAll('#file-list > li[data-path]').length === 200 && !document.getElementById('send').disabled && document.getElementById('totals').textContent.replaceAll(',', '').includes('${PICK_FILES} files')`,
          timeout: 60000,
        },
      ],
    },
    {
      page: '/audit', list: [
        {
          name: 'audit: table filter apply (event=link_created)', page: '/audit',
          setup: () => open('/audit', `document.querySelectorAll('#audit-log .audit-row').length === 250`),
          act: `
            document.getElementById('audit-event').value = 'link_created';
            document.getElementById('audit-filters').requestSubmit();`,
          expect: `document.querySelectorAll('#audit-log .audit-row').length === 250 && document.getElementById('audit-range').textContent.startsWith('Showing rows 1 to 250')`,
          timeout: 30000,
        },
        {
          name: 'audit: table load-more (+250 rows)', page: '/audit',
          setup: () => open('/audit', `document.querySelectorAll('#audit-log .audit-row').length === 250`),
          act: `document.getElementById('load-more').click();`,
          expect: `document.querySelectorAll('#audit-log .audit-row').length === 500`,
          timeout: 30000,
        },
      ],
    },
    {
      page: '/workflows', list: [
        {
          name: 'workflows: deliveries filter apply (one match)', page: '/workflows',
          setup: () => open('/workflows#jobs', jobsReady),
          act: `
            document.getElementById('workflow-query').value = 'LATQ7';
            document.getElementById('workflow-filters').requestSubmit();`,
          expect: `document.querySelectorAll('.job-card').length === 1`,
        },
        {
          name: 'workflows: deliveries load-more click', page: '/workflows',
          setup: () => open('/workflows#jobs', jobsReady),
          act: `document.getElementById('workflow-more').click();`,
          expect: `document.querySelectorAll('.job-card').length === 100`,
        },
        {
          name: 'workflows: job notification accordion toggle', page: '/workflows',
          setup: () => open('/workflows#jobs', jobsReady),
          act: () => page.locator('.job-card .notification-details > summary').first().click(),
          expect: `!!document.querySelector('.job-card .notification-details[open] .notification-mode')`,
        },
      ],
    },
    {
      page: '/tenants', list: [
        {
          name: 'tenants: tenant table load-more click', page: '/tenants',
          setup: () => open('/tenants', tenantsReady),
          act: `document.getElementById('tenant-load-more').click();`,
          expect: `document.querySelectorAll('#tenants [data-tenant]').length === ${TENANTS}`,
        },
        {
          name: 'tenants: principal search keystroke-to-results', page: '/tenants',
          skip: PRINCIPALS ? undefined : 'no VOTPORT_SCIM_TOKEN on this instance, so no principals exist',
          setup: () => open('/tenants', `document.querySelectorAll('#principals > *').length >= 50`),
          act: `
            const input = document.getElementById('principal-search');
            input.focus();
            input.value = '${stamp}-p007';
            input.dispatchEvent(new Event('input', { bubbles: true }));`,
          expect: `document.getElementById('principal-count').textContent.includes('of 1 ')`,
        },
        {
          name: 'tenants: edit namespace accordion toggle', page: '/tenants',
          setup: () => open('/tenants', tenantsReady),
          act: () => page.locator('#tenants [data-tenant] details > summary[aria-label^="Edit namespace"]').first().click(),
          expect: `!!document.querySelector('#tenants [data-tenant] details[open] form')`,
        },
      ],
    },
    {
      page: '/storage', list: [
        {
          name: 'storage: add storage editor open (form reveal)', page: '/storage',
          setup: () => open('/storage', `!document.getElementById('storage-new').disabled && !!document.getElementById('storage-new').offsetParent`),
          act: `document.getElementById('storage-new').click();`,
          expect: `!document.getElementById('workflow-save-storage').hidden`,
        },
        {
          name: 'storage: add storage editor close (form hide)', page: '/storage',
          setup: async () => {
            await open('/storage', `!document.getElementById('storage-new').disabled && !!document.getElementById('storage-new').offsetParent`);
            await page.locator('#storage-new').click();
            await page.waitForFunction(() => !document.getElementById('workflow-save-storage').hidden, undefined, { polling: 100 });
          },
          act: `document.getElementById('storage-close').click();`,
          expect: `document.getElementById('workflow-save-storage').hidden`,
        },
      ],
    },
    {
      page: '/system', list: [
        {
          name: 'system: settings save round-trip (retention days)', page: '/system',
          setup: () => open('/system', `!document.getElementById('smtp-form').inert`),
          act: `
            const input = document.getElementById('audit-retention-days');
            input.value = String(41 + Math.floor(Math.random() * 9));
            document.getElementById('retention-form').requestSubmit();`,
          expect: `document.getElementById('retention-note').textContent === 'Saved.'`,
        },
      ],
    },
    {
      page: '/notifications', list: [
        {
          name: 'notifications: send test button round-trip', page: '/notifications',
          setup: async () => {
            await open('/notifications', `document.querySelectorAll('#notification-destinations .card').length >= 1`);
            await page.evaluate(() => { document.getElementById('notification-notice').textContent = ''; });
          },
          act: () => page.locator('[data-notification-test]').first().click(),
          expect: `document.getElementById('notification-notice').textContent.startsWith('Test accepted')`,
        },
      ],
    },
  ];

  const total = interactionGroups.reduce((n, group) => n + group.list.length, 0);
  console.log(`Measuring ${total} interactions, warm-up + ${RUNS} runs each…`);
  for (const group of interactionGroups) for (const spec of group.list) await measure(spec);
  sink.close();

  // --------------------------------------------------------------- report
  const errors = rows.filter((row) => row.error);
  const meta = {
    phase: process.env.LATENCY_PHASE || 'baseline (no fixes)',
    base_url: base, engine: 'chromium', browser: browser.version(),
    runs_per_interaction: RUNS, threshold_ms: 150, seeded: Object.fromEntries(seedLog),
    big_link_label: bigLabel,
    note: 'wall-times include Playwright act dispatch + waitForFunction detection overhead; the picker act builds its 10k DataTransfer untimed and brackets from the in-page change dispatch',
    errors: errors.map((row) => ({ name: row.name, error: row.error })),
  };
  await fs.writeFile(REPORT, `${JSON.stringify({ meta, interactions: rows }, null, 2)}\n`);
  console.log(`\n=== Interaction latency baseline (${base}, chromium, ${RUNS} runs, threshold 150ms) ===`);
  console.log('interaction'.padEnd(58), 'page'.padEnd(12), 'median'.padStart(8), 'p95'.padStart(8), 'runs');
  for (const row of rows) {
    const cells = row.skipped
      ? ['—', '—', String(0), `SKIP: ${row.skipped}`]
      : row.error
        ? ['—', '—', String(row.runs), `ERROR: ${row.error}`]
        : [String(row.median_ms), String(row.p95_ms), String(row.runs), ''];
    console.log(`${row.name.padEnd(58)} ${row.page.padEnd(12)} ${cells[0].padStart(8)} ${cells[1].padStart(8)} ${cells[2].padStart(4)}  ${cells[3]}`);
  }
  console.log(`\nReport written to ${REPORT}`);
  if (errors.length) {
    console.error(`${errors.length} interaction(s) failed to measure`);
    process.exitCode = 2;
  }
} finally {
  sink.close();
  await browser.close();
}
