// votport audit page: queryable event log viewer + JSONL export.
// VOTPORT PROPRIETARY LICENSE.

import { formatWhen, requireSession } from '/assets/admin-common.js';

const $ = (id) => document.getElementById(id);
const PAGE_SIZE = 250;
const MAX_RENDERED_ROWS = 1000;
const INITIAL_CURSOR = '18446744073709551615';
let beforeRowid = INITIAL_CURSOR;
// Oldest first walks forward with the server's (at, rowid) keyset cursor:
// since is the last row's second and after_rowid its rowid. Newest first
// walks back from the top with before_rowid.
let order = 'newest';
let sinceAt = '0';
let afterRowid = '0';
let loadedRows = 0;
let loading = false;
// A search result deep-links here with the phrase in the query string.
const initialQuery = new URLSearchParams(window.location.search).get('q') || '';
let appliedFilters = { q: initialQuery, event: '' };

function formFilters() {
  return {
    q: $('audit-query').value,
    event: $('audit-event').value,
  };
}

function updateExport() {
  const query = new URLSearchParams({ limit: '10000' });
  for (const [key, value] of Object.entries(appliedFilters)) {
    if (value.trim()) query.set(key, value);
  }
  $('export').href = `/api/admin/audit?${query}`;
}

function updateEvents() {
  const events = new Set(
    [...$('audit-log').querySelectorAll('.audit-event')].map((event) => event.textContent),
  );
  $('audit-event-options').replaceChildren(
    ...[...events].sort().map((event) => {
      const option = document.createElement('option');
      option.value = event;
      return option;
    }),
  );
}

function renderRow(row) {
  const line = document.createElement('div');
  line.className = 'audit-row';

  const when = document.createElement('span');
  when.className = 'audit-when muted';
  when.textContent = formatWhen(row.at);

  const tenant = document.createElement('span');
  tenant.className = 'audit-tenant muted';
  tenant.textContent = row.tenant || 'default';

  const event = document.createElement('strong');
  event.className = 'audit-event';
  event.textContent = row.event;

  const subject = document.createElement('span');
  subject.className = 'audit-subject';
  subject.textContent = row.subject || '';

  const actor = document.createElement('span');
  actor.className = 'audit-actor muted';
  actor.textContent = row.actor || '';

  line.append(when, tenant, event, subject, actor);
  const keys = Object.keys(row.detail ?? {});
  if (keys.length) {
    const details = document.createElement('details');
    details.className = 'audit-detail muted';
    const summary = document.createElement('summary');
    summary.textContent = 'Details';
    const detail = document.createElement('div');
    detail.textContent = keys
      .map((key) => `${key}=${JSON.stringify(row.detail[key])}`)
      .join(' ');
    details.append(summary, detail);
    line.append(details);
  }
  return line;
}

function rangeText() {
  const retained = $('audit-log').childElementCount;
  return retained ? `Showing rows ${loadedRows - retained + 1} to ${loadedRows}.` : '0 rows loaded';
}

async function load(reset = false) {
  if (loading) return;
  loading = true;
  const restoreMoreFocus = document.activeElement === $('load-more');
  for (const control of $('audit-filters').elements) control.disabled = true;
  $('refresh').disabled = true;
  $('load-more').disabled = true;
  if (reset) {
    order = $('audit-order').value;
    beforeRowid = INITIAL_CURSOR;
    sinceAt = '0';
    afterRowid = '0';
    loadedRows = 0;
    if ($('audit-log').contains(document.activeElement)) $('audit-range').focus();
    $('audit-log').replaceChildren();
    $('audit-event-options').replaceChildren();
  }
  // The endpoint streams JSONL; an empty log is an empty body, so parse as
  // text rather than JSON.
  try {
    const query = new URLSearchParams({ limit: String(PAGE_SIZE), ...appliedFilters });
    if (order === 'oldest') {
      query.set('since', sinceAt);
      query.set('after_rowid', afterRowid);
    } else {
      query.set('before_rowid', beforeRowid);
    }
    const response = await fetch(`/api/admin/audit?${query}`, {
      credentials: 'same-origin',
    });
    if (!response.ok) throw new Error(`request failed (${response.status})`);
    const text = await response.text();
    const rows = text
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line));
    const container = $('audit-log');
    if (!rows.length && loadedRows === 0) container.textContent = 'No audit rows yet.';
    const focusedRow = container.contains(document.activeElement) ? document.activeElement : null;
    for (const row of rows) {
      if (container.childElementCount === MAX_RENDERED_ROWS) container.firstElementChild.remove();
      container.append(renderRow(row));
    }
    updateEvents();
    if (focusedRow && !focusedRow.isConnected) $('audit-range').focus();
    loadedRows += rows.length;
    if (rows.length) {
      const last = rows[rows.length - 1];
      if (order === 'oldest') {
        sinceAt = String(last.at);
        afterRowid = String(last.rowid);
      } else {
        beforeRowid = String(last.rowid);
      }
    }
    $('audit-range').textContent = rangeText();
    $('load-more').hidden = rows.length < PAGE_SIZE;
  } finally {
    loading = false;
    for (const control of $('audit-filters').elements) control.disabled = false;
    $('refresh').disabled = false;
    $('load-more').disabled = false;
    if (restoreMoreFocus && document.activeElement === document.body) {
      ($('load-more').hidden ? $('audit-range') : $('load-more')).focus();
    }
  }
}

function showLoadError(error) {
  if (loadedRows > 0) {
    $('audit-range').textContent = `${rangeText()} · ${error.message}`;
  } else {
    $('audit-log').textContent = error.message;
  }
}

$('refresh').addEventListener('click', () => {
  load(true).catch(showLoadError);
});

$('audit-filters').addEventListener('submit', (event) => {
  event.preventDefault();
  appliedFilters = formFilters();
  updateExport();
  load(true).catch(showLoadError);
});

$('audit-order').addEventListener('change', () => {
  load(true).catch(showLoadError);
});

$('audit-clear').addEventListener('click', () => {
  $('audit-query').value = '';
  $('audit-event').value = '';
  appliedFilters = { q: '', event: '' };
  updateExport();
  load(true).catch(showLoadError);
});

$('load-more').addEventListener('click', () => {
  load().catch(showLoadError);
});

$('audit-query').value = initialQuery;
updateExport();
// The first page loads alongside the session check, one round trip for both.
const [session] = await Promise.all([requireSession(), load(true).catch(showLoadError)]);
if (!session.pages.includes('audit')) {
  window.location.replace('/receive');
}
