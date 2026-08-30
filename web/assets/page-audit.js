// votport audit page: queryable event log viewer + JSONL export.
// VOTPORT PROPRIETARY LICENSE.

import { formatWhen, requireSession } from '/assets/admin-common.js';

const $ = (id) => document.getElementById(id);
const PAGE_SIZE = 250;
const INITIAL_CURSOR = '18446744073709551615';
let beforeRowid = INITIAL_CURSOR;
let loadedRows = 0;
let loading = false;
let appliedFilters = { q: '', event: '' };

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

function addEvents(rows) {
  const events = new Set(
    [...$('audit-event-options').options].map((option) => option.value),
  );
  for (const row of rows) events.add(row.event);
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
  when.className = 'muted';
  when.textContent = `${formatWhen(row.at)} · ${row.tenant || 'default'}`;

  const event = document.createElement('strong');
  event.textContent = ` ${row.event}`;

  const subject = document.createElement('span');
  subject.textContent = row.subject ? ` ${row.subject}` : '';

  const actor = document.createElement('span');
  actor.className = 'muted';
  actor.textContent = row.actor ? ` · actor ${row.actor}` : '';

  const keys = Object.keys(row.detail ?? {});
  let details;
  if (keys.length) {
    details = document.createElement('details');
    details.className = 'muted file-id';
    const summary = document.createElement('summary');
    summary.textContent = 'Details';
    const detail = document.createElement('div');
    detail.textContent = keys
      .map((key) => `${key}=${JSON.stringify(row.detail[key])}`)
      .join(' ');
    details.append(summary, detail);
  }

  line.append(when, event, subject, actor);
  if (details) line.append(details);
  return line;
}

async function load(reset = false) {
  if (loading) return;
  loading = true;
  for (const control of $('audit-filters').elements) control.disabled = true;
  $('refresh').disabled = true;
  $('load-more').disabled = true;
  if (reset) {
    beforeRowid = INITIAL_CURSOR;
    loadedRows = 0;
    $('audit-log').replaceChildren();
    $('audit-event-options').replaceChildren();
  }
  // The endpoint streams JSONL; an empty log is an empty body, so parse as
  // text rather than JSON.
  try {
    const query = new URLSearchParams({ limit: String(PAGE_SIZE), ...appliedFilters });
    query.set('before_rowid', beforeRowid);
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
    addEvents(rows);
    for (const row of rows) container.append(renderRow(row));
    loadedRows += rows.length;
    if (rows.length) beforeRowid = String(rows[rows.length - 1].rowid);
    $('audit-range').textContent = `${loadedRows} rows loaded`;
    $('load-more').hidden = rows.length < PAGE_SIZE;
  } finally {
    loading = false;
    for (const control of $('audit-filters').elements) control.disabled = false;
    $('refresh').disabled = false;
    $('load-more').disabled = false;
  }
}

function showLoadError(error) {
  if (loadedRows > 0) {
    $('audit-range').textContent = `${loadedRows} rows loaded · ${error.message}`;
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

const session = await requireSession();
if (!session.pages.includes('audit')) {
  window.location.replace('/receive');
}
updateExport();
await load(true).catch(showLoadError);
