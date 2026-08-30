// votport audit page: queryable event log viewer + JSONL export.
// AGPL-3.0-only.

import { formatWhen, requireSession } from '/assets/admin-common.js';

const $ = (id) => document.getElementById(id);
const PAGE_SIZE = 250;
const INITIAL_CURSOR = '18446744073709551615';
let beforeRowid = INITIAL_CURSOR;
let loadedRows = 0;
let loading = false;

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

  const detail = document.createElement('div');
  detail.className = 'muted file-id';
  const keys = Object.keys(row.detail ?? {});
  if (keys.length) {
    detail.textContent = keys
      .map((key) => `${key}=${JSON.stringify(row.detail[key])}`)
      .join(' ');
  }

  line.append(when, event, subject);
  if (keys.length) line.append(detail);
  return line;
}

async function load(reset = false) {
  if (loading) return;
  loading = true;
  $('refresh').disabled = true;
  $('load-more').disabled = true;
  if (reset) {
    beforeRowid = INITIAL_CURSOR;
    loadedRows = 0;
    $('audit-log').replaceChildren();
  }
  // The endpoint streams JSONL; an empty log is an empty body, so parse as
  // text rather than JSON.
  try {
    const query = new URLSearchParams({ limit: String(PAGE_SIZE) });
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
    for (const row of rows) container.append(renderRow(row));
    loadedRows += rows.length;
    if (rows.length) beforeRowid = String(rows[rows.length - 1].rowid);
    $('audit-range').textContent = `${loadedRows} rows loaded`;
    $('load-more').hidden = rows.length < PAGE_SIZE;
  } finally {
    loading = false;
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

$('load-more').addEventListener('click', () => {
  load().catch(showLoadError);
});

const session = await requireSession();
if (!session.pages.includes('audit')) {
  window.location.replace('/links');
}
await load(true).catch(showLoadError);
