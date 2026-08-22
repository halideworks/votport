// votport audit page: queryable event log viewer + JSONL export.
// AGPL-3.0-only.

import { api, formatWhen, requireSession } from '/assets/admin-common.js';

const $ = (id) => document.getElementById(id);

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

async function load() {
  // Newest window first: fetch a bounded page from the beginning of the log
  // and display its tail; the JSONL export covers full-history needs.
  const rows = await api('/api/admin/audit?limit=10000');
  const container = $('audit-log');
  container.replaceChildren();
  $('audit-range').textContent = `${rows.length} rows shown`;
  if (!rows.length) {
    container.textContent = 'No audit rows yet.';
    return;
  }
  for (const row of [...rows].reverse()) {
    container.append(renderRow(row));
  }
}

$('refresh').addEventListener('click', () => {
  load().catch((error) => {
    $('audit-log').textContent = error.message;
  });
});

const session = await requireSession();
if (!session.pages.includes('audit')) {
  window.location.replace('/links');
}
await load().catch((error) => {
  $('audit-log').textContent = error.message;
});
