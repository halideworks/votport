// votport audit page: queryable event log viewer + JSONL export.
// VOTPORT PROPRIETARY LICENSE.

import { formatWhen, requireSession } from '/assets/admin-common.js';

const $ = (id) => document.getElementById(id);
const PAGE_SIZE = 250;
const MAX_RENDERED_ROWS = 1000;
const INITIAL_CURSOR = '18446744073709551615';
// Audit rows have no shared server catalog. Seed stable production names, then
// merge names from retained rows so unknown historic names remain selectable.
const KNOWN_AUDIT_EVENTS = [
  'admin_login',
  'admin_login_failed',
  'admin_password_changed',
  'automation_refused',
  'automation_token_created',
  'automation_token_revoked',
  'backup_created',
  'backup_restore_pending',
  'backups_configured',
  'branding_deleted',
  'branding_logo_deleted',
  'branding_logo_updated',
  'branding_updated',
  'delivery_webhook_replayed',
  'job_notifications_changed',
  'link_active_changed',
  'link_created',
  'link_deleted',
  'link_legal_hold_changed',
  'link_notifications_changed',
  'link_password_failed',
  'link_unlocked',
  'notification_defaults_changed',
  'notification_destination_changed',
  'notification_destination_deleted',
  'outbound_downloaded',
  'outbound_fetch_minted',
  'outbound_file_deleted',
  'outbound_file_uploaded',
  'outbound_grant_created',
  'outbound_grant_extended',
  'outbound_grant_revoked',
  'outbound_grant_token_rotated',
  'outbound_integrity_failure',
  'outbound_notifications_changed',
  'principal_provisioned',
  'principal_revoked',
  'principal_unblocked',
  'push_admitted',
  'push_connected',
  'receive_workflow_changed',
  'received_file_deleted',
  'replica_pulled',
  'retention_clock_held',
  'scim_group_created',
  'scim_group_deleted',
  'scim_group_patched',
  'scim_group_replaced',
  'serve_admitted',
  'serve_completed',
  'session_rejected',
  'settings_updated',
  'sso_failed',
  'sso_login',
  'tenant_created',
  'tenant_deleted',
  'tenant_switched',
  'tenant_updated',
  'trade_endpoint_created',
  'trade_invitation_created',
  'trade_route_accepted',
  'upload_completed',
  'upload_record_cleared',
  'upload_session_created',
  'upload_session_ended',
  'uploads_expired',
];
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
  const newest = order === 'newest';
  if (newest) query.set('before_rowid', '0');
  const direction = newest ? 'newest' : 'oldest';
  const exportLink = $('export');
  exportLink.href = `/api/admin/audit?${query}`;
  exportLink.textContent = `Export ${direction} 10,000 rows`;
  exportLink.title = `Exports the current filters, ${direction} first, up to 10,000 rows`;
}

function updateEvents() {
  const events = new Set(KNOWN_AUDIT_EVENTS);
  for (const event of [...$('audit-log').querySelectorAll('.audit-event')].map((event) => event.textContent)) {
    events.add(event);
  }
  $('audit-event-options').replaceChildren(
    ...[...events].sort().map((event) => {
      const option = document.createElement('option');
      option.value = event;
      return option;
    }),
  );
}

function renderField(tag, className, label, text) {
  const field = document.createElement('span');
  field.className = `audit-field ${className.split(' ', 1)[0]}-field`;
  const caption = document.createElement('span');
  caption.className = 'audit-field-label';
  caption.textContent = `${label}:`;
  const value = document.createElement(tag);
  value.className = className;
  value.textContent = text;
  field.append(caption, value);
  return field;
}

function renderRow(row) {
  const line = document.createElement('div');
  line.className = 'audit-row';

  const when = renderField('span', 'audit-when muted', 'Time', formatWhen(row.at));
  const tenant = renderField('span', 'audit-tenant muted', 'Tenant', row.tenant || 'default');
  const event = renderField('strong', 'audit-event', 'Event', row.event || 'unknown');
  const subject = renderField('span', 'audit-subject', 'Subject', row.subject || 'None');
  const actor = renderField('span', 'audit-actor muted', 'Actor', row.actor || 'None');

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
    updateExport();
    beforeRowid = INITIAL_CURSOR;
    sinceAt = '0';
    afterRowid = '0';
    loadedRows = 0;
    if ($('audit-log').contains(document.activeElement)) $('audit-range').focus();
    $('audit-log').replaceChildren();
    updateEvents();
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
