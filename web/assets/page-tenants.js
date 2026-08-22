// votport tenants page: namespace lifecycle for platform admins.
// AGPL-3.0-only.

import {
  alertModal,
  api,
  confirmModal,
  formatBytes,
  formatWhen,
  requireSession,
} from '/assets/admin-common.js';

const $ = (id) => document.getElementById(id);

function button(text, classes, onClick) {
  const element = document.createElement('button');
  element.type = 'button';
  element.className = classes;
  element.textContent = text;
  element.addEventListener('click', () => {
    onClick().catch?.((error) => alertModal(error.message));
  });
  return element;
}

function quotaText(tenant) {
  const parts = [];
  if (tenant.max_total_bytes) parts.push(`storage ${formatBytes(tenant.max_total_bytes)}`);
  if (tenant.max_links) parts.push(`${tenant.max_links} links`);
  if (tenant.max_sessions) parts.push(`${tenant.max_sessions} concurrent uploads`);
  return parts.length ? parts.join(' · ') : 'no quotas';
}

function renderTenant(tenant) {
  const card = document.createElement('div');
  card.className = 'card link-item';

  const head = document.createElement('div');
  head.className = 'head';
  const title = document.createElement('h3');
  title.textContent = tenant.key === '' ? 'Default' : tenant.key;
  const badge = document.createElement('span');
  badge.className = 'badge';
  badge.textContent = tenant.label || 'namespace';
  head.append(title, badge);
  card.append(head);

  const meta = document.createElement('p');
  meta.className = 'muted';
  const parts = [`created ${formatWhen(tenant.created_at)}`, quotaText(tenant)];
  if (tenant.admin_group) parts.push(`admins: ${tenant.admin_group}`);
  meta.textContent = parts.join(' · ');
  card.append(meta);

  if (tenant.key !== '') {
    card.append(
      button('Delete', 'tiny danger', async () => {
        if (
          !(await confirmModal(
            'Delete tenant',
            `Delete "${tenant.key}"? Refused while its links still exist. Files under the tenant prefix are deleted; if purge fails, retry Delete.`,
            'Delete',
          ))
        )
          return;
        try {
          await api(`/api/admin/tenants/${tenant.key}`, { method: 'DELETE' });
          await refreshTenants();
        } catch (error) {
          alertModal(error.message);
        }
      }),
    );
  }
  return card;
}

async function refreshTenants() {
  const { tenants } = await api('/api/admin/tenants');
  const container = $('tenants');
  container.replaceChildren();
  if (!tenants.length) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = 'No named tenants yet.';
    container.append(empty);
    return;
  }
  for (const tenant of tenants) {
    container.append(renderTenant(tenant));
  }
}

$('tenant-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('tenant-error').hidden = true;
  const maxTotal = parseInt($('tenant-max-total').value, 10);
  const maxLinks = parseInt($('tenant-max-links').value, 10);
  const maxSessions = parseInt($('tenant-max-sessions').value, 10);
  try {
    await api('/api/admin/tenants', {
      method: 'POST',
      body: JSON.stringify({
        key: $('tenant-key').value,
        label: $('tenant-label').value,
        admin_group: $('tenant-admin-group').value || null,
        max_total_bytes: Number.isFinite(maxTotal) ? maxTotal * 1024 ** 3 : null,
        max_links: Number.isFinite(maxLinks) ? maxLinks : null,
        max_sessions: Number.isFinite(maxSessions) ? maxSessions : null,
      }),
    });
    $('tenant-form').reset();
    await refreshTenants();
  } catch (error) {
    $('tenant-error').textContent = error.message;
    $('tenant-error').hidden = false;
  }
});

const session = await requireSession();
// The page itself is hidden from non-platform admins by the nav; direct
// navigation gets bounced to their home.
if (!session.pages.includes('tenants')) {
  window.location.replace('/links');
}
await refreshTenants();
