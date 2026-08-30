// votport tenants page: namespace lifecycle for platform admins.
// VOTPORT PROPRIETARY LICENSE.

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

function nullableNumber(value) {
  if (value.trim() === '') return null;
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 1) {
    throw new Error('Quota values must be positive whole numbers.');
  }
  return number;
}

function nullableStorageBytes(value) {
  if (value.trim() === '') return null;
  const gib = Number(value);
  const bytes = Math.round(gib * 1024 ** 3);
  if (!Number.isFinite(gib) || gib <= 0 || !Number.isSafeInteger(bytes) || bytes < 1) {
    throw new Error('Storage quota must be a finite positive value.');
  }
  return bytes;
}

function editTenantForm(tenant) {
  const details = document.createElement('details');
  const summary = document.createElement('summary');
  summary.textContent = 'Edit namespace';
  details.append(summary);
  const form = document.createElement('form');
  form.className = 'tenant-edit';
  const fields = [
    ['Label', 'label', tenant.label || '', 'text'],
    ['Admin group', 'admin_group', tenant.admin_group || '', 'text'],
    ['Storage GiB', 'max_total_bytes', tenant.max_total_bytes === null || tenant.max_total_bytes === undefined ? '' : tenant.max_total_bytes / 1024 ** 3, 'number'],
    ['Link limit', 'max_links', tenant.max_links ?? '', 'number'],
    ['Concurrent uploads', 'max_sessions', tenant.max_sessions ?? '', 'number'],
  ];
  const grid = document.createElement('div');
  grid.className = 'grid';
  const inputs = {};
  for (const [label, key, value, type] of fields) {
    const wrapper = document.createElement('label');
    wrapper.textContent = label;
    const input = document.createElement('input');
    input.type = type;
    input.value = value;
    if (type === 'number') {
      input.min = key === 'max_total_bytes' ? String(1 / 1024 ** 3) : '1';
      input.step = key === 'max_total_bytes' ? 'any' : '1';
    }
    wrapper.append(input);
    grid.append(wrapper);
    inputs[key] = input;
  }
  const save = document.createElement('button');
  save.type = 'submit';
  save.className = 'tiny';
  save.textContent = 'Save';
  const error = document.createElement('p');
  error.className = 'error';
  error.hidden = true;
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!form.reportValidity()) return;
    save.disabled = true;
    error.hidden = true;
    try {
      const storageBytes = nullableStorageBytes(inputs.max_total_bytes.value);
      await api(`/api/admin/tenants/${encodeURIComponent(tenant.key)}`, {
        method: 'PATCH',
        body: JSON.stringify({
          label: inputs.label.value,
          admin_group: inputs.admin_group.value.trim() || null,
          max_total_bytes: storageBytes,
          max_links: nullableNumber(inputs.max_links.value),
          max_sessions: nullableNumber(inputs.max_sessions.value),
        }),
      });
      await refreshTenants();
    } catch (requestError) {
      error.textContent = requestError.message;
      error.hidden = false;
      save.disabled = false;
    }
  });
  form.append(grid, save, error);
  details.append(form);
  return details;
}

function renderTenant(tenant, usage) {
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
  const parts = [
    `created ${formatWhen(tenant.created_at)}`,
    `${formatBytes(usage?.received_bytes || 0)} received · ${usage?.links || 0} links`,
    quotaText(tenant),
  ];
  if (tenant.admin_group) parts.push(`admins: ${tenant.admin_group}`);
  meta.textContent = parts.join(' · ');
  card.append(meta);
  if (tenant.key !== '') card.append(editTenantForm(tenant));

  if (tenant.key !== '') {
    card.append(
      button('Delete', 'tiny danger', async () => {
        if (
          !(await confirmModal(
            'Delete tenant',
            tenant.key.includes('/')
              ? `Delete "${tenant.key}"? Refused while its links still exist. No files are deleted: nothing was ever stored under a key with a separator.`
              : `Delete "${tenant.key}"? Refused while its links still exist. Files under the tenant prefix are deleted; if purge fails, retry Delete.`,
            'Delete',
          ))
        )
          return;
        try {
          // Encoded: a key stored before the server required one segment
          // would otherwise build a two-segment path that matches no route.
          await api(`/api/admin/tenants/${encodeURIComponent(tenant.key)}`, {
            method: 'DELETE',
          });
          await refreshTenants();
        } catch (error) {
          alertModal(error.message);
        }
      }),
    );
  }
  return card;
}

function grantText(grants) {
  if (!Array.isArray(grants) || !grants.length) return 'no grants';
  return grants
    .map((grant) => `${grant.tenant === '' ? 'default' : grant.tenant}/${grant.role}`)
    .join(', ');
}

function renderPrincipal(principal) {
  const card = document.createElement('div');
  card.className = 'card link-item';

  const head = document.createElement('div');
  head.className = 'head';
  const title = document.createElement('h3');
  title.textContent = principal.subject;
  const badge = document.createElement('span');
  badge.className = principal.blocked ? 'badge off' : 'badge on';
  badge.textContent = principal.blocked ? 'blocked' : 'active';
  head.append(title, badge);
  card.append(head);

  const meta = document.createElement('p');
  meta.className = 'muted';
  const login = principal.last_login_at
    ? `last sign-in ${formatWhen(principal.last_login_at)}`
    : 'never signed in';
  const groups = Array.isArray(principal.last_groups) && principal.last_groups.length
    ? `groups: ${principal.last_groups.join(', ')}`
    : 'no groups';
  meta.textContent = [login, groups, grantText(principal.grants)].join(' · ');
  card.append(meta);

  const actions = document.createElement('div');
  actions.className = 'actions';
  if (principal.blocked) {
    actions.append(
      button('Unblock', 'tiny', async () => {
        if (
          !(await confirmModal(
            'Unblock principal',
            'They can sign in with SSO again. Old sessions stay dead. Lasting access still depends on the IdP group.',
            'Unblock',
          ))
        )
          return;
        await api('/api/admin/principals/unblock', {
          method: 'POST',
          body: JSON.stringify({ subject: principal.subject }),
        });
        await refreshTenants();
      }),
    );
  } else {
    actions.append(
      button('Revoke', 'tiny danger', async () => {
        if (
          !(await confirmModal(
            'Revoke principal',
            'Kicks current sessions and refuses SSO until unblocked; remove the IdP group to make it stick.',
            'Revoke',
          ))
        )
          return;
        await api('/api/admin/principals/revoke', {
          method: 'POST',
          body: JSON.stringify({ subject: principal.subject }),
        });
        await refreshTenants();
      }),
    );
  }
  card.append(actions);
  return card;
}

async function refreshTenants() {
  const [{ tenants, principals }, { holdings }] = await Promise.all([
    api('/api/admin/tenants'),
    api('/api/admin/holdings'),
  ]);
  const usage = new Map((holdings || []).map((item) => [item.tenant, item]));
  const container = $('tenants');
  container.replaceChildren();
  if (!tenants.length) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = 'No named tenants yet.';
    container.append(empty);
  } else {
    for (const tenant of tenants) {
      container.append(renderTenant(tenant, usage.get(tenant.key)));
    }
  }

  const list = $('principals');
  list.replaceChildren();
  if (!principals || !principals.length) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = 'No SSO principals have signed in yet.';
    list.append(empty);
    return;
  }
  for (const principal of principals) {
    list.append(renderPrincipal(principal));
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
