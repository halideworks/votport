// Shared helpers for the multi-page admin. AGPL-3.0-only.

export async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: {
      'Content-Type': 'application/json',
      'X-Votport': '1',
      ...(options.headers || {}),
    },
    credentials: 'same-origin',
    ...options,
  });
  let body = null;
  try { body = await response.json(); } catch { /* non-JSON error page */ }
  if (!response.ok) {
    throw new Error(body?.error || `request failed (${response.status})`);
  }
  return body;
}

/// Redirects to the sign-in page unless a session exists; resolves with it.
export async function requireSession() {
  let session;
  try {
    session = await api('/api/admin/session');
  } catch {
    window.location.replace('/');
    return new Promise(() => {}); // never resolves; page is leaving
  }
  buildNav(session);
  return session;
}

const NAV_ITEMS = [
  ['links', '/links', 'Links'],
  ['tenants', '/tenants', 'Tenants'],
  ['audit', '/audit', 'Audit'],
  ['system', '/system', 'System'],
];

function buildNav(session) {
  const nav = document.getElementById('nav');
  if (!nav) return;
  nav.replaceChildren();
  for (const [page, href, label] of NAV_ITEMS) {
    if (!session.pages.includes(page)) continue;
    const link = document.createElement('a');
    link.href = href;
    link.textContent = label;
    if (window.location.pathname === href) link.classList.add('active');
    nav.append(link);
  }
  // Tenant switcher appears only for multi-tenant principals.
  const switcher = document.getElementById('tenant-switcher');
  if (switcher) {
    switcher.hidden = !(Array.isArray(session.grants) && session.grants.length > 1);
    if (!switcher.hidden) {
      switcher.replaceChildren(
        ...session.grants.map((grant) => {
          const option = document.createElement('option');
          option.value = grant.tenant;
          option.textContent = grant.tenant === '' ? 'Default' : grant.tenant;
          option.selected = grant.tenant === session.tenant;
          return option;
        }),
      );
      switcher.addEventListener('change', async () => {
        await api('/api/admin/tenant', {
          method: 'POST',
          body: JSON.stringify({ tenant: switcher.value }),
        });
        window.location.reload();
      });
    }
  }
  const logout = document.getElementById('logout');
  logout?.addEventListener('click', async () => {
    await api('/api/admin/logout', { method: 'POST' });
    window.location.replace('/');
  });
}

// Styled replacements for native confirm()/alert(), sharing the one
// <dialog class="modal"> present on every admin page.
export function confirmModal(title, detail, action) {
  const dialog = document.getElementById('confirm');
  document.getElementById('confirm-title').textContent = title;
  document.getElementById('confirm-detail').textContent = detail;
  const ok = document.getElementById('confirm-ok');
  ok.textContent = action;
  ok.hidden = false;
  document.getElementById('confirm-cancel').textContent = 'Cancel';
  dialog.returnValue = 'cancel';
  dialog.showModal();
  return new Promise((resolve) => {
    dialog.addEventListener(
      'close',
      () => resolve(dialog.returnValue === 'ok'),
      { once: true },
    );
  });
}

export function alertModal(message) {
  const dialog = document.getElementById('confirm');
  document.getElementById('confirm-title').textContent = 'Something went wrong';
  document.getElementById('confirm-detail').textContent = message;
  document.getElementById('confirm-ok').hidden = true;
  document.getElementById('confirm-cancel').textContent = 'OK';
  dialog.showModal();
}

export function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  const exponent = Math.min(Math.floor(Math.log2(bytes) / 10), units.length - 1);
  const value = bytes / 2 ** (10 * exponent);
  return `${value >= 100 || exponent === 0 ? Math.round(value) : value.toFixed(1)} ${units[exponent]}`;
}

export function formatWhen(unixSeconds) {
  return new Date(unixSeconds * 1000).toLocaleString();
}

export function formatDuration(seconds) {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}
