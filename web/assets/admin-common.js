// Shared helpers for the multi-page admin. VOTPORT PROPRIETARY LICENSE.

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
  ['receive', '/receive', 'Receive'],
  ['deliver', '/deliver', 'Deliver'],
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
    const active = window.location.pathname === href
      || (href === '/receive' && window.location.pathname === '/links');
    if (active) {
      link.classList.add('active');
      link.setAttribute('aria-current', 'page');
    }
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

export { formatBytes } from '/assets/object-card.js';

/// Action button whose async handler reports failures via the shared modal.
export function button(text, classes, onClick) {
  const element = document.createElement('button');
  element.type = 'button';
  element.className = classes;
  element.textContent = text;
  element.addEventListener('click', () => {
    onClick().catch?.((error) => alertModal(error.message));
  });
  return element;
}

/// Fills the shared show-once outbound grant URL card on receive/deliver.
export function showGrantResult(url, protectedGrant = false) {
  const output = document.getElementById('outbound-url');
  document.getElementById('outbound-result').hidden = false;
  output.value = url;
  output.onclick = () => output.select();
  document.getElementById('outbound-note').textContent =
    `Shown once. Copy it now; this URL cannot be retrieved later.`
    + (protectedGrant ? ' This download is password-protected. Send the password by a separate channel.' : '');
  document.getElementById('outbound-copy').onclick = async () => {
    await navigator.clipboard.writeText(url);
    document.getElementById('outbound-copy').textContent = 'Copied';
  };
}

export function formatWhen(unixSeconds) {
  return new Date(unixSeconds * 1000).toLocaleString();
}

export function formatDuration(seconds) {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

/// Keeps a color picker and a hex text input in step. get() is the lowercase
/// #rrggbb value, or '' when the text input is blank or not a color.
export function colorPair(picker, hex) {
  const valid = () => /^#[0-9a-f]{6}$/i.test(hex.value.trim());
  picker.addEventListener('input', () => {
    hex.value = picker.value;
  });
  hex.addEventListener('input', () => {
    if (valid()) picker.value = hex.value.trim().toLowerCase();
  });
  return {
    get: () => (valid() ? hex.value.trim().toLowerCase() : ''),
    set: (value) => {
      hex.value = value || '';
      if (value) picker.value = value;
    },
  };
}
