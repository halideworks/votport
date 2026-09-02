// Shared helpers for the multi-page admin. VOTPORT PROPRIETARY LICENSE.

// Copying text with a Copied flash lives with the shared public helpers so
// public pages need not import this admin module for it.
import { copyToClipboard, formatBytes } from '/assets/object-card.js';
export { copyToClipboard };

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
    const error = new Error(body?.error || `request failed (${response.status})`);
    error.status = response.status;
    throw error;
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
  mountSearch(session);
  return session;
}

// Masthead search: one request, results grouped by what they are, each row
// a link into the page that owns it. Opens on typing, closes on Escape or a
// click elsewhere; Enter follows the first row.
function mountSearch(session) {
  const form = document.getElementById('global-search');
  const input = document.getElementById('global-search-input');
  const results = document.getElementById('global-search-results');
  if (!form || !input || !results) return;
  // The endpoint is operator-only; an audit-only session gets no box.
  const pages = session.pages || [];
  if (!pages.includes('receive') && !pages.includes('deliver')) {
    form.hidden = true;
    return;
  }
  let timer = null;
  let latest = 0;
  // Closing also retires any request still in flight so it cannot reopen
  // the panel with stale rows.
  const close = () => {
    clearTimeout(timer);
    latest += 1;
    results.hidden = true;
    results.replaceChildren();
  };
  // A row on the page already open is a fragment change, not a load.
  window.addEventListener('hashchange', () => { close(); revealHash(); });
  const group = (title, rows, render) => {
    if (!rows.length) return;
    const heading = document.createElement('div');
    heading.className = 'search-group';
    heading.textContent = title;
    results.append(heading);
    for (const row of rows) {
      const link = document.createElement('a');
      link.className = 'search-row';
      const { href, primary, secondary } = render(row);
      link.href = href;
      const main = document.createElement('span');
      main.textContent = primary;
      const meta = document.createElement('span');
      meta.className = 'muted';
      meta.textContent = secondary;
      link.append(main, meta);
      results.append(link);
    }
  };
  const run = async () => {
    const phrase = input.value.trim();
    if (phrase.length < 2) { close(); return; }
    const ticket = ++latest;
    let hit;
    try {
      hit = await api(`/api/admin/search?q=${encodeURIComponent(phrase)}`);
    } catch (error) {
      if (ticket !== latest) return;
      results.replaceChildren();
      const failed = document.createElement('div');
      failed.className = 'search-group';
      failed.textContent = `Search failed: ${error.message}`;
      results.append(failed);
      results.hidden = false;
      return;
    }
    if (ticket !== latest) return;
    results.replaceChildren();
    if (pages.includes('receive')) {
      // The phrase rides along as the list filter so a card past the first
      // page of fifty is still on the page that opens.
      group('Requests', hit.requests, (row) => ({
        href: `/receive?search=${encodeURIComponent(row.label)}#link-${row.id}`,
        primary: row.label,
        secondary: `${row.active ? 'open' : 'off'} · to /${row.dest || ''} · ${formatWhen(row.created_at)}`,
      }));
      group('Received files', hit.files, (row) => ({
        href: `/receive?search=${encodeURIComponent(row.link_label)}#link-${row.link_id}`,
        primary: row.path,
        secondary: `${formatBytes(row.bytes)} · ${row.link_label} · ${formatWhen(row.completed_at)}`,
      }));
    }
    if (pages.includes('deliver')) {
      group('Downloads', hit.downloads, (row) => ({
        href: `/deliver#grant-${row.id}`,
        primary: row.label || row.name,
        secondary: `${row.name} · ${row.revoked ? 'revoked' : 'issued'} ${formatWhen(row.created_at)}`,
      }));
    }
    if (pages.includes('audit')) {
      group('Audit', hit.audit, (row) => ({
        href: `/audit?q=${encodeURIComponent(phrase)}`,
        primary: `${row.event} · ${row.subject}`,
        secondary: `${row.actor || 'system'} · ${formatWhen(row.at)}`,
      }));
    }
    if (!results.firstChild) {
      const none = document.createElement('div');
      none.className = 'search-group';
      none.textContent = 'Nothing matches';
      results.append(none);
    }
    results.hidden = false;
  };
  input.addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(run, 180);
  });
  input.addEventListener('focus', () => { if (results.firstChild) results.hidden = false; });
  input.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') { close(); input.blur(); }
  });
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    const first = results.querySelector('a');
    if (first && !results.hidden) first.click();
    else run();
  });
  document.addEventListener('click', (event) => {
    if (!form.contains(event.target)) close();
  });
}

/// Scrolls to and highlights the card named by the location hash, once the
/// list that holds it has rendered. Search results deep-link this way.
export function revealHash({ scroll = true } = {}) {
  const id = window.location.hash.slice(1);
  if (!id) return;
  const target = document.getElementById(id);
  if (!target) return;
  if (scroll) target.scrollIntoView({ block: 'center' });
  target.classList.add('revealed');
  target.querySelector('details')?.setAttribute('open', '');
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

export { formatBytes };

/// Action button whose handler, sync or async, reports failures via the
/// shared modal.
export function button(text, classes, onClick) {
  const element = document.createElement('button');
  element.type = 'button';
  element.className = classes;
  element.textContent = text;
  element.addEventListener('click', () => {
    Promise.resolve().then(onClick).catch((error) => alertModal(error.message));
  });
  return element;
}


/// Sets a role=status line so screen readers hear the outcome of an action.
export function announce(id, text) {
  document.getElementById(id).textContent = text;
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
  const copy = document.getElementById('outbound-copy');
  copy.onclick = () => copyToClipboard(copy, url);
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
