import { mountHints } from '/assets/hints.js';
import { mountDrafts, confirmLeave } from '/assets/form-drafts.js';
// Shared helpers for the multi-page admin. VOTPORT PROPRIETARY LICENSE.

// Copying text with a Copied flash lives with the shared public helpers so
// public pages need not import this admin module for it.
import { node, copyToClipboard, formatAgo, formatBytes, formatDuration, formatWhen, confirmModal, alertModal } from '/assets/object-card.js';
import { createUndoQueue } from '/assets/undo.js';
import { searchDebounce } from '/assets/search-debounce.js';
export { copyToClipboard, formatWhen, confirmModal, alertModal };

import { api } from '/assets/admin-api.js';
export { api };

/// The switch reply reissues the session cookie, but a reload started in
/// the same breath can race the browser's cookie commit and land back in
/// the old tenant scope, which re-renders and re-persists stale state. Poll
/// the session endpoint - each request carries the committed cookie - until
/// it answers with the switched tenant, then the reload is safe.
export async function confirmSwitchedTenant(target, { session = () => api('/api/admin/session'), attempts = 20 } = {}) {
  for (let remaining = attempts; ; remaining -= 1) {
    if ((await session()).tenant === target) return;
    if (remaining <= 1) throw new Error('The tenant switch did not stick. Reload the page.');
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

/// Redirects to the sign-in page unless a session exists; resolves with it.
export async function requireSession() {
  let session;
  try {
    const embedded = document.getElementById('admin-session');
    session = embedded ? JSON.parse(embedded.textContent) : await api('/api/admin/session');
  } catch {
    window.location.replace('/');
    return new Promise(() => {}); // never resolves; page is leaving
  }
  buildNav(session);
  mountSearch(session);
  mountHints();
  mountDrafts(session);
  return session;
}

// Masthead search: one request, results grouped by what they are, each row
// a link into the page that owns it. The input keeps focus while arrows move
// through the result options; Escape or a click elsewhere closes the panel.
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
  input.setAttribute('role', 'combobox');
  input.setAttribute('autocomplete', 'off');
  input.setAttribute('aria-controls', results.id);
  input.setAttribute('aria-expanded', 'false');
  input.setAttribute('aria-autocomplete', 'list');
  input.setAttribute('aria-haspopup', 'listbox');
  results.setAttribute('role', 'listbox');
  results.setAttribute('aria-label', 'Search results');
  let status = document.getElementById('global-search-status');
  if (!status) {
    status = document.createElement('p');
    status.id = 'global-search-status';
    status.className = 'visually-hidden';
    status.setAttribute('role', 'status');
    status.setAttribute('aria-live', 'polite');
    form.append(status);
  }
  let latest = 0;
  let activeIndex = -1;
  const options = () => [...results.querySelectorAll('[role="option"]')];
  const setActive = (index) => {
    const rows = options();
    activeIndex = index < 0 || !rows.length ? -1 : index % rows.length;
    rows.forEach((row, rowIndex) => row.setAttribute('aria-selected', String(rowIndex === activeIndex)));
    if (activeIndex < 0) {
      input.removeAttribute('aria-activedescendant');
      return;
    }
    input.setAttribute('aria-activedescendant', rows[activeIndex].id);
    rows[activeIndex].scrollIntoView({ block: 'nearest' });
  };
  const setExpanded = (expanded) => {
    results.hidden = !expanded;
    input.setAttribute('aria-expanded', String(expanded));
  };
  // Closing also retires any request still in flight so it cannot reopen
  // the panel with stale rows.
  const close = () => {
    scheduleSearch.cancel();
    latest += 1;
    setActive(-1);
    setExpanded(false);
    results.replaceChildren();
    status.textContent = '';
  };
  // A row on the page already open is a fragment change, not a load.
  window.addEventListener('hashchange', () => { close(); revealHash(); });
  let optionNumber = 0;
  let resultCount = 0;
  const group = (title, rows, render) => {
    if (!rows.length) return;
    const heading = node('div', '', 'search-group');
    heading.setAttribute('role', 'presentation');
    heading.textContent = title;
    results.append(heading);
    for (const row of rows) {
      const link = node('a', '', 'search-row');
      link.id = `global-search-option-${optionNumber}`;
      optionNumber += 1;
      link.tabIndex = -1;
      link.setAttribute('role', 'option');
      link.setAttribute('aria-selected', 'false');
      const { href, primary, secondary } = render(row);
      link.href = href;
      const main = node('span', primary);
      const meta = node('span', secondary, 'muted');
      link.append(main, meta);
      link.addEventListener('click', close);
      results.append(link);
    }
    resultCount += rows.length;
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
      setActive(-1);
      results.replaceChildren();
      const failed = node('div', '', 'search-group');
      failed.textContent = `Search failed: ${error.message}`;
      results.append(failed);
      setExpanded(true);
      status.textContent = `Search failed: ${error.message}`;
      return;
    }
    if (ticket !== latest) return;
    setActive(-1);
    results.replaceChildren();
    optionNumber = 0;
    resultCount = 0;
    if (pages.includes('receive')) {
      // The id rides along as the list filter so the card is the one row on
      // the page that opens, however far down the list it would be.
      group('Requests', hit.requests, (row) => ({
        href: `/receive?search=${row.id}#link-${row.id}`,
        primary: row.label,
        secondary: `${row.active ? 'open' : 'off'} · to /${row.dest || ''} · ${formatWhen(row.created_at)}`,
      }));
      group('Received files', hit.files, (row) => ({
        href: `/receive?search=${row.link_id}#link-${row.link_id}`,
        primary: row.path,
        secondary: `${formatBytes(row.bytes)} · ${row.link_label} · ${formatWhen(row.completed_at)}`,
      }));
    }
    if (pages.includes('deliver')) {
      group('Deliveries', hit.downloads, (row) => ({
        href: `/deliver#grant-${row.id}`,
        primary: row.label || row.name,
        secondary: `${row.name} · ${row.revoked ? 'revoked' : 'issued'} ${formatWhen(row.created_at)}`,
      }));
    }
    if (pages.includes('audit')) {
      group('Audit', [phrase], () => ({
        href: `/audit?q=${encodeURIComponent(phrase)}`,
        primary: 'Search audit log',
        secondary: `for "${phrase}"`,
      }));
    }
    if (!results.firstChild) {
      const none = node('div', '', 'search-group');
      none.setAttribute('role', 'presentation');
      none.textContent = 'Nothing matches';
      results.append(none);
    }
    setExpanded(true);
    status.textContent = resultCount
      ? `${resultCount} search result${resultCount === 1 ? '' : 's'}.`
      : 'No search results.';
  };
  const scheduleSearch = searchDebounce(60, run);
  input.addEventListener('input', () => {
    latest += 1;
    setActive(-1);
    status.textContent = input.value.trim().length >= 2 ? 'Searching…' : '';
    scheduleSearch();
  });
  input.addEventListener('focus', () => { if (results.firstChild) setExpanded(true); });
  input.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' || event.key === 'Tab') close();
    if (results.hidden) return;
    const rows = options();
    if (!rows.length) return;
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      setActive(activeIndex + 1);
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      setActive(activeIndex < 0 ? rows.length - 1 : activeIndex - 1);
    } else if (event.key === 'Enter') {
      event.preventDefault();
      rows[activeIndex < 0 ? 0 : activeIndex].click();
    }
  });
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    const first = options()[activeIndex < 0 ? 0 : activeIndex];
    if (first && !results.hidden) first.click();
    else run();
  });
  document.addEventListener('click', (event) => {
    if (!form.contains(event.target)) close();
  });
}

/// Scrolls to the card named by the location hash and opens its details,
/// once the list that holds it has rendered. Search results deep-link this
/// way; the card is not marked, arriving at it is the signal.
export function revealHash({ scroll = true, focus = scroll } = {}) {
  const id = window.location.hash.slice(1);
  // Only list cards are revealed; a settings section fragment on System is
  // plain navigation.
  if (id && !/^(link|grant|job|route)-/.test(id)) return false;
  if (!id) return false;
  const target = document.getElementById(id);
  if (!target) return false;
  if (scroll) target.scrollIntoView({ block: 'center' });
  target.querySelector('details')?.setAttribute('open', '');
  if (focus && (document.activeElement === document.body
    || document.activeElement === document.getElementById('global-search-input'))) {
    target.tabIndex = -1;
    target.focus({ preventScroll: true });
  }
  return true;
}

// The theme toggle names the theme it switches to; the saved choice wins
// over the system setting.
function mountThemeToggle() {
  const toggle = document.getElementById('theme-toggle');
  if (!toggle) return;
  const media = window.matchMedia('(prefers-color-scheme: light)');
  const current = () => document.documentElement.dataset.theme || (media.matches ? 'light' : 'dark');
  const label = () => {
    const next = current() === 'light' ? 'dark' : 'light';
    toggle.textContent = next === 'dark' ? 'Dark' : 'Light';
    toggle.setAttribute('aria-label', `Switch to ${next} theme`);
  };
  toggle.addEventListener('click', () => {
    const next = current() === 'light' ? 'dark' : 'light';
    document.documentElement.dataset.theme = next;
    try { window.localStorage.setItem('votport-theme', next); } catch { /* storage blocked */ }
    label();
  });
  media.addEventListener('change', label);
  label();
}
mountThemeToggle();

const NAV_ITEMS = [
  ['receive', '/receive', 'Receive', 'Invite someone to ship files to this port.'],
  ['deliver', '/deliver', 'Deliver', 'Share files with a private delivery link.'],
  ['workflows', '/workflows', 'Deliveries', 'Prepare deliveries with reusable checks, approvals and storage connections.'],
  ['trade-routes', '/trade-routes', 'Trade routes', 'Connect ports to move files between organizations.'],
  ['storage', '/storage', 'Storage', 'Manage receiving storage, S3 buckets and shared folders.'],
  ['automation', '/automation', 'Automation', 'Connect agents and scripts with limited access.'],
  ['notifications', '/notifications', 'Notifications', 'Choose notification channels, recipients and shared defaults.'],
  ['tenants', '/tenants', 'Tenants', 'Manage separate workspaces, each with its own users and files.'],
  ['audit', '/audit', 'Audit', 'Review who did what on this port. An auditor session sees only this page.'],
  ['system', '/system', 'System', 'Manage branding, sign-in, email, backups and port settings.'],
];

function buildNav(session) {
  const nav = document.getElementById('nav');
  if (!nav) return;
  nav.replaceChildren();
  nav.setAttribute('aria-label', 'Main navigation');
  const primary = document.createElement('div'); primary.className = 'nav-primary';
  const more = document.createElement('details'); more.className = 'nav-more';
  const summary = document.createElement('summary'); summary.textContent = 'Port settings';
  const panel = document.createElement('div'); panel.className = 'nav-panel';
  more.append(summary, panel);
  const canManageStorage = session.role === 'admin' && !session.tenant;
  for (const [page, href, defaultLabel, defaultHint] of NAV_ITEMS) {
    if (!session.pages.includes(page)) continue;
    const selfBranding = page === 'tenants' && session.tenant;
    const label = selfBranding ? 'Branding' : defaultLabel;
    const hint = selfBranding ? 'Set how recipients see this tenant.' : defaultHint;
    const link = document.createElement('a'); link.href = href; link.textContent = label;
    link.dataset.hint = page === 'storage' && !canManageStorage ? 'View available storage connections.' : hint;
    const active = window.location.pathname === href || (href === '/receive' && window.location.pathname === '/links');
    if (active) { link.classList.add('active'); link.setAttribute('aria-current', 'page'); }
    if (['receive', 'deliver', 'workflows', 'trade-routes'].includes(page)) primary.append(link);
    else { panel.append(link); if (active) summary.classList.add('active'); }
  }
  nav.append(primary); if (panel.children.length) nav.append(more);
  document.addEventListener('click', (event) => { if (!more.contains(event.target)) more.open = false; });
  more.addEventListener('keydown', (event) => { if (event.key === 'Escape') { more.open = false; summary.focus(); } });
  more.addEventListener('focusout', () => setTimeout(() => { if (!more.contains(document.activeElement)) more.open = false; }, 0));
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
        switcher.disabled = true;
        try {
          if (await confirmLeave(() => api('/api/admin/tenant', {
            method: 'POST', body: JSON.stringify({ tenant: switcher.value }),
          }))) {
            await confirmSwitchedTenant(switcher.value);
            window.location.reload();
          } else switcher.value = session.tenant;
        } catch (error) { switcher.value = session.tenant; alertModal(error.message); }
        finally { switcher.disabled = false; }
      });
    }
  }
  const logout = document.getElementById('logout');
  logout?.addEventListener('click', async () => {
    logout.disabled = true;
    try {
      if (await confirmLeave(() => api('/api/admin/logout', { method: 'POST' }))) window.location.replace('/');
    } catch (error) { alertModal(error.message); }
    finally { logout.disabled = false; }
  });
}

export function teachingEmptyState(title, steps) {
  const box = node('div', '', 'empty-teach');
  const list = document.createElement('ol');
  list.append(...steps.map((step) => node('li', step)));
  box.append(node('h3', title), list);
  return box;
}

export { formatAgo, formatBytes, formatDuration };

/// Action button whose handler, sync or async, reports failures via the
/// shared modal.
export function button(text, classes, onClick) {
  const element = document.createElement('button');
  element.type = 'button';
  element.className = classes;
  element.textContent = text;
  element.addEventListener('click', () => {
    Promise.resolve()
      .then(() => onClick(element))
      .catch((error) => alertModal(error.message));
  });
  return element;
}


/// Sets a role=status line so screen readers hear the outcome of an action.
export function announce(id, text) {
  document.getElementById(id).textContent = text;
}

export function selectText(element) {
  element.focus({ preventScroll: true });
  if (typeof element.select === 'function') {
    element.select();
    return;
  }
  const selection = window.getSelection();
  if (!selection) return;
  const range = document.createRange();
  range.selectNodeContents(element);
  selection.removeAllRanges();
  selection.addRange(range);
}

// Undo toasts: the page changes at once, the server call waits six seconds
// for an Undo. Interaction pauses the window; pagehide commits with keepalive.
const undoQueue = createUndoQueue();
window.addEventListener('pagehide', () => { undoQueue.flush(); });

// Created up front so the live region exists before the first toast lands
// in it; a region created and filled in one task is not announced.
function toastStack() {
  let stack = document.getElementById('toast-stack');
  if (!stack) {
    stack = document.createElement('div');
    stack.id = 'toast-stack';
    stack.className = 'toast-stack';
    stack.setAttribute('role', 'status');
    stack.setAttribute('aria-atomic', 'false');
    document.body.append(stack);
  }
  return stack;
}
toastStack();

/// Shows `text` with an Undo button. `commit` runs when the window closes
/// (pass fetch options with keepalive so it survives unload); `restore`
/// runs on Undo. Resolves with whether it committed, once settled.
export function undoable({ text, commit, restore = () => {}, focus, returnFocus }) {
  const stack = toastStack();
  const toast = node('div', '', 'toast');
  const label = node('span', text);
  const undo = document.createElement('button');
  undo.type = 'button';
  undo.className = 'link';
  undo.textContent = 'Undo';
  undo.setAttribute('aria-label', `Undo ${text}`);
  toast.append(label, undo);
  stack.append(toast);
  return new Promise((resolve, reject) => {
    let failure = null;
    const handle = undoQueue.add({
      commit: async () => {
        try {
          await commit();
        } catch (error) {
          failure = error;
        }
      },
      restore,
      onSettled: (committed) => {
        if (toast.contains(document.activeElement)) {
          returnFocus.textContent = failure ? 'Action could not be confirmed.' : committed ? text : 'Action undone.';
          returnFocus.focus({ preventScroll: true });
        }
        toast.classList.add('leaving');
        setTimeout(() => toast.remove(), 250);
        if (failure) {
          // The server refused: put the page back before reporting it.
          restore();
          reject(failure);
        } else {
          resolve(committed);
        }
      },
    });
    undo.addEventListener('click', () => handle.undo());
    toast.addEventListener('pointerenter', () => handle.pause());
    toast.addEventListener('pointerleave', () => {
      if (!toast.contains(document.activeElement)) handle.resume();
    });
    toast.addEventListener('focusin', () => handle.pause());
    toast.addEventListener('focusout', (event) => {
      if (!toast.contains(event.relatedTarget) && !toast.matches(':hover')) handle.resume();
    });
    if (focus) undo.focus();
  });
}

/// Fills the shared outbound grant URL card on receive/deliver.
export function showGrantResult(url, protectedGrant = false, focusResult = false) {
  const output = document.getElementById('outbound-url');
  document.getElementById('outbound-result').hidden = false;
  output.value = url;
  output.onclick = () => output.select();
  document.getElementById('outbound-note').textContent =
    `You can copy this link again from Delivery links on the Deliver page.`
    + (protectedGrant ? ' This delivery is password-protected. Send the password by a separate channel.' : '');
  const copy = document.getElementById('outbound-copy');
  const status = document.querySelector('#outbound-grants-status, #links-action-status');
  const report = (text) => { if (status) announce(status.id, text); };
  if (focusResult) output.focus({ preventScroll: true });
  copy.onclick = async () => {
    try {
      await copyToClipboard(copy, url);
      report('Delivery link copied.');
    } catch {
      if (copy === document.activeElement || output === document.activeElement || document.activeElement === document.body) {
        selectText(output);
        report('Your delivery link is selected below. Copy it to share.');
      } else report('Could not copy the delivery link. Use Copy link below to retry.');
    }
  };
}

/// The stock accent for the current theme, read from the stylesheet, so a
/// reset shows the colour recipients will actually see.
export function defaultAccent() {
  const value = window.getComputedStyle(document.documentElement).getPropertyValue('--progress').trim();
  return /^#[0-9a-f]{6}$/i.test(value) ? value : '#38bdf8';
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
