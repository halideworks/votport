// votport admin UI. AGPL-3.0-only.

const $ = (id) => document.getElementById(id);

async function api(path, options = {}) {
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

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  const exponent = Math.min(Math.floor(Math.log2(bytes) / 10), units.length - 1);
  const value = bytes / 2 ** (10 * exponent);
  return `${value >= 100 || exponent === 0 ? Math.round(value) : value.toFixed(1)} ${units[exponent]}`;
}

function formatWhen(unixSeconds) {
  return new Date(unixSeconds * 1000).toLocaleString();
}

function show(section) {
  $('login').hidden = section !== 'login';
  $('dashboard').hidden = section !== 'dashboard';
}

async function refreshLinks() {
  const { links, receive_dir } = await api('/api/admin/links');
  $('receive-dir').textContent = `Receive root ${receive_dir}`;
  const container = $('links');
  container.replaceChildren();
  if (!links.length) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = 'No requests issued.';
    container.append(empty);
    return;
  }
  for (const link of [...links].reverse()) {
    container.append(renderLink(link));
  }
}

function renderLink(link) {
  const card = document.createElement('div');
  card.className = 'card link-item';

  const head = document.createElement('div');
  head.className = 'head';
  const title = document.createElement('h3');
  title.textContent = link.label;
  const badge = document.createElement('span');
  badge.className = `badge ${link.usable ? 'on' : 'off'}`;
  badge.textContent = link.usable ? 'open' : link.active ? 'expired' : 'off';
  head.append(title, badge);
  if (link.has_password) {
    const lock = document.createElement('span');
    lock.className = 'badge';
    lock.textContent = 'password';
    head.append(lock);
  }
  card.append(head);

  const url = document.createElement('p');
  url.className = 'mono';
  url.textContent = link.url;
  card.append(url);

  const meta = document.createElement('p');
  meta.className = 'muted';
  const parts = [
    `to /${link.dest || ''}`.replace(/\/$/, '') || 'to receive root',
    `created ${formatWhen(link.created_at)}`,
  ];
  if (link.expires_at) parts.push(`expires ${formatWhen(link.expires_at)}`);
  if (link.max_bytes) parts.push(`limit ${formatBytes(link.max_bytes)}`);
  meta.textContent = parts.join(' · ');
  card.append(meta);

  const actions = document.createElement('div');
  actions.className = 'actions';
  actions.append(
    button('Copy', 'tiny', () => navigator.clipboard.writeText(link.url)),
    button(link.active ? 'Deactivate' : 'Reactivate', 'tiny ghost', async () => {
      await api(`/api/admin/links/${link.id}`, {
        method: 'POST',
        body: JSON.stringify({ active: !link.active }),
      });
      await refreshLinks();
    }),
    button('Delete', 'tiny danger', async () => {
      if (!confirm(`Delete request "${link.label}"? Received files stay on disk.`)) return;
      await api(`/api/admin/links/${link.id}`, { method: 'DELETE' });
      await refreshLinks();
    }),
  );
  card.append(actions);

  if (link.uploads.length) {
    const details = document.createElement('details');
    const summary = document.createElement('summary');
    const total = link.uploads.reduce((sum, upload) => sum + upload.total_bytes, 0);
    summary.textContent = `${link.uploads.length} transfer${link.uploads.length === 1 ? '' : 's'} · ${formatBytes(total)}`;
    details.append(summary);
    const list = document.createElement('ul');
    list.className = 'uploads';
    for (const upload of [...link.uploads].reverse()) {
      const item = document.createElement('li');
      const files = upload.files
        .map((file) => `${file.stored_as} (${formatBytes(file.bytes)})`)
        .join(', ');
      item.textContent = `${formatWhen(upload.completed_at)} — ${files}`;
      const root = document.createElement('div');
      root.className = 'mono muted';
      root.textContent = `package ${upload.package_root.slice(0, 16)}…`;
      item.append(root);
      list.append(item);
    }
    details.append(list);
    card.append(details);
  }
  return card;
}

function button(text, classes, onClick) {
  const element = document.createElement('button');
  element.type = 'button';
  element.className = classes;
  element.textContent = text;
  element.addEventListener('click', () => {
    onClick().catch?.((error) => alert(error.message));
  });
  return element;
}

$('login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('login-error').hidden = true;
  try {
    await api('/api/admin/login', {
      method: 'POST',
      body: JSON.stringify({ password: $('login-password').value }),
    });
    $('login-password').value = '';
    show('dashboard');
    await refreshLinks();
  } catch (error) {
    $('login-error').textContent = error.message;
    $('login-error').hidden = false;
  }
});

$('logout').addEventListener('click', async () => {
  await api('/api/admin/logout', { method: 'POST' });
  show('login');
});

$('create-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('create-error').hidden = true;
  const maxGib = parseInt($('create-max').value, 10);
  const expires = parseInt($('create-expires').value, 10);
  try {
    const { link } = await api('/api/admin/links', {
      method: 'POST',
      body: JSON.stringify({
        label: $('create-label').value,
        dest: $('create-dest').value,
        password: $('create-password').value || null,
        expires_days: Number.isFinite(expires) ? expires : null,
        max_bytes: Number.isFinite(maxGib) ? maxGib * 1024 ** 3 : null,
      }),
    });
    $('create-form').reset();
    $('new-link').hidden = false;
    $('new-link-url').textContent = link.url;
    $('new-link-note').textContent = link.has_password
      ? 'Send the access password by a separate channel.'
      : '';
    $('new-link-copy').onclick = () => navigator.clipboard.writeText(link.url);
    await refreshLinks();
  } catch (error) {
    $('create-error').textContent = error.message;
    $('create-error').hidden = false;
  }
});

$('password-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('password-error').hidden = true;
  $('password-note').textContent = '';
  try {
    await api('/api/admin/password', {
      method: 'POST',
      body: JSON.stringify({
        current: $('password-current').value,
        new: $('password-new').value,
      }),
    });
    $('password-form').reset();
    $('password-note').textContent = 'Password updated.';
  } catch (error) {
    $('password-error').textContent = error.message;
    $('password-error').hidden = false;
  }
});

(async () => {
  try {
    await api('/api/admin/session');
    show('dashboard');
    await refreshLinks();
  } catch {
    show('login');
  }
})();
