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

// Styled replacements for the native confirm()/alert() dialogs, sharing the
// one <dialog class="modal"> in index.html. Resolves true when the action
// button is chosen; Esc and Cancel resolve false.
function confirmModal(title, detail, action) {
  const dialog = $('confirm');
  $('confirm-title').textContent = title;
  $('confirm-detail').textContent = detail;
  $('confirm-ok').textContent = action;
  $('confirm-ok').hidden = false;
  $('confirm-cancel').textContent = 'Cancel';
  dialog.returnValue = 'cancel';
  dialog.showModal();
  return new Promise((resolve) => {
    dialog.addEventListener('close', () => resolve(dialog.returnValue === 'ok'), { once: true });
  });
}

function alertModal(message) {
  const dialog = $('confirm');
  $('confirm-title').textContent = 'Something went wrong';
  $('confirm-detail').textContent = message;
  $('confirm-ok').hidden = true;
  $('confirm-cancel').textContent = 'OK';
  dialog.showModal();
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

// Connection-quality proxy: chunks the sender re-sent (its response got lost
// in transit) or the server refused. Zero for a clean transfer, so shown only
// when there was trouble.
function chunkTrouble(record) {
  let text = '';
  if (record.replayed_chunks) text += ` · ${record.replayed_chunks} re-sent chunks`;
  if (record.rejected_chunks) text += ` · ${record.rejected_chunks} rejected chunks`;
  return text;
}

function formatDuration(seconds) {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

function show(section) {
  $('login').hidden = section !== 'login';
  $('dashboard').hidden = section !== 'dashboard';
}

async function refreshLinks() {
  const { links, receive_dir, receipt_key } = await api('/api/admin/links');
  $('receive-dir').textContent =
    `Receive root ${receive_dir} · receipt key ${receipt_key || 'unavailable'}`;
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

  // Lazily-loaded QR of the request link, toggled from the actions row.
  const qr = document.createElement('div');
  qr.className = 'qr';
  qr.hidden = true;

  const actions = document.createElement('div');
  actions.className = 'actions';
  actions.append(
    button('Copy', 'tiny', () => navigator.clipboard.writeText(link.url)),
    button('QR', 'tiny ghost', async () => {
      qr.hidden = !qr.hidden;
      if (!qr.hidden && !qr.firstChild) {
        const image = document.createElement('img');
        image.alt = `QR code for ${link.url}`;
        image.src = `/api/admin/links/${link.id}/qr`;
        qr.append(image);
      }
    }),
    button(link.active ? 'Deactivate' : 'Reactivate', 'tiny ghost', async () => {
      await api(`/api/admin/links/${link.id}`, {
        method: 'POST',
        body: JSON.stringify({ active: !link.active }),
      });
      await refreshLinks();
    }),
    button('Delete', 'tiny danger', async () => {
      if (!(await confirmModal('Delete request', `Delete "${link.label}"? Received files stay on disk.`, 'Delete'))) return;
      await api(`/api/admin/links/${link.id}`, { method: 'DELETE' });
      await refreshLinks();
    }),
  );
  card.append(actions, qr);

  if (link.uploads.length) {
    const details = document.createElement('details');
    const summary = document.createElement('summary');
    const total = link.uploads.reduce((sum, upload) => sum + upload.total_bytes, 0);
    summary.textContent = `${link.uploads.length} transfer${link.uploads.length === 1 ? '' : 's'} · ${formatBytes(total)}`;
    details.append(summary);
    const list = document.createElement('ul');
    list.className = 'uploads';
    for (const upload of [...link.uploads].reverse()) {
      list.append(renderUpload(link, upload));
    }
    details.append(list);
    card.append(details);
  }

  if (link.events?.length) {
    const details = document.createElement('details');
    const summary = document.createElement('summary');
    summary.textContent =
      `${link.events.length} incomplete session${link.events.length === 1 ? '' : 's'}`;
    details.append(summary);
    const list = document.createElement('ul');
    list.className = 'uploads';
    for (const event of [...link.events].reverse()) {
      const item = document.createElement('li');
      const head = document.createElement('div');
      head.className = 'upload-head';
      const when = document.createElement('span');
      let text = `${formatWhen(event.at)} · ${event.outcome}`;
      if (event.at > event.started_at) {
        text += ` after ${formatDuration(event.at - event.started_at)}`;
      }
      text += ` · ${formatBytes(event.received_bytes)} of ${formatBytes(event.expected_bytes)} received`;
      text += chunkTrouble(event);
      when.textContent = text;
      head.append(when);
      item.append(head);
      const detail = document.createElement('div');
      detail.className = 'muted file-id';
      detail.textContent = event.detail;
      item.append(detail);
      list.append(item);
    }
    details.append(list);
    card.append(details);
  }
  return card;
}

function renderUpload(link, upload) {
  const item = document.createElement('li');

  const head = document.createElement('div');
  head.className = 'upload-head';
  const when = document.createElement('span');
  when.textContent = `${formatWhen(upload.completed_at)} · ${formatBytes(upload.total_bytes)}`;
  // started_at is 0 on records from before it was tracked.
  if (upload.started_at && upload.completed_at > upload.started_at) {
    const seconds = upload.completed_at - upload.started_at;
    when.textContent +=
      ` · ${formatDuration(seconds)} · ${formatBytes(Math.round(upload.total_bytes / seconds))}/s`;
  }
  when.textContent += chunkTrouble(upload);
  head.append(
    when,
    button('Clear record', 'tiny ghost', async () => {
      if (!(await confirmModal('Clear record', 'Remove this transfer from the history? Files on disk stay.', 'Clear'))) return;
      await api(`/api/admin/links/${link.id}/uploads/${upload.id}`, { method: 'DELETE' });
      await refreshLinks();
    }),
  );
  item.append(head);

  upload.files.forEach((file, index) => {
    const row = document.createElement('div');
    row.className = 'upload-file';

    const name = document.createElement('span');
    name.textContent = `${file.stored_as} (${formatBytes(file.bytes)})`;
    row.append(name);

    if (!file.exists) {
      const missing = document.createElement('span');
      missing.className = 'badge off';
      missing.textContent = 'missing';
      row.append(missing);
    }
    if (file.receipt) {
      const receipt = document.createElement('span');
      receipt.className = 'badge on';
      receipt.textContent = 'receipt';
      row.append(receipt);
    }
    if (file.exists) {
      row.append(
        button('Delete file', 'tiny danger', async () => {
          if (!(await confirmModal('Delete file', `Delete "${file.stored_as}" from disk? This cannot be undone.`, 'Delete'))) return;
          await api(`/api/admin/links/${link.id}/uploads/${upload.id}/files/${index}`, {
            method: 'DELETE',
          });
          await refreshLinks();
        }),
      );
    }
    item.append(row);

    const id = document.createElement('div');
    id.className = 'mono muted file-id';
    id.textContent = `${file.suite}:${file.root}`;
    item.append(id);
  });

  const root = document.createElement('div');
  root.className = 'mono muted file-id';
  root.textContent = `package ${upload.package_root}`;
  item.append(root);
  return item;
}

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
  // SSO failures come home as ?sso_error=<hex>; show the decoded message.
  const ssoError = new URLSearchParams(window.location.search).get('sso_error');
  if (ssoError) {
    try {
      const message = new TextDecoder().decode(
        Uint8Array.from(ssoError.match(/.{2}/g) ?? [], (byte) => parseInt(byte, 16)),
      );
      $('login-error').textContent = message;
      $('login-error').hidden = false;
      window.history.replaceState({}, '', '/');
    } catch { /* malformed tag: ignore */ }
  }
  // SSO sign-in appears whenever the server has an identity provider.
  try {
    const { available } = await api('/api/admin/sso');
    if (available) $('login-sso').hidden = false;
  } catch { /* login page still works without it */ }
  try {
    await api('/api/admin/session');
    show('dashboard');
    await refreshLinks();
  } catch {
    show('login');
  }
})();

$('login-sso').addEventListener('click', () => {
  window.location.href = '/api/admin/sso/start';
});
