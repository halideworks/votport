// votport links page: issue transfer requests and manage received files.
// AGPL-3.0-only.

import { appendObjectCard } from '/assets/object-card.js';
import {
  alertModal,
  api,
  confirmModal,
  formatBytes,
  formatDuration,
  formatWhen,
  requireSession,
} from '/assets/admin-common.js';

const $ = (id) => document.getElementById(id);

// Connection-quality proxy: chunks the sender re-sent or the server refused.
function chunkTrouble(record) {
  let text = '';
  if (record.replayed_chunks) text += ` · ${record.replayed_chunks} re-sent chunks`;
  if (record.rejected_chunks) text += ` · ${record.rejected_chunks} rejected chunks`;
  return text;
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
      if (
        !(await confirmModal(
          'Clear record',
          'Remove this transfer from the history? Files on disk stay.',
          'Clear',
        ))
      )
        return;
      await api(`/api/admin/links/${link.id}/uploads/${upload.id}`, { method: 'DELETE' });
      await refreshLinks();
    }),
  );
  item.append(head);

  upload.files.forEach((file, index) => {
    const extras = [];
    if (!file.exists) {
      const missing = document.createElement('span');
      missing.className = 'badge off';
      missing.textContent = 'missing';
      extras.push(missing);
    }
    if (file.receipt) {
      const receipt = document.createElement('span');
      receipt.className = 'badge on';
      receipt.textContent = 'receipt';
      extras.push(receipt);
    }
    if (file.exists) {
      extras.push(
        button('Delete file', 'tiny danger', async () => {
          if (
            !(await confirmModal(
              'Delete file',
              `Delete "${file.stored_as}" from disk? This cannot be undone.`,
              'Delete',
            ))
          )
            return;
          await api(
            `/api/admin/links/${link.id}/uploads/${upload.id}/files/${index}`,
            { method: 'DELETE' },
          );
          await refreshLinks();
        }),
      );
    }
    appendObjectCard(
      item,
      { name: file.stored_as, suite: file.suite, root: file.root },
      { tag: 'div', rowClass: 'upload-file', status: formatBytes(file.bytes), extras },
    );
  });

  const root = document.createElement('div');
  root.className = 'mono muted file-id';
  root.textContent = `package ${upload.package_root}`;
  item.append(root);
  return item;
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
      if (
        !(await confirmModal(
          'Delete request',
          `Delete "${link.label}"? Received files stay on disk.`,
          'Delete',
        ))
      )
        return;
      await api(`/api/admin/links/${link.id}`, { method: 'DELETE' });
      await refreshLinks();
    }),
  );
  card.append(actions, qr);

  if (link.uploads.length) {
    const details = document.createElement('details');
    const summary = document.createElement('summary');
    const total = link.uploads.reduce((sum, up) => sum + up.total_bytes, 0);
    summary.textContent =
      `${link.uploads.length} transfer${link.uploads.length === 1 ? '' : 's'}` +
      ` · ${formatBytes(total)}`;
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
    summary.textContent = `${link.events.length} incomplete session${link.events.length === 1 ? '' : 's'}`;
    details.append(summary);
    const list = document.createElement('ul');
    list.className = 'uploads';
    for (const event of [...link.events].reverse()) {
      const item = document.createElement('li');
      const eventHead = document.createElement('div');
      eventHead.className = 'upload-head';
      let text = `${formatWhen(event.at)} · ${event.outcome}`;
      if (event.at > event.started_at) {
        text += ` after ${formatDuration(event.at - event.started_at)}`;
      }
      text += ` · ${formatBytes(event.received_bytes)} of ${formatBytes(event.expected_bytes)} received`;
      text += chunkTrouble(event);
      eventHead.textContent = text;
      item.append(eventHead);
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

await requireSession();
await refreshLinks();
