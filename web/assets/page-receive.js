// votport receive page: issue transfer requests and manage received files.
// VOTPORT PROPRIETARY LICENSE.

import { appendObjectCard } from '/assets/object-card.js';
import {
  alertModal,
  announce,
  api,
  button,
  confirmModal,
  copyToClipboard,
  formatBytes,
  formatDuration,
  formatWhen,
  requireSession,
  revealHash,
  showGrantResult,
} from '/assets/admin-common.js';

const $ = (id) => document.getElementById(id);

// Connection-quality proxy: chunks the sender re-sent or the server refused.
function chunkTrouble(record) {
  let text = '';
  if (record.replayed_chunks) text += ` · ${record.replayed_chunks} re-sent chunks`;
  if (record.rejected_chunks) text += ` · ${record.rejected_chunks} rejected chunks`;
  return text;
}

async function issueReceivedGrant(link, upload, fileIndex, file) {
  const response = await api('/api/admin/outbound-grants', {
    method: 'POST',
    body: JSON.stringify({
      link_id: link.id,
      upload_id: upload.id,
      file_index: fileIndex,
      label: file.path,
      expires_days: 7,
    }),
  });
  const url = response.url;
  if (!url) throw new Error('server did not return a download URL');
  showGrantResult(url, response.grant?.has_password);
}

function logSentence(event) {
  const file = event.path ?? 'a file';
  switch (event.kind) {
    case 'opened': return 'Session opened, manifest verified';
    case 'reattached': return `Re-attached after a restart, ${event.count ?? 0} file${event.count === 1 ? '' : 's'} already published`;
    case 'published': return `${file} published with its receipt`
      + (event.bytes !== undefined ? ` · ${formatBytes(event.bytes)}` : '')
      + (event.secs ? ` in ${formatDuration(event.secs)}` : '');
    case 'quiet': return `Sender was quiet for ${formatDuration(event.secs ?? 0)}`;
    case 'finished': return `Finished${event.count ? ` · ${event.count} re-sent chunk${event.count === 1 ? '' : 's'}` : ''}`;
    case 'cancelled': return 'Cancelled by the sender';
    case 'interrupted': return 'Session went idle and expired';
    case 'dropped': return 'Resume refused after a restart; published files kept';
    case 'elided': return `${event.count} more events not kept`;
    default: return event.kind;
  }
}

function renderUpload(link, upload) {
  const item = document.createElement('li');
  let logBox = null;

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
  const transport = document.createElement('span');
  transport.className = 'badge';
  transport.textContent = upload.transport === 'push' ? 'native push' : 'http';
  head.append(when, transport);
  // The log, ship's-log style: one line per event, facts rendered as words.
  if (upload.log?.length) {
    const log = document.createElement('div');
    log.className = 'transfer-log';
    log.hidden = true;
    head.append(
      button('Log', 'tiny ghost', () => {
        log.hidden = !log.hidden;
        if (!log.hidden && !log.firstChild) {
          for (const event of upload.log) {
            const line = document.createElement('div');
            const at = document.createElement('span');
            at.className = 'mono muted';
            at.textContent = new Date(event.at * 1000).toLocaleTimeString();
            const text = document.createElement('span');
            text.textContent = logSentence(event);
            line.append(at, text);
            log.append(line);
          }
        }
      }),
    );
    logBox = log;
  }
  if (upload.partial) {
    const partial = document.createElement('span');
    partial.className = 'badge off';
    partial.title = 'The session ended before the sender confirmed the transfer; only the files that were received are listed.';
    partial.textContent = 'partial';
    head.append(partial);
  }
  if (!link.legal_hold) {
    head.append(
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
        announce('links-action-status', 'Transfer record cleared.');
      }),
    );
  }
  const existingFiles = upload.files.filter((file) => file.exists);
  if (!link.legal_hold && existingFiles.length) {
    head.append(
      button('Delete stored files', 'tiny danger', async () => {
        if (
          !(await confirmModal(
            'Delete stored files',
            `Delete ${existingFiles.length} stored file${existingFiles.length === 1 ? '' : 's'} from disk? This cannot be undone.`,
            'Delete',
          ))
        )
          return;
        try {
          for (const [index, file] of upload.files.entries()) {
            if (!file.exists) continue;
            await api(
              `/api/admin/links/${link.id}/uploads/${upload.id}/files/${index}`,
              { method: 'DELETE' },
            );
          }
        } catch (error) {
          try { await refreshLinks(); } catch { /* keep the deletion error visible */ }
          throw error;
        }
        await refreshLinks();
        announce('links-action-status', `Deleted ${existingFiles.length} stored file${existingFiles.length === 1 ? '' : 's'}.`);
      }),
    );
  }
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
    if (file.exists && file.receipt) {
      extras.push(button('Send', 'tiny', () => issueReceivedGrant(link, upload, index, file)));
    }
    if (file.exists && !link.legal_hold) {
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
          announce('links-action-status', `Deleted "${file.stored_as}".`);
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
  if (logBox) item.append(logBox);
  return item;
}

const LINKS_PAGE_SIZE = 50;
let linksCursor = null;
let linksBusy = false;
// Load more was used: a background refresh would collapse the list.
let linksExpanded = false;
let linksFilter = { search: '', status: '' };

/// Three-step primer shown in place of an empty list.
function teachingEmptyState(title, steps) {
  const box = document.createElement('div');
  box.className = 'empty-teach';
  const heading = document.createElement('h3');
  heading.textContent = title;
  const list = document.createElement('ol');
  for (const step of steps) {
    const item = document.createElement('li');
    item.textContent = step;
    list.append(item);
  }
  box.append(heading, list);
  return box;
}

// Live "Receiving now" line on a request card, from the status poll. `now`
// is the server's clock, the same one that stamped started_at.
function applyReceiving(card, transfers, now = null) {
  const line = card.querySelector('.receiving-now');
  if (!line) return;
  if (!transfers.length) {
    line.hidden = true;
    return;
  }
  line.replaceChildren();
  for (const transfer of transfers) {
    const row = document.createElement('span');
    const parts = [
      `Receiving now · ${formatBytes(transfer.received)} of ${formatBytes(transfer.total)}`,
    ];
    // The rate needs the server's clock; the first render waits for the poll.
    if (now !== null) {
      const elapsed = Math.max(1, now - transfer.started_at);
      parts.push(`${formatBytes(Math.round(transfer.received / elapsed))}/s`);
    }
    parts.push(`sender started ${new Date(transfer.started_at * 1000).toLocaleTimeString([], { timeStyle: 'short' })}`);
    if (transfer.transport === 'push') parts.push('native push');
    row.textContent = parts.join(' · ');
    line.append(row);
  }
  line.hidden = false;
}

// Polls fast while something is arriving, slowly otherwise, never while the
// tab is hidden. The links list re-renders only when the set of receiving
// links changes, so a finished transfer's record appears without a click.
let statusTimer = null;
let receivingKey = null;
function startOfToday() {
  const day = new Date();
  day.setHours(0, 0, 0, 0);
  return Math.floor(day.getTime() / 1000);
}
async function refreshStatus() {
  clearTimeout(statusTimer);
  if (document.hidden) return;
  let status;
  try {
    status = await api(`/api/admin/status?since=${startOfToday()}`);
  } catch (error) {
    // The session expired under an open tab: the reload lands on sign-in.
    if (error.status === 401) {
      window.location.reload();
      return;
    }
    statusTimer = setTimeout(refreshStatus, 30_000);
    return;
  }
  const strip = $('status-strip');
  strip.hidden = false;
  $('stat-active').textContent = String(status.sessions_active);
  $('stat-active-detail').textContent = status.sessions_active
    ? `${formatBytes(status.bytes_in_flight)} in flight`
    : 'nothing in flight';
  $('stat-today').textContent = String(status.today.uploads);
  $('stat-today-detail').textContent = status.today.uploads
    ? `received · ${formatBytes(status.today.bytes)}`
    : 'received';
  $('stat-disk').textContent = status.disk ? formatBytes(status.disk.free_bytes) : '–';
  $('stat-drain').textContent = status.draining ? 'on' : 'off';
  const health = $('stat-health');
  health.textContent = status.healthy ? 'healthy' : 'unhealthy';
  health.className = `badge ${status.healthy ? 'on' : 'danger'}`;
  strip.classList.toggle('draining', Boolean(status.draining));

  const byLink = new Map();
  for (const transfer of status.receiving) {
    if (!byLink.has(transfer.link_id)) byLink.set(transfer.link_id, []);
    byLink.get(transfer.link_id).push(transfer);
  }
  for (const card of $('links').querySelectorAll('[data-link-id]')) {
    applyReceiving(card, byLink.get(card.dataset.linkId) || [], status.now);
  }
  // A transfer starting or finishing changes what the list should show. The
  // first poll only records the set; a list the operator has paged through
  // or is loading is left alone.
  const key = [...byLink.keys()].sort().join(',');
  if (receivingKey !== null && key !== receivingKey) {
    // A refresh in flight defers the change to the next tick; a list the
    // operator paged through is left as it is.
    if (linksBusy) return scheduleStatus(status);
    if (!linksExpanded) refreshLinksSafe({ fromPoll: true });
  }
  receivingKey = key;
  scheduleStatus(status);
}

function scheduleStatus(status) {
  clearTimeout(statusTimer);
  statusTimer = setTimeout(refreshStatus, status.sessions_active ? 4_000 : 30_000);
}

function renderLink(link) {
  const card = document.createElement('div');
  card.className = 'card link-item';
  card.id = `link-${link.id}`;

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
  if (link.legal_hold) {
    const hold = document.createElement('span');
    hold.className = 'badge';
    hold.textContent = 'legal hold';
    head.append(hold);
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
  // Filled in by the status poll while a sender is shipping into this link.
  const receiving = document.createElement('p');
  receiving.className = 'receiving-now';
  receiving.hidden = true;
  card.dataset.linkId = link.id;
  card.append(receiving);
  applyReceiving(card, link.receiving || []);
  const notify = document.createElement('label');
  notify.className = 'toggle muted';
  const notifyInput = document.createElement('input');
  notifyInput.type = 'checkbox';
  notifyInput.name = 'notify_on_upload';
  notifyInput.checked = Boolean(link.notify_on_upload);
  notifyInput.addEventListener('change', async () => {
    notifyInput.disabled = true;
    try {
      await api(`/api/admin/links/${link.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ notify_on_upload: notifyInput.checked }),
      });
    } catch (error) {
      notifyInput.checked = !notifyInput.checked;
      alertModal(error.message);
    } finally {
      notifyInput.disabled = false;
    }
  });
  notify.append(notifyInput, document.createTextNode(' Notify when an upload completes'));
  card.append(notify);
  if (link.legal_hold) {
    const holdNote = document.createElement('p');
    holdNote.className = 'muted';
    holdNote.textContent = 'Manual deletion of stored files and transfer history is disabled while this request is under legal hold.';
    card.append(holdNote);
  }

  // Lazily-loaded QR of the request link, toggled from the actions row.
  const qr = document.createElement('div');
  qr.className = 'qr';
  qr.hidden = true;

  const actions = document.createElement('div');
  actions.className = 'actions';
  const copy = button('Copy', 'tiny', () => copyToClipboard(copy, link.url));
  actions.append(
    copy,
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
      announce('links-action-status', link.active ? 'Request deactivated.' : 'Request reactivated.');
    }),
    button(link.legal_hold ? 'Release hold' : 'Legal hold', 'tiny ghost', async () => {
      if (
        link.legal_hold &&
        !(await confirmModal(
          'Release legal hold',
          'Release this hold? Automatic retention may delete expired files.',
          'Release hold',
        ))
      )
        return;
      await api(`/api/admin/links/${link.id}`, {
        method: 'POST',
        body: JSON.stringify({ legal_hold: !link.legal_hold }),
      });
      await refreshLinks();
      announce('links-action-status', link.legal_hold ? 'Legal hold released.' : 'Legal hold set.');
    }),
  );
  if (!link.legal_hold) {
    actions.append(
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
        announce('links-action-status', `Request "${link.label}" deleted.`);
      }),
    );
  }
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

async function refreshLinks({ append = false, fromPoll = false } = {}) {
  linksBusy = true;
  try {
    await refreshLinksInner({ append, fromPoll });
  } finally {
    linksBusy = false;
  }
}

async function refreshLinksInner({ append, fromPoll }) {
  if (append) {
    linksExpanded = true;
  } else {
    // A poll-driven refresh keeps the submitted filter; unsubmitted text in
    // the search box stays where it is.
    if (!fromPoll) {
      linksFilter = {
        search: $('links-query').value.trim(),
        status: $('links-status').value,
      };
    }
    linksExpanded = false;
    linksCursor = null;
    $('links').replaceChildren();
    $('links-load-more').hidden = true;
  }
  const params = new URLSearchParams({ limit: String(LINKS_PAGE_SIZE) });
  if (linksFilter.search) params.set('search', linksFilter.search);
  if (linksFilter.status) params.set('status', linksFilter.status);
  if (append && linksCursor) {
    params.set('before_created_at', String(linksCursor.created));
    params.set('before_id', linksCursor.id);
  }
  const response = await api(`/api/admin/links?${params}`);
  const { links, receive_dir } = response;
  $('receive-dir').textContent = `Receive root ${receive_dir}`;
  const container = $('links');
  if (!append && !links.length) {
    if (linksFilter.search || linksFilter.status) {
      const empty = document.createElement('p');
      empty.className = 'muted';
      empty.textContent = 'No matching requests.';
      container.append(empty);
    } else {
      container.append(teachingEmptyState('How receiving works', [
        'Issue a request above and choose where its files should land.',
        'Send the link to whoever has the files.',
        'Files arrive verified, each with a receipt, and appear here.',
      ]));
    }
  } else {
    for (const link of links) {
      container.append(renderLink(link));
    }
  }
  const nextCursor = response.next_cursor;
  linksCursor = nextCursor?.created_at !== undefined
    && nextCursor.created_at !== null
    && nextCursor.id
    ? { created: nextCursor.created_at, id: nextCursor.id }
    : null;
  $('links-load-more').hidden = !linksCursor;
  $('links-error').hidden = true;
  // A re-render (the status poll, an action) keeps the deep-linked card marked.
  revealHash({ scroll: false });
}

async function refreshLinksSafe(options = {}) {
  if (linksBusy) return;
  try {
    await refreshLinks(options);
  } catch (error) {
    $('links-error').textContent = error.message;
    $('links-error').hidden = false;
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
        notify_on_upload: $('create-notify-on-upload').checked,
      }),
    });
    $('create-form').reset();
    $('new-link').hidden = false;
    $('new-link-url').textContent = link.url;
    $('new-link-note').textContent = link.has_password
      ? 'Send the access password by a separate channel.'
      : '';
    $('new-link-copy').onclick = () => copyToClipboard($('new-link-copy'), link.url);
    await refreshLinks();
  } catch (error) {
    $('create-error').textContent = error.message;
    $('create-error').hidden = false;
  }
});

$('links-filter').addEventListener('submit', (event) => {
  event.preventDefault();
  refreshLinksSafe();
});
$('links-refresh').addEventListener('click', () => refreshLinksSafe());
$('links-load-more').addEventListener('click', async () => {
  const loadMore = $('links-load-more');
  loadMore.disabled = true;
  await refreshLinksSafe({ append: true });
  loadMore.disabled = false;
});

await requireSession();
await refreshLinks();
refreshStatus();
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) refreshStatus();
});
revealHash();
