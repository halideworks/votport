import { isFormDirty, markFormSaved } from '/assets/form-drafts.js';
import { notificationEditor, notificationDetails, uploadEvents, workflowEvents } from '/assets/notifications.js';
// votport receive page: issue transfer requests and manage received files.
// VOTPORT PROPRIETARY LICENSE.

import { appendObjectCard } from '/assets/object-card.js';
import { narrate, summarize, timelineJson } from '/assets/timeline.js';
import { startStatusPoll } from '/assets/status-strip.js';
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
  undoable,
} from '/assets/admin-common.js';

const $ = (id) => document.getElementById(id);
const creatingRoute = new URLSearchParams(window.location.search).get('trade-route') === '1';
$('trade-return-guide').hidden = !creatingRoute;
if (creatingRoute) {
  $('create-password').disabled = true; $('create-password').closest('label').hidden = true;
  $('create-notification-options').hidden = true;
  $('create-form').querySelector('button[type="submit"]').textContent = 'Continue to route permissions';
}
let createNotifications = notificationEditor({ events: uploadEvents });
$('create-notifications').append(createNotifications.element);

let receiveProjects = [], receiveAdministrator = false, createWorkflow = null;
function workflowEditor(current = null) {
  const element = document.createElement('fieldset'), legend = document.createElement('legend'); legend.textContent = 'After files arrive'; element.append(legend);
  const label = document.createElement('label'); label.textContent = 'Reception project';
  const select = document.createElement('select'); select.add(new window.Option('Keep files here; no workflow', ''));
  for (const project of receiveProjects) select.add(new window.Option(project.label, project.id));
  if (current?.project_id && !receiveProjects.some((project) => project.id === current.project_id)) select.add(new window.Option(`${current.project_id} (unavailable)`, current.project_id));
  select.value = current?.project_id || ''; label.append(select); element.append(label);
  const help = document.createElement('p'); help.className = 'field-help'; help.textContent = 'Completed uploads run this project’s checks, approvals and destination copies. Incomplete uploads do not start a workflow.';
  const fields = document.createElement('div'); fields.className = 'grid';
  const notificationHost = document.createElement('div'); let workflowNotifications;
  const manage = document.createElement('a'); manage.href = '/workflows#projects'; manage.className = 'text-link'; manage.textContent = 'Manage reception projects →';
  element.append(help, fields, notificationHost, manage);
  function render() {
    fields.replaceChildren(); const project = receiveProjects.find((project) => project.id === select.value);
    notificationHost.replaceChildren(); workflowNotifications = null;
    if (project) { workflowNotifications = notificationEditor({ policy: current?.project_id === project.id ? current.notifications : null, inherit: project.notifications || null, events: workflowEvents }); notificationHost.append(workflowNotifications.element); }
    for (const key of project?.required_metadata || []) {
      const label = document.createElement('label'), input = document.createElement('input'); label.textContent = key.replace(/[_-]/g, ' ');
      input.dataset.metadata = key; input.required = true; input.maxLength = 4096; input.value = current?.project_id === project.id ? current.metadata[key] || '' : ''; label.append(input); fields.append(label);
    }
    for (const recipient of project?.recipients || []) {
      const label = document.createElement('label'), input = document.createElement('input'); label.className = 'check'; input.type = 'checkbox'; input.dataset.recipient = recipient.holder;
      input.checked = current?.project_id === project.id ? current.recipients.includes(recipient.holder) : true; label.append(input, document.createTextNode(recipient.email)); fields.append(label);
    }
  }
  select.addEventListener('change', render); render();
  return { element, read() {
    if (!select.value) return null;
    const project = receiveProjects.find((project) => project.id === select.value);
    if (!project) throw new Error('Choose an available reception project or turn off the workflow.');
    const metadata = Object.fromEntries([...fields.querySelectorAll('[data-metadata]')].map((input) => {
      if (!input.reportValidity()) throw new Error('Complete the required project fields.'); return [input.dataset.metadata, input.value.trim()];
    }));
    const recipients = [...fields.querySelectorAll('[data-recipient]:checked')].map((input) => input.dataset.recipient);
    if (project.recipients.length && !recipients.length) throw new Error('Choose at least one enrolled recipient.');
    return { project_id: select.value, metadata, recipients, notifications: workflowNotifications?.read() || null };
  } };
}

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

// The transfer timeline: summary figures and one line per log event, in
// the shared dialog. Everything shown is read from the record.
function openTimeline(link, upload) {
  const dialog = $('timeline');
  const summary = summarize(upload);
  $('timeline-kicker').textContent = link.label;
  $('timeline-title').textContent = `Transfer on ${formatWhen(upload.started_at || upload.completed_at)}`;
  const meta = [
    `${summary.files} file${summary.files === 1 ? '' : 's'}`,
    formatBytes(summary.bytes),
    summary.transport === 'push' ? 'native push' : 'http',
    summary.outcome === 'finished' ? `finished ${formatWhen(upload.completed_at)}` : summary.outcome,
  ];
  $('timeline-meta').textContent = meta.join(' · ');
  const stats = $('timeline-stats');
  stats.replaceChildren();
  const cell = (label, value, note) => {
    const box = document.createElement('div');
    box.className = 'stat';
    const head = document.createElement('span');
    head.className = 'stat-label';
    head.textContent = label;
    const strong = document.createElement('strong');
    strong.textContent = value;
    box.append(head, strong);
    if (note) {
      const small = document.createElement('span');
      small.className = 'muted';
      small.textContent = note;
      box.append(small);
    }
    return box;
  };
  stats.append(
    cell('Duration', summary.duration === null ? '–' : formatDuration(summary.duration)),
    cell('Average rate', summary.average === null ? '–' : `${formatBytes(summary.average)}/s`,
      summary.peak === null ? undefined : `peak ${formatBytes(summary.peak)}/s`),
    cell('Pauses', summary.pauses ? formatDuration(summary.pauses) : 'none',
      summary.restarts ? `${summary.restarts} restart${summary.restarts === 1 ? '' : 's'}` : undefined),
    cell('Re-sent chunks', String(summary.resent), `${summary.rejected} rejected`),
  );
  const events = $('timeline-events');
  events.replaceChildren();
  for (const event of upload.log || []) {
    const row = document.createElement('li');
    row.dataset.kind = event.kind;
    const when = document.createElement('span');
    when.className = 'when mono';
    when.textContent = new Date(event.at * 1000).toLocaleTimeString();
    const text = document.createElement('span');
    const line = narrate(event);
    text.textContent = line.text;
    row.append(when, text);
    if (line.detail) {
      const detail = document.createElement('span');
      detail.className = 'detail';
      detail.textContent = line.detail;
      row.append(detail);
    }
    events.append(row);
  }
  if (!events.firstChild) {
    const row = document.createElement('li');
    row.textContent = 'This transfer predates the timeline; only its record is known.';
    events.append(row);
  }
  const download = $('timeline-download');
  download.onclick = () => {
    const blob = new window.Blob([timelineJson(link, upload)], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `votport-transfer-${upload.id}.json`;
    anchor.click();
    setTimeout(() => window.URL.revokeObjectURL(url), 1000);
  };
  $('timeline-audit').href = `/audit?q=${encodeURIComponent(link.id)}`;
  dialog.showModal();
}

// Actions inside an undo window, keyed by what they change. The renderer
// reads these so any refresh (the status poll, another action) shows the
// pending state; the server hears about it when the window closes.
const pendingClears = new Set();
const pendingLinks = new Map();
// Cards whose transfer list is open, so a re-render does not collapse them.
const openLinks = new Set();

// Records a pending change, re-renders, and opens the undo window. Undo and
// commit both drop the record and re-render, so the list always matches
// either the server or the pending intent, never a detached node.
async function deferred({ text, mark, unmark, commit }) {
  mark();
  await refreshLinksSafe();
  try {
    await undoable({
      text,
      restore: () => { unmark(); refreshLinksSafe(); },
      commit,
    });
  } finally {
    unmark();
  }
  await refreshLinksSafe();
}

function renderUpload(link, upload) {
  const item = document.createElement('li');
  // A hold being released is still a hold until the window closes.
  const held = link.legal_hold || pendingLinks.get(link.id)?.legal_hold === false;

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
  head.append(button('Timeline', 'tiny ghost', () => openTimeline(link, upload)));
  if (upload.route) {
    head.append(button(upload.route.revoked_at ? 'Revoked trade route · evidence' : 'Trade route · evidence', 'tiny ghost', async () => {
      try {
        const evidence = await api(`/api/admin/links/${link.id}/uploads/${upload.id}/route`);
        const url = window.URL.createObjectURL(new window.Blob([JSON.stringify(evidence, null, 2)], { type: 'application/json' }));
        const anchor = document.createElement('a'); anchor.href = url; anchor.download = `trade-route-${upload.id}.json`; anchor.click();
        setTimeout(() => window.URL.revokeObjectURL(url), 1000);
      } catch (error) { await alertModal('Could not load custody evidence', error.message); }
    }));
  }
  if (upload.partial) {
    const partial = document.createElement('span');
    partial.className = 'badge off';
    partial.title = 'The session ended before the sender confirmed the transfer; only the files that were received are listed.';
    partial.textContent = 'partial';
    head.append(partial);
  }
  if (!held) {
    head.append(
      // Files on disk stay, so this needs an undo window, not a modal.
      button('Clear record', 'tiny ghost', () => deferred({
        text: 'Transfer record cleared.',
        mark: () => pendingClears.add(upload.id),
        unmark: () => pendingClears.delete(upload.id),
        commit: async () => {
          await api(`/api/admin/links/${link.id}/uploads/${upload.id}`, {
            method: 'DELETE',
            keepalive: true,
          });
        },
      })),
    );
  }
  const existingFiles = upload.files.filter((file) => file.exists);
  if (!held && existingFiles.length) {
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
    if (file.exists && !held) {
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
  return item;
}

const LINKS_PAGE_SIZE = 50;
let linksCursor = null;
let linksBusy = false;
// Load more was used: a background refresh would collapse the list.
let linksExpanded = false;
// A search result deep-links with the request's id as the list filter.
let linksFilter = { search: new URLSearchParams(window.location.search).get('search') || '', status: '' };

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
let receivingKey = null;
let linksRefreshPending = false;
function renderStatus(status) {
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
  $('stat-stored').textContent = formatBytes(status.stored.bytes);
  const stored = status.stored;
  let detail = `${stored.files} received file${stored.files === 1 ? '' : 's'} on disk`;
  if (stored.missing_files) {
    detail += ` · ${stored.missing_files} record${stored.missing_files === 1 ? '' : 's'} (${formatBytes(stored.missing_bytes)}) not on disk`;
  }
  $('stat-stored-detail').textContent = detail;
  $('stat-disk').textContent = status.disk ? formatBytes(status.disk.free_bytes) : '–';

  const byLink = new Map();
  for (const transfer of status.receiving) {
    if (!byLink.has(transfer.link_id)) byLink.set(transfer.link_id, []);
    byLink.get(transfer.link_id).push(transfer);
  }
  for (const card of $('links').querySelectorAll('[data-link-id]')) {
    applyReceiving(card, byLink.get(card.dataset.linkId) || [], status.now);
  }
  // A transfer starting or finishing changes what the list should show. The
  // first poll only records the set; a refresh in flight defers the change
  // to the next tick, and a list the operator paged through is left alone.
  const key = [...byLink.keys()].sort().join(',');
  if (linksRefreshPending || (receivingKey !== null && key !== receivingKey)) {
    if (linksBusy || receptionEditing()) return;
    if (!linksExpanded) refreshLinksSafe({ fromPoll: true });
  }
  receivingKey = key;
}

function renderLink(link) {
  // A change inside its undo window shows as if the server had it.
  const pending = pendingLinks.get(link.id);
  if (pending) {
    const expired = link.expires_at && Date.now() / 1000 >= link.expires_at;
    link = { ...link, ...pending };
    if (pending.active !== undefined) link.usable = pending.active && !expired;
  }
  // A record being cleared is gone from the count and total as well.
  if (pendingClears.size) {
    link = { ...link, uploads: link.uploads.filter((upload) => !pendingClears.has(upload.id)) };
  }
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
  if (link.workflow) {
    const route = document.createElement('p'); route.className = 'connection-meta';
    route.textContent = `After receiving: ${receiveProjects.find((project) => project.id === link.workflow.project_id)?.label || link.workflow.project_id}`;
    const jobs = document.createElement('a'); jobs.href = '/workflows#jobs'; jobs.className = 'text-link'; jobs.textContent = 'Follow workflow deliveries →'; card.append(route, jobs);
  }
  if (receiveAdministrator) {
    const details = document.createElement('details'), summary = document.createElement('summary'); summary.textContent = 'Reception workflow'; details.className = 'reception-workflow'; details.setAttribute('data-unsaved', '');
    const editor = workflowEditor(link.workflow), result = document.createElement('p'); result.setAttribute('role', 'status'); result.className = 'muted';
    editor.element.addEventListener('input', () => { details.dataset.dirty = 'true'; });
    const save = button('Save reception workflow', 'ghost', async () => {
      save.disabled = true;
      try { const workflow = editor.read(); editor.element.disabled = true; await api(`/api/admin/links/${link.id}`, { method: 'PATCH', body: JSON.stringify({ workflow: workflow || { project_id: '', metadata: {}, recipients: [] } }) }); linksRevision++; link.workflow = workflow; markFormSaved(details); delete details.dataset.dirty; result.textContent = 'Saved. This applies to future uploads; existing jobs keep their captured rules.'; }
      catch (error) { result.textContent = error.message; }
      finally { save.disabled = false; editor.element.disabled = false; }
    });
    details.append(summary, editor.element, save, result); card.append(details);
  }
  // Filled in by the status poll while a sender is shipping into this link.
  const receiving = document.createElement('p');
  receiving.className = 'receiving-now';
  receiving.hidden = true;
  card.dataset.linkId = link.id;
  card.append(receiving);
  applyReceiving(card, link.receiving || []);
  card.append(notificationDetails({ policy: link.notifications, events: uploadEvents, readOnly: !receiveAdministrator,
    save: async (notifications) => {
      await api(`/api/admin/links/${link.id}`, { method: 'PATCH', body: JSON.stringify({ notifications }) });
      linksRevision++; link.notifications = notifications;
    },
  }));
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
    button(link.active ? 'Deactivate' : 'Reactivate', 'tiny ghost', (control) => {
      if (pending) return;
      control.disabled = true;
      return deferred({
        text: link.active ? 'Request deactivated.' : 'Request reactivated.',
        mark: () => pendingLinks.set(link.id, { active: !link.active }),
        unmark: () => pendingLinks.delete(link.id),
        commit: async () => {
          await api(`/api/admin/links/${link.id}`, {
            method: 'POST',
            body: JSON.stringify({ active: !link.active }),
            keepalive: true,
          });
        },
      });
    }),
    button(link.legal_hold ? 'Release hold' : 'Legal hold', 'tiny ghost', async (control) => {
      if (pending) return;
      if (!link.legal_hold) {
        await api(`/api/admin/links/${link.id}`, {
          method: 'POST',
          body: JSON.stringify({ legal_hold: true }),
        });
        await refreshLinks();
        announce('links-action-status', 'Legal hold set.');
        return;
      }
      // Releasing lets retention run, so it waits for the undo window.
      control.disabled = true;
      await deferred({
        text: 'Legal hold released.',
        mark: () => pendingLinks.set(link.id, { legal_hold: false }),
        unmark: () => pendingLinks.delete(link.id),
        commit: async () => {
          await api(`/api/admin/links/${link.id}`, {
            method: 'POST',
            body: JSON.stringify({ legal_hold: false }),
            keepalive: true,
          });
        },
      });
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
        for (const editor of card.querySelectorAll('[data-unsaved]')) markFormSaved(editor);
        card.remove();
        await refreshLinks();
        announce('links-action-status', `Request "${link.label}" deleted.`);
      }),
    );
  }
  // Inside an undo window only Copy stays live; disabled buttons leave the
  // tab order as well as the pointer.
  if (pending) {
    for (const control of actions.querySelectorAll('button')) {
      if (control !== copy) control.disabled = true;
    }
  }
  card.append(actions, qr);

  if (link.uploads.length) {
    const details = document.createElement('details');
    details.open = openLinks.has(link.id);
    details.addEventListener('toggle', () => {
      if (details.open) openLinks.add(link.id);
      else openLinks.delete(link.id);
    });
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
    details.open = openLinks.has(`${link.id}:events`);
    details.addEventListener('toggle', () => {
      if (details.open) openLinks.add(`${link.id}:events`);
      else openLinks.delete(`${link.id}:events`);
    });
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

function receptionEditing() {
  return !!$('links').querySelector('.reception-workflow[open], .reception-workflow[data-dirty], .reception-workflow > button:disabled, .notification-details[open], .notification-details[data-dirty], .notification-details > button:disabled');
}

let linksRevision = 0;
async function refreshLinksInner({ append, fromPoll }) {
  if (fromPoll && receptionEditing()) return;
  const revision = ++linksRevision;
  const filter = append || fromPoll ? linksFilter : { search: $('links-query').value.trim(), status: $('links-status').value };
  const params = new URLSearchParams({ limit: String(LINKS_PAGE_SIZE) });
  if (filter.search) params.set('search', filter.search);
  if (filter.status) params.set('status', filter.status);
  if (append && linksCursor) {
    params.set('before_created_at', String(linksCursor.created));
    params.set('before_id', linksCursor.id);
  }
  const response = await api(`/api/admin/links?${params}`);
  await projectsReady;
  if (revision !== linksRevision) { linksRefreshPending = true; return; }
  if (fromPoll && receptionEditing()) { linksRefreshPending = true; return; }
  const { links, receive_dir } = response;
  $('receive-dir').textContent = `Receive root ${receive_dir}`;
  const container = $('links');
  const edits = new Map([...container.querySelectorAll('[data-link-id]')].map((card) => [card.dataset.linkId, [...card.querySelectorAll('[data-unsaved]')].filter(isFormDirty)]).filter(([, editors]) => editors.length));
  if (!append) {
    const omitted = [...edits].filter(([id]) => !links.some((link) => link.id === id)).flatMap(([, editors]) => editors);
    if (omitted.length && !window.confirm('Discard unsaved edits on requests outside these results?')) return;
    for (const editor of omitted) markFormSaved(editor);
  }
  linksFilter = filter; linksExpanded = append;
  linksRefreshPending = false;
  if (!append) container.replaceChildren();
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
      const card = renderLink(link);
      for (const editor of edits.get(link.id) || []) card.querySelector(`.${editor.className}`).replaceWith(editor);
      container.append(card);
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
  // A re-render (the status poll, an action) keeps the deep-linked card open.
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
  const submit = event.currentTarget.querySelector('button[type="submit"]');
  if (submit.disabled) return;
  submit.disabled = true; $('create-form').inert = true;
  $('create-error').hidden = true;
  const maxGib = parseInt($('create-max').value, 10);
  const expires = parseInt($('create-expires').value, 10);
  try {
    const { link } = await api('/api/admin/links', {
      method: 'POST',
      body: JSON.stringify({
        label: $('create-label').value,
        dest: $('create-dest').value,
        password: creatingRoute ? null : $('create-password').value || null,
        expires_days: Number.isFinite(expires) ? expires : null,
        max_bytes: Number.isFinite(maxGib) ? maxGib * 1024 ** 3 : null,
        notifications: creatingRoute ? { mode: 'off', rules: [] } : createNotifications.read(),
        workflow: createWorkflow?.read() || null,
      }),
    });
    markFormSaved($('create-form'));
    if (creatingRoute) { window.location.assign(`/trade-routes?receive=${encodeURIComponent(link.id)}#receive`); return; }
    $('create-form').reset();
    createNotifications = notificationEditor({ events: uploadEvents }); $('create-notifications').replaceChildren(createNotifications.element);
    createWorkflow = workflowEditor(); $('create-workflow').replaceChildren(createWorkflow.element);
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
  } finally { submit.disabled = false; $('create-form').inert = false; }
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

// The session check, the list, and the strip go out together; each is one
// round trip, and none of them needs the others to have answered first.
const sessionReady = requireSession();
$('create-form').inert = true;
const projectsReady = Promise.all([sessionReady, api('/api/workflows/projects')]).then(([session, response]) => {
  receiveAdministrator = session.role === 'admin'; receiveProjects = response.projects.filter((project) => project.receive);
  createWorkflow = workflowEditor(); $('create-workflow').replaceChildren(createWorkflow.element);
}).catch((error) => { $('create-error').textContent = `Could not load reception projects: ${error.message}`; $('create-error').hidden = false; })
  .finally(() => { $('create-form').inert = false; });

$('links-query').value = linksFilter.search;
startStatusPoll({ render: renderStatus, active: (status) => status.sessions_active > 0 });
await Promise.all([sessionReady, refreshLinksSafe()]);
revealHash();
