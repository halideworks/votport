// votport links page: issue transfer requests and manage received files.
// AGPL-3.0-only.

import { appendObjectCard } from '/assets/object-card.js';
import {
  buildLibraryTree,
  filterLibraryFiles,
  libraryFilesIn,
  libraryTreeNode,
  parseLibraryPath,
  projectDirectoryPrefixes,
  selectedLibraryStats,
  toggleFolderSelection,
} from '/assets/library-paths.js';
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

function showGrantResult(url, protectedGrant = false) {
  $('outbound-result').hidden = false;
  $('outbound-url').value = url;
  $('outbound-url').onclick = () => $('outbound-url').select();
  $('outbound-note').textContent =
    `Shown once. Copy it now; this URL cannot be retrieved later.`
    + (protectedGrant ? ' This download is password-protected. Send the password by a separate channel.' : '');
  $('outbound-copy').onclick = async () => {
    await navigator.clipboard.writeText(url);
    $('outbound-copy').textContent = 'Copied';
  };
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
  await refreshGrants();
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
  const transport = document.createElement('span');
  transport.className = 'badge';
  transport.textContent = upload.transport === 'push' ? 'native push' : 'http';
  head.append(when, transport);
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

function grantStatus(grant) {
  if (grant.revoked_at) return 'revoked';
  if (Number.isFinite(grant.max_downloads) && (grant.downloads ?? 0) >= grant.max_downloads) return 'used';
  if (grant.expires_at && grant.expires_at <= Math.floor(Date.now() / 1000)) return 'expired';
  return 'active';
}

function automationTokenStatus(token) {
  if (token.revoked_at) return 'revoked';
  if (token.expires_at && token.expires_at <= Math.floor(Date.now() / 1000)) return 'expired';
  return 'active';
}

function renderAutomationTokens(tokens) {
  const container = $('automation-tokens');
  container.replaceChildren();
  if (!tokens.length) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = 'No automation tokens issued.';
    container.append(empty);
    return;
  }
  for (const token of [...tokens].reverse()) {
    const card = document.createElement('div');
    card.className = 'card link-item';
    const head = document.createElement('div');
    head.className = 'head';
    const title = document.createElement('h3');
    title.textContent = token.label || 'Automation token';
    const status = automationTokenStatus(token);
    const badge = document.createElement('span');
    badge.className = `badge ${status === 'active' ? 'on' : 'off'}`;
    badge.textContent = status;
    head.append(title, badge);
    card.append(head);

    const meta = document.createElement('p');
    meta.className = 'muted';
    const parts = [
      `created ${formatWhen(token.created_at)}`,
      `expires ${formatWhen(token.expires_at)}`,
      Number.isFinite(token.last_used_at)
        ? `last used ${formatWhen(token.last_used_at)}`
        : 'never used',
    ];
    meta.textContent = parts.join(' · ');
    card.append(meta);

    if (status === 'active') {
      card.append(
        button('Revoke', 'tiny danger', async () => {
          if (
            !(await confirmModal(
              'Revoke automation token',
              `Revoke "${token.label || 'this token'}"? Automation using it will stop working.`,
              'Revoke',
            ))
          )
            return;
          await api(`/api/admin/automation-tokens/${encodeURIComponent(token.id)}`, {
            method: 'DELETE',
          });
          await refreshAutomationTokens();
        }),
      );
    }
    container.append(card);
  }
}

async function refreshAutomationTokens() {
  try {
    const { tokens } = await api('/api/admin/automation-tokens');
    renderAutomationTokens(tokens || []);
  } catch (error) {
    const message = document.createElement('p');
    message.className = 'error';
    message.textContent = error.message;
    $('automation-tokens').replaceChildren(message);
  }
}

function renderGrants(grants) {
  const container = $('outbound-grants');
  container.replaceChildren();
  if (!grants.length) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = 'No downloads issued.';
    container.append(empty);
    return;
  }
  for (const grant of [...grants].reverse()) {
    const card = document.createElement('div');
    card.className = 'card link-item';
    const head = document.createElement('div');
    head.className = 'head';
    const title = document.createElement('h3');
    title.textContent = grant.label || 'Outbound download';
    const status = grantStatus(grant);
    const badge = document.createElement('span');
    badge.className = `badge ${status === 'active' ? 'on' : 'off'}`;
    badge.textContent = status;
    head.append(title, badge);
    if (grant.has_password) {
      const protectedBadge = document.createElement('span');
      protectedBadge.className = 'badge';
      protectedBadge.textContent = 'protected';
      head.append(protectedBadge);
    }
    card.append(head);

    const name = document.createElement('p');
    name.className = 'mono';
    name.textContent = grant.name;
    card.append(name);

    const meta = document.createElement('p');
    meta.className = 'muted';
    const expiry = `expires ${formatWhen(grant.expires_at)}`;
    const downloads = grant.downloads ?? 0;
    const downloadSummary = Number.isFinite(grant.max_downloads)
      ? `${downloads} / ${grant.max_downloads} download starts`
      : `${downloads} download start${downloads === 1 ? '' : 's'} · unlimited`;
    const metaParts = [expiry, downloadSummary];
    if (Number.isFinite(grant.first_download_at)) {
      metaParts.push(`first ${formatWhen(grant.first_download_at)}`);
    }
    if (Number.isFinite(grant.last_download_at)) {
      metaParts.push(`last ${formatWhen(grant.last_download_at)}`);
    }
    meta.textContent = metaParts.join(' · ');
    card.append(meta);

    if (Array.isArray(grant.files) && grant.files.length > 1) {
      const files = document.createElement('ul');
      files.className = 'uploads';
      for (const file of grant.files) {
        const item = document.createElement('li');
        const fileName = document.createElement('div');
        fileName.className = 'mono';
        fileName.textContent = file.name;
        const fileMeta = document.createElement('div');
        fileMeta.className = 'muted';
        const fileDownloads = file.downloads ?? 0;
        const fileParts = [
          `${fileDownloads} download start${fileDownloads === 1 ? '' : 's'}`,
        ];
        if (Number.isFinite(file.first_download_at)) {
          fileParts.push(`first ${formatWhen(file.first_download_at)}`);
        }
        if (Number.isFinite(file.last_download_at)) {
          fileParts.push(`last ${formatWhen(file.last_download_at)}`);
        }
        fileMeta.textContent = fileParts.join(' · ');
        item.append(fileName, fileMeta);
        files.append(item);
      }
      card.append(files);
    }

    if (status !== 'revoked') {
      const actions = document.createElement('div');
      actions.className = 'actions';
      if (status === 'active') {
        actions.append(
          button('New address', 'tiny', async () => {
            if (
              !(await confirmModal(
                'Rotate download address',
                'Create a new address? The old address will stop working immediately.',
                'Create',
              ))
            )
              return;
            const response = await api(`/api/admin/outbound-grants/${grant.id}`, {
              method: 'PATCH',
              body: JSON.stringify({ rotate: true }),
            });
            if (!response.url) throw new Error('server did not return a download URL');
            showGrantResult(response.url, grant.has_password);
            await refreshGrants();
          }),
        );
      }
      actions.append(
        button('Extend 7 days', 'tiny', async () => {
          await api(`/api/admin/outbound-grants/${grant.id}`, {
            method: 'PATCH',
            body: JSON.stringify({ extend_days: 7 }),
          });
          await refreshGrants();
        }),
        button('Revoke', 'tiny danger', async () => {
          if (
            !(await confirmModal(
              'Revoke download',
              'Revoke this download link? Anyone with it will lose access.',
              'Revoke',
            ))
          )
            return;
          await api(`/api/admin/outbound-grants/${grant.id}`, { method: 'DELETE' });
          await refreshGrants();
        }),
      );
      card.append(actions);
    }
    container.append(card);
  }
}

async function refreshGrants() {
  try {
    const { grants } = await api('/api/admin/outbound-grants');
    renderGrants(grants || []);
  } catch {
    const error = document.createElement('p');
    error.className = 'muted';
    error.textContent = 'Issued downloads could not be loaded.';
    $('outbound-grants').replaceChildren(error);
  }
}

const MAX_LIBRARY_SELECTION = 64;
const MAX_LIBRARY_SEARCH_RESULTS = 200;
const selectedLibraryPaths = new Set();
let libraryFiles = [];
let libraryTree = buildLibraryTree([]);
let libraryDirectory = '';

function libraryPath(file) {
  const relative = file.webkitRelativePath || file.name;
  const project = $('deliver-project').value.trim().replace(/^\/+|\/+$/g, '');
  return project ? `${project}/${relative}` : relative;
}

async function uploadLibraryFile(file, path) {
  const response = await fetch(`/api/admin/outbound-files?path=${encodeURIComponent(path)}`, {
    method: 'POST',
    headers: { 'Content-Type': file.type || 'application/octet-stream', 'X-Votport': '1' },
    credentials: 'same-origin',
    body: file,
  });
  let body = null;
  try { body = await response.json(); } catch { /* empty success response */ }
  if (!response.ok) throw new Error(body?.error || `upload failed (${response.status})`);
}

function updateProjectSuggestions(files) {
  const options = projectDirectoryPrefixes(files);
  $('deliver-project-options').replaceChildren(
    ...options.map((value) => {
      const option = document.createElement('option');
      option.value = value;
      return option;
    }),
  );
}

function updateLibrarySelectionStatus() {
  const { count, bytes } = selectedLibraryStats(libraryFiles, selectedLibraryPaths);
  $('library-selection-status').textContent = `${count} file${count === 1 ? '' : 's'} selected · ${formatBytes(bytes)}`;
}

function showLibrarySelectionError() {
  $('library-selection-error').textContent =
    `Select at most ${MAX_LIBRARY_SELECTION} files. Deselect some files before selecting this folder.`;
  $('library-selection-error').hidden = false;
  updateLibrarySelectionStatus();
}

function applyLibrarySelection(next) {
  selectedLibraryPaths.clear();
  for (const path of next) selectedLibraryPaths.add(path);
  $('library-selection-error').hidden = true;
  updateLibrarySelectionStatus();
}

function selectionCheckbox(paths) {
  const checkbox = document.createElement('input');
  checkbox.type = 'checkbox';
  const selected = paths.filter((path) => selectedLibraryPaths.has(path)).length;
  checkbox.checked = paths.length > 0 && selected === paths.length;
  checkbox.indeterminate = selected > 0 && selected < paths.length;
  checkbox.addEventListener('change', () => {
    const next = toggleFolderSelection(selectedLibraryPaths, paths, MAX_LIBRARY_SELECTION);
    if (!next) {
      renderLibraryView();
      showLibrarySelectionError();
      return;
    }
    applyLibrarySelection(next);
    renderLibraryView();
  });
  return checkbox;
}

function renderLibraryBreadcrumbs() {
  const breadcrumbs = $('library-breadcrumbs');
  breadcrumbs.replaceChildren();
  const root = button('Library', 'tiny ghost', async () => {
    libraryDirectory = '';
    renderLibraryView();
  });
  if (!libraryDirectory) root.setAttribute('aria-current', 'page');
  breadcrumbs.append(root);
  const parts = libraryDirectory ? parseLibraryPath(libraryDirectory) : [];
  if (!parts) return;
  let path = '';
  for (const part of parts) {
    path = path ? `${path}/${part}` : part;
    breadcrumbs.append(document.createTextNode(' / '));
    const crumbPath = path;
    const crumb = button(part, 'tiny ghost', async () => {
      libraryDirectory = crumbPath;
      renderLibraryView();
    });
    if (crumbPath === libraryDirectory) crumb.setAttribute('aria-current', 'page');
    breadcrumbs.append(crumb);
  }
}

function renderLibraryFile(file, container, showPath = false) {
  const label = document.createElement('label');
  label.className = 'library-file';
  const checkbox = selectionCheckbox([file.path]);
  checkbox.value = file.path;
  const name = document.createElement('span');
  name.className = 'mono';
  name.textContent = showPath ? file.path : file.path.slice(file.path.lastIndexOf('/') + 1);
  const size = document.createElement('span');
  size.className = 'muted';
  size.textContent = formatBytes(file.bytes);
  label.append(checkbox, name, size);
  container.append(label);
}

function renderLibraryFolder(folder, container) {
  const files = libraryFilesIn(folder);
  const row = document.createElement('div');
  row.className = 'library-file library-folder';
  const checkbox = selectionCheckbox(files.map((file) => file.path));
  const open = button(folder.name, 'tiny ghost', async () => {
    libraryDirectory = folder.path;
    renderLibraryView();
  });
  open.setAttribute('aria-label', `Open folder ${folder.name}`);
  const count = document.createElement('span');
  count.className = 'muted';
  count.textContent = `${files.length} file${files.length === 1 ? '' : 's'}`;
  row.append(checkbox, open, count);
  container.append(row);
}

function renderLibraryView() {
  renderLibraryBreadcrumbs();
  const container = $('library-files');
  container.replaceChildren();
  const query = $('library-search').value;
  if (query.trim()) {
    const matches = filterLibraryFiles(libraryFiles, query).sort((left, right) =>
      left.path.localeCompare(right.path),
    );
    if (!matches.length) {
      const empty = document.createElement('p');
      empty.className = 'muted';
      empty.textContent = 'No matching library files.';
      container.append(empty);
      return;
    }
    for (const file of matches.slice(0, MAX_LIBRARY_SEARCH_RESULTS)) {
      renderLibraryFile(file, container, true);
    }
    if (matches.length > MAX_LIBRARY_SEARCH_RESULTS) {
      const note = document.createElement('p');
      note.className = 'muted';
      note.textContent = `Showing first ${MAX_LIBRARY_SEARCH_RESULTS}; refine search.`;
      container.append(note);
    }
    return;
  }
  const folder = libraryTreeNode(libraryTree, libraryDirectory);
  if (!folder) {
    libraryDirectory = '';
    renderLibraryView();
    return;
  }
  const folders = [...folder.children.values()].sort((left, right) =>
    left.name.localeCompare(right.name),
  );
  const files = [...folder.files].sort((left, right) => left.path.localeCompare(right.path));
  for (const child of folders) renderLibraryFolder(child, container);
  for (const file of files) renderLibraryFile(file, container);
  if (!folders.length && !files.length) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = 'No library files.';
    container.append(empty);
  }
}

function renderLibrary(files) {
  const safeFiles = files.filter((file) => parseLibraryPath(file.path));
  libraryFiles = safeFiles;
  libraryTree = buildLibraryTree(safeFiles);
  const available = new Set(safeFiles.map((file) => file.path));
  for (const path of selectedLibraryPaths) {
    if (!available.has(path)) selectedLibraryPaths.delete(path);
  }
  updateProjectSuggestions(safeFiles);
  updateLibrarySelectionStatus();
  renderLibraryView();
}

async function refreshLibrary() {
  try {
    const { files } = await api('/api/admin/outbound-files');
    renderLibrary(files || []);
  } catch (error) {
    const message = document.createElement('p');
    message.className = 'error';
    message.textContent = error.message;
    $('library-files').replaceChildren(message);
  }
}

const LINKS_PAGE_SIZE = 50;
let linksCursor = null;
let linksFilter = { search: '', status: '' };

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

async function refreshLinks({ append = false } = {}) {
  if (!append) {
    linksFilter = {
      search: $('links-query').value.trim(),
      status: $('links-status').value,
    };
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
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = linksFilter.search || linksFilter.status
      ? 'No matching requests.'
      : 'No requests issued.';
    container.append(empty);
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
}

async function refreshLinksSafe(options = {}) {
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

$('automation-token-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const error = $('automation-token-error');
  error.hidden = true;
  const label = $('automation-token-label').value.trim();
  const expires = Number($('automation-token-expires').value);
  if (!label || label.length > 100) {
    error.textContent = 'Label must be 1 to 100 characters.';
    error.hidden = false;
    return;
  }
  if (!Number.isInteger(expires) || expires < 1 || expires > 365) {
    error.textContent = 'Expiry must be between 1 and 365 days.';
    error.hidden = false;
    return;
  }
  const submit = $('automation-token-submit');
  submit.disabled = true;
  try {
    const response = await api('/api/admin/automation-tokens', {
      method: 'POST',
      body: JSON.stringify({ label, expires_days: expires }),
    });
    if (!response.token) throw new Error('server did not return the automation token');
    $('automation-token-form').reset();
    $('automation-token-value').value = response.token;
    $('automation-token-result').hidden = false;
    $('automation-token-copy').textContent = 'Copy token';
    $('automation-token-copy').onclick = async () => {
      await navigator.clipboard.writeText(response.token);
      $('automation-token-copy').textContent = 'Copied';
    };
    await refreshAutomationTokens();
  } catch (requestError) {
    error.textContent = requestError.message;
    error.hidden = false;
  } finally {
    submit.disabled = false;
  }
});

$('library-refresh').addEventListener('click', () => refreshLibrary());
$('library-search').addEventListener('input', () => renderLibraryView());

$('deliver-upload-form').addEventListener('submit', (event) => event.preventDefault());
$('library-input').addEventListener('change', async (event) => {
  const input = event.currentTarget;
  const files = [...input.files];
  if (!files.length) return;
  input.disabled = true;
  $('library-status').textContent = `Uploading 0 of ${files.length} files…`;
  try {
    for (const [index, file] of files.entries()) {
      await uploadLibraryFile(file, libraryPath(file));
      $('library-status').textContent = `Uploading ${index + 1} of ${files.length} files…`;
    }
    $('library-status').textContent = `${files.length} file${files.length === 1 ? '' : 's'} added.`;
    await refreshLibrary();
  } catch (error) {
    $('library-status').textContent = error.message;
  } finally {
    input.disabled = false;
    input.value = '';
  }
});

$('deliver-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('deliver-error').hidden = true;
  const paths = [...selectedLibraryPaths];
  if (paths.length > MAX_LIBRARY_SELECTION) {
    $('deliver-error').textContent = `Select at most ${MAX_LIBRARY_SELECTION} files.`;
    $('deliver-error').hidden = false;
    return;
  }
  const expires = Number($('deliver-expires').value);
  const maxDownloadsValue = $('deliver-max-downloads').value.trim();
  const maxDownloads = maxDownloadsValue ? Number(maxDownloadsValue) : null;
  if (!paths.length) {
    $('deliver-error').textContent = 'Select at least one file.';
    $('deliver-error').hidden = false;
    return;
  }
  if (!Number.isInteger(expires) || expires < 1 || expires > 30) {
    $('deliver-error').textContent = 'Expiry must be between 1 and 30 days.';
    $('deliver-error').hidden = false;
    return;
  }
  if (maxDownloads !== null && (!Number.isInteger(maxDownloads) || maxDownloads < 1 || maxDownloads > 10000)) {
    $('deliver-error').textContent = 'Max downloads must be between 1 and 10000.';
    $('deliver-error').hidden = false;
    return;
  }
  $('deliver-submit').disabled = true;
  try {
    const response = await api('/api/admin/outbound-grants', {
      method: 'POST',
      body: JSON.stringify({
        paths,
        label: $('deliver-label').value,
        expires_days: expires,
        password: $('deliver-password').value || null,
        max_downloads: maxDownloads,
      }),
    });
    if (!response.url) throw new Error('server did not return a download URL');
    showGrantResult(response.url, response.grant?.has_password);
    $('deliver-password').value = '';
    await refreshGrants();
  } catch (error) {
    $('deliver-error').textContent = error.message;
    $('deliver-error').hidden = false;
  } finally {
    $('deliver-submit').disabled = false;
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
await Promise.all([refreshLinks(), refreshGrants(), refreshLibrary(), refreshAutomationTokens()]);
