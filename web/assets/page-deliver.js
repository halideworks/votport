// votport deliver page: build outbound downloads and manage issued links.
// VOTPORT PROPRIETARY LICENSE.

import {
  parseLibraryPath,
} from '/assets/library-paths.js';
import { entryFiles, runUploadBatch } from '/assets/upload-entries.js';
import {
  alertModal,
  announce,
  api,
  button,
  confirmModal,
  copyToClipboard,
  formatBytes,
  formatWhen,
  requireSession,
  showGrantResult,
} from '/assets/admin-common.js';

const $ = (id) => document.getElementById(id);

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
    message.setAttribute('role', 'alert');
    message.textContent = error.message;
    $('automation-tokens').replaceChildren(message);
  }
}

let grantRows = [];
let grantTotal = 0;
let grantHasMore = false;
let grantLoading = false;

function renderGrants() {
  const grants = grantRows;
  const container = $('outbound-grants');
  container.replaceChildren();
  $('outbound-grants-count').textContent = grantTotal
    ? `Showing ${grants.length} of ${grantTotal} issued downloads.`
    : '0 issued downloads.';
  $('outbound-grants-load-more').hidden = !grantHasMore;
  if (!grants.length) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = 'No downloads issued.';
    container.append(empty);
    return;
  }
  for (const grant of grants) {
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
      ? `${downloads} / ${grant.max_downloads} complete deliveries`
      : `${downloads} complete deliver${downloads === 1 ? 'y' : 'ies'} · unlimited`;
    const metaParts = [expiry, downloadSummary];
    if (Number.isFinite(grant.first_download_at)) {
      metaParts.push(`first ${formatWhen(grant.first_download_at)}`);
    }
    if (Number.isFinite(grant.last_download_at)) {
      metaParts.push(`last ${formatWhen(grant.last_download_at)}`);
    }
    meta.textContent = metaParts.join(' · ');
    card.append(meta);
    const notify = document.createElement('label');
    notify.className = 'toggle muted';
    const notifyInput = document.createElement('input');
    notifyInput.type = 'checkbox';
    notifyInput.name = 'notify_on_download';
    notifyInput.checked = Boolean(grant.notify_on_download);
    notifyInput.addEventListener('change', async () => {
      notifyInput.disabled = true;
      try {
        await api(`/api/admin/outbound-grants/${grant.id}`, {
          method: 'PATCH',
          body: JSON.stringify({ notify_on_download: notifyInput.checked }),
        });
      } catch (error) {
        notifyInput.checked = !notifyInput.checked;
        alertModal(error.message);
      } finally {
        notifyInput.disabled = false;
      }
    });
    notify.append(notifyInput, document.createTextNode(' Notify on first download and delivery completion'));
    card.append(notify);

    if (grant.files_truncated) {
      const summary = document.createElement('p');
      summary.className = 'muted';
      summary.textContent = `${Number(grant.file_count).toLocaleString()} files in this delivery.`;
      card.append(summary);
    } else if (Array.isArray(grant.files) && grant.files.length > 1) {
      const files = document.createElement('ul');
      files.className = 'uploads';
      for (const file of grant.files) {
        const item = document.createElement('li');
        item.className = 'upload-file';
        const fileName = document.createElement('span');
        fileName.className = 'mono';
        fileName.textContent = file.name;
        const fileMeta = document.createElement('span');
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
            announce('outbound-grants-status', 'Download address rotated.');
          }),
        );
      }
      actions.append(
        button('Extend 7 days', 'tiny', async () => {
          // Same base as the server: seven days past the later of now and the current expiry.
          const base = Math.max(grant.expires_at, Math.floor(Date.now() / 1000));
          const until = formatWhen(base + 7 * 86_400);
          if (!(await confirmModal('Extend download', `Extend this download until ${until}?`, 'Extend')))
            return;
          const { expires_at } = await api(`/api/admin/outbound-grants/${grant.id}`, {
            method: 'PATCH',
            body: JSON.stringify({ extend_days: 7 }),
          });
          await refreshGrants();
          announce('outbound-grants-status', `Download extended until ${formatWhen(expires_at)}.`);
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
          announce('outbound-grants-status', 'Download revoked.');
        }),
      );
      card.append(actions);
    }
    container.append(card);
  }
}

async function refreshGrants(reset = true) {
  if (grantLoading) return;
  grantLoading = true;
  const offset = reset ? 0 : grantRows.length;
  const loadMore = $('outbound-grants-load-more');
  loadMore.disabled = true;
  try {
    const response = await api(`/api/admin/outbound-grants?limit=50&offset=${offset}`);
    if (reset) grantRows = [];
    grantRows.push(...(response.grants || []));
    grantTotal = response.total ?? grantRows.length;
    grantHasMore = Boolean(response.has_more);
    renderGrants();
  } catch (error) {
    if (reset || !grantRows.length) {
      const message = document.createElement('p');
      message.className = 'muted';
      message.textContent = 'Issued downloads could not be loaded.';
      $('outbound-grants').replaceChildren(message);
    } else {
      alertModal(error.message);
    }
  } finally {
    grantLoading = false;
    loadMore.disabled = false;
  }
}

$('outbound-grants-load-more').addEventListener('click', () => refreshGrants(false));

const MAX_LIBRARY_SELECTION = 64;
const MAX_LIBRARY_SEARCH_RESULTS = 200;
const selectedLibraryPaths = new Map();
let deliverGrantBusy = false;
let libraryFiles = [];
let libraryDirectories = [];
let libraryDirectory = '';
let libraryTruncated = false;
let libraryRequestGeneration = 0;
let librarySearchTimer;
let libraryUploading = false;
const libraryProjectSuggestions = new Set();
const libraryFolderSelections = new Map();

function libraryPath(relative) {
  const project = $('deliver-project').value.trim().replace(/^\/+|\/+$/g, '');
  return project ? `${project}/${relative}` : relative;
}

async function uploadLibraryFile(file, path, progress = () => {}) {
  if (file.size === 0) {
    const response = await fetch(`/api/admin/outbound-files?path=${encodeURIComponent(path)}`, {
      method: 'POST',
      headers: { 'Content-Type': file.type || 'application/octet-stream', 'X-Votport': '1' },
      credentials: 'same-origin',
      body: file,
    });
    let body = null;
    try { body = await response.json(); } catch { /* empty error response */ }
    if (!response.ok) throw new Error(body?.error || `upload failed (${response.status})`);
    progress(0);
    return;
  }
  const encoded = new TextEncoder().encode(JSON.stringify([path, file.size, file.lastModified]));
  const digest = await globalThis.crypto.subtle.digest('SHA-256', encoded);
  const uploadId = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  const chunkSize = 8 * 1024 * 1024;
  let offset = 0;
  while (offset < file.size) {
    const end = Math.min(offset + chunkSize, file.size);
    let retries = 0;
    while (true) {
      try {
        const response = await fetch(`/api/admin/outbound-files?path=${encodeURIComponent(path)}`, {
          method: 'POST',
          headers: {
            'Content-Type': file.type || 'application/octet-stream',
            'Content-Range': `bytes ${offset}-${end - 1}/${file.size}`,
            'X-Votport': '1',
            'X-Votport-Upload-Id': uploadId,
          },
          credentials: 'same-origin',
          body: file.slice(offset, end),
        });
        let body = null;
        try { body = await response.json(); } catch { /* empty error response */ }
        if (response.status === 409 && Number.isInteger(body?.offset)) {
          if (body.offset < 0 || body.offset > file.size) throw new Error('server returned invalid upload offset');
          offset = body.offset;
          progress(offset);
          break;
        }
        if (!response.ok) throw new Error(body?.error || `upload failed (${response.status})`);
        if (!Number.isInteger(body?.offset) || body.offset !== end) throw new Error('server returned invalid upload offset');
        offset = body.offset;
        progress(offset);
        break;
      } catch (error) {
        if (retries++ >= 3) throw error;
        await new Promise((resolve) => setTimeout(resolve, 200 * retries));
      }
    }
  }
}

function libraryFilePairs(files) {
  return [...files].map((file) => ({
    path: file.webkitRelativePath || file.name,
    file,
  }));
}

async function uploadLibraryFiles(pairs) {
  if (!pairs.length || libraryUploading) return;
  let uploads;
  try {
    uploads = pairs.map(({ path, file }) => ({ path: libraryPath(path), file }));
    for (const { path } of uploads) {
      if (!parseLibraryPath(path)) throw new Error(`"${path}" is not a valid library path.`);
    }
  } catch (error) {
    $('library-status').textContent = error.message;
    return;
  }
  libraryUploading = true;
  const controls = [$('library-add-files'), $('library-add-folder'), $('library-input'), $('library-folder-input')];
  controls.forEach((control) => { control.disabled = true; });
  libraryDrop.setAttribute('aria-busy', 'true');
  $('library-status').textContent = `Uploading 0 of ${uploads.length} files…`;
  let completedUploads = 0;
  try {
    await runUploadBatch(
      uploads,
      ({ file, path }, progress) => uploadLibraryFile(file, path, progress),
      ({ file }, offset, completed, total) => {
        const percent = file.size ? Math.floor((offset / file.size) * 100) : 100;
        $('library-status').textContent =
          `Uploading ${file.name}: ${percent}% (${completed} of ${total} files complete)`;
      },
      ({ file }, completed, total) => {
        completedUploads = completed;
        $('library-status').textContent =
          `Uploading ${file.name}: 100% (${completed} of ${total} files complete)`;
      },
    );
    await refreshLibrary();
    $('library-status').textContent = `${uploads.length} file${uploads.length === 1 ? '' : 's'} added.`;
  } catch (error) {
    if (completedUploads > 0) {
      await refreshLibrary();
      $('library-status').textContent =
        `${error.message} ${completedUploads} of ${uploads.length} files added.`;
    } else {
      $('library-status').textContent = error.message;
    }
  } finally {
    libraryUploading = false;
    libraryDrop.removeAttribute('aria-busy');
    controls.forEach((control) => { control.disabled = false; });
    $('library-input').value = '';
    $('library-folder-input').value = '';
  }
}

function updateProjectSuggestions(directories) {
  const options = [...directories].sort();
  $('deliver-project-options').replaceChildren(
    ...options.map((value) => {
      const option = document.createElement('option');
      option.value = value;
      return option;
    }),
  );
}

async function browseLibrary(directory) {
  clearTimeout(librarySearchTimer);
  $('library-search').value = '';
  libraryDirectory = directory;
  await refreshLibrary();
}

function updateLibrarySelectionStatus() {
  const count = selectedLibraryPaths.size;
  const bytes = [...selectedLibraryPaths.values()].reduce((total, value) => total + value, 0);
  $('library-selection-status').textContent = `${count} file${count === 1 ? '' : 's'} selected · ${formatBytes(bytes)}`;
}

function showLibrarySelectionError() {
  $('library-selection-error').textContent =
    `Select at most ${MAX_LIBRARY_SELECTION} files.`;
  $('library-selection-error').hidden = false;
  updateLibrarySelectionStatus();
}

function selectionCheckbox(file) {
  const checkbox = document.createElement('input');
  checkbox.type = 'checkbox';
  checkbox.checked = selectedLibraryPaths.has(file.path);
  checkbox.addEventListener('change', () => {
    if (checkbox.checked) {
      if (selectedLibraryPaths.size >= MAX_LIBRARY_SELECTION) {
        checkbox.checked = false;
        showLibrarySelectionError();
        return;
      }
      selectedLibraryPaths.set(file.path, Number(file.bytes) || 0);
    } else {
      selectedLibraryPaths.delete(file.path);
    }
    $('library-selection-error').hidden = true;
    updateLibrarySelectionStatus();
  });
  return checkbox;
}

function updateLibraryFolderCheckbox(directory, checkbox) {
  const known = libraryFolderSelections.get(directory);
  const selected = known && [...known.keys()].filter((path) => selectedLibraryPaths.has(path)).length;
  checkbox.checked = Boolean(known && selected === known.size);
  checkbox.indeterminate = Boolean(known && selected > 0 && selected < known.size);
}

async function toggleLibraryFolder(directory, checkbox) {
  const known = libraryFolderSelections.get(directory);
  if (!checkbox.checked) {
    if (!known) return;
    for (const path of known.keys()) selectedLibraryPaths.delete(path);
    libraryFolderSelections.delete(directory);
    updateLibrarySelectionStatus();
    return;
  }
  if (known) {
    const additions = [...known.keys()].filter((path) => !selectedLibraryPaths.has(path));
    if (selectedLibraryPaths.size + additions.length > MAX_LIBRARY_SELECTION) {
      updateLibraryFolderCheckbox(directory, checkbox);
      showLibrarySelectionError();
      return;
    }
    for (const [path, bytes] of known) selectedLibraryPaths.set(path, bytes);
    $('library-selection-error').hidden = true;
    updateLibrarySelectionStatus();
    return;
  }
  checkbox.disabled = true;
  try {
    const response = await api(`/api/admin/outbound-files?selection=${encodeURIComponent(directory)}`);
    const files = (response.files || []).filter((file) => parseLibraryPath(file.path));
    const additions = files.filter((file) => !selectedLibraryPaths.has(file.path));
    if (selectedLibraryPaths.size + additions.length > MAX_LIBRARY_SELECTION) {
      throw new Error(`Select at most ${MAX_LIBRARY_SELECTION} files.`);
    }
    libraryFolderSelections.set(
      directory,
      new Map(files.map((file) => [file.path, Number(file.bytes) || 0])),
    );
    for (const file of files) selectedLibraryPaths.set(file.path, Number(file.bytes) || 0);
    $('library-selection-error').hidden = true;
    updateLibrarySelectionStatus();
  } catch (error) {
    checkbox.checked = false;
    $('library-selection-error').textContent = error.message;
    $('library-selection-error').hidden = false;
    updateLibrarySelectionStatus();
  } finally {
    checkbox.disabled = false;
  }
}

function renderLibraryBreadcrumbs() {
  const breadcrumbs = $('library-breadcrumbs');
  breadcrumbs.replaceChildren();
  const root = button('Library', 'tiny ghost', async () => {
    await browseLibrary('');
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
      await browseLibrary(crumbPath);
    });
    if (crumbPath === libraryDirectory) crumb.setAttribute('aria-current', 'page');
    breadcrumbs.append(crumb);
  }
}

function renderLibraryFile(file, container, showPath = false) {
  const label = document.createElement('label');
  label.className = 'library-file';
  const checkbox = selectionCheckbox(file);
  checkbox.value = file.path;
  const name = document.createElement('span');
  name.className = 'mono';
  name.textContent = showPath ? file.path : file.path.slice(file.path.lastIndexOf('/') + 1);
  const size = document.createElement('span');
  size.className = 'muted';
  size.textContent = formatBytes(file.bytes);
  const remove = button('Delete', 'tiny danger', async () => {
    if (!(await confirmModal(
      'Delete outbound file',
      `Delete "${file.path}"? Active download grants will block this if they still reference it.`,
      'Delete',
    ))) return;
    remove.disabled = true;
    try {
      await api(`/api/admin/outbound-files?path=${encodeURIComponent(file.path)}`, { method: 'DELETE' });
      selectedLibraryPaths.delete(file.path);
      for (const [directory, paths] of libraryFolderSelections) {
        paths.delete(file.path);
        if (!paths.size) libraryFolderSelections.delete(directory);
      }
      await refreshLibrary();
    } finally {
      remove.disabled = false;
    }
  });
  remove.setAttribute('aria-label', `Delete ${file.path}`);
  remove.addEventListener('click', (event) => {
    event.preventDefault();
    event.stopPropagation();
  }, { capture: true });
  label.append(checkbox, name, size, remove);
  container.append(label);
}

function renderLibraryDirectory(directory, container) {
  const name = directory.slice(directory.lastIndexOf('/') + 1);
  const select = document.createElement('input');
  select.type = 'checkbox';
  updateLibraryFolderCheckbox(directory, select);
  select.setAttribute('aria-label', `Select folder ${directory}`);
  select.title = 'Select all files in this folder';
  select.addEventListener('change', () => toggleLibraryFolder(directory, select));
  const open = button(name, 'tiny ghost', async () => {
    await browseLibrary(directory);
  });
  open.setAttribute('aria-label', `Open folder ${name}`);
  open.title = name;
  const share = button('Share folder', 'tiny', async () => {
    await submitDeliverGrant({ directory }, share);
  });
  share.dataset.libraryFolderShare = 'true';
  share.setAttribute('aria-label', `Share folder ${directory}`);
  const row = document.createElement('div');
  row.className = 'library-file library-folder';
  row.append(select, open, share);
  container.append(row);
}

function renderLibraryView() {
  renderLibraryBreadcrumbs();
  const container = $('library-files');
  container.replaceChildren();
  const query = $('library-search').value.trim();
  if (query) {
    for (const file of libraryFiles) renderLibraryFile(file, container, true);
    if (libraryTruncated) {
      const note = document.createElement('p');
      note.className = 'muted';
      note.textContent = `Showing first ${MAX_LIBRARY_SEARCH_RESULTS}; refine search.`;
      container.append(note);
    }
    if (!libraryFiles.length) {
      const empty = document.createElement('p');
      empty.className = 'muted';
      empty.textContent = 'No matching library files.';
      container.append(empty);
    }
    return;
  }
  for (const directory of libraryDirectories) renderLibraryDirectory(directory, container);
  for (const file of libraryFiles) renderLibraryFile(file, container);
  if (libraryTruncated) {
    const note = document.createElement('p');
    note.className = 'muted';
    note.textContent = 'Showing the first 1000 entries; refine with search.';
    container.append(note);
  }
  if (!libraryDirectories.length && !libraryFiles.length) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = 'No library files.';
    container.append(empty);
  }
}

function renderLibrary(response) {
  libraryFiles = (response.files || []).filter((file) => parseLibraryPath(file.path));
  libraryDirectories = (response.directories || []).filter((path) => parseLibraryPath(path));
  libraryTruncated = Boolean(response.truncated);
  if (!$('library-search').value.trim()) {
    if (libraryDirectory) libraryProjectSuggestions.add(libraryDirectory);
    for (const directory of libraryDirectories) libraryProjectSuggestions.add(directory);
    updateProjectSuggestions(libraryProjectSuggestions);
  }
  updateLibrarySelectionStatus();
  renderLibraryView();
}

async function refreshLibrary() {
  const generation = ++libraryRequestGeneration;
  const query = $('library-search').value.trim();
  const params = query
    ? `q=${encodeURIComponent(query)}`
    : `directory=${encodeURIComponent(libraryDirectory)}`;
  try {
    const response = await api(`/api/admin/outbound-files?${params}`);
    if (generation !== libraryRequestGeneration) return;
    renderLibrary(response);
  } catch (error) {
    if (generation !== libraryRequestGeneration) return;
    const message = document.createElement('p');
    message.className = 'error';
    message.setAttribute('role', 'alert');
    message.textContent = error.message;
    $('library-files').replaceChildren(message);
  }
}

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
    $('automation-token-copy').onclick = () => copyToClipboard($('automation-token-copy'), response.token);
    await refreshAutomationTokens();
  } catch (requestError) {
    error.textContent = requestError.message;
    error.hidden = false;
  } finally {
    submit.disabled = false;
  }
});

$('library-refresh').addEventListener('click', () => refreshLibrary());
$('library-search').addEventListener('input', () => {
  libraryRequestGeneration += 1;
  clearTimeout(librarySearchTimer);
  librarySearchTimer = setTimeout(() => refreshLibrary(), 200);
});

$('deliver-upload-form').addEventListener('submit', (event) => event.preventDefault());
$('library-add-files').addEventListener('click', () => $('library-input').click());
$('library-add-folder').addEventListener('click', () => $('library-folder-input').click());
$('library-input').addEventListener('change', (event) => uploadLibraryFiles(libraryFilePairs(event.currentTarget.files)));
$('library-folder-input').addEventListener('change', (event) => uploadLibraryFiles(libraryFilePairs(event.currentTarget.files)));

const libraryDrop = $('library-drop');
const carriesFiles = (event) => [...(event.dataTransfer?.types || [])].includes('Files');
for (const eventName of ['dragenter', 'dragover']) {
  document.addEventListener(eventName, (event) => {
    if (!carriesFiles(event)) return;
    event.preventDefault();
    libraryDrop.classList.add('hover');
  });
}
for (const eventName of ['dragleave', 'drop']) {
  document.addEventListener(eventName, (event) => {
    if (!carriesFiles(event)) return;
    if (eventName === 'dragleave' && event.relatedTarget) return;
    event.preventDefault();
    libraryDrop.classList.remove('hover');
  });
}
document.addEventListener('drop', async (event) => {
  if (!carriesFiles(event)) return;
  if (libraryUploading) {
    $('library-status').textContent = 'An upload is already in progress.';
    return;
  }
  const items = event.dataTransfer.items;
  const entries = items
    ? [...items].map((item) => item.getAsEntry?.() || item.webkitGetAsEntry?.()).filter(Boolean)
    : [];
  if (!entries.length) {
    await uploadLibraryFiles(libraryFilePairs(event.dataTransfer.files));
    return;
  }
  try {
    await uploadLibraryFiles((await Promise.all(entries.map(entryFiles))).flat());
  } catch {
    $('library-status').textContent = 'Could not read a dropped folder; use the folder picker instead.';
  }
});

function deliverFormValues(selection) {
  $('deliver-error').hidden = true;
  const paths = selection.directory === undefined
    ? [...selectedLibraryPaths.keys()]
    : [];
  if (selection.directory === undefined && paths.length > MAX_LIBRARY_SELECTION) {
    throw new Error(`Select at most ${MAX_LIBRARY_SELECTION} files.`);
  }
  const expires = Number($('deliver-expires').value);
  const maxDownloadsValue = $('deliver-max-downloads').value.trim();
  const maxDownloads = maxDownloadsValue ? Number(maxDownloadsValue) : null;
  if (selection.directory === undefined && !paths.length) {
    throw new Error('Select at least one file.');
  }
  if (!Number.isInteger(expires) || expires < 1 || expires > 30) {
    throw new Error('Expiry must be between 1 and 30 days.');
  }
  if (maxDownloads !== null && (!Number.isInteger(maxDownloads) || maxDownloads < 1 || maxDownloads > 10000)) {
    throw new Error('Max downloads must be between 1 and 10000.');
  }
  const label = $('deliver-label').value;
  const directoryLabel = selection.directory?.split('/').filter(Boolean).pop();
  return {
    ...(selection.directory === undefined ? { paths } : { directory: selection.directory }),
    label: selection.directory !== undefined && !label.trim() ? directoryLabel : label,
    expires_days: expires,
    password: $('deliver-password').value || null,
    max_downloads: maxDownloads,
    notify_on_download: $('deliver-notify-on-download').checked,
  };
}

async function submitDeliverGrant(selection, control) {
  if (deliverGrantBusy) return;
  const error = $('deliver-error');
  error.hidden = true;
  let request;
  try {
    request = deliverFormValues(selection);
  } catch (validationError) {
    error.textContent = validationError.message;
    error.hidden = false;
    return;
  }
  deliverGrantBusy = true;
  const submit = $('deliver-submit');
  submit.disabled = true;
  document.querySelectorAll('[data-library-folder-share]').forEach((button) => {
    button.disabled = true;
  });
  control.disabled = true;
  try {
    const response = await api('/api/admin/outbound-grants', {
      method: 'POST',
      body: JSON.stringify(request),
    });
    if (!response.url) throw new Error('server did not return a download URL');
    showGrantResult(response.url, response.grant?.has_password);
    $('deliver-password').value = '';
    await refreshGrants();
  } catch (requestError) {
    $('deliver-error').textContent = requestError.message;
    $('deliver-error').hidden = false;
  } finally {
    deliverGrantBusy = false;
    submit.disabled = false;
    document.querySelectorAll('[data-library-folder-share]').forEach((button) => {
      button.disabled = false;
    });
    control.disabled = false;
  }
}

$('deliver-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  await submitDeliverGrant({}, $('deliver-submit'));
});

await requireSession();
await Promise.all([refreshGrants(), refreshLibrary(), refreshAutomationTokens()]);
