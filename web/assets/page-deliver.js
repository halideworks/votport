// votport deliver page: build outbound downloads and manage issued links.
// VOTPORT PROPRIETARY LICENSE.

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
  formatWhen,
  requireSession,
} from '/assets/admin-common.js';

const $ = (id) => document.getElementById(id);

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
const selectedLibraryPaths = new Set();
let libraryFiles = [];
let libraryTree = buildLibraryTree([]);
let libraryDirectory = '';

function libraryPath(file) {
  const relative = file.webkitRelativePath || file.name;
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
      const path = libraryPath(file);
      await uploadLibraryFile(file, path, (offset) => {
        const percent = file.size ? Math.floor((offset / file.size) * 100) : 100;
        $('library-status').textContent =
          `Uploading ${file.name}: ${percent}% (${index + 1} of ${files.length} files)`;
      });
      $('library-status').textContent =
        `Uploading ${file.name}: 100% (${index + 1} of ${files.length} files)`;
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
        notify_on_download: $('deliver-notify-on-download').checked,
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

await requireSession();
await Promise.all([refreshGrants(), refreshLibrary(), refreshAutomationTokens()]);
