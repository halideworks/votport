import { isFormDirty, markFormChanged, markFormSaved } from '/assets/form-drafts.js';
import { notificationEditor, notificationDetails, downloadEvents } from '/assets/notifications.js';
if (window.location.hash === '#workflows') window.location.replace('/workflows');

// votport deliver page: build outbound deliveries and manage delivery links.
// VOTPORT PROPRIETARY LICENSE.

import {
  parseLibraryPath,
  retainLibraryProjectSuggestions,
} from '/assets/library-paths.js';
import { entryFiles, runUploadBatch, uploadLibraryFile } from '/assets/upload-entries.js';
import {
  alertModal,
  announce,
  api,
  button,
  confirmModal,
  copyToClipboard,
  formatAgo,
  formatBytes,
  formatWhen,
  requireSession,
  revealHash,
  selectText,
  showGrantResult,
} from '/assets/admin-common.js';
import { startStatusPoll } from '/assets/status-strip.js';
import { fieldError } from '/assets/object-card.js';

const $ = (id) => document.getElementById(id);
const deliverError = fieldError($('deliver-label'), $('deliver-error'));
const createNotifications = notificationEditor({ events: downloadEvents });
$('deliver-notifications').append(createNotifications.element);
let notificationsReadOnly = true;
let deliverAdministrator = false;

// One mapped table per class: delivery link badges print labels, never wire
// values (audit item 446).
const grantStatusNames = { active: 'Active', used: 'Used up', expired: 'Expired', revoked: 'Revoked' };

function grantStatus(grant) {
  if (grant.revoked_at) return 'revoked';
  if (Number.isFinite(grant.max_downloads) && (grant.downloads ?? 0) >= grant.max_downloads) return 'used';
  if (grant.expires_at && grant.expires_at <= Math.floor(Date.now() / 1000)) return 'expired';
  return 'active';
}

let grantRows = [];
let grantTotal = 0;
let grantHasMore = false;
let grantLoading = false;

function renderGrants() {
  const grants = grantRows;
  const container = $('outbound-grants');
  const editingNotifications = new Map([...container.querySelectorAll('.link-item')]
    .map((card) => [card.id, card.querySelector('.notification-details')])
    .filter(([id, editor]) => editor && isFormDirty(editor) && grants.some((grant) => `grant-${grant.id}` === id)));
  const retainedEditors = new Set(editingNotifications.values());
  for (const editor of container.querySelectorAll('.notification-details')) if (!retainedEditors.has(editor)) editor.destroy?.();
  if (container.contains(document.activeElement)) {
    announce('outbound-grants-status', 'Deliveries updated.');
    $('outbound-grants-status').focus({ preventScroll: true });
  }
  container.replaceChildren();
  $('outbound-grants-count').textContent = grantTotal
    ? `Showing ${grants.length} of ${grantTotal} deliveries.`
    : '0 deliveries.';
  $('outbound-grants-load-more').hidden = !grantHasMore;
  if (!grants.length) {
    const empty = document.createElement('div');
    empty.className = 'empty-teach';
    const heading = document.createElement('h3');
    heading.textContent = 'How delivering works';
    const steps = document.createElement('ol');
    for (const text of [
      'Add files to the library, or pick ones that already arrived.',
      'Issue a delivery link, with a password or expiry if you like.',
      'Recipients request verified files; each file request is recorded here.',
    ]) {
      const item = document.createElement('li');
      item.textContent = text;
      steps.append(item);
    }
    empty.append(heading, steps);
    container.append(empty);
    return;
  }
  for (const grant of grants) {
    const card = document.createElement('div');
    card.className = 'card link-item';
    card.id = `grant-${grant.id}`;
    const head = document.createElement('div');
    head.className = 'head';
    const title = document.createElement('h3');
    title.textContent = grant.label || 'Delivery';
    const status = grantStatus(grant);
    const badge = document.createElement('span');
    badge.className = `badge ${status === 'active' ? 'on' : 'off'}`;
    badge.textContent = grantStatusNames[status];
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
      ? `${downloads} / ${grant.max_downloads} request set${grant.max_downloads === 1 ? '' : 's'}`
      : `${downloads} request set${downloads === 1 ? '' : 's'} · unlimited`;
    const metaParts = [expiry, downloadSummary];
    if (Number.isFinite(grant.first_download_at)) {
      metaParts.push(`first ${formatWhen(grant.first_download_at)}`);
    }
    if (Number.isFinite(grant.last_download_at)) {
      metaParts.push(`last ${formatWhen(grant.last_download_at)}`);
    }
    meta.textContent = metaParts.join(' · ');
    card.append(meta);
    card.append(editingNotifications.get(card.id) || notificationDetails({ policy: grant.notifications, events: downloadEvents, readOnly: notificationsReadOnly,
      save: async (notifications) => {
        await api(`/api/admin/outbound-grants/${grant.id}`, { method: 'PATCH', body: JSON.stringify({ notifications }) });
        grant.notifications = notifications;
      },
    }));

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
          `${fileDownloads} file request${fileDownloads === 1 ? '' : 's'}`,
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
        const copyLink = button('Copy link', 'tiny', async (control) => {
          control.disabled = true;
          try {
            const { url } = await api(`/api/admin/outbound-grants/${grant.id}/url`);
            const focusResult = control === document.activeElement || document.activeElement === document.body;
            showGrantResult(url, grant.has_password, focusResult);
            try {
              await copyToClipboard(control, url);
              announce('outbound-grants-status', 'Delivery link copied.');
            } catch {
              const ownsResultFocus = control === document.activeElement
                || $('outbound-url') === document.activeElement
                || document.activeElement === document.body;
              if (ownsResultFocus) {
                selectText($('outbound-url'));
                announce('outbound-grants-status', 'Your delivery link is selected below. Copy it to share.');
              } else announce('outbound-grants-status', 'Could not copy the delivery link. Use Copy link below to retry.');
            }
          } finally {
            control.disabled = false;
          }
        });
        actions.append(copyLink);
        if (deliverAdministrator) {
          const newAddress = button('Replace link', 'tiny', async (control) => {
            if (
              !(await confirmModal(
                'Replace delivery link',
                'Create a new link? The old link will stop working immediately.',
                'Replace',
              ))
            )
              return;
            const response = await api(`/api/admin/outbound-grants/${grant.id}`, {
              method: 'PATCH',
              body: JSON.stringify({ rotate: true }),
            });
            if (!response.url) throw new Error('server did not return a download URL');
            const focusResult = control === document.activeElement || document.activeElement === document.body;
            showGrantResult(response.url, grant.has_password, focusResult);
            await refreshGrants();
            announce('outbound-grants-status', 'Delivery link replaced.');
          });
          newAddress.setAttribute('aria-label', `Replace link: ${grant.label || grant.name}`);
          actions.append(newAddress);
        }
      }
      if (deliverAdministrator) {
        const extend = button('Extend 7 days', 'tiny', async () => {
          // Same base as the server: seven days past the later of now and the current expiry.
          const base = Math.max(grant.expires_at, Math.floor(Date.now() / 1000));
          const until = formatWhen(base + 7 * 86_400);
          if (!(await confirmModal('Extend delivery', `Extend this delivery until ${until}?`, 'Extend')))
            return;
          const { expires_at } = await api(`/api/admin/outbound-grants/${grant.id}`, {
            method: 'PATCH',
            body: JSON.stringify({ extend_days: 7 }),
          });
          await refreshGrants();
          announce('outbound-grants-status', `Delivery extended until ${formatWhen(expires_at)}.`);
        });
        extend.setAttribute('aria-label', `Extend 7 days: ${grant.label || grant.name}`);
        const revoke = button('Revoke', 'tiny danger', async () => {
          if (
            !(await confirmModal(
              'Revoke delivery',
              'Revoke this delivery link? Anyone with it will lose access.',
              'Revoke',
            ))
          )
            return;
          await api(`/api/admin/outbound-grants/${grant.id}`, { method: 'DELETE' });
          await refreshGrants();
          announce('outbound-grants-status', 'Delivery revoked.');
        });
        revoke.setAttribute('aria-label', `Revoke: ${grant.label || grant.name}`);
        actions.append(extend, revoke);
      }
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
    await sessionReady; renderGrants();
  } catch (error) {
    if (reset || !grantRows.length) {
      const message = document.createElement('p');
      message.className = 'muted';
      message.textContent = 'Deliveries could not be loaded.';
      if ($('outbound-grants').contains(document.activeElement)) {
        announce('outbound-grants-status', message.textContent);
        $('outbound-grants-status').focus({ preventScroll: true });
      }
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

const MAX_LIBRARY_SELECTION = 100_000;
const LIBRARY_PAGE_SIZE = 1000;
const MAX_LIBRARY_PROJECT_SUGGESTIONS = 200;
const selectedLibraryPaths = new Map();
let deliverGrantBusy = false;
let librarySelectionsPending = 0;
let libraryFiles = [];
let libraryDirectories = [];
let libraryDirectory = '';
let libraryTruncated = false;
let libraryAfter = null;
let libraryNextCursor = null;
const libraryPageHistory = [];
let libraryLoading = false;
let libraryError = '';
let libraryRequestGeneration = 0;
let librarySearchTimer;
let libraryLastSuccessfulView;
let libraryUploading = false;
const libraryProjectSuggestions = new Set();
const libraryFolderSelections = new Map();

function libraryPath(relative) {
  const project = $('deliver-project').value.trim().replace(/^\/+|\/+$/g, '');
  return project ? `${project}/${relative}` : relative;
}

function libraryFilePairs(files) {
  return [...files].map((file) => ({
    path: file.webkitRelativePath || file.name,
    file,
  }));
}

async function uploadLibraryFiles(pairs) {
  if (!deliverAdministrator || !pairs.length || libraryUploading) return;
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
  libraryAfter = null;
  libraryNextCursor = null;
  libraryPageHistory.length = 0;
  libraryError = '';
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
  if (!deliverAdministrator) return;
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
  librarySelectionsPending += 1;
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
    librarySelectionsPending -= 1;
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
  const row = document.createElement('div');
  row.className = 'library-file';
  const label = document.createElement('label');
  label.className = 'library-file-name';
  const checkbox = selectionCheckbox(file);
  checkbox.value = file.path;
  const name = document.createElement('span');
  name.className = 'mono';
  name.textContent = showPath ? file.path : file.path.slice(file.path.lastIndexOf('/') + 1);
  const size = document.createElement('span');
  size.className = 'muted';
  size.textContent = formatBytes(file.bytes);
  if (!deliverAdministrator) {
    checkbox.disabled = true;
    label.append(checkbox, name);
    row.append(label, size);
    container.append(row);
    return;
  }
  const remove = button('Delete', 'tiny danger', async () => {
    if (!(await confirmModal(
      'Delete outbound file',
      `Delete "${file.path}"? Active deliveries will block this if they still reference it.`,
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
  label.append(checkbox, name);
  row.append(label, size, remove);
  container.append(row);
}

function renderLibraryDirectory(directory, container) {
  const name = directory.slice(directory.lastIndexOf('/') + 1);
  const select = document.createElement('input');
  select.type = 'checkbox';
  select.disabled = !deliverAdministrator;
  updateLibraryFolderCheckbox(directory, select);
  select.setAttribute('aria-label', `Select folder ${directory}`);
  select.title = 'Select all files in this folder';
  select.addEventListener('change', () => toggleLibraryFolder(directory, select));
  const open = button(name, 'tiny ghost', async () => {
    await browseLibrary(directory);
  });
  open.setAttribute('aria-label', `Open folder ${name}`);
  open.title = name;
  const row = document.createElement('div');
  row.className = 'library-file library-folder';
  row.append(select, open);
  container.append(row);
}

function renderLibraryView() {
  renderLibraryBreadcrumbs();
  renderLibraryPagination();
  const container = $('library-files');
  container.replaceChildren();
  if (libraryError) {
    const message = document.createElement('p');
    message.className = 'error';
    message.setAttribute('role', 'alert');
    message.textContent = libraryError;
    container.append(message);
  }
  const query = $('library-search').value.trim();
  if (query) {
    for (const file of libraryFiles) renderLibraryFile(file, container, true);
    if (libraryTruncated) {
      const note = document.createElement('p');
      note.className = 'muted';
      note.textContent = 'Search incomplete. Refine your search or browse folders.';
      container.append(note);
    } else if (!libraryFiles.length) {
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
    note.textContent = 'More entries are available on the next page.';
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
  libraryError = '';
  libraryFiles = (response.files || []).filter((file) => parseLibraryPath(file.path));
  libraryDirectories = (response.directories || []).filter((path) => parseLibraryPath(path));
  libraryTruncated = Boolean(response.truncated);
  libraryNextCursor = typeof response.next_cursor === 'string' ? response.next_cursor : null;
  if (!$('library-search').value.trim()) {
    retainLibraryProjectSuggestions(
      libraryProjectSuggestions,
      libraryDirectories,
      libraryDirectory,
      MAX_LIBRARY_PROJECT_SUGGESTIONS,
    );
    updateProjectSuggestions(libraryProjectSuggestions);
  }
  updateLibrarySelectionStatus();
  libraryLastSuccessfulView = {
    directory: libraryDirectory,
    search: $('library-search').value,
    files: libraryFiles,
    directories: libraryDirectories,
    truncated: libraryTruncated,
    after: libraryAfter,
    nextCursor: libraryNextCursor,
    history: [...libraryPageHistory],
  };
  const restoreFocus = $('library-files').contains(document.activeElement)
    || $('library-breadcrumbs').contains(document.activeElement);
  renderLibraryView();
  if (restoreFocus) $('library-breadcrumbs').querySelector('[aria-current=page]').focus();
}

function restoreLibraryView() {
  if (!libraryLastSuccessfulView) return;
  libraryDirectory = libraryLastSuccessfulView.directory;
  $('library-search').value = libraryLastSuccessfulView.search;
  libraryFiles = libraryLastSuccessfulView.files;
  libraryDirectories = libraryLastSuccessfulView.directories;
  libraryTruncated = libraryLastSuccessfulView.truncated;
  libraryAfter = libraryLastSuccessfulView.after;
  libraryNextCursor = libraryLastSuccessfulView.nextCursor;
  libraryPageHistory.length = 0;
  libraryPageHistory.push(...libraryLastSuccessfulView.history);
}

function renderLibraryPagination() {
  const controls = $('library-pagination');
  const searching = $('library-search').value.trim().length > 0;
  const previous = $('library-pagination-previous');
  const next = $('library-pagination-next');
  controls.hidden = searching || (!libraryPageHistory.length && libraryNextCursor === null);
  previous.hidden = libraryPageHistory.length === 0;
  next.hidden = libraryNextCursor === null;
  previous.disabled = libraryLoading;
  next.disabled = libraryLoading;
  $('library-pagination-status').textContent = controls.hidden ? '' : 'Browse another page';
}

async function previousLibraryPage() {
  if (libraryLoading || !libraryPageHistory.length) return;
  libraryAfter = libraryPageHistory.pop();
  await refreshLibrary();
}

async function nextLibraryPage() {
  if (libraryLoading || libraryNextCursor === null) return;
  libraryPageHistory.push(libraryAfter);
  libraryAfter = libraryNextCursor;
  await refreshLibrary();
}

async function refreshLibrary() {
  const generation = ++libraryRequestGeneration;
  libraryLoading = true;
  renderLibraryPagination();
  const query = $('library-search').value.trim();
  const params = query
    ? `q=${encodeURIComponent(query)}`
    : new URLSearchParams({
      directory: libraryDirectory,
      limit: String(LIBRARY_PAGE_SIZE),
      ...(libraryAfter ? { after: libraryAfter } : {}),
    }).toString();
  try {
    const response = await api(`/api/admin/outbound-files?${params}`);
    if (generation !== libraryRequestGeneration) return false;
    renderLibrary(response);
    return true;
  } catch (error) {
    if (generation !== libraryRequestGeneration) return false;
    libraryError = error.message;
    restoreLibraryView();
    const restoreFocus = $('library-files').contains(document.activeElement);
    renderLibraryView();
    if (restoreFocus) $('library-breadcrumbs').querySelector('[aria-current=page]').focus();
    return false;
  } finally {
    if (generation === libraryRequestGeneration) {
      libraryLoading = false;
      renderLibraryPagination();
    }
  }
}

$('library-refresh').addEventListener('click', () => refreshLibrary());
$('library-pagination-previous').addEventListener('click', () => previousLibraryPage());
$('library-pagination-next').addEventListener('click', () => nextLibraryPage());
$('library-search').addEventListener('input', () => {
  libraryRequestGeneration += 1;
  libraryAfter = null;
  libraryNextCursor = null;
  libraryPageHistory.length = 0;
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
  if (!deliverAdministrator) return;
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

function deliverFormValues() {
  deliverError.clear();
  if (librarySelectionsPending) throw new Error('Wait for the folder selection to finish before creating a link.');
  const paths = [...selectedLibraryPaths.keys()];
  if (paths.length > MAX_LIBRARY_SELECTION) {
    throw new Error(`Select at most ${MAX_LIBRARY_SELECTION} files.`);
  }
  const expires = Number($('deliver-expires').value);
  const maxDownloadsValue = $('deliver-max-downloads').value.trim();
  const maxDownloads = maxDownloadsValue ? Number(maxDownloadsValue) : null;
  if (!paths.length) {
    throw new Error('Select at least one file.');
  }
  if (!Number.isInteger(expires) || expires < 1 || expires > 30) {
    throw new Error('Expiry must be between 1 and 30 days.');
  }
  if (maxDownloads !== null && (!Number.isInteger(maxDownloads) || maxDownloads < 1 || maxDownloads > 10000)) {
    throw new Error('Max downloads must be between 1 and 10000.');
  }
  const label = $('deliver-label').value;
  // A selection that is exactly one ticked folder shares the way the folder
  // itself does: one directory field instead of a body of every path
  // (finding 539). Anything mixed or partial still sends its paths.
  const folder = [...libraryFolderSelections].find(([directory, known]) => known.size === paths.length && paths.every((path) => known.has(path)));
  if (folder) {
    return {
      directory: folder[0],
      label,
      expires_days: expires,
      password: $('deliver-password').value || null,
      max_downloads: maxDownloads,
      notifications: createNotifications.read(),
    };
  }
  return {
    paths,
    label,
    expires_days: expires,
    password: $('deliver-password').value || null,
    max_downloads: maxDownloads,
    notifications: createNotifications.read(),
  };
}

async function submitDeliverGrant() {
  if (!deliverAdministrator || deliverGrantBusy) return;
  const error = $('deliver-error');
  deliverError.clear();
  let request;
  try {
    request = deliverFormValues();
  } catch (validationError) {
    deliverError.show(validationError.message);
    return;
  }
  deliverGrantBusy = true;
  const submittedFocus = document.activeElement;
  const form = $('deliver-form');
  const submit = $('deliver-submit');
  const progress = $('deliver-progress');
  form.setAttribute('aria-busy', 'true');
  $('deliver-fields').disabled = true;
  $('library-files').disabled = true;
  submit.textContent = 'Preparing link…';
  progress.textContent = 'Verifying selected files and preparing your delivery link. Large files can take a few minutes. Keep this page open.';
  progress.hidden = false;
  progress.focus({ preventScroll: true });
  $('outbound-result').hidden = true;
  try {
    const response = await api('/api/admin/outbound-grants', {
      method: 'POST',
      body: JSON.stringify(request),
    });
    if (!response.url) throw new Error('server did not return a download URL');
    markFormSaved($('deliver-form'));
    const focusResult = document.activeElement === submittedFocus
      || document.activeElement === progress
      || document.activeElement === document.body;
    showGrantResult(response.url, response.grant?.has_password, focusResult);
    announce('outbound-grants-status', 'Delivery link ready.');
    $('deliver-password').value = '';
    refreshGrants();
  } catch (requestError) {
    deliverError.show(requestError.message);
  } finally {
    const focusError = !error.hidden && (document.activeElement === progress || document.activeElement === document.body);
    deliverGrantBusy = false;
    form.removeAttribute('aria-busy');
    $('deliver-fields').disabled = false;
    $('library-files').disabled = false;
    submit.textContent = 'Create delivery link';
    progress.hidden = true;
    if (focusError) error.focus();
  }
}

$('deliver-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!deliverAdministrator) return;
  await submitDeliverGrant();
});

// A search result may name a grant past the first page: page forward until
// it is on the page. ponytail: bounded at ten pages; a grant lookup by id
// is the upgrade if active deliveries ever run to thousands.
async function revealGrant() {
  if (!window.location.hash.startsWith('#grant-')) return;
  for (let pages = 0; !revealHash() && grantHasMore && pages < 10; pages += 1) {
    await refreshGrants(false);
  }
}
window.addEventListener('hashchange', () => { revealGrant().catch(() => {}); });

function renderStatus(status) {
  const outbound = status.outbound || {};
  const active = outbound.active ?? null;
  $('status-strip').hidden = false;
  $('stat-active').textContent = active === null ? 'not measured' : String(active);
  $('stat-active-detail').textContent = active === null
    ? 'unavailable'
    : active
    ? `recipient${active === 1 ? '' : 's'} downloading now`
    : 'nothing being served';
  $('stat-open').textContent = String(outbound.open_grants ?? 'not measured');
  $('stat-deliveries').textContent = String(outbound.deliveries ?? 'not measured');
  $('stat-disk').textContent = outbound.disk ? formatBytes(outbound.disk.free_bytes) : 'not measured';
  const note = $('status-cache-note');
  note.hidden = false;
  note.textContent = status.stale
    ? (status.sampled_at
      ? `Status sampled ${formatAgo(status.sampled_at)} (${formatWhen(status.sampled_at)}) and may be out of date.${status.stale_error ? ` ${status.stale_error}.` : ''}`
      : 'Totals are temporarily unavailable.')
    : 'Totals refresh about once a minute. Transfer activity is live.';
}

// The session check and every list go out together; each is one round trip.
startStatusPoll({ render: renderStatus, active: (status) => status.outbound.active > 0 });
$('deliver-upload-form').inert = true;
$('deliver-form').inert = true;
$('deliver-submit').disabled = true;
for (const control of [$('library-add-files'), $('library-add-folder'), $('library-input'), $('library-folder-input')]) control.disabled = true;
const sessionReady = requireSession().then(async (session) => {
  deliverAdministrator = session.role === 'admin';
  notificationsReadOnly = !deliverAdministrator;
  $('deliver-upload-form').inert = !deliverAdministrator;
  $('deliver-form').inert = !deliverAdministrator;
  $('deliver-submit').disabled = !deliverAdministrator;
  $('library-add-files').disabled = !deliverAdministrator;
  $('library-add-folder').disabled = !deliverAdministrator;
  $('library-input').disabled = !deliverAdministrator;
  $('library-folder-input').disabled = !deliverAdministrator;
  $('library-files').querySelectorAll('input[type="checkbox"]').forEach((input) => { input.disabled = !deliverAdministrator; });
  await createNotifications.ready;
  createNotifications.element.disabled = notificationsReadOnly;
  if (deliverAdministrator) renderLibraryView();
});
await Promise.all([sessionReady, refreshGrants(), refreshLibrary()]);
await revealGrant();

$('library-files').addEventListener('change', () => markFormChanged($('deliver-form')));
