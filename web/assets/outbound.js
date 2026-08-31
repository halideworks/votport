// votport public verified download page. VOTPORT PROPRIETARY LICENSE.

import { applyBranding } from '/assets/branding.js';
import { appendObjectCard, formatBytes } from '/assets/object-card.js';
import {
  appendMetadataPage,
  batchDownloadEligible,
  BatchDownloadUnsupportedError,
  dedupeFilenames,
  FILE_RENDER_BATCH_SIZE,
  metadataMoreAvailable,
  nextFileBatch,
  publicMetadataPageUrl,
  runWorkerPool,
  saveBatchFiles,
  streamToWritable,
  summarizeFailures,
} from '/assets/outbound-download.js';

const $ = (id) => document.getElementById(id);
const token = window.location.pathname.split('/').filter(Boolean).pop();
let metadataFiles = [];
let renderedFileCount = 0;
let metadataTotal = 0;
let metadataHasMore = false;
let metadataLoading = false;
let batchUrl = null;
let anchorDownloadPreflight = null;

function when(seconds) {
  return new Date(seconds * 1000).toLocaleString();
}

function showError(message) {
  $('download-gate').hidden = true;
  $('bundle-download').hidden = true;
  $('download-content').hidden = true;
  $('download-error-message').textContent = message;
  $('download-error').hidden = false;
  $('status').textContent = 'Download unavailable';
}

function showPasswordGate() {
  $('download-content').hidden = true;
  $('download-gate').hidden = false;
  $('status').textContent = 'Password required';
  $('download-password').focus();
}

function downloadButton(text, url, classes) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = classes;
  button.textContent = text;
  button.addEventListener('click', () => { window.location.assign(url); });
  return button;
}

function renderNextFileBatch() {
  const batch = nextFileBatch(metadataFiles, renderedFileCount);
  for (const file of batch) {
    const extras = [
      downloadButton('Download file', file.download_url, 'tiny'),
      downloadButton('Download receipt', file.receipt_url, 'tiny ghost'),
    ];
    const row = appendObjectCard(
      $('object'),
      { name: file.name, suite: file.suite, root: file.root },
      { status: formatBytes(file.bytes), extras },
    );
    row.setAttribute('aria-label', `Verified ${file.name}`);
  }
  renderedFileCount += batch.length;
  const controls = $('file-list-controls');
  const more = $('show-more-files');
  const status = $('file-list-status');
  controls.hidden = metadataTotal <= FILE_RENDER_BATCH_SIZE;
  more.hidden = !metadataMoreAvailable(renderedFileCount, metadataFiles.length, metadataHasMore);
  status.textContent = `Showing ${renderedFileCount} of ${metadataTotal} files`;
}

function showMetadataProgress() {
  $('file-list-controls').hidden = metadataTotal <= FILE_RENDER_BATCH_SIZE;
  $('show-more-files').hidden = !metadataMoreAvailable(
    renderedFileCount,
    metadataFiles.length,
    metadataHasMore,
  );
  $('file-list-status').textContent = `Showing ${renderedFileCount} of ${metadataTotal} files`;
}

function validateMetadataFiles(files) {
  if (files.some((file) =>
    !file.download_url ||
    !file.receipt_url ||
    !file.name ||
    !file.suite ||
    !file.root ||
    typeof file.bytes !== 'number'
  )) {
    throw new Error('The server returned incomplete download metadata.');
  }
}

async function saveFile(directory, file, name) {
  const handle = await directory.getFileHandle(name, { create: true });
  const writable = await handle.createWritable();
  try {
    await streamToWritable((...args) => fetch(...args), writable, file);
    await writable.close();
  } catch (error) {
    await writable.abort().catch(() => {});
    throw error;
  }
}

async function triggerSeparateDownloads(files, names) {
  for (const [index, file] of files.entries()) {
    const link = document.createElement('a');
    link.href = file.download_url;
    link.download = names[index];
    link.hidden = true;
    document.body.append(link);
    link.click();
    link.remove();
    // WebKit drops later downloads unless each anchor yields to the event loop.
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

let separateDownloadBusy = false;

async function prepareAnchorDownloads() {
  if (separateDownloadBusy) return;
  separateDownloadBusy = true;
  const button = $('separate-download-button');
  const status = $('separate-download-status');
  button.disabled = true;
  try {
    const files = metadataHasMore ? await loadRemainingMetadata() : metadataFiles;
    anchorDownloadPreflight = { files, names: dedupeFilenames(files.map((file) => file.name)) };
    $('separate-download-confirm-detail').textContent =
      `This will download ${files.length} payload files individually to your browser's configured download location. ` +
      'No ZIP or receipt files are included. Your browser may ask you to allow multiple downloads; accept that prompt to receive every file.';
    const dialog = $('separate-download-confirm');
    dialog.returnValue = 'cancel';
    dialog.showModal();
  } catch (error) {
    status.textContent = `Could not prepare downloads: ${error.message}`;
  } finally {
    separateDownloadBusy = false;
    button.disabled = false;
  }
}

async function startAnchorDownloads() {
  const pending = anchorDownloadPreflight;
  if (!pending || separateDownloadBusy) return;
  anchorDownloadPreflight = null;
  $('separate-download-confirm').close('start');
  const button = $('separate-download-button');
  const status = $('separate-download-status');
  separateDownloadBusy = true;
  button.disabled = true;
  try {
    await triggerSeparateDownloads(pending.files, pending.names);
    status.textContent =
      `Requested ${pending.files.length} downloads. Your browser may ask you to allow multiple downloads; accept that prompt to receive every file.`;
  } finally {
    separateDownloadBusy = false;
    button.disabled = false;
  }
}

async function fetchMetadataPage(offset, limit = FILE_RENDER_BATCH_SIZE) {
  let response;
  try {
    response = await fetch(publicMetadataPageUrl(token, offset, limit), {
      credentials: 'same-origin',
    });
  } catch {
    throw new Error('The download could not be loaded. Check your connection and try again.');
  }
  let body = null;
  try { body = await response.json(); } catch { /* non-JSON error page */ }
  if ((body?.needs_password || body?.has_password) && !body.authorized) {
    if (offset === 0) showPasswordGate();
    throw new Error('outbound grant password required');
  }
  if (!response.ok) {
    throw new Error(
      response.status === 404
        ? 'This download link was not found or has expired.'
        : body?.error || `The download could not be loaded (${response.status}).`,
    );
  }
  if (body?.expires_at && body.expires_at <= Math.floor(Date.now() / 1000)) {
    throw new Error('This download link has expired.');
  }
  const files = Array.isArray(body?.files) && body.files.length
    ? body.files
    : body?.download_url && body.receipt_url
      ? [{
          name: body.name,
          suite: body.suite,
          root: body.root,
          bytes: body.bytes ?? body.length,
          download_url: body.download_url,
          receipt_url: body.receipt_url,
        }]
      : [];
  if (!files.length) throw new Error('The server returned incomplete download metadata.');
  validateMetadataFiles(files);
  const pagingFields = ['files_total', 'offset', 'limit', 'has_more'];
  const hasPagingFields = pagingFields.some((field) => Object.hasOwn(body ?? {}, field));
  if (!hasPagingFields) {
    return {
      ...body,
      files,
      files_total: files.length,
      offset: 0,
      limit: files.length,
      has_more: false,
    };
  }
  if (!Number.isSafeInteger(body.files_total) || !Number.isSafeInteger(body.offset) ||
      !Number.isSafeInteger(body.limit) || typeof body.has_more !== 'boolean') {
    throw new Error('The server returned incomplete download metadata.');
  }
  return { ...body, files };
}

async function appendMetadataPageAt(offset, limit = FILE_RENDER_BATCH_SIZE) {
  const page = await fetchMetadataPage(offset, limit);
  const next = appendMetadataPage(
    { files: metadataFiles, total: metadataFiles.length ? metadataTotal : null },
    page,
  );
  metadataFiles = next.files;
  metadataTotal = next.total;
  metadataHasMore = next.hasMore;
  return page;
}

async function loadRemainingMetadata() {
  if (metadataLoading) throw new Error('File metadata is already loading.');
  metadataLoading = true;
  try {
    while (metadataHasMore) {
      $('file-list-status').textContent = `Loading file metadata: ${metadataFiles.length} of ${metadataTotal}`;
      await appendMetadataPageAt(metadataFiles.length, 500);
    }
    showMetadataProgress();
    return metadataFiles;
  } finally {
    metadataLoading = false;
  }
}

async function downloadSeparately() {
  if (separateDownloadBusy) return;
  separateDownloadBusy = true;
  const button = $('separate-download-button');
  const status = $('separate-download-status');
  button.disabled = true;
  try {
    let directory;
    if (typeof window.showDirectoryPicker === 'function') {
      directory = await window.showDirectoryPicker({ mode: 'readwrite' });
    }
    const files = metadataHasMore ? await loadRemainingMetadata() : metadataFiles;
    const names = dedupeFilenames(files.map((file) => file.name));
    let remainingFiles = files;
    let remainingNames = names;
    let batchSaved = 0;
    if (batchUrl && batchDownloadEligible(files)) {
      status.textContent = `Downloading files in optimized batch mode: 0/${files.length}`;
      try {
        const response = await fetch(batchUrl, { credentials: 'same-origin' });
        if (response.status === 413 || response.status === 507) {
          throw new BatchDownloadUnsupportedError(`batch unavailable (${response.status})`);
        }
        if (response.status === 404) throw new Error('The verified batch is no longer available.');
        if (!response.ok) throw new Error(`server returned ${response.status}`);
        await saveBatchFiles(response, directory, files, names, (completed, total) => {
          batchSaved = completed;
          status.textContent = `Downloading files in optimized batch mode: ${completed}/${total}`;
        });
        status.textContent = `Downloaded ${files.length} files.`;
        return;
      } catch (error) {
        if (error?.name === 'AbortError') throw error;
        // Files the batch fully wrote stay on disk; finish the rest
        // individually instead of failing the whole set.
        remainingFiles = files.slice(batchSaved);
        remainingNames = names.slice(batchSaved);
        status.textContent = error instanceof BatchDownloadUnsupportedError
          ? 'Batch mode unavailable; downloading files individually…'
          : `Batch stream interrupted; downloading the remaining ${remainingFiles.length} files individually…`;
      }
    }
    const failures = [];
    await runWorkerPool(
      remainingFiles,
      async (file, index) => {
        try {
          await saveFile(directory, file, remainingNames[index]);
        } catch (error) {
          failures.push(`${remainingNames[index]}: ${error.message}`);
        }
      },
      4,
      (_file, _index, completed, _total) => {
        status.textContent = `Downloading files: ${batchSaved + completed}/${files.length}`;
      },
    );
    const saved = files.length - failures.length;
    status.textContent = failures.length
      ? `Downloaded ${saved}/${files.length}. Failed: ${summarizeFailures(failures)}`
      : `Downloaded ${files.length} files.`;
  } catch (error) {
    status.textContent = error?.name === 'AbortError'
      ? 'Download cancelled.'
      : `Could not download files: ${error.message}`;
  } finally {
    separateDownloadBusy = false;
    button.disabled = false;
  }
}

async function loadMetadata() {
  let body;
  try {
    body = await fetchMetadataPage(0);
  } catch (error) {
    if (error.message === 'outbound grant password required') return;
    showError(error.message);
    return;
  }
  if (!body.receipt_key) {
    showError('The server returned incomplete download metadata.');
    return;
  }

  $('download-gate').hidden = true;
  $('object').replaceChildren();
  metadataFiles = [];
  metadataTotal = 0;
  metadataHasMore = false;
  renderedFileCount = 0;
  let next;
  try {
    next = appendMetadataPage({ files: [], total: null }, body);
  } catch (error) {
    showError(error.message);
    return;
  }
  metadataFiles = next.files;
  metadataTotal = next.total;
  metadataHasMore = next.hasMore;
  batchUrl = body.batch_url || null;
  renderNextFileBatch();
  const bundle = $('bundle-download');
  bundle.hidden = !body.bundle_url;
  if (body.bundle_url) $('bundle-download-button').onclick = () => window.location.assign(body.bundle_url);
  const separate = $('separate-download');
  separate.hidden = metadataTotal < 2;
  if (metadataTotal > 1) {
    const separateNote = $('separate-download-note');
    const separateButton = $('separate-download-button');
    const pickerAvailable = typeof window.showDirectoryPicker === 'function';
    if (pickerAvailable) {
      separateNote.textContent = 'Choose a folder to save every payload file individually. No ZIP or receipt files are included.';
      separateButton.onclick = () => downloadSeparately();
      separateButton.disabled = false;
      $('separate-download-status').textContent = '';
    } else {
      separateNote.textContent = 'Download files individually to your browser\'s configured download location. Your browser may ask you to allow multiple downloads; accept that prompt to receive every file.';
      separateButton.onclick = () => prepareAnchorDownloads();
      separateButton.disabled = false;
      $('separate-download-status').textContent = '';
    }
  }
  $('title').textContent = body.label || 'Verified download';
  applyBranding(body.branding, `/api/s/${encodeURIComponent(token)}/logo`);
  $('status').textContent = 'The server verifies the file against this identity before download.';
  $('expires').textContent = body.expires_at
    ? `Link expires ${when(body.expires_at)}`
    : 'This link does not expire.';
  $('receipt-key').textContent = body.receipt_key;
  $('download-content').hidden = false;
}

$('separate-download-start').addEventListener('click', startAnchorDownloads);
$('separate-download-confirm').addEventListener('close', (event) => {
  if (event.target.returnValue !== 'start') anchorDownloadPreflight = null;
});

$('show-more-files').addEventListener('click', async () => {
  if (metadataLoading || !metadataMoreAvailable(renderedFileCount, metadataFiles.length, metadataHasMore)) return;
  metadataLoading = true;
  $('show-more-files').disabled = true;
  try {
    if (renderedFileCount >= metadataFiles.length && metadataHasMore) {
      await appendMetadataPageAt(metadataFiles.length);
    }
    renderNextFileBatch();
  } catch (error) {
    $('file-list-status').textContent = error.message;
  } finally {
    metadataLoading = false;
    $('show-more-files').disabled = false;
  }
});

$('download-password-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const error = $('download-password-error');
  const submit = $('download-password-submit');
  error.hidden = true;
  submit.disabled = true;
  try {
    const response = await fetch(`/api/s/${encodeURIComponent(token)}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ password: $('download-password').value }),
    });
    let body = null;
    try { body = await response.json(); } catch { /* non-JSON error page */ }
    if (!response.ok) throw new Error(body?.error || `verification failed (${response.status})`);
    $('download-password').value = '';
    await loadMetadata();
  } catch (verificationError) {
    error.textContent = verificationError.message;
    error.hidden = false;
    $('download-password').focus();
  } finally {
    submit.disabled = false;
  }
});

loadMetadata();
