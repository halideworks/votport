// votport public verified download page. VOTPORT PROPRIETARY LICENSE.

import { appendObjectCard, formatBytes } from '/assets/object-card.js';
import {
  anchorDownloadsAllowed,
  dedupeFilenames,
  FILE_RENDER_BATCH_SIZE,
  nextFileBatch,
  MAX_ANCHOR_DOWNLOADS,
  runWorkerPool,
  summarizeFailures,
} from '/assets/outbound-download.js';

const $ = (id) => document.getElementById(id);
const token = window.location.pathname.split('/').filter(Boolean).pop();
let metadataFiles = [];
let renderedFileCount = 0;

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
  controls.hidden = metadataFiles.length <= FILE_RENDER_BATCH_SIZE;
  more.hidden = renderedFileCount >= metadataFiles.length;
  status.textContent = `Showing ${renderedFileCount} of ${metadataFiles.length} files`;
}

async function saveFile(directory, file, name) {
  const response = await fetch(file.download_url, { credentials: 'same-origin' });
  if (!response.ok) throw new Error(`server returned ${response.status}`);
  if (!response.body) throw new Error('browser cannot stream this response');
  const handle = await directory.getFileHandle(name, { create: true });
  const writable = await handle.createWritable();
  try {
    await response.body.pipeTo(writable);
  } catch (error) {
    await writable.abort().catch(() => {});
    throw error;
  }
}

function triggerSeparateDownloads(files, names) {
  for (const [index, file] of files.entries()) {
    const link = document.createElement('a');
    link.href = file.download_url;
    link.download = names[index];
    link.hidden = true;
    document.body.append(link);
    link.click();
    link.remove();
  }
}

let separateDownloadBusy = false;

async function downloadSeparately(files) {
  if (typeof window.showDirectoryPicker !== 'function' && !anchorDownloadsAllowed(files.length)) return;
  if (separateDownloadBusy) return;
  separateDownloadBusy = true;
  const button = $('separate-download-button');
  const status = $('separate-download-status');
  const names = dedupeFilenames(files.map((file) => file.name));
  button.disabled = true;
  try {
    if (typeof window.showDirectoryPicker !== 'function') {
      triggerSeparateDownloads(files, names);
      status.textContent =
        `Requested ${files.length} downloads. Your browser may ask once to allow multiple downloads.`;
      return;
    }
    const directory = await window.showDirectoryPicker({ mode: 'readwrite' });
    const failures = [];
    await runWorkerPool(
      files,
      async (file, index) => {
        try {
          await saveFile(directory, file, names[index]);
        } catch (error) {
          failures.push(`${names[index]}: ${error.message}`);
        }
      },
      4,
      (_file, _index, completed, total) => {
        status.textContent = `Downloading files: ${completed}/${total}`;
      },
    );
    status.textContent = failures.length
      ? `Downloaded ${files.length - failures.length}/${files.length}. Failed: ${summarizeFailures(failures)}`
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
  let response;
  try {
    response = await fetch(`/api/s/${encodeURIComponent(token)}`, {
      credentials: 'same-origin',
    });
  } catch {
    showError('The download could not be loaded. Check your connection and try again.');
    return;
  }

  let body = null;
  try { body = await response.json(); } catch { /* non-JSON error page */ }
  if ((body?.needs_password || body?.has_password) && !body.authorized) {
    showPasswordGate();
    return;
  }
  if (!response.ok) {
    showError(
      response.status === 404
        ? 'This download link was not found or has expired.'
        : body?.error || `The download could not be loaded (${response.status}).`,
    );
    return;
  }
  if (body.expires_at && body.expires_at <= Math.floor(Date.now() / 1000)) {
    showError('This download link has expired.');
    return;
  }
  const files = Array.isArray(body.files) && body.files.length
    ? body.files
    : body.download_url && body.receipt_url
      ? [{
          name: body.name,
          suite: body.suite,
          root: body.root,
          bytes: body.bytes ?? body.length,
          download_url: body.download_url,
          receipt_url: body.receipt_url,
        }]
      : [];
  if (!body.receipt_key || !files.length || files.some((file) =>
    !file.download_url ||
    !file.receipt_url ||
    !file.name ||
    !file.suite ||
    !file.root ||
    typeof file.bytes !== 'number'
  )) {
    showError('The server returned incomplete download metadata.');
    return;
  }

  $('download-gate').hidden = true;
  $('object').replaceChildren();
  metadataFiles = files;
  renderedFileCount = 0;
  renderNextFileBatch();
  const bundle = $('bundle-download');
  bundle.hidden = !body.bundle_url;
  if (body.bundle_url) $('bundle-download-button').onclick = () => window.location.assign(body.bundle_url);
  const separate = $('separate-download');
  separate.hidden = files.length < 2;
  if (files.length > 1) {
    const separateNote = $('separate-download-note');
    const separateButton = $('separate-download-button');
    const pickerAvailable = typeof window.showDirectoryPicker === 'function';
    if (pickerAvailable) {
      separateNote.textContent = 'Choose a folder and save each payload file separately.';
      separateButton.onclick = () => downloadSeparately(files);
      separateButton.disabled = false;
      $('separate-download-status').textContent = '';
    } else if (anchorDownloadsAllowed(files.length)) {
      separateNote.textContent = 'Your browser may ask once to allow multiple downloads.';
      separateButton.onclick = () => downloadSeparately(files);
      separateButton.disabled = false;
      $('separate-download-status').textContent = '';
    } else {
      separateNote.textContent =
        `This browser cannot request more than ${MAX_ANCHOR_DOWNLOADS} separate downloads. Use Download everything or Chrome/Edge folder selection.`;
      separateButton.disabled = true;
      $('separate-download-status').textContent = 'Separate downloads are unavailable for this link in this browser.';
    }
  }
  $('title').textContent = body.label || 'Verified download';
  $('status').textContent = 'The server verifies the file against this identity before download.';
  $('expires').textContent = body.expires_at
    ? `Link expires ${when(body.expires_at)}`
    : 'This link does not expire.';
  $('receipt-key').textContent = body.receipt_key;
  $('download-content').hidden = false;
}

$('show-more-files').addEventListener('click', renderNextFileBatch);

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
