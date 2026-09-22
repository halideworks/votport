// votport public verified download page. VOTPORT PROPRIETARY LICENSE.

import { deliveryMetadata, initDeliveryEvidence } from '/assets/delivery-evidence.js';
import { applyBranding } from '/assets/branding.js';
import { node, $, offerApp, appendObjectCard, fieldError, formatBytes } from '/assets/object-card.js';
import {
  appendMetadataPage,
  batchDownloadEligible,
  BatchDownloadUnsupportedError,
  createDownloadFile,
  dedupeFilenames,
  FILE_RENDER_BATCH_SIZE,
  METADATA_PAGE_SIZE,
  metadataMoreAvailable,
  nextFileBatch,
  publicMetadataPageUrl,
  runWorkerPool,
  saveBatchFiles,
  streamToWritable,
  summarizeFailures,
} from '/assets/outbound-download.js';

const votFetchError = fieldError($('vot-fetch-key'), $('vot-fetch-error'));
const token = window.location.pathname.split('/').filter(Boolean).pop();
let metadataHasPassword = false;
let evidenceMetadata = null;
let metadataFiles = [];
let renderedFileCount = 0;
let metadataTotal = 0;
let metadataHasMore = false;
let metadataLoading = false;
let batchUrl = null;
let anchorDownloadPreflight = null;
let anchorDownloadStop = null;
let totalBytes = 0;
// Manifest rows by file index, so a finished download can mark its row.
const rows = new Map();
// Saved file indexes, counted whether or not their row is rendered yet
// (rows past the first page appear only after Show more).
const saved = new Set();
const savedNames = new Map();
const pendingSavedRows = new Set();
let savedFeedbackFrame = null;
let separateDownloadStatus = '';

function manifestStatus() {
  $('manifest-status').textContent = saved.size
    ? `${saved.size} of ${metadataTotal} saved to this device`
    : `${metadataTotal} file${metadataTotal === 1 ? '' : 's'}, each verified by the server before it is sent`;
}

function setSeparateDownloadStatus(text, defer = false) {
  separateDownloadStatus = text;
  if (defer) {
    scheduleSavedFeedback();
    return;
  }
  $('separate-download-status').textContent = text;
}

function applySavedFeedback() {
  manifestStatus();
  for (const index of pendingSavedRows) {
    const row = rows.get(index);
    if (row && saved.has(index)) landedBadge(row);
  }
  pendingSavedRows.clear();
  $('separate-download-status').textContent = separateDownloadStatus;
}

function cancelSavedFeedback() {
  if (savedFeedbackFrame !== null) window.cancelAnimationFrame(savedFeedbackFrame);
  savedFeedbackFrame = null;
  pendingSavedRows.clear();
}

function flushSavedFeedback() {
  if (savedFeedbackFrame !== null) window.cancelAnimationFrame(savedFeedbackFrame);
  savedFeedbackFrame = null;
  applySavedFeedback();
}

function scheduleSavedFeedback() {
  if (savedFeedbackFrame !== null) return;
  savedFeedbackFrame = window.requestAnimationFrame(() => {
    savedFeedbackFrame = null;
    applySavedFeedback();
  });
}

// Saving and the optional signed verification of saved files have separate status.
function landedBadge(row) {
  if (row.classList.contains('saved')) return;
  row.classList.add('saved');
  const badge = node('span', 'landed', 'badge on');
  row.querySelector('.status').after(badge);
}

function markSaved(index, name) {
  savedNames.set(index, name);
  if (saved.has(index)) return;
  saved.add(index);
  pendingSavedRows.add(index);
  scheduleSavedFeedback();
}

function availability(body) {
  const parts = [
    `${metadataTotal} file${metadataTotal === 1 ? '' : 's'}`,
    formatBytes(totalBytes),
    body.expires_at ? `available until ${when(body.expires_at)}` : 'does not expire',
  ];
  if (body.has_password && body.authorized) parts.push('password checked');
  return parts.join(' · ');
}

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

// A refused download answers JSON, so every handoff probes with HEAD and
// renders the refusal here instead of navigating the top frame to it.
// HEAD runs the same admission checks without recording a download.
async function triggerDownload(url, name) {
  let response;
  try {
    response = await fetch(url, { method: 'HEAD' });
  } catch {
    showError('The download could not be reached. Check your connection and try again.');
    return false;
  }
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    showError(body?.error || `The download was refused (${response.status}).`);
    return false;
  }
  const link = document.createElement('a');
  link.href = url;
  if (name) link.download = name;
  link.hidden = true;
  document.body.append(link);
  link.click();
  link.remove();
  return true;
}

function downloadButton(text, url, classes, name) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = classes;
  button.textContent = text;
  button.setAttribute('aria-label', `${text}: ${name}`);
  button.addEventListener('click', () => { triggerDownload(url, name); });
  return button;
}

function renderNextFileBatch(limit = FILE_RENDER_BATCH_SIZE) {
  const batch = nextFileBatch(metadataFiles, renderedFileCount, limit);
  for (const [offset, file] of batch.entries()) {
    const extras = [
      downloadButton('Download file', file.download_url, 'tiny', file.name),
    ];
    if (file.receipt_url) extras.push(downloadButton('Download receipt', file.receipt_url, 'tiny ghost', file.name));
    const row = appendObjectCard(
      $('object'),
      { name: file.name, suite: file.suite, root: file.root },
      { status: formatBytes(file.bytes), extras },
    );
    row.setAttribute('aria-label', `Verified ${file.name}`);
    // The id line ellipsizes; the full identity stays readable on hover.
    const id = row.querySelector('.file-id');
    id.title = `${id.textContent} (click to copy)`;
    const index = renderedFileCount + offset;
    rows.set(index, row);
    // A file saved before its row was rendered still gets its badge.
    if (saved.has(index)) landedBadge(row);
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
    (file.receipt_url !== null && typeof file.receipt_url !== 'string') ||
    !file.name ||
    !file.suite ||
    !file.root ||
    typeof file.bytes !== 'number'
  )) {
    throw new Error('The server returned incomplete download metadata.');
  }
}

// Resolvers waiting for the next successful password verification, from a
// download whose cookie stopped verifying mid-file.
const reauthorizeWaiters = [];

// Called by a streaming save when the server answers 401 or 403 mid-file:
// after a failover that rotated the cookie secret the verified-password
// cookie is dead. Shows the password gate and resolves true once the
// recipient has verified again, so the save resumes from its offset.
function reauthorizeDownload() {
  if (!$('download-gate') || !metadataHasPassword) return Promise.resolve(false);
  showPasswordGate();
  $('status').textContent = 'Password required to continue the download';
  return new Promise((resolve) => { reauthorizeWaiters.push(resolve); });
}

async function saveFile(directory, file, name) {
  const handle = await createDownloadFile(directory, name);
  const writable = await handle.createWritable();
  try {
    await streamToWritable((...args) => fetch(...args), writable, file, {
      onAuthLost: reauthorizeDownload,
    });
    await writable.close();
    return handle.name;
  } catch (error) {
    await writable.abort().catch(() => {});
    throw error;
  }
}

async function triggerSeparateDownloads(files, names, stop, onProgress) {
  let requested = 0;
  for (const [index, file] of files.entries()) {
    if (stop.stopped) break;
    const link = document.createElement('a');
    link.href = file.download_url;
    link.download = names[index];
    link.hidden = true;
    document.body.append(link);
    link.click();
    link.remove();
    requested += 1;
    onProgress(requested, files.length);
    // WebKit drops later downloads unless each anchor yields to the event loop.
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  return { requested, stopped: stop.stopped };
}

let separateDownloadBusy = false;

async function prepareAnchorDownloads() {
  if (separateDownloadBusy) return;
  separateDownloadBusy = true;
  const button = $('separate-download-button');
  button.disabled = true;
  try {
    if (metadataHasMore) {
      setSeparateDownloadStatus(`Loading file metadata: ${metadataFiles.length} of ${metadataTotal}`);
    }
    const files = metadataHasMore ? await loadRemainingMetadata() : metadataFiles;
    anchorDownloadPreflight = { files, names: dedupeFilenames(files.map((file) => file.name)) };
    setSeparateDownloadStatus(`Ready to request ${files.length} of ${metadataTotal} downloads.`);
    $('separate-download-confirm-detail').textContent =
      `This will download ${files.length} payload files individually to your browser's configured download location. ` +
      'No ZIP or receipt files are included. Your browser may ask you to allow multiple downloads; accept that prompt to receive every file. ' +
      'Keep this tab open until requests are handed off, then check browser downloads for blocked or failed files.';
    const dialog = $('separate-download-confirm');
    dialog.returnValue = 'cancel';
    dialog.showModal();
  } catch (error) {
    setSeparateDownloadStatus(`Could not prepare downloads: ${error.message}`);
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
  separateDownloadBusy = true;
  button.disabled = true;
  const stop = { stopped: false };
  anchorDownloadStop = stop;
  const stopButton = $('separate-download-stop');
  stopButton.hidden = false;
  setSeparateDownloadStatus(`Requested 0 of ${pending.files.length} downloads`);
  try {
    const result = await triggerSeparateDownloads(
      pending.files,
      pending.names,
      stop,
      (requested, total) => setSeparateDownloadStatus(`Requested ${requested} of ${total} downloads`),
    );
    const handoff = 'Keep this tab open until requests are handed off, then check browser downloads for blocked or failed files.';
    setSeparateDownloadStatus(result.stopped && result.requested < pending.files.length
      ? `Requested ${result.requested} of ${pending.files.length} downloads. Remaining requests stopped. ${handoff}`
      : `Requested ${result.requested} of ${pending.files.length} downloads. ${handoff}`);
  } finally {
    anchorDownloadStop = null;
    stopButton.hidden = true;
    separateDownloadBusy = false;
    button.disabled = false;
  }
}

async function fetchMetadataPage(offset, limit = METADATA_PAGE_SIZE) {
  let response;
  try {
    response = await deliveryMetadata(publicMetadataPageUrl(token, offset, limit), token);
  } catch (error) {
    throw new Error(error.message || 'The download could not be loaded. Check your connection and try again.');
  }
  let body = null;
  try { body = await response.json(); } catch { /* non-JSON error page */ }
  metadataHasPassword = Boolean(body?.needs_password || body?.has_password);
  if (metadataHasPassword && !body.authorized) {
    if (offset === 0) showPasswordGate();
    throw new Error('delivery password required');
  }
  if (!response.ok) {
    throw new Error(
      response.status === 404
        ? 'This delivery link was not found or has expired.'
        : body?.error || `The download could not be loaded (${response.status}).`,
    );
  }
  if (body?.expires_at && body.expires_at <= Math.floor(Date.now() / 1000)) {
    throw new Error('This delivery link has expired.');
  }
  const files = Array.isArray(body?.files) && body.files.length
    ? body.files
    : body?.download_url
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

async function appendMetadataPageAt(offset, limit = METADATA_PAGE_SIZE) {
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
      await appendMetadataPageAt(metadataFiles.length, METADATA_PAGE_SIZE);
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
      setSeparateDownloadStatus(`Downloading files in optimized batch mode: 0/${files.length}`);
      try {
        const response = await fetch(batchUrl, { credentials: 'same-origin' });
        if (response.status === 413 || response.status === 507) {
          throw new BatchDownloadUnsupportedError(`batch unavailable (${response.status})`);
        }
        if (response.status === 404) throw new Error('The verified batch is no longer available.');
        if (!response.ok) throw new Error(`server returned ${response.status}`);
        await saveBatchFiles(response, directory, files, names, (completed, total, name) => {
          batchSaved = completed;
          markSaved(completed - 1, name);
          setSeparateDownloadStatus(`Saving files: ${completed} of ${total}`, true);
        });
        flushSavedFeedback();
        setSeparateDownloadStatus(`Downloaded ${files.length} files.`);
        return;
      } catch (error) {
        if (error?.name === 'AbortError') throw error;
        // Files the batch fully wrote stay on disk; finish the rest
        // individually instead of failing the whole set.
        remainingFiles = files.slice(batchSaved);
        remainingNames = names.slice(batchSaved);
        setSeparateDownloadStatus(error instanceof BatchDownloadUnsupportedError
          ? 'Batch mode unavailable; downloading files individually…'
          : `Batch stream interrupted; downloading the remaining ${remainingFiles.length} files individually…`);
      }
    }
    const failures = [];
    await runWorkerPool(
      remainingFiles,
      async (file, index) => {
        try {
          const name = await saveFile(directory, file, remainingNames[index]);
          markSaved(batchSaved + index, name);
        } catch (error) {
          failures.push(`${remainingNames[index]}: ${error.message}`);
        }
      },
      4,
      (_file, _index, completed, _total) => {
        setSeparateDownloadStatus(`Saving files: ${batchSaved + completed} of ${files.length}`, true);
      },
    );
    const savedFiles = files.length - failures.length;
    flushSavedFeedback();
    setSeparateDownloadStatus(failures.length
      ? `Downloaded ${savedFiles}/${files.length}. Failed: ${summarizeFailures(failures)}`
      : `Downloaded ${files.length} files.`);
  } catch (error) {
    flushSavedFeedback();
    setSeparateDownloadStatus(error?.name === 'AbortError'
      ? 'Download cancelled.'
      : `Could not download files: ${error.message}`);
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
    if (error.message === 'delivery password required') return;
    showError(error.message);
    return;
  }
  if (!body.receipt_key) {
    showError('The server returned incomplete download metadata.');
    return;
  }

  $('download-gate').hidden = true;
  cancelSavedFeedback();
  $('object').replaceChildren();
  rows.clear();
  saved.clear();
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
  evidenceMetadata = body;
  batchUrl = body.batch_url || null;
  totalBytes = Number.isFinite(body.total_bytes) ? body.total_bytes : 0;
  renderNextFileBatch();
  manifestStatus();
  const bundle = $('bundle-download');
  bundle.hidden = !body.bundle_url;
  if (body.bundle_url) $('bundle-download-button').onclick = () => triggerDownload(body.bundle_url);
  const separateNote = $('separate-download-note');
  const separateButton = $('separate-download-button');
  setSeparateDownloadStatus('');
  $('separate-download-stop').hidden = true;
  separateButton.disabled = false;
  if (metadataTotal > 1) {
    const pickerAvailable = typeof window.showDirectoryPicker === 'function';
    if (pickerAvailable) {
      separateNote.textContent = 'You choose the folder; each file is saved as it arrives. Receipt files are not included.';
      separateButton.onclick = () => downloadSeparately();
    } else {
      separateNote.textContent = 'Files go to your browser\'s download location. Your browser may ask you to allow multiple downloads; accept that prompt to receive every file.';
      separateButton.onclick = () => prepareAnchorDownloads();
    }
  } else {
    // One file: the primary action is that file.
    separateButton.textContent = 'Download file';
    separateNote.textContent = '';
    const only = metadataFiles[0];
    separateButton.onclick = async () => {
      if (!(await triggerDownload(only.download_url, only.name))) return;
      setSeparateDownloadStatus('Download handed to the browser. Check browser downloads for completion.');
    };
  }
  const fetchBlock = $('vot-fetch');
  fetchBlock.hidden = !body.fetch;
  if (body.fetch) {
    // The page mints with the recipient's cookie, so a password-gated grant
    // works here where a copied curl would not; the secret key never leaves
    // the recipient's machine.
    $('vot-fetch-form').onsubmit = async (event) => {
      event.preventDefault();
      const command = $('vot-fetch-command');
      votFetchError.clear();
      command.hidden = true;
      try {
        const response = await fetch(body.fetch.mint_url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ holder_key: $('vot-fetch-key').value.trim() }),
        });
        if (!response.ok) {
          const detail = await response.json().catch(() => ({}));
          throw new Error(detail.error || `Mint refused (${response.status}).`);
        }
        const minted = await response.json();
        command.textContent = [
          `echo '${minted.capability}' | base64 -d > fetch-token.cbor`,
          'export HOLDER_SECRET=ed25519-secret:<hex of your secret key>',
          'VOT_FETCH_CAPABILITY=fetch-token.cbor VOT_FETCH_HOLDER_KEY=env:HOLDER_SECRET \\',
          `VOT_FETCH_SERVE_IDENTITY=${minted.certificate_digest} \\`,
          `vot fetch ${minted.address} ./delivery-bundle ${minted.package_root}`,
          `# token good until ${new Date(minted.expires_at * 1000).toLocaleString()}`,
        ].join('\n');
        command.hidden = false;
      } catch (failure) {
        votFetchError.show(failure.message || 'Could not mint a fetch token.');
      }
    };
  }
  $('title').textContent = body.label || 'Verified download';
  applyBranding(body.branding, `/api/s/${encodeURIComponent(token)}/logo`);
  $('status').textContent = availability(body);
  $('receipt-key').textContent = body.receipt_key;
  $('receipt-key').title = body.receipt_key;
  $('download-content').hidden = false;
  offerApp('s', token);
}

$('separate-download-start').addEventListener('click', startAnchorDownloads);
$('separate-download-stop').addEventListener('click', () => {
  if (anchorDownloadStop) anchorDownloadStop.stopped = true;
});
$('separate-download-confirm').addEventListener('close', (event) => {
  if (event.target.returnValue !== 'start') anchorDownloadPreflight = null;
});

$('show-more-files').addEventListener('click', async () => {
  if (metadataLoading || !metadataMoreAvailable(renderedFileCount, metadataFiles.length, metadataHasMore)) return;
  metadataLoading = true;
  $('show-more-files').disabled = true;
  try {
    const target = renderedFileCount + METADATA_PAGE_SIZE;
    while (metadataFiles.length < target && metadataHasMore) {
      await appendMetadataPageAt(metadataFiles.length, METADATA_PAGE_SIZE);
    }
    renderNextFileBatch(METADATA_PAGE_SIZE);
  } catch (error) {
    $('file-list-status').textContent = error.message;
  } finally {
    metadataLoading = false;
    $('show-more-files').disabled = false;
  }
});

const downloadPasswordError = fieldError($('download-password'), $('download-password-error'));

$('download-password-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const submit = $('download-password-submit');
  downloadPasswordError.clear();
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
    if (reauthorizeWaiters.length) {
      // A save is waiting: hand the page back to it instead of reloading.
      $('download-gate').hidden = true;
      $('download-content').hidden = false;
      $('status').textContent = 'Resuming download';
      for (const resolve of reauthorizeWaiters.splice(0)) resolve(true);
      return;
    }
    await loadMetadata();
  } catch (verificationError) {
    downloadPasswordError.show(verificationError.message);
    $('download-password').focus();
  } finally {
    submit.disabled = false;
  }
});

loadMetadata();

initDeliveryEvidence(async () => ({ ...evidenceMetadata, files: metadataHasMore ? await loadRemainingMetadata() : metadataFiles }), savedNames);
