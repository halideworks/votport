// votport public verified download page. AGPL-3.0-only.

import { appendObjectCard, formatBytes } from '/assets/object-card.js';

const $ = (id) => document.getElementById(id);
const token = window.location.pathname.split('/').filter(Boolean).pop();

function when(seconds) {
  return new Date(seconds * 1000).toLocaleString();
}

function showError(message) {
  $('download-content').hidden = true;
  $('download-error-message').textContent = message;
  $('download-error').hidden = false;
  $('status').textContent = 'Download unavailable';
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
  if (
    !body.download_url ||
    !body.receipt_url ||
    !body.receipt_key ||
    !body.name ||
    !body.suite ||
    !body.root ||
    typeof body.bytes !== 'number'
  ) {
    showError('The server returned incomplete download metadata.');
    return;
  }

  $('title').textContent = body.label || 'Verified download';
  $('status').textContent = 'The server verifies the file against this identity before download.';
  appendObjectCard(
    $('object'),
    { name: body.name, suite: body.suite, root: body.root },
    { status: formatBytes(body.bytes) },
  );
  $('expires').textContent = body.expires_at
    ? `Link expires ${when(body.expires_at)}`
    : 'This link does not expire.';
  $('receipt-key').textContent = body.receipt_key;
  $('download-file').addEventListener('click', () => { window.location.assign(body.download_url); });
  $('download-receipt').addEventListener('click', () => { window.location.assign(body.receipt_url); });
  $('download-content').hidden = false;
}

loadMetadata();
