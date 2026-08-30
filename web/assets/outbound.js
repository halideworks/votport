// votport public verified download page. AGPL-3.0-only.

import { appendObjectCard, formatBytes } from '/assets/object-card.js';

const $ = (id) => document.getElementById(id);
const token = window.location.pathname.split('/').filter(Boolean).pop();

function when(seconds) {
  return new Date(seconds * 1000).toLocaleString();
}

function showError(message) {
  $('download-gate').hidden = true;
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
  $('title').textContent = body.label || 'Verified download';
  $('status').textContent = 'The server verifies the file against this identity before download.';
  for (const file of files) {
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
  $('expires').textContent = body.expires_at
    ? `Link expires ${when(body.expires_at)}`
    : 'This link does not expire.';
  $('receipt-key').textContent = body.receipt_key;
  $('download-content').hidden = false;
}

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
