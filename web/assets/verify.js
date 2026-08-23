// votport public receipt check: POST the sidecar bytes to /api/verify and,
// when a payload file is present, hash it locally with the same worker the
// sender uses. The payload never leaves the tab. AGPL-3.0-only.

import { appendObjectCard, formatBytes } from '/assets/object-card.js';

const $ = (id) => document.getElementById(id);

let payloadFile = null;
let sidecarFile = null;
let ignoredCount = 0;

function showError(message) {
  $('verify-error').textContent = message;
  $('verify-error').hidden = false;
}

function clearError() {
  $('verify-error').hidden = true;
}

function refreshPickedNote() {
  const parts = [];
  if (payloadFile) parts.push(`file: ${payloadFile.name}`);
  if (sidecarFile) parts.push(`receipt: ${sidecarFile.name}`);
  if (payloadFile && !sidecarFile) parts.push('pick the .vot-receipt to check');
  const note = $('picked-note');
  if (parts.length) {
    note.textContent = parts.join(' · ');
    note.hidden = false;
  } else {
    note.hidden = true;
  }
  // A lone sidecar is enough to check issuance; a lone payload is not.
  $('check').disabled = !sidecarFile;
}

// One payload plus one sidecar per Check; anything else dropped on the zone
// is named so the sender knows it was not checked.
function takeFiles(files) {
  ignoredCount = 0;
  for (const file of files) {
    if (!sidecarFile && file.name.endsWith('.vot-receipt')) {
      sidecarFile = file;
    } else if (!payloadFile) {
      payloadFile = file;
    } else {
      ignoredCount += 1;
    }
  }
  if (ignoredCount) {
    $('ignore-note').textContent =
      'Only one file and one receipt are checked. Extra files were ignored.';
    $('ignore-note').hidden = false;
  }
  clearError();
  refreshPickedNote();
}

// hash-worker.js posts {req, step} per 8 MiB read and only the final message
// carries done: {suite, root (Uint8Array), length (bigint)}.
function hashPayload(file) {
  return new Promise((resolve, reject) => {
    const worker = new Worker('/assets/hash-worker.js', { type: 'module' });
    worker.onmessage = async ({ data }) => {
      if (data.step !== undefined) return; // progress tick, not a result
      if (data.error) {
        worker.terminate();
        reject(new Error(data.error));
        return;
      }
      // Terminate frees the worker heap including any pinned tree; no drop
      // round-trip needed on a worker we are about to destroy.
      worker.terminate();
      resolve(data.done);
    };
    worker.onerror = () => {
      worker.terminate();
      reject(new Error('local verification failed'));
    };
    worker.postMessage({ op: 'hash', req: 1, key: 'verify', file });
  });
}

function toHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function check() {
  clearError();
  $('check').disabled = true;
  try {
    let response;
    try {
      response = await fetch('/api/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: await sidecarFile.arrayBuffer(),
      });
    } catch {
      showError('Could not reach the server. Reload the page to try again.');
      return;
    }
    let result = null;
    try {
      result = await response.json();
    } catch {
      // A 413 body is empty axum text; treat any non-JSON as not-a-receipt.
    }
    if (!response.ok || !result?.ok) {
      showError(result?.error ?? 'This is not a vot-receipt.');
      return;
    }

    const list = $('verify-list');
    list.replaceChildren();
    const resultCard = $('verify-result');
    const next = $('verify-next');
    next.hidden = true;
    resultCard.classList.remove('ok');

    if (!payloadFile) {
      appendObjectCard(
        list,
        { name: sidecarFile.name, suite: result.suite, root: result.root },
        {
          tag: 'li',
          rowClass: 'done',
          status: `${formatBytes(result.length)} · receipt ✓`,
        },
      );
      next.textContent =
        'Receipt is from this server. Drop the file to check the bytes.';
      next.hidden = false;
      resultCard.hidden = false;
      return;
    }

    let done;
    try {
      done = await hashPayload(payloadFile);
    } catch {
      showError('Could not read the file. Pick it again.');
      resultCard.hidden = false;
      return;
    }
    const root = toHex(done.root);
    const length = Number(done.length);
    const match = root === result.root && length === Number(result.length);
    appendObjectCard(
      list,
      { name: payloadFile.name, suite: result.suite, root },
      { tag: 'li', rowClass: 'done', status: `${formatBytes(length)} · receipt ✓` },
    );
    if (match) {
      resultCard.classList.add('ok');
    } else {
      next.textContent = 'This file is not the object in the receipt.';
      next.hidden = false;
    }
    resultCard.hidden = false;
  } finally {
    $('check').disabled = !sidecarFile;
  }
}

try {
  const response = await fetch('/api/receipt-key');
  if (!response.ok) throw new Error(response.status);
  const { receipt_key: key } = await response.json();
  $('receipt-key').textContent = key;
} catch {
  $('receipt-key').textContent = '';
  showError('Could not reach the server. Reload the page to try again.');
}

$('pick-payload').addEventListener('click', () => $('payload-input').click());
$('pick-sidecar').addEventListener('click', () => $('sidecar-input').click());
$('payload-input').addEventListener('change', (e) => takeFiles(e.target.files));
$('sidecar-input').addEventListener('change', (e) =>
  takeFiles(e.target.files),
);
const dropZone = $('verify-drop');
dropZone.addEventListener('dragover', (e) => e.preventDefault());
dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  takeFiles([...e.dataTransfer.files]);
});
dropZone.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') $('payload-input').click();
});
$('verify-form').addEventListener('submit', (e) => {
  e.preventDefault();
  check();
});
