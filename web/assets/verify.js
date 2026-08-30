// votport public receipt check: POST the sidecar bytes to /api/verify and,
// when a payload file is present, hash it locally with the same worker the
// sender uses. The payload never leaves the tab. VOTPORT PROPRIETARY LICENSE.

import { appendObjectCard, formatBytes } from '/assets/object-card.js';

const $ = (id) => document.getElementById(id);

let payloadFile = null;
let sidecarFile = null;
let checking = false;

function showError(message) {
  $('verify-error').textContent = message;
  $('verify-error').hidden = false;
}

function reportIgnored(count) {
  showError(
    count === 1
      ? 'One extra file was ignored; only a file and its receipt are checked.'
      : `${count} extra files were ignored; only a file and its receipt are checked.`,
  );
}

function clearError() {
  $('verify-error').hidden = true;
}

function renderSlots() {
  const payloadName = $('payload-name');
  const sidecarName = $('sidecar-name');
  if (payloadFile) {
    payloadName.textContent = `${payloadFile.name} (${formatBytes(payloadFile.size)})`;
    payloadName.classList.remove('muted');
  } else {
    payloadName.textContent = 'not picked';
    payloadName.classList.add('muted');
  }
  if (sidecarFile) {
    sidecarName.textContent = sidecarFile.name;
    sidecarName.classList.remove('muted');
  } else {
    sidecarName.textContent = 'the .vot-receipt is enough on its own';
    sidecarName.classList.add('muted');
  }
  $('clear-payload').hidden = !payloadFile;
  $('clear-sidecar').hidden = !sidecarFile;
  // A lone sidecar is enough to check issuance; a lone payload is not.
  $('check').disabled = checking || !sidecarFile;
}

// One payload plus one sidecar per Check; anything else dropped on the zone
// is named so the sender knows it was not checked.
function takeFiles(files) {
  let ignored = 0;
  for (const file of files) {
    if (!sidecarFile && file.name.endsWith('.vot-receipt')) {
      sidecarFile = file;
    } else if (!payloadFile && !file.name.endsWith('.vot-receipt')) {
      payloadFile = file;
    } else {
      ignored += 1;
    }
  }
  clearError();
  renderSlots();
  return ignored;
}

function setChecking(active) {
  checking = active;
  $('check').textContent = active ? 'Checking…' : 'Check receipt';
  renderSlots();
}

function showResult({ ok, title, file, bytes, next, suite, root }) {
  const card = $('verify-result');
  card.classList.toggle('ok', Boolean(ok));
  card.hidden = false;
  $('verify-title').textContent = title;

  const list = $('verify-list');
  list.replaceChildren();
  appendObjectCard(
    list,
    { name: file, suite, root },
    {
      tag: 'li',
      rowClass: ok ? 'done' : '',
      // The receipt mark is only true when the bytes matched too.
      status: `${formatBytes(bytes)}${ok ? ' · receipt ✓' : ''}`,
    },
  );

  const nextLine = $('verify-next');
  nextLine.textContent = next || '';
  nextLine.hidden = !next;
  $('reset').hidden = false;
}

function reset() {
  payloadFile = null;
  sidecarFile = null;
  $('payload-input').value = '';
  $('sidecar-input').value = '';
  $('verify-result').hidden = true;
  $('reset').hidden = true;
  clearError();
  renderSlots();
}

// hash-worker.js posts {req, step} per 8 MiB read and only the final message
// carries done: {suite, root (Uint8Array), length (bigint)}. Steps drive no
// UI here beyond the button state; a check is short relative to an upload.
function hashPayload(file) {
  return new Promise((resolve, reject) => {
    const worker = new Worker('/assets/hash-worker.js', { type: 'module' });
    worker.onmessage = ({ data }) => {
      if (data.step !== undefined) return; // progress tick, not a result
      // Terminate frees the worker heap including any pinned tree; no drop
      // round-trip needed on a worker we are about to destroy.
      worker.terminate();
      if (data.error) {
        reject(new Error(data.error));
        return;
      }
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
  setChecking(true);
  try {
    await runCheck();
  } finally {
    setChecking(false);
  }
}

async function runCheck() {
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

  if (!payloadFile) {
    showResult({
      ok: false,
      title: 'Genuine receipt',
      suite: result.suite,
      root: result.root,
      file: sidecarFile.name,
      bytes: Number(result.length),
      next: 'This receipt was issued by this server. Pick the file too if you also want its bytes checked.',
    });
    return;
  }

  let done;
  try {
    done = await hashPayload(payloadFile);
  } catch {
    showError('Could not read the file. Pick it again.');
    return;
  }
  const root = toHex(done.root);
  const length = Number(done.length);
  const match = root === result.root && length === Number(result.length);
  showResult({
    ok: match,
    title: match ? 'Verified' : 'Does not match',
    suite: result.suite,
    root,
    file: payloadFile.name,
    bytes: length,
    next: match
      ? 'Every byte of this file matches what the server received.'
      : 'This file is not the object in the receipt. Compare names — a receipt proves one exact file.',
  });
}

$('pick-payload').addEventListener('click', () => $('payload-input').click());
$('pick-sidecar').addEventListener('click', () => $('sidecar-input').click());
$('clear-payload').addEventListener('click', () => {
  payloadFile = null;
  $('payload-input').value = '';
  clearError();
  renderSlots();
});
$('clear-sidecar').addEventListener('click', () => {
  sidecarFile = null;
  $('sidecar-input').value = '';
  clearError();
  renderSlots();
});
$('payload-input').addEventListener('change', (e) => {
  const ignored = takeFiles(e.target.files);
  if (ignored) reportIgnored(ignored);
});
$('sidecar-input').addEventListener('change', (e) => {
  const ignored = takeFiles(e.target.files);
  if (ignored) reportIgnored(ignored);
});
const dropZone = $('verify-drop');
dropZone.addEventListener('dragover', (e) => e.preventDefault());
dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  const ignored = takeFiles([...e.dataTransfer.files]);
  if (ignored) reportIgnored(ignored);
});
dropZone.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') $('payload-input').click();
});
$('reset').addEventListener('click', reset);
$('verify-form').addEventListener('submit', (e) => {
  e.preventDefault();
  check();
});

// Last, and not awaited at module scope: a slow answer here must not delay
// wiring the controls above.
(async () => {
  try {
    const response = await fetch('/api/receipt-key');
    if (!response.ok) throw new Error(response.status);
    const { receipt_key: key } = await response.json();
    $('receipt-key').textContent = key || 'unavailable';
  } catch {
    $('receipt-key').textContent = 'unavailable';
  }
})();
