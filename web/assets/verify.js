// votport public receipt check: verify the receipt sidecar's Ed25519
// signature in this tab, with the same wasm the sender uses, against the
// receipt key this server publishes, and hash any payload file locally with
// the same worker the sender uses. The payload never leaves the tab and the
// verdict here never comes from a server answer. VOTPORT PROPRIETARY LICENSE.

import { $, appendObjectCard, formatBytes } from '/assets/object-card.js';
import init, {
  ErrorCode,
  verifyReceiptEd25519,
} from '/assets/vendor/vot_wasm.js';

let payloadFile = null;
let sidecarFile = null;
let checking = false;
// The only key this tab will accept a receipt under. It is the same answer
// that fills the printed key box below, so a check and the displayed key
// cannot disagree.
const receiptKey = (async () => {
  try {
    const response = await fetch('/api/receipt-key');
    if (!response.ok) throw new Error(response.status);
    const { receipt_key: key } = await response.json();
    $('receipt-key').textContent = key || 'unavailable';
    return hexBytes(key);
  } catch {
    $('receipt-key').textContent = 'unavailable';
    return null;
  }
})();
let wasmReady = null;

function showError(message) {
  $('verify-error').textContent = message;
  $('verify-error').hidden = false;
}

function reportIgnored(count) {
  showError(
    count === 1
      ? 'One extra file was ignored; only a file and its receipt are verified.'
      : `${count} extra files were ignored; only a file and its receipt are verified.`,
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
  $('check').textContent = active ? 'Verifying…' : 'Verify receipt';
  renderSlots();
}

function showResult({ ok, title, file, bytes, next, suite, root, observedAt }) {
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

  // The receipt's signed observation time is the one authoritative stamp:
  // shown verbatim (it ends in Z) and labelled UTC (audit finding 404).
  const observed = $('verify-observed');
  observed.textContent = observedAt ? `Observed ${observedAt} (UTC)` : '';
  observed.hidden = !observedAt;

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

function hexBytes(text) {
  if (!/^[0-9a-f]{64}$/.test(text ?? '')) return null;
  return new Uint8Array(text.match(/../g).map((pair) => parseInt(pair, 16)));
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
  const key = await receiptKey;
  if (!key) {
    showError('This port’s receipt key is unavailable. Reload the page and try again.');
    return;
  }
  wasmReady ??= init();
  try {
    await wasmReady;
  } catch {
    wasmReady = null;
    showError('Local verification failed to load. Reload the page and try again.');
    return;
  }
  let receipt;
  try {
    receipt = verifyReceiptEd25519(
      new Uint8Array(await sidecarFile.arrayBuffer()),
      key,
    );
  } catch (error) {
    showError(
      error?.code === ErrorCode.Malformed
        ? 'This is not a vot-receipt.'
        : 'This receipt was not signed by the receipt key this port publishes.',
    );
    return;
  }
  const subject = receipt.subjectId;
  const signedRoot = toHex(subject.root);
  const signedLength = Number(subject.length);

  if (!payloadFile) {
    showResult({
      ok: false,
      title: 'Signature verified',
      suite: subject.suite,
      root: signedRoot,
      file: sidecarFile.name,
      bytes: signedLength,
      observedAt: receipt.observedAt,
      next: 'This receipt carries this port’s signature. Pick the file too if you also want its bytes verified.',
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
  // Verified only when the root signed in the receipt is the root hashed in
  // this tab; nothing the server answers can produce a Verified card.
  const match = signedRoot === root && signedLength === length;
  showResult({
    ok: match,
    title: match ? 'Verified' : 'Does not match',
    suite: done.suite,
    root,
    file: payloadFile.name,
    bytes: length,
    observedAt: receipt.observedAt,
    next: match
      ? 'Every byte of this file matches the root signed in the receipt.'
      : 'This file is not the object in the receipt. Compare names; a receipt proves one exact file.',
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
  if (e.key === 'Enter' || e.key === ' ') {
    e.preventDefault();
    $('payload-input').click();
  }
});
$('reset').addEventListener('click', reset);
$('verify-form').addEventListener('submit', (e) => {
  e.preventDefault();
  check();
});
