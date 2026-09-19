// votport uploader: hashes files with vot-wasm, builds a VOT package, and
// streams proven ranges to the server. VOTPORT PROPRIETARY LICENSE.

import { applyBranding } from '/assets/branding.js';
import { appendObjectCard, appLink, copyToClipboard, fieldError, formatBytes, formatDuration } from '/assets/object-card.js';
import { entryFiles, runUploadBatch } from '/assets/upload-entries.js';
import {
  clearResumeRecord,
  expireForeignResumes,
  finishMayBeComplete,
  loadResumeRecord,
  resumeDropId,
  retryDecision,
  saveResumeRecord,
  sessionUnknown,
} from '/assets/upload-retry.js';
import { segments } from '/assets/hash-plan.js';
import init, {
  ObjectId,
  PackageBuilder,
  PackageEntry,
  PackagePath,
  Suite,
  proofLeafSize,
} from '/assets/vendor/vot_wasm.js';

const $ = (id) => document.getElementById(id);
const token = window.location.pathname.split('/').filter(Boolean).pop();

const UPLOADS_IN_FLIGHT = 8;
const MAX_VISIBLE_FILE_ROWS = 200;
let chunkBytes = 2 * 1024 * 1024;
let maxBytes = null;
// Server-reported hash of the sender assets at page load; a mismatch later
// means a deploy happened underneath this tab.
let webBuild = null;
let reloading = false;

// After a deploy, an old tab keeps talking to a server whose contract may
// have moved. Instead of surfacing that as a fatal error, reload so the
// sender resumes from the saved cursor with the current script.
async function reloadIfServerUpdated() {
  if (!webBuild) return;
  try {
    const info = await apiJson(`/api/r/${token}`);
    if (info.web_build && info.web_build !== webBuild) {
      $('subtitle').textContent = 'The port was updated. Reloading to resume…';
      reloading = true;
      window.location.reload();
      // The page is going away; never let the caller carry on with old code.
      await new Promise(() => {});
    }
  } catch { /* the original error stands */ }
}
const picked = new Map(); // relative path -> File
let deliveredPaths = new Set(); // paths delivered so far, including hidden rows
let uploading = false;
let cancelled = false;
let allowHidden = true; // the server's VOTPORT_ALLOW_HIDDEN, from the link info
let maxEntries = 20000; // the server's package entry cap, from the link info
let controller = null; // aborts in-flight requests on cancellation or refusal

// ------------------------------------------------------------- hash workers
// Hashing and the merkle trees live in workers so the page stays responsive
// and hashing genuinely overlaps upload bookkeeping. Each file's tree stays
// in the worker that owns it, which also serves its range proofs. A large
// file is hashed as segments across the whole pool and assembled on its
// owner. Every tree of a drop stays pinned until the drop finishes, since
// one package announces them all.

// Measured 2026-09-02 on a 20-core desktop hashing 256 MiB per worker:
// Firefox 157, 326, 545 MiB/s at 1, 2, 4 workers (flat beyond), Chromium
// 691 to 3336 MiB/s at 1 to 8. One worker is left for the page.
const MAX_WORKERS = 8;
// Below this a file hashes in one piece; splitting costs a read pipeline per
// worker and a join, worth it only when the file dwarfs that.
const PARALLEL_MIN_BYTES = 64 * 1024 * 1024;
const MIN_SEGMENT_BYTES = 16 * 1024 * 1024;
// Proof leaf size, read from the wasm once it is up, so a repin that
// changes the leaf cannot leave a stale literal misaligning the segment
// plan. Segments are only built after init.
let proofLeafBytes = 0;
// One file at a time takes the whole pool for segments while the other
// lanes keep hashing whole files, so live read buffers can reach twice the
// pool size.
let parallelHashing = false;

let hashWorkers = [];
const workerByPath = new Map(); // path -> the worker holding its tree
const workerRequests = new Map(); // req -> {resolve, reject, onStep}
let nextRequest = 0;

function startWorkers() {
  const count = Math.min(MAX_WORKERS, Math.max(1, (navigator.hardwareConcurrency || 2) - 1));
  hashWorkers = Array.from({ length: count }, () => {
    const worker = new Worker('/assets/hash-worker.js', { type: 'module' });
    worker.onmessage = ({ data }) => {
      const pending = workerRequests.get(data.req);
      if (!pending) return;
      if (data.step !== undefined) {
        pending.onStep?.(data.step);
        return;
      }
      workerRequests.delete(data.req);
      if (data.error !== undefined) {
        // A failed prove means the tree was not on that worker yet — a
        // recovery straggler, retried as a pause. Hash, leaves, and assemble
        // failures are real: the file changed or could not be read.
        const error = new Error(data.error);
        if (pending.op === 'prove') error.paused = true;
        pending.reject(error);
      } else pending.resolve(data.done);
    };
    worker.onerror = () => recoverWorkers();
    return worker;
  });
}

// 'hash' and 'assemble' pin the file's tree to a worker; 'prove' and 'drop'
// follow it. 'leaves' is one segment's work and pins nothing.
function workerFor(message, index) {
  if (message.op === 'hash' || message.op === 'assemble') {
    const worker = hashWorkers[index % hashWorkers.length];
    workerByPath.set(message.key, worker);
    return worker;
  }
  if (message.op === 'leaves') return hashWorkers[index % hashWorkers.length];
  return workerByPath.get(message.key);
}

function workerCall(message, index = 0, onStep = null) {
  return new Promise((resolve, reject) => {
    const worker = hashWorkers.length ? workerFor(message, index) : null;
    if (!worker) {
      // An empty pool mid-transfer is a dead worker awaiting recovery, not
      // a user cancel; the send loop retries after the pool is restored.
      reject(uploading ? new Paused() : new Cancelled());
      return;
    }
    const req = nextRequest;
    nextRequest += 1;
    workerRequests.set(req, { resolve, reject, onStep, op: message.op });
    worker.postMessage({ ...message, req });
  });
}

// Terminating the workers is what makes Cancel instant mid-hash: there is no
// cooperative flag to poll, the threads just stop.
function stopWorkers(error) {
  for (const worker of hashWorkers) worker.terminate();
  hashWorkers = [];
  workerByPath.clear();
  for (const pending of workerRequests.values()) {
    pending.reject(error || new Cancelled());
  }
  workerRequests.clear();
}

class Paused extends Error {
  constructor() {
    super('connection interrupted');
    this.paused = true;
  }
}

// Worker death is a pause, not a failure. Only this function touches the
// pool while uploading: it snapshots the pinned trees, restarts the workers,
// and re-hashes every path whose tree is gone. The send loop is the only
// place that begins sessions or sends ranges; it waits for recovery to finish
// before its next prove and re-begins from the server's covered_bytes.
const WORKER_RESTART_CAP = 3;
let workerRestarts = 0;
let recovering = false;
let readySignal = null; // promise owned by the recovery round in flight
let workerFatal = null; // set once the restart cap fires; every pause turns fatal

async function recoverWorkers() {
  if (!uploading || cancelled) {
    stopWorkers();
    return;
  }
  if (recovering) {
    // A second death during this round: tear the pool down so the round's
    // own re-hash calls reject Paused and the round releases; the pause
    // paths then re-enter here for a fresh round.
    stopWorkers(new Paused());
    return;
  }
  if (workerRestarts >= WORKER_RESTART_CAP) {
    workerFatal = new Error('Verification stopped. Try sending again');
    stopWorkers(workerFatal);
    return;
  }
  recovering = true;
  const paths = [...workerByPath.keys()];
  // In-flight calls reject with Paused so their owners retry instead of
  // treating the death as a cancel.
  stopWorkers(new Paused());
  let release;
  readySignal = new Promise((resolve) => { release = resolve; });
  workerRestarts += 1;
  startWorkers();
  setPhase('Preparing');
  try {
    // Delivered files released their trees, so only the ones still to send
    // are here; spread them over the fresh pool like the first pass did.
    let index = 0;
    for (const path of paths) {
      const file = picked.get(path);
      if (!file) continue;
      await workerCall({ op: 'hash', key: path, file }, index);
      index += 1;
    }
  } catch (error) {
    // Another death mid-recovery: its owner retries through the normal pause
    // paths, which re-enter here once this round releases.
  }
  recovering = false;
  release();
}

// The send loop awaits this before touching any tree after a pause.
function waitWorkersReady() {
  return readySignal || Promise.resolve();
}

class Cancelled extends Error {
  constructor() {
    super('Transfer cancelled.');
    this.cancelled = true;
  }
}

function checkCancelled() {
  if (cancelled) throw new Cancelled();
  if (controller?.signal.aborted) throw controller.signal.reason;
}

// Offers the desktop app the same link: `votport://<kind>/<token>?base=<origin>`,
// which the app prefills and the user confirms. Phones have no app.
function offerApp(kind) {
  if (/Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent)) return;
  const link = document.getElementById('open-in-app-link');
  if (!link) return;
  link.href = appLink(kind, token);
  link.hidden = false;
  const holder = document.getElementById('open-in-app');
  if (holder) holder.hidden = false;
}

// A record of the session currently in flight, so an interrupted transfer can
// re-attach to it instead of re-sending bytes the server already verified.
// Cleared on success and on cancel, kept on failure — failure is the case it
// exists for. Keyed per drop with an id this tab mints on the first save, so
// two tabs on one link hold separate records instead of fighting over one
// session. The server sweeps the session itself once it goes idle.
const dropId = () => resumeDropId(token);
const saveResume = (record) => saveResumeRecord(token, record);
const loadResume = () => loadResumeRecord(token, dropId());
const clearResume = () => clearResumeRecord(token, dropId());

// The verified-password cookie replaced the plaintext copy an earlier build
// kept in localStorage; scrub any leftover.
try { localStorage.removeItem(`votport-pass-${token}`); } catch { /* private mode */ }

function hex(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

// ---------------------------------------------------------------- formatting

// Throughput over a trailing window. A cumulative average keeps reporting a
// speed the transfer no longer has once it stalls, which is exactly when
// someone is staring at the number.
const RATE_WINDOW_MS = 4000;

function makeRate() {
  const samples = [[performance.now(), 0]];
  let windowed = 0;
  return (step) => {
    const now = performance.now();
    samples.push([now, step]);
    windowed += step;
    while (samples.length > 1 && now - samples[0][0] > RATE_WINDOW_MS) {
      windowed -= samples.shift()[1];
    }
    const seconds = (now - samples[0][0]) / 1000;
    return seconds >= 0.5 ? windowed / seconds : null;
  };
}

// Screen wake lock while sending: an unattended laptop otherwise hits its
// sleep timer mid-transfer and the upload dies. Best effort; browsers without
// the API (or a denied request) just keep today's behavior. A closed lid
// still sleeps the machine; no web API can prevent that.
let wakeLock = null;

async function keepAwake() {
  try { wakeLock = await navigator.wakeLock?.request('screen'); } catch { /* unsupported or denied */ }
}

async function releaseWakeLock() {
  try { await wakeLock?.release(); } catch { /* already released */ }
  wakeLock = null;
}

// The browser auto-releases the lock whenever the tab is hidden; take it back
// as soon as the sender returns while an upload is still running.
document.addEventListener('visibilitychange', () => {
  if (!(uploading && document.visibilityState === 'visible')) return;
  keepAwake();
  // iOS may have killed the pool while the tab was hidden; run the same
  // recovery a worker death would. If the pool is alive this is a no-op.
  if (!hashWorkers.length) recoverWorkers();
});

// " The one already delivered is kept." or " The N already delivered are kept."
function keptPhrase(count) {
  if (!count) return '';
  return count === 1
    ? ' The one already delivered is kept.'
    : ` The ${count} already delivered are kept.`;
}

function fail(message) {
  $('upload-error').textContent = message;
  $('upload-error').hidden = false;
}

// ------------------------------------------------- portable path validation
// Mirrors VOT's portable path profile (vot-manifest) so problems surface
// before hashing starts. The server re-checks everything.

const FORBIDDEN = new RegExp(
  '[\\x00-\\x1f/\\\\<>:"|?*~\\u200c\\u200d\\u202a-\\u202e\\u2066-\\u2069\\ufeff]',
  'u',
);
const utf8 = new TextEncoder();

// Full Unicode case folding for the spellings toLowerCase leaves alone while
// macOS, SMB3 and NTFS collapse them: final sigma, long s, sharp s, and the
// rest of CaseFolding.txt. Mirrors the server's unicase pass over the pinned
// crate's per-character key (audit finding 503); code point pairs, keyed on
// the already-lowercased character.
const FOLDS_FULL = new Map([
  [0xb5, [0x3bc]],
  [0xdf, [0x73, 0x73]],
  [0x149, [0x2bc, 0x6e]],
  [0x17f, [0x73]],
  [0x1f0, [0x6a, 0x30c]],
  [0x345, [0x3b9]],
  [0x390, [0x3b9, 0x308, 0x301]],
  [0x3b0, [0x3c5, 0x308, 0x301]],
  [0x3c2, [0x3c3]],
  [0x3d0, [0x3b2]],
  [0x3d1, [0x3b8]],
  [0x3d5, [0x3c6]],
  [0x3d6, [0x3c0]],
  [0x3f0, [0x3ba]],
  [0x3f1, [0x3c1]],
  [0x3f5, [0x3b5]],
  [0x587, [0x565, 0x582]],
  [0x13f8, [0x13f0]],
  [0x13f9, [0x13f1]],
  [0x13fa, [0x13f2]],
  [0x13fb, [0x13f3]],
  [0x13fc, [0x13f4]],
  [0x13fd, [0x13f5]],
  [0x1c80, [0x432]],
  [0x1c81, [0x434]],
  [0x1c82, [0x43e]],
  [0x1c83, [0x441]],
  [0x1c84, [0x442]],
  [0x1c85, [0x442]],
  [0x1c86, [0x44a]],
  [0x1c87, [0x463]],
  [0x1c88, [0xa64b]],
  [0x1e96, [0x68, 0x331]],
  [0x1e97, [0x74, 0x308]],
  [0x1e98, [0x77, 0x30a]],
  [0x1e99, [0x79, 0x30a]],
  [0x1e9a, [0x61, 0x2be]],
  [0x1e9b, [0x1e61]],
  [0x1f50, [0x3c5, 0x313]],
  [0x1f52, [0x3c5, 0x313, 0x300]],
  [0x1f54, [0x3c5, 0x313, 0x301]],
  [0x1f56, [0x3c5, 0x313, 0x342]],
  [0x1f80, [0x1f00, 0x3b9]],
  [0x1f81, [0x1f01, 0x3b9]],
  [0x1f82, [0x1f02, 0x3b9]],
  [0x1f83, [0x1f03, 0x3b9]],
  [0x1f84, [0x1f04, 0x3b9]],
  [0x1f85, [0x1f05, 0x3b9]],
  [0x1f86, [0x1f06, 0x3b9]],
  [0x1f87, [0x1f07, 0x3b9]],
  [0x1f90, [0x1f20, 0x3b9]],
  [0x1f91, [0x1f21, 0x3b9]],
  [0x1f92, [0x1f22, 0x3b9]],
  [0x1f93, [0x1f23, 0x3b9]],
  [0x1f94, [0x1f24, 0x3b9]],
  [0x1f95, [0x1f25, 0x3b9]],
  [0x1f96, [0x1f26, 0x3b9]],
  [0x1f97, [0x1f27, 0x3b9]],
  [0x1fa0, [0x1f60, 0x3b9]],
  [0x1fa1, [0x1f61, 0x3b9]],
  [0x1fa2, [0x1f62, 0x3b9]],
  [0x1fa3, [0x1f63, 0x3b9]],
  [0x1fa4, [0x1f64, 0x3b9]],
  [0x1fa5, [0x1f65, 0x3b9]],
  [0x1fa6, [0x1f66, 0x3b9]],
  [0x1fa7, [0x1f67, 0x3b9]],
  [0x1fb2, [0x1f70, 0x3b9]],
  [0x1fb3, [0x3b1, 0x3b9]],
  [0x1fb4, [0x3ac, 0x3b9]],
  [0x1fb6, [0x3b1, 0x342]],
  [0x1fb7, [0x3b1, 0x342, 0x3b9]],
  [0x1fbe, [0x3b9]],
  [0x1fc2, [0x1f74, 0x3b9]],
  [0x1fc3, [0x3b7, 0x3b9]],
  [0x1fc4, [0x3ae, 0x3b9]],
  [0x1fc6, [0x3b7, 0x342]],
  [0x1fc7, [0x3b7, 0x342, 0x3b9]],
  [0x1fd2, [0x3b9, 0x308, 0x300]],
  [0x1fd3, [0x3b9, 0x308, 0x301]],
  [0x1fd6, [0x3b9, 0x342]],
  [0x1fd7, [0x3b9, 0x308, 0x342]],
  [0x1fe2, [0x3c5, 0x308, 0x300]],
  [0x1fe3, [0x3c5, 0x308, 0x301]],
  [0x1fe4, [0x3c1, 0x313]],
  [0x1fe6, [0x3c5, 0x342]],
  [0x1fe7, [0x3c5, 0x308, 0x342]],
  [0x1ff2, [0x1f7c, 0x3b9]],
  [0x1ff3, [0x3c9, 0x3b9]],
  [0x1ff4, [0x3ce, 0x3b9]],
  [0x1ff6, [0x3c9, 0x342]],
  [0x1ff7, [0x3c9, 0x342, 0x3b9]],
  [0xab70, [0x13a0]],
  [0xab71, [0x13a1]],
  [0xab72, [0x13a2]],
  [0xab73, [0x13a3]],
  [0xab74, [0x13a4]],
  [0xab75, [0x13a5]],
  [0xab76, [0x13a6]],
  [0xab77, [0x13a7]],
  [0xab78, [0x13a8]],
  [0xab79, [0x13a9]],
  [0xab7a, [0x13aa]],
  [0xab7b, [0x13ab]],
  [0xab7c, [0x13ac]],
  [0xab7d, [0x13ad]],
  [0xab7e, [0x13ae]],
  [0xab7f, [0x13af]],
  [0xab80, [0x13b0]],
  [0xab81, [0x13b1]],
  [0xab82, [0x13b2]],
  [0xab83, [0x13b3]],
  [0xab84, [0x13b4]],
  [0xab85, [0x13b5]],
  [0xab86, [0x13b6]],
  [0xab87, [0x13b7]],
  [0xab88, [0x13b8]],
  [0xab89, [0x13b9]],
  [0xab8a, [0x13ba]],
  [0xab8b, [0x13bb]],
  [0xab8c, [0x13bc]],
  [0xab8d, [0x13bd]],
  [0xab8e, [0x13be]],
  [0xab8f, [0x13bf]],
  [0xab90, [0x13c0]],
  [0xab91, [0x13c1]],
  [0xab92, [0x13c2]],
  [0xab93, [0x13c3]],
  [0xab94, [0x13c4]],
  [0xab95, [0x13c5]],
  [0xab96, [0x13c6]],
  [0xab97, [0x13c7]],
  [0xab98, [0x13c8]],
  [0xab99, [0x13c9]],
  [0xab9a, [0x13ca]],
  [0xab9b, [0x13cb]],
  [0xab9c, [0x13cc]],
  [0xab9d, [0x13cd]],
  [0xab9e, [0x13ce]],
  [0xab9f, [0x13cf]],
  [0xaba0, [0x13d0]],
  [0xaba1, [0x13d1]],
  [0xaba2, [0x13d2]],
  [0xaba3, [0x13d3]],
  [0xaba4, [0x13d4]],
  [0xaba5, [0x13d5]],
  [0xaba6, [0x13d6]],
  [0xaba7, [0x13d7]],
  [0xaba8, [0x13d8]],
  [0xaba9, [0x13d9]],
  [0xabaa, [0x13da]],
  [0xabab, [0x13db]],
  [0xabac, [0x13dc]],
  [0xabad, [0x13dd]],
  [0xabae, [0x13de]],
  [0xabaf, [0x13df]],
  [0xabb0, [0x13e0]],
  [0xabb1, [0x13e1]],
  [0xabb2, [0x13e2]],
  [0xabb3, [0x13e3]],
  [0xabb4, [0x13e4]],
  [0xabb5, [0x13e5]],
  [0xabb6, [0x13e6]],
  [0xabb7, [0x13e7]],
  [0xabb8, [0x13e8]],
  [0xabb9, [0x13e9]],
  [0xabba, [0x13ea]],
  [0xabbb, [0x13eb]],
  [0xabbc, [0x13ec]],
  [0xabbd, [0x13ed]],
  [0xabbe, [0x13ee]],
  [0xabbf, [0x13ef]],
  [0xfb00, [0x66, 0x66]],
  [0xfb01, [0x66, 0x69]],
  [0xfb02, [0x66, 0x6c]],
  [0xfb03, [0x66, 0x66, 0x69]],
  [0xfb04, [0x66, 0x66, 0x6c]],
  [0xfb05, [0x73, 0x74]],
  [0xfb06, [0x73, 0x74]],
  [0xfb13, [0x574, 0x576]],
  [0xfb14, [0x574, 0x565]],
  [0xfb15, [0x574, 0x56b]],
  [0xfb16, [0x57e, 0x576]],
  [0xfb17, [0x574, 0x56d]],
]);

function fold(component) {
  let folded = '';
  for (const character of component.normalize('NFC')) {
    if (character === 'I' || character === 'i' || character === 'İ' || character === 'ı') {
      folded += 'i';
    } else {
      folded += character.toLowerCase();
    }
  }
  let out = '';
  for (const character of folded) {
    const spelling = FOLDS_FULL.get(character.codePointAt(0));
    out += spelling === undefined ? character : String.fromCodePoint(...spelling);
  }
  return out.normalize('NFC');
}

function validateComponent(component) {
  if (!component || utf8.encode(component).length > 255) {
    return 'name is empty or longer than 255 bytes';
  }
  if (FORBIDDEN.test(component)) {
    return 'name contains a character that does not travel well (\\ / < > : " | ? * ~ or control characters)';
  }
  if (component.endsWith('.') || component.endsWith(' ')) {
    return 'name may not end with a dot or space';
  }
  if (component.startsWith('.')) {
    // Mirrors paths::admit_component so a refusal costs nothing hashed.
    if (!allowHidden) return 'hidden names (starting with a dot) are not accepted here';
    if (/[^\x00-\x7f]/.test(component)) return 'non-ASCII hidden names are reserved';
    if (/^\.votport-(lease|workflows)$/i.test(component)
      || /^\.vot-stage$/i.test(component)
      || /^\.vot-tenants\.stage$/i.test(component)
      || /^\.vot-push-[0-9a-f]{32}$/.test(component)
      || /^\.vot-.*\.(stage|journal)$/.test(component)) {
      return "this name is reserved for the port's own files";
    }
  }
  const compatibility = component.normalize('NFKC');
  if (compatibility === '.' || compatibility === '..') return 'name is a directory reference';
  const folded = fold(component);
  if (folded.endsWith('.vot-receipt')) return 'this name is reserved for signed receipts';
  if (folded === '' || folded === '.' || folded === '..') return 'name is a directory reference';
  const stem = folded.split('.')[0];
  if (/^(con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³])$/.test(stem)) {
    return `"${stem}" is a reserved device name on Windows`;
  }
  return null;
}

// Same folding as pathKeyBytes, as a string, for the pick-time collision check.
function pathKeyString(components) {
  return components.map((component) => fold(component).replace(/[. ]+$/, '')).join('\0');
}

function pathKeyBytes(components) {
  const key = components
    .map((component) => fold(component).replace(/[. ]+$/, ''))
    .join('\0');
  return utf8.encode(key);
}

function compareBytes(a, b) {
  const length = Math.min(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    if (a[index] !== b[index]) return a[index] - b[index];
  }
  return a.length - b.length;
}

// -------------------------------------------------------------- file picking

function relativePath(file) {
  return file.webkitRelativePath && file.webkitRelativePath.length
    ? file.webkitRelativePath
    : file.name;
}

function addFiles(files) {
  addNamed([...files].map((file) => ({ path: relativePath(file), file })));
}

function addNamed(pairs) {
  if (uploading) return;
  // Validate the whole batch before touching `picked`, so a refusal leaves
  // the selection, its rows, and the collision keys consistent.
  const keys = new Map(pickedKeys);
  const accepted = [];
  for (const { path, file } of pairs) {
    const components = path.split('/').filter(Boolean);
    for (const component of components) {
      const problem = validateComponent(component);
      if (problem) {
        fail(`"${path}": ${problem}`);
        return;
      }
    }
    if (utf8.encode(components.at(-1) ?? '').length > 242) {
      fail(`"${path}": filename exceeds 242 UTF-8 bytes; shorten it to leave room for its signed receipt and receive journal`);
      return;
    }
    const joined = components.join('/');
    // One package holds the whole drop, so two names that fold to the same
    // key would be refused at the manifest; catch it before hashing.
    const key = pathKeyString(components);
    const other = keys.get(key);
    if (other !== undefined && other !== joined) {
      fail(`"${other}" and "${joined}" collide once case is folded; rename one`);
      return;
    }
    keys.set(key, joined);
    accepted.push([joined, file]);
  }
  for (const [joined, file] of accepted) {
    picked.set(joined, file);
    deliveredPaths.delete(joined);
  }
  $('upload-error').hidden = true;
  renderPicked();
}

// path -> its list row, so per-chunk status updates skip the O(files) scan.
let rows = new Map();
// folded path key -> path, rebuilt with the rows, for the collision check.
let pickedKeys = new Map();
let sizeLimitError = false;

function sizeLimitMessage(total) {
  if (maxBytes !== null && total > maxBytes) {
    return `Selected files total ${formatBytes(total)} exceeds this link's ${formatBytes(maxBytes)} limit. Clear the selection and choose fewer files.`;
  }
  if (picked.size > maxEntries) {
    return `${picked.size} files selected; a request holds up to ${maxEntries.toLocaleString()} files. Clear the selection and send it in parts.`;
  }
  return null;
}

function renderPicked() {
  const list = $('file-list');
  list.replaceChildren();
  rows = new Map();
  pickedKeys = new Map();
  let total = 0;
  let visible = 0;
  for (const [path, file] of picked) {
    total += file.size;
    pickedKeys.set(pathKeyString(path.split('/')), path);
    if (visible >= MAX_VISIBLE_FILE_ROWS) continue;
    visible += 1;
    const item = document.createElement('li');
    item.dataset.path = path;
    const name = document.createElement('span');
    name.textContent = path;
    const status = document.createElement('span');
    status.className = 'status';
    status.textContent = formatBytes(file.size);
    item.append(name, status);
    list.append(item);
    rows.set(path, item);
  }
  const limitError = sizeLimitMessage(total);
  $('totals').hidden = picked.size === 0;
  const preview = picked.size > visible
    ? ` · Showing first ${visible.toLocaleString()} of ${picked.size.toLocaleString()} selected files`
    : '';
  $('totals').textContent = `${picked.size} file${picked.size === 1 ? '' : 's'}, ${formatBytes(total)} total${maxBytes === null ? '' : ` · limit ${formatBytes(maxBytes)}`}${preview}`;
  $('clear-files').hidden = picked.size === 0;
  if (limitError) {
    fail(limitError);
    sizeLimitError = true;
  } else if (sizeLimitError) {
    $('upload-error').hidden = true;
    sizeLimitError = false;
  }
  $('send').disabled = picked.size === 0 || Boolean(limitError);
}

// Each row carries the honest state of that file: hashing before anything
// is sent, sending with its own meter, paused while the pool or network
// recovers, verified once the server has published it with a receipt.
function setStatus(path, text, done = false, fraction = null) {
  if (done) deliveredPaths.add(path);
  else deliveredPaths.delete(path);
  const item = rows.get(path);
  if (!item) return;
  item.querySelector('.status').textContent = text;
  item.classList.toggle('done', done);
  // data-state is the one source of truth; the stylesheet colours by it.
  const state = done ? 'verified'
    : text === 'Preparing' ? 'hashing'
      : text === 'Paused' ? 'paused'
        : text === 'Ready' ? 'ready'
          : 'sending';
  item.dataset.state = state;
  let badge = item.querySelector('.state');
  if (!badge) {
    badge = document.createElement('span');
    badge.className = 'badge state';
    item.querySelector('.status').before(badge);
  }
  badge.textContent = state;
  let meter = item.querySelector('.row-meter');
  if (fraction !== null && !done) {
    if (!meter) {
      meter = document.createElement('div');
      meter.className = 'row-meter';
      meter.append(document.createElement('div'));
      item.append(meter);
    }
    const percent = Math.max(0, Math.min(100, Math.round(fraction * 100)));
    meter.setAttribute('role', 'progressbar');
    meter.setAttribute('aria-label', `${path} upload progress`);
    meter.setAttribute('aria-valuemin', '0');
    meter.setAttribute('aria-valuemax', '100');
    meter.setAttribute('aria-valuenow', String(percent));
    meter.firstChild.style.width = `${percent}%`;
  } else if (meter && done) {
    // A state change without a fraction (a retry's Continuing) keeps the
    // last known progress on screen instead of flickering the bar away.
    meter.remove();
  }
}

function showClosed(label, message) {
  $('title').textContent = label;
  document.title = `VOTPort · ${label}`;
  $('closed').querySelector('h2').textContent = label;
  if (message) $('closed').querySelector('p').textContent = message;
  $('closed').hidden = false;
}

// ------------------------------------------------------------------- network

async function apiJson(path, options = {}) {
  const response = await fetch(path, { signal: controller?.signal, ...options });
  let body = null;
  try { body = await response.json(); } catch { /* not JSON */ }
  if (!response.ok) {
    const error = new Error(body?.error || `request failed (${response.status})`);
    error.status = response.status;
    throw error;
  }
  return body;
}

// Every POST in the send path goes through here. A transient failure — a
// 5xx, a 429, a lost connection — is retried a bounded number of times
// within a bounded budget and honoring the server's Retry-After, instead of
// pausing forever against a server that may be down. A refusal the server
// names (admission caps, draining) stops the transfer with the server's own
// words, and a user cancel never retries. A single-shot POST is never
// replayed into its session: on a transient failure the caller restarts the
// session, since a replay that reached the server is refused outright.
async function postWithRetry(path, options = {}) {
  const { singleShot = false, drainPhase = false, ...request } = options;
  const startedAt = Date.now();
  for (let attempt = 0; ; attempt += 1) {
    checkCancelled();
    let status = null;
    let body = null;
    let retryAfterMs = null;
    let failure = null;
    try {
      const response = await fetch(path, {
        method: 'POST',
        signal: controller?.signal,
        ...request,
      });
      status = response.status;
      if (status === 429 || status >= 500) {
        // An absent header must keep the exponential backoff (Number(null)
        // is 0); only a real Retry-After may replace it.
        const header = response.headers.get('Retry-After');
        const seconds = header === null ? NaN : Number(header);
        if (Number.isFinite(seconds) && seconds >= 0) retryAfterMs = seconds * 1000;
      }
      try { body = await response.json(); } catch { /* not JSON */ }
      if (response.ok) {
        resumePhase();
        return body;
      }
      failure = Object.assign(new Error(body?.error || `request failed (${status})`), { status });
    } catch (error) {
      checkCancelled();
      failure = error;
    }
    const decision = retryDecision({
      attempt,
      elapsedMs: Date.now() - startedAt,
      status,
      body,
      retryAfterMs,
      failure,
      online: navigator.onLine !== false,
    });
    if (!decision.retry) {
      // A refusal ends the transfer with its message; an exhausted transient
      // failure pauses the send loop, which resumes from the server's own
      // coverage. An AbortError outside the shared controller propagates raw.
      const refused = decision.message !== undefined
        || (status !== null && status !== 429 && status < 500)
        || body?.retryable === false;
      if (refused) {
        if (singleShot && sessionUnknown(failure)) {
          // A restart between the seal or a page and the next request leaves
          // the new server holding no sessions at all: the same unknown-
          // session 404 the chunk loop treats as rebegin, so restart the
          // session instead of failing a transfer it never received.
          failure.restart = true;
        } else {
          failure.fatal = true;
        }
      } else if (failure?.name !== 'AbortError') {
        failure.paused = true;
        if (status === 503 && drainPhase) {
          // The retry budget ran out against a drain 503 on session
          // admission; the send loop retries this session, so the phase
          // keeps saying why it waits. Other 503s stay Paused: upload
          // tests key their release handshake on that phase.
          setPhase('Not accepting new transfers right now, retrying');
        }
      }
      throw failure;
    }
    if (singleShot) {
      // The seal and pages cannot be replayed into the session they were
      // addressed to: a replay that reached the server is refused (409
      // already provided, 422 malformed). Mark the session for a fresh
      // start, as the expired-session path does; the server's per-link
      // dedupe keeps the restart from resending delivered bytes.
      failure.restart = true;
      throw failure;
    }
    // A drained or restarting server answers 503 on session admission:
    // name that state instead of a bare Paused over 0 B (audit finding 497).
    // Only session-create posts say this; other 503s keep the Paused phase.
    setPhase(status === 503 && drainPhase
      ? 'Not accepting new transfers right now, retrying'
      : 'Paused');
    await sleepCancellable(decision.delayMs);
    resumePhase();
  }
}

// Sleep that wakes early on cancellation or a sibling's permanent refusal.
function sleepCancellable(ms) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      clearInterval(poll);
      resolve();
    }, ms);
    const poll = setInterval(() => {
      if (!cancelled && !controller?.signal.aborted) return;
      clearTimeout(timer);
      clearInterval(poll);
      reject(cancelled ? new Cancelled() : controller.signal.reason);
    }, 250);
  });
}

// ------------------------------------------------------------------- phases

// #phase is only ever Preparing, Sending, or Paused. Sending starts with the
// first range POST, not with session setup.
let rangePostSeen = false;

function resumePhase() {
  setPhase(rangePostSeen ? 'Sending' : 'Preparing');
}

function setPhase(text) {
  $('progress-card').hidden = false;
  $('phase').textContent = text;
}

// The note shows the honest rates: preparing while hashing is live, sending
// while ranges move, sizes always. A clause whose sample is stale prints
// nothing rather than a frozen or zero rate.
let totalForNote = 0;
let sentForNote = 0;
let lastHashBps = null;
let lastSendBps = null;
let lastHashAt = 0;
let lastSendAt = 0;

function renderNote() {
  const now = performance.now();
  const parts = [];
  if (now - lastHashAt < RATE_WINDOW_MS && lastHashBps > 0) {
    parts.push(`preparing ${formatBytes(Math.round(lastHashBps))}/s`);
  }
  if (now - lastSendAt < RATE_WINDOW_MS && lastSendBps > 0) {
    parts.push(`sending ${formatBytes(Math.round(lastSendBps))}/s`);
    const remaining = totalForNote - sentForNote;
    if (remaining > 0) parts.push(`${formatDuration(remaining / lastSendBps)} left`);
  }
  parts.push(`${formatBytes(sentForNote)} of ${formatBytes(totalForNote)}`);
  const verified = deliveredPaths.size;
  if (picked.size > 1) parts.push(`${verified} of ${picked.size} files verified`);
  $('progress-note').textContent = parts.join(' · ');
}

function setMeter(fraction) {
  const percent = Math.min(100, Math.round(fraction * 100));
  $('meter-fill').style.width = `${percent}%`;
  $('meter').setAttribute('aria-valuenow', String(percent));
}


function buildPackage(items) {
  // Canonical manifest order: case-folded path keys, byte-wise.
  items.sort((a, b) => compareBytes(a.key, b.key));
  for (let index = 1; index < items.length; index += 1) {
    if (compareBytes(items[index - 1].key, items[index].key) === 0) {
      throw new Error(
        `"${items[index - 1].path}" and "${items[index].path}" collide once case is folded; rename one`,
      );
    }
  }
  const builder = new PackageBuilder();
  const drafts = [];
  for (const item of items) {
    const packagePath = new PackagePath();
    for (const component of item.components) packagePath.push(component);
    const entry = PackageEntry.direct(packagePath, item.objectId);
    const page = builder.push(entry);
    if (page) drafts.push(page);
  }
  const assembly = builder.finish();
  const summary = assembly.summary;
  drafts.push(assembly.takeFinalPage());
  const finalizer = assembly.takeFinalizer();
  const pages = drafts.map((draft) => finalizer.push(draft).bytes());
  const seal = finalizer.finish().bytes();
  return { summary, pages, seal };
}

async function uploadEntryChunks(sessionId, entryIndex, item, from, onProgress) {
  const { file } = item;
  const size = BigInt(file.size);
  let next = from;
  let failure = null;
  // Ranges start 64 KiB aligned and advance by whole chunks, so a proof
  // always covers exactly what was asked; the check below guards the maths.
  const take = () => {
    if (next >= size) return null;
    const offset = next;
    const want = size - offset < BigInt(chunkBytes) ? size - offset : BigInt(chunkBytes);
    next = offset + want;
    return { offset, want };
  };
  // Each sender prepares one proven range and keeps at most one POST in flight.
  const send = async () => {
    while (!failure) {
      const range = take();
      if (!range) return;
      try {
        checkCancelled();
        const proof = await workerCall({
          op: 'prove',
          key: item.path,
          offset: range.offset,
          length: range.want,
        });
        const start = Number(proof.coveredOffset);
        const length = Number(proof.coveredLength);
        if (BigInt(start) !== range.offset || BigInt(length) !== range.want) {
          throw new Error(`"${item.path}" failed an upload check; retry the upload`);
        }
        const data = await file.slice(start, start + length).arrayBuffer().catch(() => null);
        if (!data || data.byteLength !== length) {
          throw Object.assign(new Error(`"${item.path}" changed while uploading; pick it again`), {
            sourceChanged: true,
          });
        }
        const body = new window.Blob([proof.bytes, data]);
        const progress = await postWithRetry(
          `/api/session/${sessionId}/chunk?entry=${entryIndex}&offset=${start}`,
          {
            headers: {
              'Content-Type': 'application/octet-stream',
              'X-Votport-Proof': String(proof.bytes.length),
            },
            body,
          },
        );
        onProgress(length);
        // The server restarted and re-attached this session from its
        // checkpoint; ranges past that prefix are gone. Begin again to
        // learn the prefix instead of finishing into a refusal.
        if (progress?.rebegin) {
          throw Object.assign(new Error('server restarted; resuming'), { rebegin: true });
        }
      } catch (error) {
        if (error.sourceChanged || error.fatal) controller?.abort(error);
        failure ||= error;
      }
    }
  };
  await Promise.all(Array.from({ length: UPLOADS_IN_FLIGHT }, send));
  if (failure) throw failure;
}

async function runUpload() {
  const password = $('link-password').value;
  const files = [...picked.entries()];
  const totalBytes = files.reduce((sum, [, file]) => sum + file.size, 0);
  const hashRate = makeRate();
  const sendRate = makeRate();
  let sent = 0;
  const delivered = [];
  totalForNote = totalBytes;
  sentForNote = 0;
  lastHashBps = null;
  lastSendBps = null;
  lastHashAt = 0;
  lastSendAt = 0;
  rangePostSeen = false;
  workerRestarts = 0;
  workerFatal = null;

  async function hashOne([path, file], index) {
    checkCancelled();
    const components = path.split('/');
    setStatus(path, 'Preparing');
    let done = null;
    // A worker death mid-hash rejects this call with Paused; wait for the
    // restored pool and hash again rather than failing the transfer.
    for (;;) {
      checkCancelled();
      await waitWorkersReady();
      try {
        const onStep = (step) => {
          lastHashBps = hashRate(step);
          lastHashAt = performance.now();
          renderNote();
        };
        const plan = file.size >= PARALLEL_MIN_BYTES && !parallelHashing
          ? segments(file.size, proofLeafBytes, hashWorkers.length, MIN_SEGMENT_BYTES)
          : [[0, file.size]];
        if (plan.length < 2) {
          done = await workerCall({ op: 'hash', key: path, file }, index, onStep);
        } else {
          // Every worker hashes one segment at once; the owner joins the
          // leaves into the tree it will prove ranges from.
          parallelHashing = true;
          try {
            const leaves = await Promise.all(plan.map(([start, end], segment) =>
              workerCall({ op: 'leaves', key: path, file, start, end }, index + segment, onStep)));
            done = await workerCall(
              { op: 'assemble', key: path, length: file.size, leaves },
              index,
            );
          } finally {
            parallelHashing = false;
          }
        }
        break;
      } catch (error) {
        if (error.cancelled || !error.paused) throw error;
        if (workerFatal) throw workerFatal;
        if (!hashWorkers.length && !recovering) recoverWorkers();
        setStatus(path, 'Paused');
      }
    }
    setStatus(path, 'Ready');
    const objectId = new ObjectId(done.suite, done.root, done.length);
    return { path, components, file, objectId, key: pathKeyBytes(components) };
  }

  function isExpiredSession(error) {
    return error.status === 404
      || error.status === 410
      || /unknown or expired session/.test(error.message || '');
  }

  async function sendDrop(items) {
    // One VOT package for the whole drop: one session, one upload record, one
    // notification, and files already published stay published if a later
    // one fails (the server records them as a partial upload and dedupes
    // them on the next send). buildPackage sorts items into manifest order,
    // so entry.index addresses items directly.
    const { summary, pages, seal } = buildPackage(items);
    const packageId = summary.objectId;
    const rootHex = hex(packageId.root);
    const suite = packageId.suite === Suite.Blake3Bao64 ? 'blake3' : 'sha256';
    // Hashing is done; this is the session announce, seal, and pages.
    for (const item of items) setStatus(item.path, 'Opening');

    // Re-attach to an interrupted session for this exact drop. The package
    // root covers every file's bytes and path, so a file edited or added
    // since the interruption starts over rather than failing deep inside
    // range verification.
    const saved = loadResume();
    const resume = saved && saved.root === rootHex ? saved : null;
    let sessionId = resume?.session || null;
    if (sessionId) {
      // Keep the interrupted run's chunk grid: a different chunk size would
      // straddle extents the server already accepted and be rejected as
      // partial overlaps.
      chunkBytes = resume.chunk || chunkBytes;
    }

    // Per-entry bytes already counted into `sent`, so a recovery round that
    // re-reads begin's covered_bytes does not double-count them.
    const counted = new Map();
    let stalledRounds = 0;

    for (;;) {
      checkCancelled();
      // After a worker-death pause the trees are not back until recovery
      // says so; proving before that would just reject again.
      await waitWorkersReady();
      try {
        let entries = null;
        if (sessionId) {
          try {
          try {
            ({ entries } = await postWithRetry(`/api/session/${sessionId}/begin`, {}));
          } catch (error) {
            if (sessionUnknown(error)) {
              // The server restarted between the last page and begin and
              // holds no sessions: restart the way the re-begin 404 below
              // does, instead of failing at Preparing.
              error.restart = true;
            }
            throw error;
          }
          for (const item of items) {
              // deliveredPaths is the authority: rows past the visible
              // limit have no element, so a done-class check would reset
              // their delivered mark on every rebegin.
              if (!deliveredPaths.has(item.path)) {
                setStatus(item.path, 'Continuing');
              }
            }
          } catch (error) {
            if (error.cancelled || error.paused) throw error;
            // Session swept or server restarted: fall through and create a
            // fresh one, seal and pages included. Anything else is fatal.
            if (!isExpiredSession(error)) throw error;
            // The server no longer holds this session, so the saved record
            // (and the note built on it) would claim bytes it has dropped.
            clearResume();
            sessionId = null;
          }
        }
        if (!entries) {
          // Retried like every other call in the send path. A retry after a
          // request that reached the server can orphan a session; the server
          // sweeps idle sessions, so that costs nothing durable.
          const session = await postWithRetry(`/api/r/${token}/session`, {
            drainPhase: true,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              password: password || null,
              package: { suite, root: rootHex, length: Number(packageId.length) },
            }),
          });
          sessionId = session.session;
          chunkBytes = session.chunk_bytes || chunkBytes;
          // Written once per session: the server's begin reply is the authority
          // on how far the transfer got, so nothing needs saving per chunk.
          saveResume({
            session: sessionId,
            files: items.length,
            size: totalBytes,
            root: rootHex,
            chunk: chunkBytes,
          });
          await postWithRetry(`/api/session/${sessionId}/seal`, {
            singleShot: true,
            headers: { 'Content-Type': 'application/octet-stream' },
            body: seal,
          });
          for (const page of pages) {
            await postWithRetry(`/api/session/${sessionId}/page`, {
              singleShot: true,
              headers: { 'Content-Type': 'application/octet-stream' },
              body: page,
            });
          }
          ({ entries } = await postWithRetry(`/api/session/${sessionId}/begin`, {}));
        }

        rangePostSeen ||= entries.some((entry) => !entry.complete);
        const sendEntry = async (entry) => {
          const item = items[entry.index];
          // covered_bytes is the server's contiguous verified prefix, so it is
          // safe to restart from even when chunks landed out of order.
          const already = entry.complete
            ? item.file.size
            : Math.min(entry.covered_bytes ?? 0, item.file.size);
          const countedBefore = counted.get(entry.index) ?? 0;
          if (already !== countedBefore) {
            // Reconcile in both directions: ranges posted past the server's
            // contiguous prefix come back off `sent` at the next begin.
            sent += already - countedBefore;
            counted.set(entry.index, already);
          }
          if (entry.complete) {
            setMeter(totalBytes ? sent / totalBytes : 1);
            markDelivered(item);
            return;
          }
          let fileSent = already;
          // A delivered entry released its tree; if a later begin reports it
          // incomplete after all (a kill inside the checkpoint window), hash
          // it again rather than proving against nothing.
          if (!workerByPath.has(item.path)) await hashOne([item.path, item.file], entry.index);
          await uploadEntryChunks(sessionId, entry.index, item, BigInt(already), (step) => {
            sent += step;
            sentForNote = sent;
            stalledRounds = 0;
            fileSent += step;
            // Keep the reconciliation baseline current, so a later begin
            // corrects `sent` by the difference rather than re-adding the
            // server's prefix on top of what was already counted.
            counted.set(entry.index, fileSent);
            setMeter(totalBytes ? sent / totalBytes : 1);
            lastSendBps = sendRate(step);
            lastSendAt = performance.now();
            renderNote();
            setStatus(
              item.path,
              `${formatBytes(fileSent)} / ${formatBytes(item.file.size)}`,
              false,
              item.file.size ? fileSent / item.file.size : 1,
            );
          });
          // Every range was verified on arrival and the last one published
          // the file, so it is delivered even if the drop stops here.
          markDelivered(item);
        };
        for (let offset = 0; offset < entries.length; offset += UPLOADS_IN_FLIGHT) {
          const batch = entries.slice(offset, offset + UPLOADS_IN_FLIGHT);
          if (batch.every((entry) => items[entry.index].file.size <= chunkBytes)) {
            await runUploadBatch(batch, sendEntry);
          } else {
            for (const entry of batch) await sendEntry(entry);
          }
        }
        let report;
        try {
          report = await postWithRetry(`/api/session/${sessionId}/finish`, {});
        } catch (error) {
          // Coverage lost across a restart before any range reply carried
          // rebegin: the begin reply says where to resume. SessionError::bad
          // is 422, so the earlier check for 400 never matched.
          if (error.status === 422 && /not fully received/.test(error.message || '')) {
            error.rebegin = true;
          } else if (finishMayBeComplete(error)) {
            // The finish may have committed before its reply was lost; a
            // resend would re-hash every byte and land a second record. Keep
            // the resume record: the next begin reconciles against the
            // server's stored report, so the confirmation arrives without
            // resending bytes.
            error.mayComplete = true;
          }
          throw error;
        }
        delivered.push(...report.files);
        clearResume();
        return;
      } catch (error) {
        // Another sender's refusal can follow an earlier restart response.
        if (controller?.signal.aborted) {
          error = cancelled ? new Cancelled() : controller.signal.reason;
        }
        // A network failure or dead worker retries this same session;
        // partially written bytes stay on the server until it goes idle.
        if (error.cancelled) {
          await abortSession(sessionId);
          throw error;
        }
        if (error.mayComplete) {
          // Do not re-begin or abort a session that may have finished; the
          // record and the message below carry the reconciliation.
          throw error;
        }
        if (error.restart) {
          // The manifest phase cannot be replayed into the same session; the
          // abort records what did publish now and frees the link's slot.
          await abortSession(sessionId);
          sessionId = null;
          stalledRounds += 1;
          if (stalledRounds > 100) {
            throw new Error('Transfer kept pausing');
          }
          continue;
        }
        if (error.paused || error.rebegin) {
          // The pool may have died again while we were between proves.
          if (!hashWorkers.length && !recovering) recoverWorkers();
          if (workerFatal) throw workerFatal;
          stalledRounds += 1;
          if (stalledRounds > 100) {
            throw new Error('Transfer kept pausing');
          }
          continue;
        }
        if (error.status === 422 || error.status === 409 || error.sourceChanged) {
          // Refused for good: abort so the server records what did publish
          // now (a swept session would only do so after the idle timeout)
          // and the next send dedupes it instead of landing suffixed copies.
          await abortSession(sessionId);
        }
        throw error;
      }
    }
  }

  // Awaited, so a re-send within one round trip finds the partial record
  // the abort writes rather than landing suffixed copies.
  async function abortSession(sessionId) {
    if (sessionId) {
      // Bounded: a cancel pressed on a dead line must not hang on this.
      await fetch(`/api/session/${sessionId}/abort`, {
        method: 'POST',
        keepalive: true,
        // Chrome before 103 lacks the helper; a throw here would replace
        // the error being handled and skip clearResume.
        signal: globalThis.AbortSignal?.timeout?.(5000),
      }).catch(() => {});
    }
    clearResume();
  }

  // A delivered file's tree is no longer needed for proofs, and dropping it
  // keeps a worker-death recovery from re-hashing files already landed.
  function markDelivered(item) {
    setStatus(item.path, 'delivered \u2713', true);
    const worker = workerByPath.get(item.path);
    if (worker) {
      worker.postMessage({ op: 'drop', key: item.path });
      workerByPath.delete(item.path);
    }
  }

  $('progress-note').textContent = 'verifying files locally';
  setMeter(0);

  // The package root covers every file, so the drop cannot be announced
  // until the last file is hashed. Files hash in parallel, one lane per
  // worker; the lane number pins each file's tree to that lane's worker.
  // ponytail: hashing no longer overlaps sending, so hash time adds to wall
  // time (a tenth or less on typical client links); batch packages by bytes
  // if a measurement shows it on the wire.
  const items = new Array(files.length);
  let next = 0;
  const lane = async (laneIndex) => {
    for (;;) {
      const index = next;
      next += 1;
      if (index >= files.length) return;
      items[index] = await hashOne(files[index], laneIndex);
    }
  };
  await Promise.all(
    Array.from({ length: Math.max(1, hashWorkers.length) }, (_, laneIndex) => lane(laneIndex)),
  );
  await sendDrop(items);
  showDone({ files: delivered });
}

function showDone(report) {
  $('confirm-cancel').close('keep');
  const restoreFocus = $('progress-card').contains(document.activeElement)
    || $('upload-form').contains(document.activeElement);
  $('progress-card').hidden = true;
  $('upload-form').hidden = true;
  $('done-card').hidden = false;
  const bytes = report.files.reduce((sum, file) => sum + file.bytes, 0);
  const at = new Date().toLocaleString();
  const count = report.files.length;
  $('upload-status').textContent = `${count} file${count === 1 ? '' : 's'} shipped and verified.`;
  deliveredPaths = new Set(report.files.map((file) => file.path));
  const visible = Math.min(count, MAX_VISIBLE_FILE_ROWS);
  const preview = count > visible
    ? ` Showing first ${visible.toLocaleString()} of ${count.toLocaleString()} delivered files below.`
    : '';
  // The per-file identities below are what the server attested; the host
  // and time are the sender's own record of when it shipped.
  const summary = `${count} file${count === 1 ? '' : 's'} · ${formatBytes(bytes)} · delivered to ${window.location.host}, verified on receipt, ${at}.${preview}`;
  $('done-summary').textContent = summary;
  const proof = [
    summary,
    ...report.files.map((file) => `${file.path}  ${file.suite}:${file.root}`),
  ].join('\n');
  const copy = $('copy-proof');
  if (restoreFocus) copy.focus();
  copy.onclick = () => copyToClipboard(copy, proof);
  const list = $('done-list');
  list.replaceChildren();
  for (const file of report.files.slice(0, MAX_VISIBLE_FILE_ROWS)) {
    appendObjectCard(
      list,
      { name: file.path, suite: file.suite, root: file.root },
      {
        tag: 'li',
        rowClass: 'done',
        status: formatBytes(file.bytes) + (file.receipt ? ' · receipt ✓' : ''),
      },
    );
  }
}

// -------------------------------------------------------------------- wiring

$('cancel').addEventListener('click', () => {
  // Delivered files are tracked separately from visible rows, so hidden rows
  // still produce an honest cancellation summary.
  const delivered = deliveredPaths.size;
  $('confirm-cancel-detail').textContent = delivered
    ? `Files still in progress are discarded.${keptPhrase(delivered)}`
    : 'Files still in progress are discarded. Nothing already delivered is affected.';
  $('confirm-cancel').returnValue = 'keep';
  $('confirm-cancel').showModal();
});

$('confirm-cancel').addEventListener('close', () => {
  if ($('confirm-cancel').returnValue !== 'cancel') return;
  cancelled = true;
  controller?.abort(); // kills the request in flight rather than waiting it out
  stopWorkers(); // stops a hash mid-file instead of waiting for it to finish
});

$('pick').addEventListener('click', () => $('file-input').click());
$('pick-folder').addEventListener('click', () => $('folder-input').click());
$('folder-input').addEventListener('change', (event) => addFiles(event.target.files));
$('file-input').addEventListener('change', (event) => addFiles(event.target.files));
$('clear-files').addEventListener('click', () => {
  if (uploading) return;
  picked.clear();
  deliveredPaths.clear();
  $('file-input').value = '';
  $('folder-input').value = '';
  renderPicked();
});

const drop = $('drop');
// The whole zone is clickable; #pick has its own handler, so skip it here.
drop.addEventListener('click', (event) => {
  if (!event.target.closest('button')) $('file-input').click();
});
const carriesFiles = (event) => [...(event.dataTransfer?.types || [])].includes('Files');
for (const eventName of ['dragenter', 'dragover']) {
  document.addEventListener(eventName, (event) => {
    if ($('uploader').hidden || !carriesFiles(event)) return;
    event.preventDefault();
    drop.classList.add('hover');
  });
}
for (const eventName of ['dragleave', 'drop']) {
  document.addEventListener(eventName, (event) => {
    if (!carriesFiles(event)) return;
    if (eventName === 'dragleave' && event.relatedTarget) return;
    event.preventDefault();
    drop.classList.remove('hover');
  });
}
document.addEventListener('drop', async (event) => {
  if ($('uploader').hidden || !carriesFiles(event)) return;
  // Entries must be captured before the first await; the DataTransferItemList
  // is neutered as soon as the handler yields.
  const items = event.dataTransfer.items;
  const entries = items
    ? [...items].map((item) => item.getAsEntry?.() || item.webkitGetAsEntry?.()).filter(Boolean)
    : [];
  if (!entries.length) {
    addFiles(event.dataTransfer.files);
    return;
  }
  try {
    addNamed((await Promise.all(entries.map(entryFiles))).flat());
  } catch {
    fail('Could not read a dropped folder; use the folder picker instead.');
  }
});

window.addEventListener('beforeunload', (event) => {
  if (uploading && !reloading) event.preventDefault();
});

const gateError = fieldError($('link-password'), $('gate-error'));

$('gate-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  gateError.clear();
  const button = $('gate-continue');
  button.disabled = true;
  try {
    // Success sets an HttpOnly cookie server-side, so later visits (and the
    // session creation below) are authorized without keeping the password.
    await apiJson(`/api/r/${token}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: $('link-password').value }),
    });
    $('gate').hidden = true;
    $('uploader').hidden = false;
  } catch (error) {
    gateError.show(error.message);
    $('link-password').focus();
  } finally {
    button.disabled = false;
  }
});

$('upload-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (uploading || picked.size === 0) return;
  const total = [...picked.values()].reduce((sum, file) => sum + file.size, 0);
  const limitError = sizeLimitMessage(total);
  if (limitError) {
    fail(limitError);
    sizeLimitError = true;
    return;
  }
  uploading = true;
  cancelled = false;
  controller = new AbortController();
  startWorkers();
  keepAwake();
  setPhase('Preparing');
  if (document.activeElement === $('send')) $('cancel').focus();
  $('upload-status').textContent = '';
  $('send').disabled = true;
  $('clear-files').disabled = true;
  $('upload-error').hidden = true;
  // renderNote only runs from progress callbacks, so its staleness windows
  // never re-evaluate during a quiet stretch and the note freezes. A tick
  // bounded to the transfer keeps rate and time-left honest; the finally
  // below clears it on every end path.
  const noteTick = setInterval(renderNote, 1000);
  try {
    await runUpload();
  } catch (error) {
    // All range senders have settled; the build check needs a live signal.
    if (!cancelled && controller?.signal.aborted) controller = new AbortController();
    // Any failure but a deliberate cancel may be a stale tab after a deploy;
    // the reload only happens when the server's build hash actually differs.
    if (!error.cancelled) await reloadIfServerUpdated();
    // The server no longer holds the session, so the saved resume record is
    // useless; clearing it also hides the stale "held on the server" note and
    // keeps the advice below honest. A finish that may have committed is the
    // exception: the record is what the reload re-attaches to.
    const expired = error.status === 404
      || error.status === 410
      || /unknown or expired session/.test(error.message);
    if (expired && !error.mayComplete) clearResume();
    // Permanent refusals need corrected files, with any deliveries kept.
    const unverified = error.status === 422 || error.status === 409 || error.sourceChanged;
    const kept = deliveredPaths.size;
    const keptNote = keptPhrase(kept);
    fail(error.cancelled
      ? error.message
      : error.mayComplete
        ? `${error.message}.${keptNote} The transfer may have completed. Reload this page and reselect the same files to confirm.`
        : unverified
          ? `${error.message}.${keptNote} ${kept ? 'Fix the rest and send them again.' : 'Any files already delivered are kept. Fix the selection and send again.'}`
          : expired
            ? `${error.message}.${keptNote} The partial transfer was discarded, reselect the same files to send them again from the start.`
            : `${error.message}.${keptNote} Reselect the same files to resume where this stopped.`);
    $('confirm-cancel').close('keep');
    const restoreFocus = $('progress-card').contains(document.activeElement);
    $('progress-card').hidden = true;
    $('send').disabled = false;
    $('clear-files').disabled = false;
    if (restoreFocus) $('send').focus();
    showResumeNote();
  } finally {
    clearInterval(noteTick);
    uploading = false;
    controller = null;
    stopWorkers();
    releaseWakeLock();
  }
});

function showResumeNote() {
  // Expire records other tabs left behind before reading this tab's own, so
  // the note never speaks for a session no live sender holds.
  expireForeignResumes(token);
  const saved = loadResume();
  const note = $('resume-note');
  if (!saved) {
    note.hidden = true;
    return;
  }
  $('resume-detail').textContent = saved.path
    ? `${formatBytes(saved.size)} of "${saved.path}" is held on the server.`
    : `A ${saved.files === 1 ? 'file' : `${saved.files}-file request`} of ${formatBytes(saved.size)} is held on the server.`;
  note.hidden = false;
}

$('resume-discard').addEventListener('click', () => {
  clearResume();
  showResumeNote();
});

(async () => {
  // Only a definitive server answer (404/410, or usable:false below) means the
  // link is closed. Anything else — Caddy 502 while the container restarts, a
  // network blip — used to show the "Request closed" card and made senders
  // think their link died; retry those instead.
  let info;
  for (let attempt = 0; ; attempt += 1) {
    try {
      info = await apiJson(`/api/r/${token}`);
      break;
    } catch (error) {
      if (error.status === 404 || error.status === 410) {
        if (error.status === 404) {
          showClosed('Request not found', 'This link was not found. Check that the full URL was copied.');
        } else {
          showClosed('Request closed');
        }
        return;
      }
      if (attempt >= 4) {
        $('title').textContent = 'Request unavailable';
        document.title = 'VOTPort · Request unavailable';
        $('subtitle').textContent =
          'Could not reach the server. Reload the page to try again.';
        return;
      }
      $('subtitle').textContent = 'Connecting…';
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
  }
  if (!info.usable) {
    showClosed('Request closed');
    return;
  }
  document.title = `VOTPort · ${info.label}`;
  $('title').textContent = info.label;
  offerApp('r');
  $('subtitle').textContent = 'Files are verified on receipt.';
  applyBranding(info.branding, `/api/r/${token}/logo`);
  chunkBytes = info.chunk_bytes || chunkBytes;
  allowHidden = info.allow_hidden !== false;
  maxEntries = info.max_entries || maxEntries;
  maxBytes = Number.isFinite(info.max_bytes) ? info.max_bytes : null;
  webBuild = info.web_build || null;
  try {
    await init();
    proofLeafBytes = Number(proofLeafSize());
  } catch {
    $('subtitle').textContent =
      'This browser could not load the verification engine. It requires WebAssembly '
      + 'with SIMD and module workers: Safari 16.4, Chrome 91, Firefox 114 or newer.';
    return;
  }
  // Password first, always. Hashing is the expensive step and it happens
  // entirely in the browser, so revealing the drop zone before the password is
  // checked invites someone to spend an hour hashing and then get rejected.
  if (info.needs_password && !info.authorized) {
    $('gate').hidden = false;
    $('link-password').focus();
  } else {
    $('uploader').hidden = false;
  }
  showResumeNote();
})();
