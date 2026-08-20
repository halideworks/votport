// votport uploader: hashes files with vot-wasm, builds a VOT package, and
// streams proven ranges to the server. AGPL-3.0-only.

import init, {
  ObjectId,
  PackageBuilder,
  PackageEntry,
  PackagePath,
  Suite,
} from '/assets/vendor/vot_wasm.js';

const $ = (id) => document.getElementById(id);
const token = window.location.pathname.split('/').filter(Boolean).pop();

const UPLOADS_IN_FLIGHT = 8;
let chunkBytes = 2 * 1024 * 1024;
let picked = new Map(); // relative path -> File
let uploading = false;
let cancelled = false;
let controller = null; // aborts in-flight requests when the sender cancels

// Hash this many files ahead of the one being uploaded; they hash in parallel
// across the worker pool, and the gate keeps the finished merkle trees pinned
// in worker memory bounded.
const LOOKAHEAD = 2;

// ------------------------------------------------------------- hash workers
// Hashing and the merkle trees live in workers so the page stays responsive
// and hashing genuinely overlaps upload bookkeeping. Each file's tree stays
// in the worker that hashed it, which also serves its range proofs. The pool
// hashes up to LOOKAHEAD+1 files in parallel — the lookahead gate already
// caps how many files may be ahead of the upload cursor.

let hashWorkers = [];
const workerByPath = new Map(); // path -> the worker holding its tree
const workerRequests = new Map(); // req -> {resolve, reject, onStep}
let nextRequest = 0;

function startWorkers() {
  const count = Math.min(LOOKAHEAD + 1, Math.max(1, (navigator.hardwareConcurrency || 2) - 1));
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
      if (data.error !== undefined) pending.reject(new Error(data.error));
      else pending.resolve(data.done);
    };
    worker.onerror = () => stopWorkers(new Error('a hash worker failed'));
    return worker;
  });
}

// 'hash' pins the file's tree to a worker; 'prove' and 'drop' follow it.
function workerFor(message, index) {
  if (message.op === 'hash') {
    const worker = hashWorkers[index % hashWorkers.length];
    workerByPath.set(message.key, worker);
    return worker;
  }
  return workerByPath.get(message.key);
}

function workerCall(message, index = 0, onStep = null) {
  return new Promise((resolve, reject) => {
    const worker = hashWorkers.length ? workerFor(message, index) : null;
    if (!worker) {
      reject(new Cancelled());
      return;
    }
    const req = nextRequest;
    nextRequest += 1;
    workerRequests.set(req, { resolve, reject, onStep });
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

class Cancelled extends Error {
  constructor() {
    super('Transfer cancelled.');
    this.cancelled = true;
  }
}

function checkCancelled() {
  if (cancelled) throw new Cancelled();
}

// A record of the session currently in flight, so an interrupted transfer can
// re-attach to it instead of re-sending bytes the server already verified.
// Cleared on success and on cancel, kept on failure — failure is the case it
// exists for. The server sweeps the session itself once it goes idle.
const RESUME_KEY = `votport-resume-${token}`;

function saveResume(record) {
  try { localStorage.setItem(RESUME_KEY, JSON.stringify(record)); } catch { /* private mode */ }
}

function loadResume() {
  try { return JSON.parse(localStorage.getItem(RESUME_KEY) || 'null'); } catch { return null; }
}

function clearResume() {
  try { localStorage.removeItem(RESUME_KEY); } catch { /* private mode */ }
}

// The verified-password cookie replaced the plaintext copy an earlier build
// kept in localStorage; scrub any leftover.
try { localStorage.removeItem(`votport-pass-${token}`); } catch { /* private mode */ }

function hex(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

// ---------------------------------------------------------------- formatting

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  const exponent = Math.min(Math.floor(Math.log2(bytes) / 10), units.length - 1);
  const value = bytes / 2 ** (10 * exponent);
  return `${value >= 100 || exponent === 0 ? Math.round(value) : value.toFixed(1)} ${units[exponent]}`;
}

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

// Decimal units here, unlike the binary units used for sizes: transfer rates
// are quoted decimally everywhere else a sender will compare them.
function formatRate(bytesPerSecond) {
  if (bytesPerSecond === null) return '';
  const units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
  let value = bytesPerSecond;
  let unit = 0;
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000;
    unit += 1;
  }
  return `${value >= 100 || unit === 0 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
}

function fail(message) {
  $('upload-error').textContent = message;
  $('upload-error').hidden = false;
}

// ------------------------------------------------- portable path validation
// Mirrors VOT's portable path profile (vot-manifest) so problems surface
// before hashing starts. The server re-checks everything.

const FORBIDDEN = new RegExp(
  '[\\x00-\\x1f/\\\\<>:"|?*\\u200c\\u200d\\u202a-\\u202e\\u2066-\\u2069\\ufeff]',
  'u',
);
const utf8 = new TextEncoder();

function fold(component) {
  let folded = '';
  for (const character of component.normalize('NFC')) {
    if (character === 'I' || character === 'i' || character === 'İ' || character === 'ı') {
      folded += 'i';
    } else {
      folded += character.toLowerCase();
    }
  }
  return folded.normalize('NFC');
}

function validateComponent(component) {
  if (!component || utf8.encode(component).length > 255) {
    return 'name is empty or longer than 255 bytes';
  }
  if (FORBIDDEN.test(component)) {
    return 'name contains a character that does not travel well (\\ / < > : " | ? * or control characters)';
  }
  if (component.endsWith('.') || component.endsWith(' ')) {
    return 'name may not end with a dot or space';
  }
  const compatibility = component.normalize('NFKC');
  if (compatibility === '.' || compatibility === '..') return 'name is a directory reference';
  const folded = fold(component);
  if (folded === '' || folded === '.' || folded === '..') return 'name is a directory reference';
  const stem = folded.split('.')[0];
  if (/^(con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³])$/.test(stem)) {
    return `"${stem}" is a reserved device name on Windows`;
  }
  return null;
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

// Collects every file under a dropped directory entry, keeping its path.
function entryFiles(entry) {
  return new Promise((resolve, reject) => {
    if (entry.isFile) {
      entry.file(
        (file) => resolve([{ path: entry.fullPath.replace(/^\//, ''), file }]),
        reject,
      );
    } else if (entry.isDirectory) {
      const reader = entry.createReader();
      const children = [];
      // readEntries returns at most ~100 entries per call; drain it.
      const drain = () => reader.readEntries(async (batch) => {
        if (batch.length) {
          children.push(...batch);
          drain();
          return;
        }
        try {
          resolve((await Promise.all(children.map(entryFiles))).flat());
        } catch (error) {
          reject(error);
        }
      }, reject);
      drain();
    } else {
      resolve([]);
    }
  });
}

function addNamed(pairs) {
  if (uploading) return;
  for (const { path, file } of pairs) {
    const components = path.split('/').filter(Boolean);
    for (const component of components) {
      const problem = validateComponent(component);
      if (problem) {
        fail(`"${path}": ${problem}`);
        return;
      }
    }
    picked.set(components.join('/'), file);
  }
  $('upload-error').hidden = true;
  renderPicked();
}

// path -> its list row, so per-chunk status updates skip the O(files) scan.
let rows = new Map();

function renderPicked() {
  const list = $('file-list');
  list.replaceChildren();
  rows = new Map();
  let total = 0;
  for (const [path, file] of picked) {
    total += file.size;
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
  $('totals').hidden = picked.size === 0;
  $('totals').textContent = `${picked.size} file(s), ${formatBytes(total)} total`;
  $('send').disabled = picked.size === 0;
}

function setStatus(path, text, done = false) {
  const item = rows.get(path);
  if (!item) return;
  item.querySelector('.status').textContent = text;
  item.classList.toggle('done', done);
}

// ------------------------------------------------------------------- network

async function apiJson(path, options = {}) {
  const response = await fetch(path, { signal: controller?.signal, ...options });
  let body = null;
  try { body = await response.json(); } catch { /* not JSON */ }
  if (!response.ok) {
    throw new Error(body?.error || `request failed (${response.status})`);
  }
  return body;
}

async function postWithRetry(path, options, attempts = 3) {
  for (let attempt = 1; ; attempt += 1) {
    checkCancelled();
    try {
      const response = await fetch(path, {
        method: 'POST',
        signal: controller?.signal,
        ...options,
      });
      if (response.status >= 500 || response.status === 429) {
        throw new Error(`server busy (${response.status})`);
      }
      let body = null;
      try { body = await response.json(); } catch { /* not JSON */ }
      if (!response.ok) throw Object.assign(new Error(body?.error || `failed (${response.status})`), { fatal: true });
      return body;
    } catch (error) {
      if (cancelled) throw new Cancelled();
      if (error.fatal || attempt >= attempts) throw error;
      await new Promise((resolve) => { setTimeout(resolve, 1000 * attempt); });
    }
  }
}

// ------------------------------------------------------------------- phases

function setPhase(text, note = '') {
  $('progress-card').hidden = false;
  $('phase').textContent = text;
  $('progress-note').textContent = note;
}

function setMeter(fraction) {
  $('meter-fill').style.width = `${Math.min(100, Math.round(fraction * 100))}%`;
}

function setNote(done, total, bytesPerSecond) {
  const parts = [`${formatBytes(done)} of ${formatBytes(total)}`];
  const rate = formatRate(bytesPerSecond);
  if (rate) {
    parts.push(rate);
    const remaining = total - done;
    if (remaining > 0 && bytesPerSecond > 0) {
      parts.push(`${formatDuration(remaining / bytesPerSecond)} left`);
    }
  }
  $('progress-note').textContent = parts.join(' · ');
}

function formatDuration(seconds) {
  if (seconds < 60) return `${Math.ceil(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  return `${Math.floor(seconds / 3600)}h ${Math.round((seconds % 3600) / 60)}m`;
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
          throw new Error('a proof covered an unexpected range; retry the upload');
        }
        const data = new Uint8Array(await file.slice(start, start + length).arrayBuffer());
        if (data.length !== length) {
          throw new Error(`"${item.path}" changed while uploading; pick it again`);
        }
        const body = new Uint8Array(proof.bytes.length + data.length);
        body.set(proof.bytes, 0);
        body.set(data, proof.bytes.length);
        await postWithRetry(
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
      } catch (error) {
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
  let hashed = 0;
  let sent = 0;
  const delivered = [];

  async function hashOne([path, file], index) {
    checkCancelled();
    const components = path.split('/');
    let fileHashed = 0;
    setStatus(path, 'hashing 0%');
    const done = await workerCall({ op: 'hash', key: path, file }, index, (step) => {
      hashed += step;
      fileHashed += step;
      const rate = hashRate(step);
      setStatus(path, `hashing ${Math.floor((fileHashed / (file.size || 1)) * 100)}%`);
      // Before the first upload starts there is no send rate to show, so the
      // note reports what is actually happening: local hashing throughput.
      if (sent === 0) {
        $('progress-note').textContent =
          [`verifying ${formatBytes(hashed)} of ${formatBytes(totalBytes)}`, formatRate(rate)]
            .filter(Boolean)
            .join(' \u00b7 ');
      }
    });
    setStatus(path, 'ready');
    const objectId = new ObjectId(done.suite, done.root, done.length);
    return { path, components, file, objectId, key: pathKeyBytes(components) };
  }

  async function sendOne(item, position) {
    // One VOT package per file. A package root is a hash over every entry it
    // contains, so a batch package cannot be announced until the last file is
    // hashed — which is precisely what would prevent overlapping hashing with
    // uploading. Per file, each package is announced the moment its own file
    // is ready, and anything already delivered stays delivered if a later
    // file fails.
    const { summary, pages, seal } = buildPackage([item]);
    const packageId = summary.objectId;
    const rootHex = hex(packageId.root);
    const suite = packageId.suite === Suite.Blake3Bao64 ? 'blake3' : 'sha256';
    setPhase(`Sending ${position} of ${files.length}`);

    // Re-attach to an interrupted session for this exact file. The root is
    // part of the match, so a file edited since the interruption starts over
    // rather than failing deep inside range verification.
    const saved = loadResume();
    const resume = saved && saved.root === rootHex && saved.path === item.path
      ? saved
      : null;
    let sessionId = resume?.session || null;
    let entries = null;
    if (sessionId) {
      try {
        ({ entries } = await postWithRetry(`/api/session/${sessionId}/begin`, {}, 1));
        setStatus(item.path, 'resuming…');
        // Keep the interrupted run's chunk grid: a different chunk size would
        // straddle extents the server already accepted and be rejected as
        // partial overlaps.
        chunkBytes = resume.chunk || chunkBytes;
      } catch (error) {
        if (error.cancelled) throw error;
        sessionId = null; // session swept or server restarted; start over
      }
    }
    if (!sessionId) {
      const session = await apiJson(`/api/r/${token}/session`, {
        method: 'POST',
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
        path: item.path,
        size: item.file.size,
        root: rootHex,
        chunk: chunkBytes,
      });
      await postWithRetry(`/api/session/${sessionId}/seal`, {
        headers: { 'Content-Type': 'application/octet-stream' },
        body: seal,
      });
      for (const page of pages) {
        await postWithRetry(`/api/session/${sessionId}/page`, {
          headers: { 'Content-Type': 'application/octet-stream' },
          body: page,
        });
      }
      ({ entries } = await postWithRetry(`/api/session/${sessionId}/begin`, {}));
    }

    try {
      for (const entry of entries) {
        // covered_bytes is the server's contiguous verified prefix, so it is
        // safe to restart from even when chunks landed out of order.
        const already = entry.complete
          ? item.file.size
          : Math.min(entry.covered_bytes ?? 0, item.file.size);
        sent += already;
        if (entry.complete) {
          setMeter(totalBytes ? sent / totalBytes : 1);
          continue;
        }
        let fileSent = already;
        await uploadEntryChunks(sessionId, entry.index, item, BigInt(already), (step) => {
          sent += step;
          fileSent += step;
          setMeter(totalBytes ? sent / totalBytes : 1);
          setNote(sent, totalBytes, sendRate(step));
          setStatus(item.path, `${formatBytes(fileSent)} / ${formatBytes(item.file.size)}`);
        });
      }
      const report = await postWithRetry(`/api/session/${sessionId}/finish`, {});
      delivered.push(...report.files);
      clearResume();
      workerByPath.get(item.path)?.postMessage({ op: 'drop', key: item.path }); // frees the tree
      setStatus(item.path, 'delivered \u2713', true);
    } catch (error) {
      // Only a deliberate cancel throws the session away. A network failure is
      // precisely what the resume record exists for, so it is left in place
      // and the partially written bytes stay on the server until it goes idle.
      if (error.cancelled) {
        fetch(`/api/session/${sessionId}/abort`, { method: 'POST' }).catch(() => {});
        clearResume();
      }
      throw error;
    }
  }

  setPhase('Preparing', 'verifying the first file locally');
  setMeter(0);

  // Hashing runs ahead of uploading by up to LOOKAHEAD files, and those files
  // hash in parallel across the worker pool. The gate keeps hashing from
  // running further ahead than that and pinning many finished merkle trees in
  // worker memory at once.
  const uploaded = files.map(() => {
    let release;
    return { promise: new Promise((resolve) => { release = resolve; }), release };
  });
  const hashes = files.map((entry, index) => {
    const gate = index >= LOOKAHEAD ? uploaded[index - LOOKAHEAD].promise : Promise.resolve();
    return gate.then(() => hashOne(entry, index));
  });
  // Each is awaited in order below; this only stops the ones after a failure
  // from being reported as unhandled rejections.
  hashes.forEach((promise) => { promise.catch(() => {}); });

  for (let index = 0; index < files.length; index += 1) {
    const item = await hashes[index];
    try {
      await sendOne(item, index + 1);
    } catch (error) {
      if (delivered.length) {
        error.message += ` — ${delivered.length} file(s) already delivered and kept`;
      }
      throw error;
    }
    uploaded[index].release();
  }
  showDone({ files: delivered });
}

function showDone(report) {
  $('progress-card').hidden = true;
  $('upload-form').hidden = true;
  $('done-card').hidden = false;
  const list = $('done-list');
  list.replaceChildren();
  for (const file of report.files) {
    const item = document.createElement('li');
    item.className = 'done';
    const name = document.createElement('span');
    name.textContent = file.path;
    const status = document.createElement('span');
    status.className = 'status';
    status.textContent = formatBytes(file.bytes) + (file.receipt ? ' · receipt ✓' : '');
    const id = document.createElement('div');
    id.className = 'mono muted file-id';
    id.textContent = `${file.suite}:${file.root}`;
    item.append(name, status, id);
    list.append(item);
  }
}

// -------------------------------------------------------------------- wiring

$('cancel').addEventListener('click', () => {
  // Delivered rows are marked .done in the staged list as each file lands;
  // #done-list only exists after the whole transfer finishes.
  const delivered = $('file-list').querySelectorAll('.done').length;
  const kept = delivered === 1
    ? 'The one already delivered is kept.'
    : `The ${delivered} already delivered are kept.`;
  $('confirm-cancel-detail').textContent = delivered
    ? `The file in progress is discarded. ${kept}`
    : 'The file in progress is discarded. Nothing already delivered is affected.';
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

const drop = $('drop');
// The whole zone is clickable; #pick has its own handler, so skip it here.
drop.addEventListener('click', (event) => {
  if (!event.target.closest('button')) $('file-input').click();
});
for (const eventName of ['dragenter', 'dragover']) {
  drop.addEventListener(eventName, (event) => {
    event.preventDefault();
    drop.classList.add('hover');
  });
}
for (const eventName of ['dragleave', 'drop']) {
  drop.addEventListener(eventName, (event) => {
    event.preventDefault();
    drop.classList.remove('hover');
  });
}
drop.addEventListener('drop', async (event) => {
  // Entries must be captured before the first await; the DataTransferItemList
  // is neutered as soon as the handler yields.
  const items = event.dataTransfer.items;
  const entries = items
    ? [...items].map((item) => item.webkitGetAsEntry?.()).filter(Boolean)
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
  if (uploading) event.preventDefault();
});

$('gate-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('gate-error').hidden = true;
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
    $('gate-error').textContent = error.message;
    $('gate-error').hidden = false;
  } finally {
    button.disabled = false;
  }
});

$('upload-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (uploading || picked.size === 0) return;
  uploading = true;
  cancelled = false;
  controller = new AbortController();
  startWorkers();
  $('send').disabled = true;
  $('upload-error').hidden = true;
  try {
    await runUpload();
  } catch (error) {
    fail(error.cancelled
      ? error.message
      : `${error.message} — reselect the same files to resume where this stopped.`);
    $('progress-card').hidden = true;
    $('send').disabled = false;
    showResumeNote();
  } finally {
    uploading = false;
    controller = null;
    stopWorkers();
  }
});

function showResumeNote() {
  const saved = loadResume();
  const note = $('resume-note');
  if (!saved) {
    note.hidden = true;
    return;
  }
  note.textContent =
    `An interrupted transfer of "${saved.path}" is held on the server. `
    + 'Select the same file again and it continues from where it stopped, '
    + 'as long as it has not been left idle too long.';
  note.hidden = false;
}

(async () => {
  let info;
  try {
    info = await apiJson(`/api/r/${token}`);
  } catch {
    $('closed').hidden = false;
    return;
  }
  if (!info.usable) {
    $('closed').hidden = false;
    return;
  }
  $('title').textContent = info.label;
  chunkBytes = info.chunk_bytes || chunkBytes;
  try {
    await init();
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
