// votport uploader: hashes files with vot-wasm, builds a VOT package, and
// streams proven ranges to the server. AGPL-3.0-only.

import init, {
  ObjectBuilder,
  PackageBuilder,
  PackageEntry,
  PackagePath,
  Suite,
} from '/assets/vendor/vot_wasm.js';

const $ = (id) => document.getElementById(id);
const token = window.location.pathname.split('/').filter(Boolean).pop();

const HASH_READ_BYTES = 8 * 1024 * 1024;
let chunkBytes = 2 * 1024 * 1024;
let picked = new Map(); // relative path -> File
let uploading = false;

// ---------------------------------------------------------------- formatting

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  const exponent = Math.min(Math.floor(Math.log2(bytes) / 10), units.length - 1);
  const value = bytes / 2 ** (10 * exponent);
  return `${value >= 100 || exponent === 0 ? Math.round(value) : value.toFixed(1)} ${units[exponent]}`;
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
  if (uploading) return;
  for (const file of files) {
    const path = relativePath(file);
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

function renderPicked() {
  const list = $('file-list');
  list.replaceChildren();
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
  }
  $('totals').hidden = picked.size === 0;
  $('totals').textContent = `${picked.size} file(s), ${formatBytes(total)} total`;
  $('send').disabled = picked.size === 0;
}

function setStatus(path, text, done = false) {
  for (const item of $('file-list').children) {
    if (item.dataset.path === path) {
      item.querySelector('.status').textContent = text;
      item.classList.toggle('done', done);
    }
  }
}

// ------------------------------------------------------------------- network

async function apiJson(path, options = {}) {
  const response = await fetch(path, options);
  let body = null;
  try { body = await response.json(); } catch { /* not JSON */ }
  if (!response.ok) {
    throw new Error(body?.error || `request failed (${response.status})`);
  }
  return body;
}

async function postWithRetry(path, options, attempts = 3) {
  for (let attempt = 1; ; attempt += 1) {
    try {
      const response = await fetch(path, { method: 'POST', ...options });
      if (response.status >= 500 || response.status === 429) {
        throw new Error(`server busy (${response.status})`);
      }
      let body = null;
      try { body = await response.json(); } catch { /* not JSON */ }
      if (!response.ok) throw Object.assign(new Error(body?.error || `failed (${response.status})`), { fatal: true });
      return body;
    } catch (error) {
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

async function hashFile(file, onProgress) {
  const size = BigInt(file.size);
  const builder = new ObjectBuilder(Suite.Blake3Bao64, size, size);
  let offset = 0;
  while (offset < file.size) {
    const slice = file.slice(offset, Math.min(offset + HASH_READ_BYTES, file.size));
    const bytes = new Uint8Array(await slice.arrayBuffer());
    builder.update(bytes);
    offset += bytes.length;
    onProgress(bytes.length);
  }
  return builder.finish();
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
    const entry = PackageEntry.direct(packagePath, item.prepared.objectId);
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

async function uploadEntryChunks(sessionId, entryIndex, item, onProgress) {
  const { file, prepared } = item;
  let offset = 0n;
  const size = BigInt(file.size);
  while (offset < size) {
    const want = size - offset < BigInt(chunkBytes) ? size - offset : BigInt(chunkBytes);
    const proof = prepared.prove(offset, want);
    const coveredOffset = proof.coveredOffset;
    const coveredLength = proof.coveredLength;
    const start = Number(coveredOffset);
    const length = Number(coveredLength);
    const data = new Uint8Array(await file.slice(start, start + length).arrayBuffer());
    if (data.length !== length) {
      throw new Error(`"${item.path}" changed while uploading; pick it again`);
    }
    const proofBytes = proof.bytes();
    const body = new Uint8Array(proofBytes.length + data.length);
    body.set(proofBytes, 0);
    body.set(data, proofBytes.length);
    await postWithRetry(
      `/api/session/${sessionId}/chunk?entry=${entryIndex}&offset=${start}`,
      {
        headers: {
          'Content-Type': 'application/octet-stream',
          'X-Votport-Proof': String(proofBytes.length),
        },
        body,
      },
    );
    offset = coveredOffset + coveredLength;
    onProgress(length);
  }
}

async function runUpload() {
  const password = $('link-password').value;
  const files = [...picked.entries()];
  const totalBytes = files.reduce((sum, [, file]) => sum + file.size, 0);

  // Phase 1: hash everything locally.
  setPhase('Verifying files locally…', 'computing cryptographic identities');
  let hashed = 0;
  const items = [];
  for (const [path, file] of files) {
    setStatus(path, 'hashing…');
    const prepared = await hashFile(file, (step) => {
      hashed += step;
      setMeter(totalBytes ? hashed / totalBytes : 1);
    });
    const components = path.split('/');
    items.push({ path, components, file, prepared, key: pathKeyBytes(components) });
    setStatus(path, 'hashed');
  }

  // Phase 2: build the package manifest.
  const { summary, pages, seal } = buildPackage(items);
  const packageId = summary.objectId;
  const suite = packageId.suite === Suite.Blake3Bao64 ? 'blake3' : 'sha256';

  // Phase 3: announce, then stream the manifest.
  setPhase('Starting transfer…');
  setMeter(0);
  const session = await apiJson(`/api/r/${token}/session`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      password: password || null,
      package: {
        suite,
        root: [...packageId.root].map((byte) => byte.toString(16).padStart(2, '0')).join(''),
        length: Number(packageId.length),
      },
    }),
  });
  const sessionId = session.session;
  chunkBytes = session.chunk_bytes || chunkBytes;

  try {
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
    const { entries } = await postWithRetry(`/api/session/${sessionId}/begin`, {});

    // Phase 4: stream proven ranges.
    setPhase('Sending files…');
    const byPath = new Map(items.map((item) => [item.path, item]));
    let sent = 0;
    for (const entry of entries) {
      const item = byPath.get(entry.path);
      if (!item) throw new Error(`server listed unknown entry "${entry.path}"`);
      if (entry.complete) {
        setStatus(item.path, 'delivered ✓', true);
        continue;
      }
      setStatus(item.path, 'sending…');
      let fileSent = 0;
      await uploadEntryChunks(sessionId, entry.index, item, (step) => {
        sent += step;
        fileSent += step;
        setMeter(totalBytes ? sent / totalBytes : 1);
        setStatus(item.path, `${formatBytes(fileSent)} / ${formatBytes(item.file.size)}`);
      });
      setStatus(item.path, 'delivered ✓', true);
    }

    // Phase 5: finish.
    const report = await postWithRetry(`/api/session/${sessionId}/finish`, {});
    showDone(report);
  } catch (error) {
    fetch(`/api/session/${sessionId}/abort`, { method: 'POST' }).catch(() => {});
    throw error;
  }
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
    status.textContent = `${formatBytes(file.bytes)} · ${file.suite}:${file.root.slice(0, 12)}…`;
    item.append(name, status);
    list.append(item);
  }
}

// -------------------------------------------------------------------- wiring

$('pick').addEventListener('click', () => $('file-input').click());
$('file-input').addEventListener('change', (event) => addFiles(event.target.files));

const drop = $('drop');
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
drop.addEventListener('drop', (event) => addFiles(event.dataTransfer.files));

window.addEventListener('beforeunload', (event) => {
  if (uploading) event.preventDefault();
});

$('upload-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (uploading || picked.size === 0) return;
  uploading = true;
  $('send').disabled = true;
  $('upload-error').hidden = true;
  try {
    await runUpload();
  } catch (error) {
    fail(error.message);
    $('progress-card').hidden = true;
    $('send').disabled = false;
  } finally {
    uploading = false;
  }
});

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
  $('password-row').hidden = !info.needs_password;
  try {
    await init();
  } catch {
    $('subtitle').textContent = 'Could not load the verification engine (WebAssembly).';
    return;
  }
  $('uploader').hidden = false;
})();
