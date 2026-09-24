// Browser file-entry traversal shared by the request and Deliver pages.

export function entryFiles(entry) {
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

const UPLOAD_CONCURRENCY = 8;

// Begin replies are compact: `total` counts every manifest entry and
// `entries` lists only the files the sender cannot infer (a renamed
// admission, progress, or completion); absence means admitted as requested
// with no progress.
export function expandBeginEntries(reply) {
  const entries = Array.from({ length: reply.total }, (_, index) => ({
    index, complete: false, covered_bytes: 0,
  }));
  for (const entry of reply.entries) entries[entry.index] = { ...entries[entry.index], ...entry };
  return entries;
}

export async function runUploadBatch(items, upload, onProgress = () => {}, onComplete = () => {}) {
  let next = 0;
  let completed = 0;
  let failed = false;
  let firstError;

  async function worker() {
    while (next < items.length && !failed) {
      const index = next++;
      const item = items[index];
      try {
        await upload(item, (value) => onProgress(item, value, completed, items.length));
        completed += 1;
        onComplete(item, completed, items.length);
      } catch (error) {
        if (!failed) {
          failed = true;
          firstError = error;
        }
      }
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(UPLOAD_CONCURRENCY, items.length) }, worker),
  );
  if (failed) throw firstError;
}

const LIBRARY_CHUNK_BYTES = 8 * 1024 * 1024;

// Hash fixed-size chunks into a chain so identification stays bounded in memory.
export async function libraryFileIdentity(file) {
  let digest = new Uint8Array(32);
  for (let offset = 0; offset < file.size; offset += LIBRARY_CHUNK_BYTES) {
    const bytes = new Uint8Array(await file.slice(offset, offset + LIBRARY_CHUNK_BYTES).arrayBuffer());
    if (bytes.length !== Math.min(LIBRARY_CHUNK_BYTES, file.size - offset)) throw new Error('The selected file could not be read completely. Select it again.');
    const input = new Uint8Array(digest.length + bytes.length);
    input.set(digest);
    input.set(bytes, digest.length);
    digest = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
  }
  return [...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

export async function uploadLibraryFile(file, path, progress = () => {}) {
  if (file.size === 0) {
    const response = await fetch(`/api/admin/outbound-files?path=${encodeURIComponent(path)}`, {
      method: 'POST',
      headers: { 'Content-Type': file.type || 'application/octet-stream', 'X-Votport': '1' },
      credentials: 'same-origin',
      body: file,
    });
    let body = null;
    try { body = await response.json(); } catch { /* empty error response */ }
    if (!response.ok) throw new Error(body?.error || `upload failed (${response.status})`);
    progress(0);
    return;
  }
  const uploadId = await libraryFileIdentity(file);
  const checkpoint = `votport-library-v1:${encodeURIComponent(path)}:${uploadId}`;
  let offset = 0;
  try {
    const saved = Number(sessionStorage.getItem(checkpoint));
    if (Number.isSafeInteger(saved) && saved > 0 && saved < file.size) offset = saved;
  } catch { /* storage unavailable; the upload can still start at zero */ }
  const remember = () => {
    try {
      if (offset === file.size) sessionStorage.removeItem(checkpoint);
      else sessionStorage.setItem(checkpoint, String(offset));
    } catch { /* upload retries in this selection remain available */ }
  };
  let rewinds = 0;
  while (offset < file.size) {
    const end = Math.min(offset + LIBRARY_CHUNK_BYTES, file.size);
    let retries = 0;
    while (true) {
      try {
        const response = await fetch(`/api/admin/outbound-files?path=${encodeURIComponent(path)}`, {
          method: 'POST',
          headers: {
            'Content-Type': file.type || 'application/octet-stream',
            'Content-Range': `bytes ${offset}-${end - 1}/${file.size}`,
            'X-Votport': '1',
            'X-Votport-Upload-Id': uploadId,
          },
          credentials: 'same-origin',
          body: file.slice(offset, end),
        });
        let body = null;
        try { body = await response.json(); } catch { /* empty error response */ }
        if (response.status === 409 && Number.isInteger(body?.offset)) {
          if (body.offset < 0 || body.offset >= file.size || body.offset === offset) throw new Error('server returned invalid upload offset');
          // Idle cleanup or failover can lose a stage; bound repeated loss
          // across successful chunks so a rewind cycle cannot run forever.
          if (body.offset < offset && ++rewinds > 3) throw new Error('server repeatedly lost upload progress');
          offset = body.offset;
          remember();
          progress(offset);
          break;
        }
        if (!response.ok) throw new Error(body?.error || `upload failed (${response.status})`);
        if (!Number.isInteger(body?.offset) || (body.offset !== end && body.offset !== file.size)) throw new Error('server returned invalid upload offset');
        offset = body.offset;
        remember();
        progress(offset);
        break;
      } catch (error) {
        if (rewinds > 3 || retries++ >= 3) throw error;
        await new Promise((resolve) => setTimeout(resolve, 200 * retries));
      }
    }
  }
}
