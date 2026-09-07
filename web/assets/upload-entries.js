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
  // ponytail: cross-selection resume needs a content identity, not file metadata.
  const uploadId = [...globalThis.crypto.getRandomValues(new Uint8Array(32))]
    .map((byte) => byte.toString(16).padStart(2, '0')).join('');
  const chunkSize = 8 * 1024 * 1024;
  let offset = 0;
  while (offset < file.size) {
    const end = Math.min(offset + chunkSize, file.size);
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
          if (body.offset < 0 || body.offset > file.size) throw new Error('server returned invalid upload offset');
          offset = body.offset;
          progress(offset);
          break;
        }
        if (!response.ok) throw new Error(body?.error || `upload failed (${response.status})`);
        // `file.size` after any chunk: the stage already held the whole file
        // (a last chunk whose reply was lost) and the server has published it.
        if (!Number.isInteger(body?.offset) || (body.offset !== end && body.offset !== file.size)) throw new Error('server returned invalid upload offset');
        offset = body.offset;
        progress(offset);
        break;
      } catch (error) {
        if (retries++ >= 3) throw error;
        await new Promise((resolve) => setTimeout(resolve, 200 * retries));
      }
    }
  }
}
