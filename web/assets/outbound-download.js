// Pure helpers for the public separate-download flow.

export const FILE_RENDER_BATCH_SIZE = 100;
export const BATCH_DOWNLOAD_THRESHOLD = 100;
export const BATCH_LARGE_FILE_BYTES = 1024 ** 3;
export class BatchDownloadUnsupportedError extends Error {}

export function batchDownloadEligible(files) {
  return files.length >= BATCH_DOWNLOAD_THRESHOLD ||
    (files.length > 1 && files.some((file) => file.bytes >= BATCH_LARGE_FILE_BYTES));
}

export async function saveBatchFiles(response, directory, files, names, onComplete) {
  if (!response?.body) throw new BatchDownloadUnsupportedError('batch streaming unavailable');
  const contentType = response.headers?.get?.('content-type')?.split(';', 1)[0].trim().toLowerCase();
  if (contentType !== 'application/vnd.votport.batch') {
    throw new BatchDownloadUnsupportedError('unexpected batch content type');
  }
  if (!Array.isArray(files) || files.length !== names.length) throw new Error('batch metadata mismatch');
  const sizes = files.map((file) => file.bytes);
  if (sizes.some((bytes) => !Number.isSafeInteger(bytes) || bytes < 0)) {
    throw new Error('batch metadata has invalid file size');
  }
  const reader = response.body.getReader();
  let pending = new Uint8Array(); let pendingOffset = 0; let done = false;
  const nextBytes = async () => {
    while (pendingOffset >= pending.length && !done) {
      const result = await reader.read(); pending = result.value || new Uint8Array();
      pendingOffset = 0; done = Boolean(result.done);
    }
    return pendingOffset < pending.length ? pending.subarray(pendingOffset) : null;
  };
  try {
    for (let index = 0; index < files.length; index += 1) {
      const expected = sizes[index];
      const handle = await directory.getFileHandle(names[index], { create: true });
      const writable = await handle.createWritable();
      let remaining = expected;
      try {
        while (remaining) {
          const chunk = await nextBytes();
          if (!chunk) throw new Error('batch response truncated');
          const length = Math.min(chunk.length, remaining);
          await writable.write(chunk.subarray(0, length));
          pendingOffset += length;
          remaining -= length;
        }
        await writable.close();
      } catch (error) {
        await writable.abort().catch(() => {});
        throw error;
      }
      onComplete?.(index + 1, files.length);
    }
    if (await nextBytes()) throw new Error('batch response has trailing bytes');
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally {
    reader.releaseLock();
  }
}

// A failover (drain, stop, promote) takes minutes, not seconds; keep
// resuming for this much waiting before giving a file up. Time spent
// streaming does not count, so a long transfer keeps its retries.
export const SAVE_RETRY_BUDGET_MS = 10 * 60 * 1000;
export const SAVE_RETRY_CAP_MS = 8000;

// Streams file.download_url into an open writable, retrying transient
// failures with a byte-range resume so bytes already on disk are kept. A
// resume answered with 200 instead of 206 (a server that ignored the range)
// starts the file over. Retries run until options.retries attempts when
// given, otherwise until options.retryBudgetMs of backoff has been slept.
// A 401 or 403 mid-file means the authorization cookie stopped verifying
// (a failover that rotated the cookie secret); options.onAuthLost may
// restore it, and a true return resumes from the same offset. The caller
// closes or aborts the writable. fetchFn and sleep are injectable for tests.
export async function streamToWritable(fetchFn, writable, file, options = {}) {
  if (!Number.isSafeInteger(file.bytes) || file.bytes < 0) {
    throw new Error('invalid file size');
  }
  const retries = options.retries;
  const budgetMs = options.retryBudgetMs ?? SAVE_RETRY_BUDGET_MS;
  const sleep = options.sleep || ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  let waited = 0;
  let written = 0;
  let reauthorized = 0;
  for (let attempt = 0; ; attempt += 1) {
    try {
      const headers = written ? { Range: `bytes=${written}-` } : {};
      const response = await fetchFn(file.download_url, { credentials: 'same-origin', headers });
      if (!response.ok) await response.body?.cancel().catch(() => {});
      if (response.status >= 500 || response.status === 429) {
        throw Object.assign(new Error(`server returned ${response.status}`), { transient: true });
      }
      if ((response.status === 401 || response.status === 403) && options.onAuthLost && reauthorized < 2) {
        reauthorized += 1;
        if (await options.onAuthLost()) {
          attempt -= 1;
          continue;
        }
      }
      if (!response.ok) throw new Error(`server returned ${response.status}`);
      if (!response.body) throw new Error('browser cannot stream this response');
      if (response.status === 206) {
        const range = /^bytes (\d+)-(\d+)\/(\d+)$/.exec(response.headers.get('content-range'));
        if (!range || Number(range[1]) !== written || Number(range[2]) !== file.bytes - 1 ||
            Number(range[3]) !== file.bytes || written >= file.bytes) {
          await response.body.cancel().catch(() => {});
          throw new Error('download response has an invalid byte range');
        }
      } else if (response.status !== 200) {
        await response.body.cancel().catch(() => {});
        throw new Error(`unexpected download status ${response.status}`);
      }
      if (written && response.status !== 206) {
        await writable.truncate(0);
        written = 0;
      }
      const reader = response.body.getReader();
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          if (value.byteLength > file.bytes - written) {
            throw new Error('download response exceeds the file size');
          }
          await writable.write(value);
          written += value.byteLength;
        }
        if (written !== file.bytes) {
          throw Object.assign(new Error('download response truncated'), { transient: true });
        }
      } catch (error) {
        await reader.cancel().catch(() => {});
        throw error;
      } finally {
        reader.releaseLock();
      }
      return written;
    } catch (error) {
      const transient = error.transient || error instanceof TypeError;
      if (!transient) throw error;
      const delay = Math.min(500 * 2 ** Math.min(attempt, 10), SAVE_RETRY_CAP_MS);
      const exhausted = retries === undefined
        ? waited + delay > budgetMs
        : attempt + 1 >= retries;
      if (exhausted) throw error;
      waited += delay;
      await sleep(delay);
    }
  }
}

export function nextFileBatch(files, offset = 0) {
  const start = Math.max(0, Math.min(offset, files.length));
  return files.slice(start, start + FILE_RENDER_BATCH_SIZE);
}

export function metadataMoreAvailable(renderedCount, loadedCount, hasMore) {
  return renderedCount < loadedCount || hasMore;
}

export function appendMetadataPage(state, page) {
  if (!Number.isSafeInteger(page?.files_total) || page.files_total < 1) {
    throw new Error('invalid file metadata total');
  }
  if (!Number.isSafeInteger(page.offset) || page.offset !== state.files.length) {
    throw new Error('file metadata page offset changed');
  }
  if (!Number.isSafeInteger(page.limit) || page.limit < 1 ||
      !Array.isArray(page.files) ||
      page.files.length > page.limit) {
    throw new Error('invalid file metadata page');
  }
  if (state.total !== null && page.files_total !== state.total) {
    throw new Error('file metadata total changed');
  }
  if (page.offset + page.files.length > page.files_total) {
    throw new Error('invalid file metadata page');
  }
  const files = [...state.files, ...page.files];
  const urls = new Set(state.files.map((file) => file.download_url));
  for (const [index, file] of page.files.entries()) {
    const globalIndex = page.offset + index;
    const indexedUrls = typeof file?.download_url === 'string' &&
      typeof file?.receipt_url === 'string' &&
      file.download_url.endsWith(`/files/${globalIndex}`) &&
      file.receipt_url.endsWith(`/receipts/${globalIndex}`);
    const legacyUrl = globalIndex === 0 && typeof file?.download_url === 'string' &&
      typeof file?.receipt_url === 'string' && file.download_url.endsWith('/file') &&
      file.receipt_url.endsWith('/receipt');
    if (!file || typeof file.download_url !== 'string' || typeof file.receipt_url !== 'string' ||
        urls.has(file.download_url) ||
        (!indexedUrls && !legacyUrl)) {
      throw new Error('invalid or duplicate file metadata');
    }
    urls.add(file.download_url);
  }
  const hasMore = page.offset + page.files.length < page.files_total;
  if (page.has_more !== hasMore || (hasMore && page.files.length !== page.limit)) {
    throw new Error('file metadata page is incomplete');
  }
  return { files, total: page.files_total, hasMore };
}

export function publicMetadataPageUrl(token, offset = 0, limit = FILE_RENDER_BATCH_SIZE) {
  const query = new URLSearchParams({ offset: String(offset), limit: String(limit) });
  return `/api/s/${encodeURIComponent(token)}?${query}`;
}

export function sanitizeFilename(name) {
  let value = String(name ?? '').split(/[\\/]/).pop();
  value = value.replace(/[<>:"|?*\u0000-\u001f\u007f]/g, '_').trim();
  value = value.replace(/[. ]+$/g, '');
  if (!value || value === '.' || value === '..') value = 'download';
  if (/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i.test(value)) value = `_${value}`;
  return value;
}

export function dedupeFilenames(names) {
  const used = new Set();
  const nextSuffix = new Map();
  return names.map((name) => {
    const original = sanitizeFilename(name);
    const key = original.toLowerCase();
    const extensionIndex = original.lastIndexOf('.');
    const stem = extensionIndex > 0 ? original.slice(0, extensionIndex) : original;
    const extension = extensionIndex > 0 ? original.slice(extensionIndex) : '';
    let candidate = original;
    let suffix = nextSuffix.get(key) || 2;
    while (used.has(candidate.toLowerCase())) candidate = `${stem} (${suffix++})${extension}`;
    nextSuffix.set(key, suffix);
    used.add(candidate.toLowerCase());
    return candidate;
  });
}

export function summarizeFailures(failures, limit = 3) {
  const shown = failures.slice(0, limit);
  const remaining = failures.length - shown.length;
  return shown.join('; ') + (remaining > 0 ? `; and ${remaining} more` : '');
}

export async function runWorkerPool(items, worker, limit = 4, onComplete) {
  const values = [...items];
  const results = new Array(values.length);
  let next = 0;
  let completed = 0;
  const count = Math.max(1, Math.min(Number(limit) || 1, values.length || 1));
  async function run() {
    while (true) {
      const index = next++;
      if (index >= values.length) return;
      results[index] = await worker(values[index], index);
      completed += 1;
      onComplete?.(values[index], index, completed, values.length);
    }
  }
  await Promise.all(Array.from({ length: count }, run));
  return results;
}
