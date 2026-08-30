// Pure helpers for the public separate-download flow.

export const MAX_ANCHOR_DOWNLOADS = 10;
export const FILE_RENDER_BATCH_SIZE = 100;

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

export function anchorDownloadsAllowed(count) {
  return count <= MAX_ANCHOR_DOWNLOADS;
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
  return names.map((name) => {
    const original = sanitizeFilename(name);
    const extensionIndex = original.lastIndexOf('.');
    const stem = extensionIndex > 0 ? original.slice(0, extensionIndex) : original;
    const extension = extensionIndex > 0 ? original.slice(extensionIndex) : '';
    let candidate = original;
    let suffix = 2;
    while (used.has(candidate.toLowerCase())) candidate = `${stem} (${suffix++})${extension}`;
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
