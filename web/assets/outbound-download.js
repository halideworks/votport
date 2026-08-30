// Pure helpers for the public separate-download flow.

export const MAX_ANCHOR_DOWNLOADS = 10;
export const FILE_RENDER_BATCH_SIZE = 100;

export function nextFileBatch(files, offset = 0) {
  const start = Math.max(0, Math.min(offset, files.length));
  return files.slice(start, start + FILE_RENDER_BATCH_SIZE);
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
