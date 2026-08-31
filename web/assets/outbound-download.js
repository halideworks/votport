// Pure helpers for the public separate-download flow.

export const MAX_ANCHOR_DOWNLOADS = 10;
export const FILE_RENDER_BATCH_SIZE = 100;
export const BATCH_DOWNLOAD_THRESHOLD = 100;
const ZIP_LOCAL_SIGNATURE = 0x04034b50;
const ZIP_CENTRAL_SIGNATURE = 0x02014b50;
const ZIP_END_SIGNATURE = 0x06054b50;
const ZIP64_END_SIGNATURE = 0x06064b50;
const ZIP64_END_LOCATOR_SIGNATURE = 0x07064b50;
const ZIP64_SENTINEL = 0xffffffff;
const ZIP64_EXTRA = 0x0001;
const MAX_ZIP_FIELD_BYTES = 64 * 1024;
export class StoredZipUnsupportedError extends Error {}
function zipUnsupported(message) {
  return new StoredZipUnsupportedError(message);
}
function integer(bytes, offset, size) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return size === 2 ? view.getUint16(offset, true) : view.getUint32(offset, true);
}
function uint64(bytes, offset) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const value = (BigInt(view.getUint32(offset + 4, true)) << 32n) | BigInt(view.getUint32(offset, true));
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw zipUnsupported('ZIP64 size exceeds browser limits');
  return Number(value);
}
function zip64Sizes(extra, compressed, uncompressed) {
  if (compressed !== ZIP64_SENTINEL && uncompressed !== ZIP64_SENTINEL) return { compressed, uncompressed };
  let offset = 0; let values = [];
  while (offset + 4 <= extra.length) {
    const kind = integer(extra, offset, 2); const length = integer(extra, offset + 2, 2);
    offset += 4; if (offset + length > extra.length) throw zipUnsupported('invalid ZIP extra field');
    if (kind === ZIP64_EXTRA) {
      if (length % 8 !== 0) throw zipUnsupported('invalid ZIP64 extra field');
      values = Array.from({ length: length / 8 }, (_, index) => uint64(extra, offset + index * 8));
      break;
    }
    offset += length;
  }
  let valueIndex = 0;
  const read = (value) => value !== ZIP64_SENTINEL ? value :
    valueIndex < values.length ? values[valueIndex++] : (() => { throw zipUnsupported('missing ZIP64 size'); })();
  return { uncompressed: read(uncompressed), compressed: read(compressed) };
}
function safeArchiveName(bytes) {
  let name;
  try { name = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
  catch { throw zipUnsupported('invalid ZIP filename'); }
  if (!name || name.endsWith('/') || name.includes('\u0000') || name.startsWith('/') ||
      name.startsWith('\\') || /^[A-Za-z]:[\\/]/.test(name) || name.split(/[\\/]/).includes('..')) {
    throw zipUnsupported('unsafe ZIP filename');
  }
}

class StreamBytes {
  constructor(body) {
    this.reader = body.getReader(); this.chunk = new Uint8Array();
    this.offset = 0; this.done = false;
  }

  async nextChunk() {
    while (this.offset >= this.chunk.length && !this.done) {
      const result = await this.reader.read(); this.chunk = result.value || new Uint8Array();
      this.offset = 0; this.done = Boolean(result.done);
    }
    return this.offset < this.chunk.length ? this.chunk.subarray(this.offset) : null;
  }

  async readExactly(length) {
    if (!Number.isSafeInteger(length) || length < 0 || length > MAX_ZIP_FIELD_BYTES) {
      throw zipUnsupported('ZIP field is too large');
    }
    const output = new Uint8Array(length); let offset = 0;
    while (offset < length) {
      const chunk = await this.nextChunk(); if (!chunk) throw zipUnsupported('truncated ZIP');
      const count = Math.min(chunk.length, length - offset);
      output.set(chunk.subarray(0, count), offset); this.offset += count; offset += count;
    }
    return output;
  }

  async consume(length, sink) {
    if (!Number.isSafeInteger(length) || length < 0) throw zipUnsupported('invalid ZIP size');
    let remaining = length;
    while (remaining) {
      const chunk = await this.nextChunk(); if (!chunk) throw zipUnsupported('truncated ZIP payload');
      const count = Math.min(chunk.length, remaining);
      await sink?.(chunk.subarray(0, count)); this.offset += count; remaining -= count;
    }
  }

  async cancel() {
    await this.reader.cancel().catch(() => {});
  }
}

function zipFields(bytes, central) {
  const flags = integer(bytes, central ? 4 : 6, 2); const method = integer(bytes, central ? 6 : 8, 2);
  if ((flags & ~0x800) !== 0) throw zipUnsupported('encrypted or streamed ZIP entry');
  if (method !== 0) throw zipUnsupported('compressed ZIP entry');
  const nameLength = integer(bytes, central ? 24 : 26, 2); const extraLength = integer(bytes, central ? 26 : 28, 2);
  if (nameLength > MAX_ZIP_FIELD_BYTES || extraLength > MAX_ZIP_FIELD_BYTES) {
    throw zipUnsupported('ZIP field is too large');
  }
  return { nameLength, extraLength, compressed: integer(bytes, central ? 16 : 18, 4), uncompressed: integer(bytes, central ? 20 : 22, 4) };
}

async function readStoredEntry(stream, directory, name, expectedBytes) {
  const header = await stream.readExactly(30);
  if (integer(header, 0, 4) !== ZIP_LOCAL_SIGNATURE) throw zipUnsupported('unsupported ZIP entry layout');
  const fields = zipFields(header, false);
  const nameBytes = await stream.readExactly(fields.nameLength);
  safeArchiveName(nameBytes);
  const extra = await stream.readExactly(fields.extraLength);
  const sizes = zip64Sizes(extra, fields.compressed, fields.uncompressed);
  if (sizes.compressed !== sizes.uncompressed || sizes.uncompressed !== expectedBytes) {
    throw zipUnsupported('ZIP entry size mismatch');
  }
  const handle = await directory.getFileHandle(name, { create: true });
  const writable = await handle.createWritable();
  try {
    await stream.consume(sizes.compressed, (chunk) => writable.write(chunk)); await writable.close();
  } catch (error) {
    await writable.abort().catch(() => {});
    throw error;
  }
  return sizes.uncompressed;
}

async function readCentralDirectory(stream, expectedSizes) {
  let centralCount = 0;
  while (true) {
    const signature = integer(await stream.readExactly(4), 0, 4);
    if (signature === ZIP_CENTRAL_SIGNATURE) {
      const header = await stream.readExactly(42);
      const fields = zipFields(header, true);
      const name = await stream.readExactly(fields.nameLength);
      safeArchiveName(name);
      const extra = await stream.readExactly(fields.extraLength);
      await stream.consume(integer(header, 28, 2));
      const sizes = zip64Sizes(extra, fields.compressed, fields.uncompressed);
      if (centralCount >= expectedSizes.length || sizes.compressed !== sizes.uncompressed || sizes.uncompressed !== expectedSizes[centralCount]) {
        throw zipUnsupported('ZIP central directory mismatch');
      }
      centralCount += 1;
      continue;
    }
    if (signature === ZIP_END_SIGNATURE) {
      await readZipEnd(stream, expectedSizes, centralCount, false);
      return;
    }
    if (signature === ZIP64_END_SIGNATURE) {
      const size = uint64(await stream.readExactly(8), 0); if (size < 44) throw zipUnsupported('invalid ZIP64 end record');
      const body = await stream.readExactly(44); await stream.consume(size - 44);
      if (integer(body, 4, 4) !== 0 || integer(body, 8, 4) !== 0 || uint64(body, 12) !== centralCount || uint64(body, 20) !== centralCount) {
        throw zipUnsupported('ZIP64 central directory count mismatch');
      }
      if (integer(await stream.readExactly(4), 0, 4) !== ZIP64_END_LOCATOR_SIGNATURE) throw zipUnsupported('invalid ZIP64 end locator');
      const locator = await stream.readExactly(16);
      if (integer(locator, 0, 4) !== 0 || integer(locator, 12, 4) !== 1) {
        throw zipUnsupported('invalid ZIP64 end locator');
      }
      if (integer(await stream.readExactly(4), 0, 4) !== ZIP_END_SIGNATURE) throw zipUnsupported('missing ZIP end record');
      await readZipEnd(stream, expectedSizes, centralCount, true); return;
    }
    throw zipUnsupported('unsupported ZIP central directory');
  }
}

async function readZipEnd(stream, expectedSizes, centralCount, zip64) {
  const end = await stream.readExactly(18);
  const entriesOnDisk = integer(end, 4, 2); const entriesTotal = integer(end, 6, 2);
  const countsMatch = zip64 ? entriesOnDisk === 0xffff && entriesTotal === 0xffff :
    entriesOnDisk === centralCount && entriesTotal === centralCount;
  if (integer(end, 0, 2) !== 0 || integer(end, 2, 2) !== 0 || !countsMatch) {
    throw zipUnsupported('ZIP central directory count mismatch');
  }
  await stream.consume(integer(end, 16, 2));
  if (centralCount !== expectedSizes.length || await stream.nextChunk()) throw zipUnsupported('ZIP entry count or trailing data mismatch');
}

export async function saveStoredZipFiles(response, directory, files, names, onComplete) {
  if (!response?.body) throw zipUnsupported('streaming ZIP response unavailable');
  if (!Array.isArray(files) || files.length !== names.length) throw new Error('batch metadata mismatch');
  const expectedSizes = files.map((file) => file.bytes);
  if (expectedSizes.some((bytes) => !Number.isSafeInteger(bytes) || bytes < 0)) {
    throw new Error('batch metadata has invalid file sizes');
  }
  const stream = new StreamBytes(response.body);
  let filesWritten = 0;
  try {
    for (let index = 0; index < files.length; index += 1) {
      await readStoredEntry(stream, directory, names[index], expectedSizes[index]);
      filesWritten += 1;
      onComplete?.(index + 1, files.length);
    }
    await readCentralDirectory(stream, expectedSizes);
  } catch (error) {
    await stream.cancel();
    if (error instanceof StoredZipUnsupportedError) error.filesWritten = filesWritten;
    throw error;
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
