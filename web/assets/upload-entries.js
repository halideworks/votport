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
