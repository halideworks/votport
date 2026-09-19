// Delete stored files: the paging DELETE loop for the receive page.
// VOTPORT PROPRIETARY LICENSE.
//
// Audit finding 533: the loop used to live inline in page-receive.js issuing
// one DELETE per file with no progress and no way to stop, and its error path
// re-fetched the whole link list before rethrowing. The request sequence
// lives here so paging, progress and stop checks are unit-tested; the page
// wires it to a button that doubles as the Stop control.

// Pages through an upload's file list, deletes every stored file, reports
// progress after each deletion, and stops between requests when asked.
// Already-gone files are skipped and not counted; `upload.file_count` is the
// progress denominator. Resolves with { stopped, done }; stopping is a
// result, never an error.
export async function deleteStoredFiles({
  upload,
  fetchPage,
  deleteFile,
  onProgress = () => {},
  shouldStop = () => false,
}) {
  let done = 0;
  let offset = 0;
  do {
    if (shouldStop()) return { stopped: true, done };
    const page = await fetchPage(offset);
    if (page.file_count !== upload.file_count) {
      throw new Error('Transfer history changed. Review the files before deleting them.');
    }
    for (const file of page.files) {
      if (shouldStop()) return { stopped: true, done };
      if (!file.exists) continue;
      await deleteFile(file.file_index);
      done += 1;
      onProgress(done, page.file_count);
    }
    offset = page.next_offset;
  } while (offset !== null);
  return { stopped: false, done };
}
