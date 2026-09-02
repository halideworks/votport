// Segment plan for hashing one file across the worker pool.
// VOTPORT PROPRIETARY LICENSE.
//
// Proof leaves depend only on their bytes and their offset, so a file can be
// hashed in independent segments and the leaves joined in order. Every
// segment but the last must be a whole number of leaves, so segment starts
// are leaf multiples and only the file's tail may be short.

/// Contiguous [start, end) ranges covering `size` exactly. One range when the
/// file is too small to be worth splitting or the pool has one worker.
export function segments(size, leafSize, workers, minSegment) {
  if (size <= 0) return [];
  if (workers < 2 || size < 2 * minSegment) return [[0, size]];
  const count = Math.min(workers, Math.floor(size / minSegment));
  const leaves = Math.ceil(size / leafSize);
  const perSegment = Math.ceil(leaves / count) * leafSize;
  const out = [];
  for (let start = 0; start < size; start += perSegment) {
    out.push([start, Math.min(start + perSegment, size)]);
  }
  return out;
}
