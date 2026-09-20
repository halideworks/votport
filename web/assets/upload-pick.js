// Pick admission for the request page: a huge selection admits in slices so
// the first preview rows paint without holding the main thread for the whole
// fold. DOM-free on purpose: upload.js wires the page, tests drive the seam
// directly. VOTPORT PROPRIETARY LICENSE.

// Preview page size: the first slice admits synchronously, so the first
// paint waits for the slice, never the whole pick.
export const PICK_FIRST_SLICE = 200;
// Roughly a frame of folding per idle slice at pick-test sizes; big enough
// that a 10k pick needs only a couple of idle yields to settle.
export const PICK_SLICE = 5000;

const utf8 = new TextEncoder();

// Idle slices keep the page responsive while the rest of the batch admits;
// rAF covers engines without idle callbacks, a timeout covers tests. The
// short idle timeout keeps slice pacing bounded on a busy main thread.
export function yieldSlice() {
  const idle = globalThis.requestIdleCallback;
  if (idle) return new Promise((resolve) => idle(() => resolve(), { timeout: 10 }));
  const frame = globalThis.requestAnimationFrame;
  if (frame) return new Promise((resolve) => frame(() => resolve()));
  return new Promise((resolve) => setTimeout(resolve, 0));
}

/// Admits a whole pick batch across slices: the first slice synchronously,
/// the rest after each `slice()` yield. Admission stays all-or-nothing like
/// the old synchronous path: a refusal rolls every entry this batch already
/// admitted back out, so the selection, its rows and the collision keys end
/// exactly as they began, with the refusal message shown by `fail`.
/// `render` paints after every slice; `settled` is false while the batch is
/// still growing, so the page can hold the send button until the final
/// render. Returns true when the whole batch was admitted.
export async function admitPickBatch(pairs, {
  picked, deliveredPaths, keys, validate, keyOf, render, fail,
  slice = yieldSlice, aborted = () => false,
}) {
  const undo = [];
  const admitSlice = (start, end) => {
    for (let index = start; index < end; index += 1) {
      const { path, file } = pairs[index];
      const components = path.split('/').filter(Boolean);
      for (const component of components) {
        const problem = validate(component);
        if (problem) return `"${path}": ${problem}`;
      }
      if (utf8.encode(components.at(-1) ?? '').length > 242) {
        return `"${path}": filename exceeds 242 UTF-8 bytes; shorten it to leave room for its signed receipt and receive journal`;
      }
      const key = keyOf(path, components);
      // One package holds the whole drop, so two names that fold to the
      // same key would be refused at the manifest; catch it before hashing.
      const other = keys.get(key);
      if (other !== undefined && other !== path) {
        return `"${other}" and "${path}" collide once case is folded; rename one`;
      }
      keys.set(key, path);
      undo.push({ path, prior: picked.get(path), wasDelivered: deliveredPaths.delete(path) });
      picked.set(path, file);
    }
    return null;
  };
  const rollback = () => {
    for (let index = undo.length - 1; index >= 0; index -= 1) {
      const { path, prior, wasDelivered } = undo[index];
      if (prior === undefined) picked.delete(path);
      else picked.set(path, prior);
      if (wasDelivered) deliveredPaths.add(path);
    }
  };
  for (let start = 0; ; ) {
    const end = Math.min(start + (start === 0 ? PICK_FIRST_SLICE : PICK_SLICE), pairs.length);
    const refusal = admitSlice(start, end);
    if (refusal) {
      rollback();
      render(true);
      fail(refusal);
      return false;
    }
    const settled = end >= pairs.length;
    render(settled);
    if (settled) return true;
    await slice();
    if (aborted()) return false;
    start = end;
  }
}
