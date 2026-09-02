// Deferred actions with an undo window. VOTPORT PROPRIETARY LICENSE.
//
// An action is applied to the page at once and committed to the server only
// when its window closes; Undo inside the window restores the page and never
// calls the server. Timers are injected so the scheduler is testable.

export function createUndoQueue({
  delayMs = 6000,
  setTimer = (fn, ms) => setTimeout(fn, ms),
  clearTimer = (id) => clearTimeout(id),
} = {}) {
  const pending = new Set();

  function add({ commit, restore = () => {}, onSettled = () => {} }) {
    const entry = { commit, restore, onSettled, timer: null, done: false };
    const settle = async (committed) => {
      if (entry.done) return;
      entry.done = true;
      clearTimer(entry.timer);
      pending.delete(entry);
      if (committed) {
        try {
          await commit();
        } finally {
          onSettled(true);
        }
      } else {
        restore();
        onSettled(false);
      }
    };
    entry.timer = setTimer(() => { settle(true); }, delayMs);
    pending.add(entry);
    return {
      undo: () => settle(false),
      commitNow: () => settle(true),
    };
  }

  /// Commits everything still waiting, for page unload.
  function flush() {
    const entries = [...pending];
    return Promise.all(entries.map((entry) => {
      if (entry.done) return null;
      entry.done = true;
      clearTimer(entry.timer);
      pending.delete(entry);
      return Promise.resolve(entry.commit()).finally(() => entry.onSettled(true));
    }));
  }

  return { add, flush, get size() { return pending.size; } };
}
