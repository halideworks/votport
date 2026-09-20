// Trailing debounce shared by the search inputs: every keystroke restarts
// the wait and drops the pending run, so fast typing fires one request
// shortly after the last key instead of one per keystroke. `schedule.cancel`
// retires a pending run without firing it. VOTPORT PROPRIETARY LICENSE.
export function searchDebounce(waitMs, run) {
  let timer = null;
  const schedule = () => {
    clearTimeout(timer);
    timer = setTimeout(run, waitMs);
  };
  schedule.cancel = () => clearTimeout(timer);
  return schedule;
}
