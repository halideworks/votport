// Share preparation progress: pure presentation for one preparation
// snapshot. The page polls /api/admin/outbound-grants/preparations/{id}
// and renders what this returns, so the state logic stays unit-testable
// and the DOM layer stays dumb. VOTPORT PROPRIETARY LICENSE.
import { formatBytes } from './object-card.js';

// A snapshot in flight: totals are unknown until the server's selection
// pass finishes, so the bar stays indeterminate until then.
export function preparationProgress(snapshot) {
  const files = count(snapshot.files_done, snapshot.files_total);
  if (snapshot.status === 'complete') {
    return { done: true, text: 'Delivery link ready.' };
  }
  if (snapshot.status === 'failed') {
    return { done: true, failed: true, text: snapshot.error || 'Preparing this link failed.' };
  }
  const present = (value) => value !== null && value !== undefined;
  const known = present(snapshot.files_total) && present(snapshot.bytes_total);
  const progress = `Hashing file ${files}`;
  if (!known) {
    return {
      indeterminate: true,
      text: `Preparing your delivery link… ${progress} so far. Large files can take a few minutes.`,
    };
  }
  const percent = snapshot.bytes_total > 0
    ? Math.min(100, Math.round(((snapshot.bytes_done ?? 0) / snapshot.bytes_total) * 100))
    : 100;
  return {
    indeterminate: false,
    percent,
    text: `${progress} · ${formatBytes(snapshot.bytes_done ?? 0)} of ${formatBytes(snapshot.bytes_total)} hashed`,
  };
}

function count(done, total) {
  return total !== null && total !== undefined ? `${done ?? 0} of ${total}` : `${done ?? 0}`;
}
