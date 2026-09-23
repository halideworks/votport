// Delivery preparation progress and workflow action eligibility.
// VOTPORT PROPRIETARY LICENSE.
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

// Polls one preparation to completion, rendering each in-flight snapshot
// through `render`; a failed preparation throws the server's reason. The long ceiling matches the job's own idea
// of a few minutes for big libraries; the 15-minute server TTL only
// applies after a preparation reaches a terminal state.
export async function pollDeliverPreparation(id, render, api) {
  const deadline = Date.now() + 15 * 60 * 1000;
  for (;;) {
    const snapshot = await api(
      `/api/admin/outbound-grants/preparations/${encodeURIComponent(id)}`,
    );
    if (snapshot.status === 'failed') throw new Error(preparationProgress(snapshot).text);
    if (snapshot.status !== 'preparing') return snapshot;
    render(snapshot);
    await new Promise((resolve) => setTimeout(resolve, 400));
    if (Date.now() > deadline) {
      throw new Error(
        'Preparing this link is taking unusually long. Keep the page open; the link also appears in Delivery links when it finishes.',
      );
    }
  }
}

export function canReprocess(job, project) {
  return Boolean(job.received && job.manifest && !job.reprocessed_as && project?.receive && project.revision !== job.project.revision
    && ['failed', 'retrying', 'awaiting_approval', 'ready'].includes(job.state));
}
