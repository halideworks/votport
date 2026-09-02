// Transfer timeline: facts derived from an upload record and its log.
// VOTPORT PROPRIETARY LICENSE.
//
// Pure functions over the record the admin API returns, so the Receive
// page's timeline view and its tests share one reading of the log.

/// Summary figures for one upload record. Every number comes from the
/// record itself; nothing is estimated.
export function summarize(upload) {
  const log = upload.log || [];
  const started = upload.started_at || 0;
  const completed = upload.completed_at || 0;
  const duration = started && completed > started ? completed - started : null;
  const bytes = upload.total_bytes || 0;
  const average = duration ? Math.round(bytes / duration) : null;
  let peak = null;
  for (const event of log) {
    if (event.kind === 'published' && event.bytes && event.secs) {
      const rate = event.bytes / event.secs;
      if (peak === null || rate > peak) peak = rate;
    }
  }
  const pauses = log
    .filter((event) => event.kind === 'quiet')
    .reduce((sum, event) => sum + (event.secs || 0), 0);
  const restarts = log.filter((event) => event.kind === 'reattached').length;
  const outcome = log.map((event) => event.kind).find((kind) =>
    ['finished', 'cancelled', 'interrupted', 'dropped'].includes(kind)) || (upload.partial ? 'partial' : 'finished');
  return {
    files: upload.files?.length || 0,
    bytes,
    duration,
    average,
    peak: peak === null ? null : Math.round(peak),
    pauses,
    restarts,
    resent: upload.replayed_chunks || 0,
    rejected: upload.rejected_chunks || 0,
    outcome,
    transport: upload.transport || 'http',
  };
}

/// One line per log event: a sentence and, when the event carries them,
/// the facts under it.
export function narrate(event) {
  const count = event.count ?? 0;
  const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
  switch (event.kind) {
    case 'opened': return { text: 'Session opened, manifest verified' };
    case 'reattached': return {
      text: 'Server restarted, session re-attached',
      detail: `${plural(count, 'file')} already published; the sender never saw an error`,
    };
    case 'published': return {
      text: `${event.path ?? 'a file'} published with its receipt`,
      detail: event.bytes !== undefined
        ? `${formatSize(event.bytes)}${event.secs ? ` in ${formatSecs(event.secs)} · ${formatSize(Math.round(event.bytes / event.secs))}/s` : ''}`
        : undefined,
    };
    case 'quiet': return { text: `Sender went quiet for ${formatSecs(event.secs ?? 0)}` };
    case 'finished': return {
      text: 'Finished, package root recorded',
      detail: count ? `${plural(count, 're-sent chunk')}` : undefined,
    };
    case 'cancelled': return { text: 'Cancelled by the sender' };
    case 'interrupted': return { text: 'Session went idle and expired' };
    case 'dropped': return { text: 'Resume refused after a restart; published files kept' };
    case 'elided': return { text: `${plural(count, 'more event')} not kept` };
    default: return { text: event.kind };
  }
}

/// The record as a document someone can keep: summary, then events.
export function timelineJson(link, upload) {
  return JSON.stringify({
    request: { id: link.id, label: link.label, dest: link.dest },
    upload: {
      id: upload.id,
      started_at: upload.started_at,
      completed_at: upload.completed_at,
      transport: upload.transport || 'http',
      package_root: upload.package_root,
      total_bytes: upload.total_bytes,
      partial: Boolean(upload.partial),
      replayed_chunks: upload.replayed_chunks || 0,
      rejected_chunks: upload.rejected_chunks || 0,
      files: (upload.files || []).map((file) => ({
        path: file.path, bytes: file.bytes, suite: file.suite, root: file.root, receipt: file.receipt,
      })),
    },
    summary: summarize(upload),
    events: upload.log || [],
  }, null, 2);
}

export function formatSecs(seconds) {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

export function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}
