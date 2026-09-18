// Retry and resume decisions for the uploader, kept pure so tests can run
// them without a browser. VOTPORT PROPRIETARY LICENSE.

// A transient failure is retried at most this many times and never past this
// much wall clock, aligned with the native client's per-request retry budget.
export const RETRY_ATTEMPTS = 3;
export const RETRY_BUDGET_MS = 90 * 1000;

// Admission caps and the drain gate refuse by name and may not clear by
// waiting, so the sender stops and shows the server's words instead of
// pausing indefinitely. Matched exactly, case-sensitive: these are the
// server's documented sentences, and a near-miss must keep retrying.
const REFUSALS = new Set([
  'too many uploads started from your address; try again in 600 seconds',
  'too many concurrent uploads for this tenant',
  'the server is draining for maintenance; your upload will resume shortly',
]);

function backoffMs(attempt) {
  return Math.min(15, 2 ** attempt) * 1000;
}

// Classifies one failed attempt. `status` is the HTTP status the server
// answered with (null when it never answered), `body` its JSON envelope,
// `retryAfterMs` a parsed Retry-After header, `failure` a thrown fetch
// error, `online` whether navigator.onLine reports a network. Returns
// `{ retry: true, delayMs }` or `{ retry: false }`, plus `message` when the
// server's own sentence names the refusal.
export function retryDecision({
  attempt,
  elapsedMs = 0,
  status = null,
  body = null,
  retryAfterMs = null,
  failure = null,
  online = true,
}) {
  // The shared controller's abort is the sender's cancel: never retried.
  if (failure?.name === 'AbortError') return { retry: false };
  const message = typeof body?.error === 'string' ? body.error : null;
  if (message !== null && (status === 429 || status === 503) && REFUSALS.has(message)) {
    return { retry: false, message };
  }
  // The server's envelope is the authority on whether a failure is worth
  // retrying: retryable false is final even in the 5xx class.
  if (body?.retryable === false) return { retry: false };
  const transient = status !== null
    ? status === 429 || status >= 500
    : failure instanceof TypeError || !online;
  if (!transient) return { retry: false };
  if (attempt >= RETRY_ATTEMPTS || elapsedMs >= RETRY_BUDGET_MS) return { retry: false };
  // A server Retry-After is honored up to what the budget still allows.
  const delayMs = Math.min(retryAfterMs ?? backoffMs(attempt), RETRY_BUDGET_MS - elapsedMs);
  return { retry: true, delayMs };
}

// A finish that failed this way may still have committed server-side: the
// reply was lost and the retry found the session gone, or the session was
// swept right after completing. The resume record stays and the next begin
// reconciles against the server's stored report instead of resending bytes.
export function finishMayBeComplete(error) {
  if (error.paused) return true;
  if (error.status === 404 || error.status === 410) return true;
  const message = error.message || '';
  return error.status === 409
    ? /nothing to finish/.test(message)
    : /unknown or expired session|upload session ended/.test(message);
}

// One resume record per drop per tab. The record is keyed by a random drop
// id this tab mints the first time it saves one and keeps in sessionStorage:
// a reload reuses the id (so the same drop re-attaches), another tab never
// sees it (so two tabs on one link hold separate records and drive separate
// server sessions instead of fighting over one). The package root inside the
// record still proves a re-selected drop is the same files.
const RESUME_PREFIX = 'votport-resume-';
const DROP_KEY_PREFIX = 'votport-drop-';
// Records this tab does not own expire after two idle sweeps: a live sender
// refreshes its record at every announce, so one this stale has no live
// session behind it and must not claim held bytes forever.
const FOREIGN_TTL_MS = 60 * 60 * 1000;

function mintDropId() {
  return [...crypto.getRandomValues(new Uint8Array(16))]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

// This tab's drop id for the link, or null before this tab has saved a record.
export function resumeDropId(token) {
  try {
    return sessionStorage.getItem(`${DROP_KEY_PREFIX}${token}`);
  } catch {
    return null;
  }
}

export function saveResumeRecord(token, record) {
  try {
    const dropKey = `${DROP_KEY_PREFIX}${token}`;
    let dropId = sessionStorage.getItem(dropKey);
    if (!dropId) {
      dropId = mintDropId();
      sessionStorage.setItem(dropKey, dropId);
    }
    localStorage.setItem(`${RESUME_PREFIX}${token}-${dropId}`, JSON.stringify({
      ...record,
      drop: dropId,
      at: Date.now(),
    }));
  } catch { /* private mode */ }
}

export function loadResumeRecord(token, dropId) {
  if (!dropId) return null;
  try {
    return JSON.parse(localStorage.getItem(`${RESUME_PREFIX}${token}-${dropId}`) || 'null');
  } catch {
    return null;
  }
}

export function clearResumeRecord(token, dropId) {
  if (!dropId) return;
  try {
    localStorage.removeItem(`${RESUME_PREFIX}${token}-${dropId}`);
  } catch { /* private mode */ }
}

// Expires the records other tabs left behind (and the whole-link single
// record an older build wrote), so they cannot claim held bytes forever.
// A record fresh enough to belong to a live sender is left alone.
export function expireForeignResumes(token) {
  try {
    const prefix = `${RESUME_PREFIX}${token}-`;
    const own = resumeDropId(token);
    const now = Date.now();
    const stale = [];
    for (let index = 0; index < localStorage.length; index += 1) {
      const key = localStorage.key(index);
      if (key === null) continue;
      if (key === `${RESUME_PREFIX}${token}`) {
        // Legacy single-record key from before per-drop keying.
        stale.push(key);
      } else if (key.startsWith(prefix) && key !== prefix + own) {
        let record = null;
        try { record = JSON.parse(localStorage.getItem(key) || 'null'); } catch { /* corrupt */ }
        if (!record || typeof record.at !== 'number' || now - record.at > FOREIGN_TTL_MS) {
          stale.push(key);
        }
      }
    }
    for (const key of stale) localStorage.removeItem(key);
  } catch { /* private mode */ }
}
