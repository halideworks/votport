// Authenticated browser requests share their CSRF and JSON defaults.

export async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: 'same-origin',
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'X-Votport': '1',
      ...(options.headers || {}),
    },
  });
  let body = null;
  try { body = await response.json(); } catch { /* non-JSON error page */ }
  if (!response.ok) {
    const error = new Error(body?.error || `request failed (${response.status})`);
    error.status = response.status;
    throw error;
  }
  return body;
}
