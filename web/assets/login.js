// votport sign-in page. AGPL-3.0-only.

import { api } from '/assets/admin-common.js';

const $ = (id) => document.getElementById(id);

$('login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('login-error').hidden = true;
  try {
    await api('/api/admin/login', {
      method: 'POST',
      body: JSON.stringify({ password: $('login-password').value }),
    });
    $('login-password').value = '';
    window.location.replace('/links');
  } catch (error) {
    $('login-error').textContent = error.message;
    $('login-error').hidden = false;
  }
});

// Already-signed-in visitors skip the form entirely.
try {
  await api('/api/admin/session');
  window.location.replace('/links');
} catch {
  /* not signed in: stay here */
}

const ssoError = new URLSearchParams(window.location.search).get('sso_error');
if (ssoError) {
  try {
    const message = new TextDecoder().decode(
      Uint8Array.from(ssoError.match(/.{2}/g) ?? [], (byte) => parseInt(byte, 16)),
    );
    $('login-error').textContent = message;
    $('login-error').hidden = false;
    window.history.replaceState({}, '', '/');
  } catch {
    /* malformed tag: ignore */
  }
}

try {
  const { available, sso_healthy, public_password_login } = await api('/api/admin/sso');
  const details = $('login-password-details');
  const summary = details.querySelector('summary');
  // Collapse only when SSO is offered; the API flag alone must not hide break-glass.
  const collapse = Boolean(available) && public_password_login === false;
  details.open = !collapse;
  if (summary) summary.hidden = !available;
  if (available) {
    const sso = $('login-sso');
    sso.hidden = false;
    if (sso_healthy === false) sso.textContent = 'SSO is not reachable';
  }
} catch {
  /* password sign-in still works */
}

$('login-sso').addEventListener('click', () => {
  window.location.assign('/api/admin/sso/start');
});
