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

try {
  const { available } = await api('/api/admin/sso');
  if (available) $('login-sso').hidden = false;
} catch {
  /* password sign-in still works */
}

$('login-sso').addEventListener('click', () => {
  window.location.assign('/api/admin/sso/start');
});
