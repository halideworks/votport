// votport sign-in page. VOTPORT PROPRIETARY LICENSE.

import { api } from '/assets/admin-common.js';
import { collapseLocalPassword } from '/assets/login-disclosure.js';
import { ssoErrorMessage } from '/assets/login-errors.js';
import { $, fieldError } from '/assets/object-card.js';

const loginError = fieldError($('login-password'), $('login-error'));

$('login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  loginError.clear();
  try {
    await api('/api/admin/login', {
      method: 'POST',
      body: JSON.stringify({ password: $('login-password').value }),
    });
    $('login-password').value = '';
    window.location.replace('/receive');
  } catch (error) {
    loginError.show(error.message);
  }
});

// Already-signed-in visitors skip the form entirely.
try {
  await api('/api/admin/session');
  window.location.replace('/receive');
} catch {
  /* not signed in: stay here */
}

const ssoError = new URLSearchParams(window.location.search).get('sso_error');
if (ssoError !== null) {
  if (ssoError) {
    loginError.show(ssoErrorMessage(ssoError));
  }
  window.history.replaceState({}, '', '/');
}

try {
  const { available, sso_healthy, public_password_login } = await api('/api/admin/sso');
  const details = $('login-password-details');
  const summary = details.querySelector('summary');
  details.open = !collapseLocalPassword({ available, public_password_login });
  if (available) {
    if (summary) summary.hidden = false;
    const sso = $('login-sso');
    sso.hidden = false;
    if (sso_healthy === false) {
      // The label stays and the button stops navigating; the status sentence
      // moves to the error paragraph, with the password way in.
      sso.disabled = true;
      loginError.show('SSO is not reachable. Sign in with the administrator password.');
    }
  }
} catch {
  /* password sign-in still works */
}

$('login-sso').addEventListener('click', () => {
  window.location.assign('/api/admin/sso/start');
});
