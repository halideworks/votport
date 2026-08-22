// votport system page: credentials, backups, verification key.
// AGPL-3.0-only.

import { api, requireSession } from '/assets/admin-common.js';

const $ = (id) => document.getElementById(id);

$('password-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('password-error').hidden = true;
  $('password-note').textContent = '';
  try {
    await api('/api/admin/password', {
      method: 'POST',
      body: JSON.stringify({
        current: $('password-current').value,
        new: $('password-new').value,
      }),
    });
    $('password-form').reset();
    $('password-note').textContent =
      'Password updated. Every other session was signed out.';
  } catch (error) {
    $('password-error').textContent = error.message;
    $('password-error').hidden = false;
  }
});

const session = await requireSession();
if (!session.pages.includes('system')) {
  window.location.replace('/links');
}
// The receipt key arrives with the links payload.
try {
  const { receipt_key } = await api('/api/admin/links');
  $('receipt-key').textContent = receipt_key || 'unavailable';
} catch {
  $('receipt-key').textContent = 'unavailable';
}
