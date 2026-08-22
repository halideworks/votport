// votport system page: credentials, backups, verification key, overlay settings.
// AGPL-3.0-only.

import { api, requireSession } from '/assets/admin-common.js';

const $ = (id) => document.getElementById(id);

function sourceLabel(source) {
  return source === 'db' ? 'saved' : 'from environment';
}

function setSource(id, source) {
  $(id).textContent = sourceLabel(source);
}

function setSecret(id, isSet) {
  $(id).value = '';
  $(id).placeholder = isSet ? 'unchanged' : '';
}

function gibValue(bytes) {
  if (bytes === null || bytes === undefined) return '';
  return String(bytes / 1024 ** 3);
}

function fillSettings(data) {
  $('notify-webhook').value = data.notify_webhook || '';
  setSource('notify-webhook-source', data.notify_webhook_source);
  $('notify-ntfy').value = data.notify_ntfy || '';
  setSource('notify-ntfy-source', data.notify_ntfy_source);
  setSecret('notify-ntfy-token', data.notify_ntfy_token_set);
  setSource('notify-ntfy-token-source', data.notify_ntfy_token_source);
  setSecret('notify-pushover-token', data.notify_pushover_token_set);
  setSource('notify-pushover-token-source', data.notify_pushover_token_source);
  setSecret('notify-pushover-user', data.notify_pushover_user_set);
  setSource('notify-pushover-user-source', data.notify_pushover_user_source);

  $('audit-retention-days').value = data.audit_retention_days;
  setSource('audit-retention-source', data.audit_retention_days_source);
  $('upload-retention-days').value = data.upload_retention_days;
  setSource('upload-retention-source', data.upload_retention_days_source);

  $('default-max-total').value = gibValue(data.default_max_total_bytes);
  setSource('default-max-total-source', data.default_max_total_bytes_source);
  $('default-max-links').value =
    data.default_max_links === null || data.default_max_links === undefined
      ? ''
      : data.default_max_links;
  setSource('default-max-links-source', data.default_max_links_source);
  $('default-max-sessions').value =
    data.default_max_sessions === null || data.default_max_sessions === undefined
      ? ''
      : data.default_max_sessions;
  setSource('default-max-sessions-source', data.default_max_sessions_source);

  const collapse = $('signin-collapse');
  collapse.checked = data.public_password_login === false;
  collapse.disabled = !data.sso_configured;
}

function formControls(form) {
  const prefix = form.id.replace(/-form$/, '');
  return { note: $(`${prefix}-note`), error: $(`${prefix}-error`) };
}

function formNote(form, message) {
  const { note, error } = formControls(form);
  if (note) note.textContent = message;
  if (error) error.hidden = true;
}

function formError(form, error) {
  const { note, error: box } = formControls(form);
  if (note) note.textContent = '';
  if (box) {
    box.textContent = error.message;
    box.hidden = false;
  }
}

async function putSettings(body) {
  return api('/api/admin/settings', {
    method: 'PUT',
    body: JSON.stringify(body),
  });
}

async function saveSettings(form, body) {
  formNote(form, '');
  try {
    fillSettings(await putSettings(body));
    formNote(form, 'Saved.');
  } catch (error) {
    formError(form, error);
  }
}

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

$('notify-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const body = {
    notify_webhook: $('notify-webhook').value,
    notify_ntfy: $('notify-ntfy').value,
  };
  // Blank secret inputs mean unchanged, not a wipe.
  if ($('notify-ntfy-token').value !== '') {
    body.notify_ntfy_token = $('notify-ntfy-token').value;
  }
  if ($('notify-pushover-token').value !== '') {
    body.notify_pushover_token = $('notify-pushover-token').value;
  }
  if ($('notify-pushover-user').value !== '') {
    body.notify_pushover_user = $('notify-pushover-user').value;
  }
  await saveSettings(event.currentTarget, body);
});

$('retention-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const body = {};
  const audit = parseInt($('audit-retention-days').value, 10);
  const upload = parseInt($('upload-retention-days').value, 10);
  if (Number.isFinite(audit) && audit >= 0) body.audit_retention_days = audit;
  if (Number.isFinite(upload) && upload >= 0) body.upload_retention_days = upload;
  await saveSettings(event.currentTarget, body);
});

$('quotas-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const body = {};
  const maxTotal = parseInt($('default-max-total').value, 10);
  const maxLinks = parseInt($('default-max-links').value, 10);
  const maxSessions = parseInt($('default-max-sessions').value, 10);
  // Never PUT 0; empty means leave the overlay as-is.
  if (Number.isFinite(maxTotal) && maxTotal > 0) {
    body.default_max_total_bytes = maxTotal * 1024 ** 3;
  }
  if (Number.isFinite(maxLinks) && maxLinks > 0) body.default_max_links = maxLinks;
  if (Number.isFinite(maxSessions) && maxSessions > 0) {
    body.default_max_sessions = maxSessions;
  }
  await saveSettings(event.currentTarget, body);
});

$('signin-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const collapse = $('signin-collapse');
  const body = {};
  // Checkbox is ignored when SSO is not configured.
  if (!collapse.disabled) {
    body.public_password_login = !collapse.checked;
  }
  await saveSettings(event.currentTarget, body);
});

for (const button of document.querySelectorAll('[data-reset]')) {
  button.addEventListener('click', async () => {
    const form = button.closest('form');
    formNote(form, '');
    try {
      fillSettings(await putSettings({ [button.dataset.reset]: null }));
      formNote(form, 'Using environment.');
    } catch (error) {
      formError(form, error);
    }
  });
}

const session = await requireSession();
if (!session.pages.includes('system')) {
  window.location.replace('/links');
}
try {
  fillSettings(await api('/api/admin/settings'));
} catch (error) {
  formError($('notify-form'), error);
}
// The receipt key arrives with the links payload.
try {
  const { receipt_key } = await api('/api/admin/links');
  $('receipt-key').textContent = receipt_key || 'unavailable';
} catch {
  $('receipt-key').textContent = 'unavailable';
}
