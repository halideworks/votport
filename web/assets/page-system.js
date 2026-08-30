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

function setNotifyActions(enabled) {
  $('notify-save').disabled = !enabled;
  $('notify-test').disabled = !enabled;
  for (const button of $('notify-form').querySelectorAll('[data-clear]')) {
    button.disabled = !enabled;
  }
}

async function testNotifications() {
  const button = $('notify-test');
  const note = $('notify-test-note');
  const error = $('notify-test-error');
  button.disabled = true;
  button.textContent = 'Sending…';
  note.textContent = 'Testing currently active notification settings…';
  error.hidden = true;
  try {
    const report = await api('/api/admin/notifications/test', { method: 'POST' });
    note.textContent = `Delivered ${report.delivered} of ${report.configured} configured notification channels.`;
  } catch (requestError) {
    note.textContent = 'Currently active notification test failed.';
    error.textContent = requestError.message;
    error.hidden = false;
  } finally {
    button.disabled = false;
    button.textContent = 'Send test';
  }
}

function setSmtpActions(enabled) {
  $('smtp-save').disabled = !enabled;
  for (const button of $('smtp-form').querySelectorAll('[data-clear]')) {
    button.disabled = !enabled;
  }
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

  $('smtp-host').value = data.smtp_host || '';
  setSource('smtp-host-source', data.smtp_host_source);
  $('smtp-port').value = data.smtp_port;
  setSource('smtp-port-source', data.smtp_port_source);
  $('smtp-starttls').checked = data.smtp_starttls !== false;
  setSource('smtp-starttls-source', data.smtp_starttls_source);
  $('smtp-username').value = data.smtp_username || '';
  setSource('smtp-username-source', data.smtp_username_source);
  setSecret('smtp-password', data.smtp_password_set);
  setSource('smtp-password-source', data.smtp_password_source);
  $('smtp-from').value = data.smtp_from || '';
  setSource('smtp-from-source', data.smtp_from_source);
  $('smtp-to').value = data.smtp_to || '';
  setSource('smtp-to-source', data.smtp_to_source);

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
  $('signin-save').disabled = !data.sso_configured;
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
  if ($('notify-save').disabled) return;
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

$('notify-test').addEventListener('click', () => testNotifications());

$('smtp-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if ($('smtp-save').disabled) return;
  const body = {
    smtp_host: $('smtp-host').value,
    smtp_starttls: $('smtp-starttls').checked,
    smtp_username: $('smtp-username').value,
    smtp_from: $('smtp-from').value,
    smtp_to: $('smtp-to').value,
  };
  const port = parseInt($('smtp-port').value, 10);
  if (Number.isFinite(port) && port >= 1 && port <= 65535) {
    body.smtp_port = port;
  }
  if ($('smtp-password').value !== '') {
    body.smtp_password = $('smtp-password').value;
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
  if ($('signin-collapse').disabled || $('signin-save').disabled) {
    if ($('signin-collapse').disabled) {
      formNote(event.currentTarget, 'SSO is not configured.');
    }
    return;
  }
  await saveSettings(event.currentTarget, {
    public_password_login: !$('signin-collapse').checked,
  });
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

for (const button of document.querySelectorAll('[data-clear]')) {
  button.addEventListener('click', async () => {
    if (button.disabled) return;
    const form = button.closest('form');
    formNote(form, '');
    try {
      fillSettings(await putSettings({ [button.dataset.clear]: '' }));
      formNote(form, 'Cleared.');
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
  setNotifyActions(true);
  setSmtpActions(true);
} catch (error) {
  formError($('notify-form'), error);
  formError($('smtp-form'), error);
}
// The public endpoint answers with the key alone; the links payload carries
// it too, but that is every link with every upload for one hex string.
try {
  const { receipt_key: key } = await api('/api/receipt-key');
  $('receipt-key').textContent = key || 'unavailable';
} catch {
  $('receipt-key').textContent = 'unavailable';
}
