import { isFormDirty, markFormChanged, markFormSaved } from '/assets/form-drafts.js';
// votport system page: credentials, backups, verification key, overlay settings.
// VOTPORT PROPRIETARY LICENSE.

import { api, colorPair, confirmModal, defaultAccent, formatBytes, formatWhen, requireSession } from '/assets/admin-common.js';
import { applyFooter } from '/assets/branding.js';

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

function setBackupSecret(input, isSet) {
  setSecret(input, isSet);
  $(`${input}-source`).textContent = isSet ? 'saved' : 'not configured';
}

function deploymentValue(id, value, fallback = 'Not configured') {
  $(id).textContent = value === null || value === undefined || value === '' ? fallback : value;
}

// Marks a deployment value the server also warns about at startup.
function deploymentWarning(id, warn, note) {
  $(id).classList.toggle('warning', warn);
  if (warn) $(id).textContent += ` (${note})`;
}

function deploymentProfile(id, profile, outbound = false) {
  const messages = {
    fast: 'Network filesystem detected. Receiving qualification is managed in Storage.',
    balanced: 'Balanced publication enabled.',
  };
  let note = messages[profile] || 'Receiving is unavailable. Review the checks in Storage.';
  if (outbound) note = `Library receipts use Fast.${profile === 'fast' ? ` ${messages.fast}` : profile ? '' : ' Filesystem detection unavailable.'}`;
  deploymentValue(id, note);
  $(id).classList.toggle('warning', profile === 'fast');
  $(`${id}-docs`).hidden = profile !== 'fast';
}

function fillDeployment(data) {
  const deployment = data.deployment;
  deploymentValue('setting-data-dir', deployment.data_dir);
  deploymentValue('setting-receive-dir', deployment.receive_dir);
  deploymentValue('setting-outbound-dir', deployment.outbound_dir);
  deploymentProfile('setting-receive-profile', deployment.receive_commit_profile);
  deploymentProfile('setting-outbound-profile', deployment.outbound_filesystem_profile, true);
  deploymentValue('setting-web-root', deployment.web_root);
  deploymentValue('setting-max-upload', formatBytes(deployment.max_upload_bytes));
  deploymentValue('setting-allow-hidden', deployment.allow_hidden ? 'Allowed' : 'Blocked');
  deploymentValue(
    'setting-idle-timeout',
    deployment.session_idle_secs === undefined
      ? null
      : `${deployment.session_idle_secs} seconds`,
  );

  deploymentValue('setting-max-total-sessions', deployment.max_total_sessions);
  deploymentValue('setting-max-link-sessions', deployment.max_link_sessions);
  deploymentValue('setting-bind', deployment.bind);
  deploymentValue('setting-public-url', deployment.public_url);
  deploymentValue(
    'setting-trusted-proxies',
    deployment.trusted_proxies?.length ? deployment.trusted_proxies.join(', ') : null,
    'Built-in loopback and private ranges',
  );
  deploymentWarning(
    'setting-trusted-proxies',
    !deployment.trusted_proxies?.length,
    'any private peer can pick its own throttle bucket; set VOTPORT_TRUSTED_PROXIES',
  );
  deploymentValue('setting-metrics', deployment.metrics_configured ? 'Configured' : 'Not configured');
  deploymentWarning(
    'setting-metrics',
    !deployment.metrics_configured,
    'unauthenticated; set VOTPORT_METRICS_TOKEN',
  );
  deploymentValue('setting-oidc-issuer', deployment.oidc_issuer);
  deploymentValue('setting-oidc-client-id', deployment.oidc_client_id);
  deploymentValue(
    'setting-oidc-admin-group',
    deployment.oidc_admin_group,
    deployment.oidc_configured ? 'All authenticated principals' : 'Not configured',
  );
  deploymentWarning(
    'setting-oidc-admin-group',
    deployment.oidc_configured && !deployment.oidc_admin_group,
    'every SSO user is a platform admin; set VOTPORT_OIDC_ADMIN_GROUP',
  );
  deploymentValue(
    'setting-oidc-secret',
    deployment.oidc_client_secret_configured ? 'Configured' : 'Not configured',
  );
  deploymentValue('setting-push-bind', deployment.push_bind);
  deploymentValue('setting-push-advertise', deployment.push_advertise);
  deploymentValue(
    'setting-push-certificate',
    deployment.push_certificate_configured ? deployment.push_certificate : null,
    deployment.push_configured ? 'Managed by VOTPort' : 'Not configured',
  );
  deploymentValue(
    'setting-push-key',
    deployment.push_private_key_configured ? 'Configured' : null,
    deployment.push_configured ? 'Managed by VOTPort' : 'Not configured',
  );
}

function gibValue(bytes) {
  if (bytes === null || bytes === undefined) return '';
  return String(bytes / 1024 ** 3);
}

function setSmtpActions(enabled) {
  $('smtp-save').disabled = !enabled;
  for (const button of $('smtp-form').querySelectorAll('[data-clear]')) {
    button.disabled = !enabled;
  }
}

function preserveSettingsEdits(exclude) {
  const edits = [...document.querySelectorAll('form[data-unsaved] input, form[data-unsaved] select, form[data-unsaved] textarea')].filter((field) => field.type !== 'file' && !exclude?.contains(field) && isFormDirty(field.closest('form'))).map((field) => [field, field.value, field.checked]);
  return () => { for (const [field, value, checked] of edits) { field.value = value; if (field.type === 'checkbox') field.checked = checked; } };
}
function fillSettings(data, exclude = null) {
  const restore = preserveSettingsEdits(exclude);
  fillDeployment(data);
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
  setSource('signin-source', data.public_password_login_source);
  // Lossy round-trip: the UI works in whole hours; an API-written value
  // under an hour must not display as 0, which would fail the min="1"
  // constraint and block saving the unrelated collapse toggle too.
  $('sso-session-hours').value = Math.max(1, Math.round(data.sso_session_secs / 3600));
  $('sso-session-hours').disabled = !data.sso_configured;
  setSource('sso-session-source', data.sso_session_secs_source);
  // SCIM keys on the OIDC subject, so it is only useful with SSO configured.
  setSecret('scim-token', data.scim_token_set);
  setSource('scim-token-source', data.scim_token_source);
  $('scim-token').disabled = !data.sso_configured;
  $('scim-token-previous-state').textContent = data.scim_token_previous_set
    ? 'A previous token is still accepted.'
    : '';
  $('require-provisioning').checked = data.require_provisioning === true;
  $('require-provisioning').disabled = !data.sso_configured;
  setSource('require-provisioning-source', data.require_provisioning_source);
  $('signin-save').disabled = !data.sso_configured;
  for (const button of $('signin-form').querySelectorAll('[data-clear]')) {
    button.disabled = !data.sso_configured;
  }

  $('drain-toggle').checked = data.draining === true;
  setSource('drain-source', data.draining_source);
  setSecret('replica-token', data.replica_token_set);
  setSource('replica-token-source', data.replica_token_source);

  // Reset and clear links only where they do something: a saved override
  // to drop, or a stored secret to wipe.
  for (const button of document.querySelectorAll('[data-reset]')) {
    button.hidden = data[`${button.dataset.reset}_source`] !== 'db';
  }
  for (const button of document.querySelectorAll('[data-clear]')) {
    button.hidden = !data[`${button.dataset.clear}_set`];
  }
  restore();
}

function syncBackupFields() {
  $('backup-s3-fields').hidden = $('backup-destination').value === 'local';
  $('backup-encryption-fields').hidden = !$('backup-encryption-enabled').checked;
}
$('backup-destination').addEventListener('change', syncBackupFields);
$('backup-encryption-enabled').addEventListener('change', syncBackupFields);

function fillBackups(data) {
  if (!isFormDirty($('backup-form'))) {
  const config = data.config;
  $('backup-destination').value = config.destination || 'local';
  $('backup-enabled').checked = config.enabled === true;
  $('backup-interval-minutes').value = config.interval_secs ? Math.ceil(config.interval_secs / 60) : 60;
  $('backup-local-path').value = config.local_path || '';
  $('backup-local-retention-days').value = config.retention_days ?? 30;
  $('backup-retention-count').value = config.retention_count ?? 30;
  $('backup-s3-endpoint').value = config.s3_endpoint || '';
  $('backup-s3-region').value = config.s3_region || '';
  $('backup-s3-bucket').value = config.s3_bucket || '';
  $('backup-s3-prefix').value = config.s3_prefix || '';
  $('backup-s3-path-style').checked = config.s3_path_style === true;
  setBackupSecret('backup-s3-access-key', config.s3_credentials_configured === true);
  setBackupSecret('backup-s3-secret-key', config.s3_credentials_configured === true);
  $('backup-encryption-enabled').checked = config.encrypt === true;
  setBackupSecret('backup-encryption-passphrase', config.passphrase_configured === true);
  syncBackupFields();
  }

  const status = data.status;
  const statusText = status.running
    ? 'Backup running…'
    : status.last_error
      ? `Last run failed: ${status.last_error}`
      : status.last_success_at
        ? `Last successful run ${formatWhen(status.last_success_at)}`
        : status.last_attempt_at
          ? `Last attempt ${formatWhen(status.last_attempt_at)}`
          : 'No backup has run yet.';
  $('backup-status').textContent = statusText;
  $('backup-status-error').hidden = !status.last_error;
  if (status.last_error) $('backup-status-error').textContent = status.last_error;
  if (!status.last_error && data.inventory_error) {
    $('backup-status-error').textContent = `Snapshot inventory unavailable: ${data.inventory_error}`;
    $('backup-status-error').hidden = false;
  }

  const snapshots = data.inventory;
  const select = $('backup-restore-snapshot');
  const addOption = (label, value) => {
    const option = document.createElement('option');
    option.textContent = label;
    option.value = value;
    select.add(option);
    return option;
  };
  select.replaceChildren();
  if (!snapshots.length) {
    addOption('No snapshots available', '');
    select.disabled = true;
  } else {
    addOption('Choose a snapshot…', '');
    for (const snapshot of snapshots) {
      const source = snapshot.source || 'local';
      const label = snapshot.name || snapshot.id;
      const when = snapshot.created_at ? ` · ${formatWhen(snapshot.created_at)}` : '';
      const bytes = snapshot.bytes === undefined ? '' : ` · ${formatBytes(snapshot.bytes)}`;
      const option = addOption(`${source}: ${label}${when}${bytes}`, snapshot.id);
      option.dataset.source = source;
    }
    select.disabled = false;
  }
  $('backup-inventory').textContent = snapshots.length
    ? `${snapshots.length} snapshot${snapshots.length === 1 ? '' : 's'} available.`
    : 'No snapshots available.';
}

function setBackupActions(enabled) {
  $('backup-save').disabled = !enabled;
  $('backup-run').disabled = !enabled;
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
    form.inert = true; const saved = await putSettings(body); markFormSaved(form); fillSettings(saved);
    formNote(form, 'Saved.');
  } catch (error) {
    formError(form, error);
  } finally { form.inert = false; }
}

$('password-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget; if (form.inert) return; form.inert = true;
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
    markFormSaved($('password-form')); $('password-form').reset();
    $('password-note').textContent =
      'Password updated. Every other session was signed out.';
  } catch (error) {
    $('password-error').textContent = error.message;
    $('password-error').hidden = false;
  } finally { form.inert = false; }
});

$('smtp-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if ($('smtp-save').disabled) return;
  const body = {
    smtp_host: $('smtp-host').value,
    smtp_starttls: $('smtp-starttls').checked,
    smtp_username: $('smtp-username').value,
    smtp_from: $('smtp-from').value,
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

const accent = colorPair($('branding-color'), $('branding-color-hex'));
// No accent stored means recipient pages use the stock colour; the picker
// shows that colour so the reset reads as a return to the default.
$('branding-color-clear').addEventListener('click', () => {
  accent.set(''); markFormChanged($('branding-form'));
  $('branding-color').value = defaultAccent();
});

async function fillBranding() {
  const branding = await api('/api/admin/branding/default');
  if (isFormDirty($('branding-form'))) { $('branding-logo-remove').disabled = !branding.has_logo; return; }
  $('branding-name').value = branding.name || '';
  accent.set(branding.color || '');
  for (const field of ['footer-text', 'footer-link-label', 'footer-link-url']) $(`branding-${field}`).value = branding[field.replaceAll('-', '_')] || '';
  $('branding-logo-remove').disabled = !branding.has_logo;
  applyFooter(branding);
}

$('branding-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  // currentTarget is null once the handler yields; keep the form.
  const form = event.currentTarget;
  formNote(form, '');
  try {
    form.inert = true;
    await api('/api/admin/branding/default', {
      method: 'PUT',
      body: JSON.stringify({
        name: $('branding-name').value,
        color: accent.get(),
        footer_text: $('branding-footer-text').value,
        footer_link_label: $('branding-footer-link-label').value,
        footer_link_url: $('branding-footer-link-url').value,
      }),
    });
    markFormSaved(form); await fillBranding();
    formNote(form, 'Saved.');
  } catch (error) {
    formError(form, error);
  } finally { form.inert = false; }
});

$('branding-logo-upload').addEventListener('click', async () => {
  const form = $('branding-form');
  formNote(form, '');
  const file = $('branding-logo').files?.[0];
  if (!file) {
    formError(form, new Error('Choose a logo file first.'));
    return;
  }
  try {
    await api('/api/admin/branding/default/logo', {
      method: 'PUT',
      headers: { 'Content-Type': file.type || 'application/octet-stream' },
      body: file,
    });
    $('branding-logo').value = '';
    await fillBranding();
    formNote(form, 'Logo uploaded.');
  } catch (error) {
    formError(form, error);
  }
});

$('branding-logo-remove').addEventListener('click', async () => {
  const form = $('branding-form');
  formNote(form, '');
  try {
    await api('/api/admin/branding/default/logo', { method: 'DELETE' });
    await fillBranding();
    formNote(form, 'Logo removed.');
  } catch (error) {
    formError(form, error);
  }
});

$('branding-remove').addEventListener('click', async () => {
  const form = $('branding-form');
  if (
    !(await confirmModal(
      'Remove branding',
      'Recipient pages for the default tenant go back to the stock appearance.',
      'Remove',
    ))
  )
    return;
  formNote(form, '');
  try {
    await api('/api/admin/branding/default', { method: 'DELETE' });
    markFormSaved(form); form.reset();
    await fillBranding();
    formNote(form, 'Branding removed.');
  } catch (error) {
    formError(form, error);
  }
});

$('signin-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if ($('signin-collapse').disabled || $('signin-save').disabled) {
    if ($('signin-collapse').disabled) {
      formNote(event.currentTarget, 'SSO is not configured.');
    }
    return;
  }
  const hours = parseInt($('sso-session-hours').value, 10);
  if (!Number.isInteger(hours) || hours < 1) {
    formError(event.currentTarget, new Error('SSO session lifetime must be at least 1 hour.'));
    return;
  }
  const body = {
    public_password_login: !$('signin-collapse').checked,
    sso_session_secs: hours * 3600,
    require_provisioning: $('require-provisioning').checked,
  };
  if ($('scim-token').value !== '') {
    body.scim_token = $('scim-token').value;
  }
  await saveSettings(event.currentTarget, body);
});

$('replica-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if ($('replica-token').value === '') {
    formNote(event.currentTarget, 'Enter a token to save.');
    return;
  }
  await saveSettings(event.currentTarget, { replica_token: $('replica-token').value });
});

$('drain-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  await saveSettings(event.currentTarget, { draining: $('drain-toggle').checked });
});

$('backup-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const interval = parseInt($('backup-interval-minutes').value, 10);
  const retention = parseInt($('backup-local-retention-days').value, 10);
  const retentionCount = parseInt($('backup-retention-count').value, 10);
  if (!Number.isInteger(interval) || interval < 1 || !Number.isInteger(retention) || retention < 0
    || !Number.isInteger(retentionCount) || retentionCount < 0) {
    formError(form, new Error('Schedule and retention must be valid numbers.'));
    return;
  }
  const body = {
    destination: $('backup-destination').value,
    enabled: $('backup-enabled').checked,
    interval_secs: interval * 60,
    local_path: $('backup-local-path').value.trim() || null,
    retention_days: retention,
    retention_count: retentionCount,
    s3_endpoint: $('backup-s3-endpoint').value.trim() || null,
    s3_region: $('backup-s3-region').value.trim() || null,
    s3_bucket: $('backup-s3-bucket').value.trim() || null,
    s3_prefix: $('backup-s3-prefix').value.trim() || null,
    s3_path_style: $('backup-s3-path-style').checked,
    encrypt: $('backup-encryption-enabled').checked,
  };
  if ($('backup-s3-access-key').value !== '') body.access_key_id = $('backup-s3-access-key').value;
  if ($('backup-s3-secret-key').value !== '') body.secret_access_key = $('backup-s3-secret-key').value;
  if ($('backup-encryption-passphrase').value !== '') {
    body.passphrase = $('backup-encryption-passphrase').value;
  }
  formNote(form, '');
  try {
    form.inert = true;
    await api('/api/admin/backups', {
      method: 'PUT',
      body: JSON.stringify(body),
    });
    markFormSaved(form); fillBackups(await api('/api/admin/backups'));
    formNote(form, 'Saved.');
  } catch (error) {
    formError(form, error);
  } finally { form.inert = false; }
});

// The snapshot route takes the CSRF header like every mutating route, so a
// plain link cannot fetch it; save the response body ourselves.
$('backup-download').addEventListener('click', async () => {
  const button = $('backup-download');
  button.disabled = true;
  $('backup-status-error').hidden = true;
  try {
    const response = await fetch('/api/admin/backup', {
      headers: { 'X-Votport': '1' },
      credentials: 'same-origin',
    });
    if (!response.ok) {
      const body = await response.json().catch(() => null);
      throw new Error(body?.error || `request failed (${response.status})`);
    }
    const name = /filename="([^"]+)"/.exec(response.headers.get('content-disposition') || '')?.[1]
      || 'votport.db';
    const url = window.URL.createObjectURL(await response.blob());
    const link = document.createElement('a');
    link.href = url;
    link.download = name;
    link.click();
    // Revoking in the same tick can cancel the save before the browser reads it.
    setTimeout(() => window.URL.revokeObjectURL(url), 0);
  } catch (error) {
    $('backup-status-error').textContent = error.message;
    $('backup-status-error').hidden = false;
  } finally {
    button.disabled = false;
  }
});

$('backup-run').addEventListener('click', async () => {
  const button = $('backup-run');
  button.disabled = true;
  $('backup-status').textContent = 'Running backup…';
  $('backup-status-error').hidden = true;
  try {
    await api('/api/admin/backups', { method: 'POST' });
    fillBackups(await api('/api/admin/backups'));
  } catch (error) {
    $('backup-status').textContent = 'Backup failed.';
    $('backup-status-error').textContent = error.message;
    $('backup-status-error').hidden = false;
  } finally {
    button.disabled = false;
  }
});

$('backup-restore-snapshot').addEventListener('change', async (event) => {
  const select = event.currentTarget;
  const option = select.selectedOptions[0];
  if (!option?.value) return;
  const source = option.dataset.source || 'local';
  const name = option.textContent;
  const confirmed = await confirmModal(
    'Restore this snapshot?',
    `Restore ${name}. Current application state will be replaced; the cookie secret will rotate and every existing admin session will be signed out. Automatic backups will be disabled until re-enabled by an admin. The staged restore will restart the supervised service.`,
    'Restore and restart',
  );
  select.value = '';
  if (!confirmed) return;
  const error = $('backup-status-error');
  error.hidden = true;
  $('backup-status').textContent = 'Staging restore…';
  try {
    await api('/api/admin/backups/restore', {
      method: 'POST',
      body: JSON.stringify({ source, id: option.value }),
    });
    $('backup-status').textContent = 'Restore staged. The supervised service will restart.';
  } catch (requestError) {
    $('backup-status').textContent = 'Restore failed.';
    error.textContent = requestError.message;
    error.hidden = false;
  }
});

for (const button of document.querySelectorAll('[data-reset]')) {
  button.addEventListener('click', async () => {
    const form = button.closest('form');
    if (form.inert) return; form.inert = true;
    formNote(form, '');
    try {
      fillSettings(await putSettings({ [button.dataset.reset]: null }), button.closest('.field'));
      formNote(form, 'Using environment.');
    } catch (error) {
      formError(form, error);
    } finally { form.inert = false; }
  });
}

for (const button of document.querySelectorAll('[data-clear]')) {
  button.addEventListener('click', async () => {
    if (button.disabled) return;
    const form = button.closest('form');
    if (form.inert) return; form.inert = true;
    formNote(form, '');
    try {
      fillSettings(await putSettings({ [button.dataset.clear]: '' }), button.closest('.field'));
      formNote(form, 'Cleared.');
    } catch (error) {
      formError(form, error);
    } finally { form.inert = false; }
  });
}

// Section nav follows the scroll position.
const navLinks = [...document.querySelectorAll('.settings-nav a')];
const observer = new IntersectionObserver(
  (entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      for (const link of navLinks) {
        const active = link.getAttribute('href') === `#${entry.target.id}`;
        link.classList.toggle('active', active);
        if (active) link.setAttribute('aria-current', 'location');
        else link.removeAttribute('aria-current');
      }
    }
  },
  { rootMargin: '-10% 0px -70% 0px' },
);
for (const section of document.querySelectorAll('.settings-group[id]')) observer.observe(section);

// Settings load alongside the session check, one round trip for both.
const settingsReady = api('/api/admin/settings');
settingsReady.catch(() => {});
const session = await requireSession();
if (!session.pages.includes('system')) {
  window.location.replace('/receive');
}
try {
  const settings = await settingsReady;
  fillSettings(settings);
  for (const form of document.querySelectorAll('form[data-unsaved]')) if (!['branding-form', 'backup-form'].includes(form.id)) form.inert = false;
  setSmtpActions(true);
} catch (error) {
  formError($('smtp-form'), error);
}
try {
  await fillBranding(); $('branding-form').inert = false;
} catch (error) {
  formError($('branding-form'), error);
}
try {
  fillBackups(await api('/api/admin/backups')); $('backup-form').inert = false;
  setBackupActions(true);
} catch (error) {
  setBackupActions(true);
  $('backup-status').textContent = 'Backup status unavailable.';
  $('backup-status-error').textContent = error.message;
  $('backup-status-error').hidden = false;
}
// The public endpoint answers with the key alone; the links payload carries
// it too, but that is every link with every upload for one hex string.
try {
  const { receipt_key: key } = await api('/api/receipt-key');
  $('receipt-key').textContent = key || 'unavailable';
} catch {
  $('receipt-key').textContent = 'unavailable';
}
