// System status rendering is separate from form submission and page mounting.

import { $, formatBytes, formatWhen } from './object-card.js';

function sourceLabel(key, overriddenKeys) {
  return overriddenKeys.includes(key) ? 'saved' : 'from environment';
}

export function setSource(id, key, overriddenKeys) {
  $(id).textContent = sourceLabel(key, overriddenKeys);
}

export function setSecret(id, isSet) {
  $(id).value = '';
  $(id).placeholder = isSet ? 'unchanged' : '';
}

export function fillRetentionClock(data) {
  const clock = data.retention_clock || {};
  const status = $('retention-clock-status');
  const confirm = $('retention-clock-ack');
  const note = $('retention-clock-note');
  const observedAt = Number.isSafeInteger(clock.raw_wall_at) ? clock.raw_wall_at : null;
  confirm.dataset.observedAt = observedAt === null ? '' : String(observedAt);
  if (observedAt === null) {
    status.textContent = 'Cleanup status is unavailable. Refresh settings to see the server time.';
    note.textContent = 'Refresh settings before confirming the server time.';
    confirm.hidden = true;
    return;
  }
  note.textContent = '';
  const observed = ` Observed server time: ${formatWhen(clock.raw_wall_at)}.`;
  if (clock.held) {
    status.textContent = `Cleanup based on file and record age is paused until an administrator confirms the server's date and time.${observed}`;
  } else if (clock.capped) {
    status.textContent = `Cleanup based on file and record age is limited to trusted time and server uptime until an administrator confirms the current date and time.${observed}`;
  } else {
    status.textContent = `Cleanup is using the trusted server time.${observed}`;
  }
  confirm.hidden = !clock.held && !clock.capped;
}

export function setBackupSecret(input, isSet) {
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
  if (outbound) note = `Sharing library files verifies their content without creating publication receipts.${profile === 'fast' ? ' Network filesystem detected.' : profile ? '' : ' Filesystem detection unavailable.'}`;
  deploymentValue(id, note);
  $(id).classList.toggle('warning', profile === 'fast');
  $(`${id}-docs`).hidden = profile !== 'fast';
}

export function fillDeployment(data) {
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

export function fillBackupStatus(data) {
  const status = data.status;
  const statusText = data.paused_reason
    ? `Backups paused: ${data.paused_reason}`
    : status.running
      ? 'Backup running…'
      : status.last_error
        ? `Last run failed: ${status.last_error}`
        : status.last_success_at
          ? `Last successful run ${formatWhen(status.last_success_at)}`
          : status.last_attempt_at
            ? `Last attempt ${formatWhen(status.last_attempt_at)}`
            : 'No backup run recorded.';
  $('backup-status').textContent = data.config.enabled === false && !data.paused_reason && !status.running
    ? `Automatic backups are off. ${statusText}`
    : statusText;
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
