import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

const html = await readFile(new URL('../web/system.html', import.meta.url), 'utf8');
const script = await readFile(new URL('../web/assets/page-system.js', import.meta.url), 'utf8');

test('system settings are grouped and deployment values have DOM targets', () => {
  const groups = [...html.matchAll(/data-group="([^"]+)"/g)].map((match) => match[1]);
  assert.deepEqual(groups, [
    'access-security',
    'storage-transfer',
    'notifications',
    'email',
    'retention',
    'default-tenant-quotas',
    'branding',
    'network-integrations',
    'maintenance-verification',
  ]);
  for (const id of [
    'setting-data-dir',
    'setting-receive-dir',
    'setting-outbound-dir',
    'setting-web-root',
    'setting-max-upload',
    'setting-allow-hidden',
    'setting-idle-timeout',
    'setting-bind',
    'setting-public-url',
    'setting-trusted-proxies',
    'setting-metrics',
    'setting-oidc-issuer',
    'setting-oidc-client-id',
    'setting-oidc-admin-group',
    'setting-oidc-secret',
    'setting-push-bind',
    'setting-push-advertise',
    'setting-push-certificate',
    'setting-push-key',
  ]) {
    assert.match(html, new RegExp(`id="${id}"`));
  }
  assert.match(html, /Editable here/);
  assert.match(html, /Deployment settings &middot; restart required/);
  assert.match(html, /id="password-form"/);
  assert.match(html, /id="signin-source"/);
});

test('deployment settings are populated without rendering secret fields', () => {
  assert.match(script, /const deployment = data\.deployment/);
  for (const field of [
    'data_dir',
    'receive_dir',
    'outbound_dir',
    'web_root',
    'max_upload_bytes',
    'allow_hidden',
    'session_idle_secs',
    'bind',
    'public_url',
    'trusted_proxies',
    'metrics_configured',
    'push_bind',
    'push_advertise',
    'push_certificate',
    'oidc_issuer',
    'oidc_client_id',
    'oidc_admin_group',
  ]) {
    assert.match(script, new RegExp(`deployment\\.${field}`));
  }
  for (const secret of ['admin_password_hash', 'admin_token_tag', 'metrics_token']) {
    assert.doesNotMatch(script, new RegExp(`deployment\\.${secret}`));
  }
  assert.doesNotMatch(script, /deployment\.oidc_client_secret(?!_configured)/);
  assert.match(script, /oidc_client_secret_configured/);
  assert.match(script, /push_private_key_configured/);
});

test('backup card exposes scoped configuration, status, and restore controls', () => {
  for (const id of [
    'backup-form',
    'backup-destination',
    'backup-enabled',
    'backup-interval-minutes',
    'backup-local-path',
    'backup-local-retention-days',
    'backup-retention-count',
    'backup-s3-endpoint',
    'backup-s3-region',
    'backup-s3-bucket',
    'backup-s3-prefix',
    'backup-s3-path-style',
    'backup-s3-access-key',
    'backup-s3-secret-key',
    'backup-encryption-enabled',
    'backup-encryption-passphrase',
    'backup-status',
    'backup-inventory',
    'backup-run',
    'backup-restore-snapshot',
  ]) {
    assert.match(html, new RegExp(`id="${id}"`));
  }
  assert.match(html, /database and VOTPort-managed\s+identity files only/);
  assert.match(html, /Received and outbound files remain separate\s+operator backups/);
  assert.match(html, /Keep an external recovery copy of the passphrase/);
  assert.match(html, /service filesystem path; blank uses &lt;data_dir&gt;\/backups/);
  assert.match(html, /backup objects only/);
  assert.match(html, /saved secrets unchanged; GET never returns them/);
  assert.match(html, /no in-app secret clear control/);
  assert.match(html, /path-style requests.*endpoints that require it/);
  assert.match(html, /Current application\s+state will be replaced/);
  assert.match(html, /cookie secret will rotate/);
  assert.match(html, /every\s+existing admin session will be signed out/);
  assert.match(html, /Automatic backups will\s+remain disabled/);
});

test('backup client uses the redacted API contract and confirmation guard', () => {
  assert.match(script, /api\('\/api\/admin\/backups'\)/);
  assert.match(script, /method: 'PUT'/);
  assert.match(script, /api\('\/api\/admin\/backups', \{ method: 'POST' \}/);
  assert.match(script, /api\('\/api\/admin\/backups\/restore'/);
  assert.match(script, /JSON\.stringify\(\{ source, id: option\.value \}\)/);
  assert.match(script, /confirmModal\(/);
  assert.match(script, /s3_credentials_configured/);
  assert.match(script, /passphrase_configured/);
  assert.match(script, /data\.status/);
  assert.match(script, /data\.inventory_error/);
  assert.match(script, /status\.running/);
  assert.match(script, /status\.last_attempt_at/);
  assert.match(script, /status\.last_success_at/);
  assert.match(script, /status\.last_error/);
  assert.match(script, /config\.encrypt/);
  for (const field of [
    'enabled',
    'interval_secs',
    'retention_days',
    'retention_count',
    'destination',
    'local_path',
    's3_endpoint',
    's3_region',
    's3_bucket',
    's3_prefix',
    's3_path_style',
    'encrypt',
    'access_key_id',
    'secret_access_key',
    'passphrase',
  ]) {
    assert.match(script, new RegExp(field));
  }
  assert.match(script, /if \(\$\('backup-s3-access-key'\)\.value !== ''\)/);
  assert.match(script, /if \(\$\('backup-s3-secret-key'\)\.value !== ''\)/);
  assert.match(script, /if \(\$\('backup-encryption-passphrase'\)\.value !== ''\)/);
  assert.doesNotMatch(script, /backups\/config/);
  assert.doesNotMatch(script, /interval_minutes|local_target|local_retention_days|encryption_enabled|s3_access_key|s3_secret_key|encryption_passphrase/);
  assert.doesNotMatch(script, /config\.encrypted/);
  assert.doesNotMatch(script, /config\.(access_key_id|secret_access_key|passphrase)(?!_configured)/);
});
