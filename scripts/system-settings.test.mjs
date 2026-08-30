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
