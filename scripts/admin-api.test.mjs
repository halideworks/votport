import assert from 'node:assert/strict';
import { test } from 'node:test';
import { api } from '../web/assets/admin-api.js';

test('custom upload headers preserve the admin CSRF header', async (t) => {
  let request;
  t.mock.method(globalThis, 'fetch', async (path, options) => {
    request = { path, ...options };
    return { ok: true, json: async () => ({ ok: true }) };
  });
  const body = new Blob(['logo'], { type: 'image/png' });
  await api('/api/admin/branding/default/logo', {
    method: 'PUT', headers: { 'Content-Type': 'image/png' }, body,
  });
  assert.equal(request.headers['X-Votport'], '1');
  assert.equal(request.headers['Content-Type'], 'image/png');
  assert.equal(request.credentials, 'same-origin');
  assert.equal(request.method, 'PUT');
  assert.equal(request.body, body);
  await api('/api/admin/links');
  assert.equal(request.headers['Content-Type'], 'application/json');
  assert.equal(request.headers['X-Votport'], '1');
  await api('/api/admin/session', { credentials: 'omit' });
  assert.equal(request.credentials, 'omit');
});
