import assert from 'node:assert/strict';
import { test } from 'node:test';
import { collapseLocalPassword } from '../web/assets/login-disclosure.js';

test('without SSO the password form stays expanded', () => {
  assert.equal(collapseLocalPassword({ available: false, public_password_login: false }), false);
  assert.equal(collapseLocalPassword({ available: false, public_password_login: true }), false);
  assert.equal(collapseLocalPassword({ available: false }), false);
});

test('SSO plus overlay false collapses; true or missing flag does not', () => {
  assert.equal(collapseLocalPassword({ available: true, public_password_login: false }), true);
  assert.equal(collapseLocalPassword({ available: true, public_password_login: true }), false);
  assert.equal(collapseLocalPassword({ available: true }), false);
});

test('sso_healthy does not collapse or expand the password form', () => {
  const closed = { available: true, public_password_login: false };
  assert.equal(collapseLocalPassword({ ...closed, sso_healthy: false }), true);
  assert.equal(collapseLocalPassword({ ...closed, sso_healthy: true }), true);
  assert.equal(
    collapseLocalPassword({
      available: true,
      public_password_login: true,
      sso_healthy: false,
    }),
    false,
  );
});
