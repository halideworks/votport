import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

// Source-level assertions on the sign-in page script: the page cannot run
// under node --test, so the pins hold the shape the finding asked for.
const login = await readFile(new URL('../web/assets/login.js', import.meta.url), 'utf8');
const page = await readFile(new URL('../web/index.html', import.meta.url), 'utf8');

test('an unreachable identity provider disables the SSO button instead of renaming it', () => {
  const branch = login.match(/if \(sso_healthy === false\) \{[\s\S]*?\n    \}/)[0];
  assert.ok(branch, 'the unhealthy SSO branch exists');
  // The label stays the affordance it always was, and the button stops
  // navigating.
  assert.doesNotMatch(branch, /textContent/);
  assert.match(branch, /sso\.disabled = true/);
  // The status sentence moves to the error paragraph, with the password way
  // in.
  assert.match(branch, /loginError\.show\('SSO is not reachable\. Sign in with the administrator password\.'\)/);
  assert.match(page, /<button id="login-sso" type="button" hidden>Sign in with SSO<\/button>/);
});
