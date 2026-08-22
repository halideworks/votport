// Login disclosure predicate: collapse only when SSO is offered.
// AGPL-3.0-only.

export function collapseLocalPassword({ available, public_password_login }) {
  return Boolean(available) && public_password_login === false;
}
