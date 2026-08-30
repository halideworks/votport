// Login disclosure predicate: collapse only when SSO is offered.
// VOTPORT PROPRIETARY LICENSE.

export function collapseLocalPassword({ available, public_password_login }) {
  return Boolean(available) && public_password_login === false;
}
