const messages = new Map([
  ['provider_refused', 'The identity provider refused sign-in. Try again or contact your administrator.'],
  ['state_invalid', 'This sign-in has expired or is invalid. Start sign-in again.'],
  ['not_configured', 'SSO is not configured. Contact your administrator.'],
  ['unavailable', 'SSO is temporarily unavailable. Try again shortly.'],
  ['provider_misconfigured', 'The identity provider is not configured correctly. Contact your administrator.'],
  ['identity_unverified', 'Your identity could not be verified. Contact your administrator.'],
  ['clock_skew', 'This port\'s clock disagrees with the identity provider. Have an administrator correct the clock, then try again.'],
  ['groups_unverified', 'Your group membership could not be verified. Try again or contact your administrator.'],
  ['account_blocked', 'This account is blocked. Contact your administrator.'],
  ['not_provisioned', 'This account has not been provisioned. Contact your administrator.'],
]);

export function ssoErrorMessage(code) {
  return messages.get(code) ?? 'SSO sign-in failed. Try again or contact your administrator.';
}
