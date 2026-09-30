# Principal identity and local state ownership

## Background

SQLite principal lookups fold subject strings to lowercase. OIDC `sub` must
retain its exact provider identity; folding distinct subjects can merge their
permissions. Desktop app and CLI processes also share private files, so
in-process guards do not serialize journal ownership or account changes.

## Behavior

For the configured `sub` claim, derive a lowercase ASCII storage key from the
issuer's SHA-256 and the exact UTF-8 subject's hexadecimal encoding. SCIM uses
the same key and displays the decoded subject only for the current issuer.
Email and preferred username keep their existing lowercase convention. The
internal key is at most 589 bytes; project member and group ID validation
allows 600 bytes. No schema change is required.

Do not infer a new exact identity from an ambiguous old lowercase principal. On
the initial cutover and every issuer change, quarantine nonlocal principals,
advance their credential versions, revoke their automation tokens, and clear
external IDs. Re-provision identities when SCIM provisioning is required,
restore SCIM group memberships where used, and update explicit project member
IDs. Otherwise the next OIDC login creates the new principal and OIDC group
claims can supply roles. Pending and retrying workflow jobs retain their old
credential version and cannot progress by unblocking a legacy principal.
Previously released grants retain their delivery authorization and require
explicit revocation when needed. Rotate the admin MAC domain to invalidate
earlier cookies, including local admin cookies. Encode current cookie payloads
with base64url and refuse full cookies larger than 4096 bytes with a visible
error.

Client state operations acquire a shared OS file lock outside the removable
state directory. Removal requires an exclusive lock. Transfers keep their
shared lease through journal updates and settlement; evidence retries keep it
through network calls and final writes. Browser sign-in keeps a cancellable
lease while pending and releases it automatically at the ten-minute deadline.
The expiry worker retains only a weak reference and ends on cancellation,
completion or object destruction. Removal asks the user to finish or cancel
work that still owns state.

Serialize stored-account replacements using a stable account lock and compare
the complete prior record before writing. Serialize watch-list updates with
their own lock. Journal entries have OS locks held for each active transfer. A
stable registry lock serializes per-entry lock opening with orphan removal, so
retained sidecars can be cleaned without splitting ownership. Close in-state
lock handles before releasing the outer lease.

Watch probes do not create lock sidecars. Completed transfers release their
handles and shared state lease before attempting cleanup. Removing a flight
sidecar requires nonblocking exclusive state ownership, which excludes both
active holders and open-descriptor waiters. Startup and minute-based cleanup
remove at most 1024 sidecars per pass, and skip an erased or absent state
directory. Lock failures refuse transfer admission. This prerelease requires
clients using the current state-ownership protocol; older native clients must
be closed and upgraded before sharing local state.

## Limits and verification

Upgrade requires signing in again. Installations using `sub` must re-provision
SCIM users when provisioning is required, restore SCIM roles where used, and
update explicit project member IDs. Changing issuer also quarantines previous
identities. An abandoned SSO attempt releases its retained lease at expiry;
an already-running exchange keeps its own lease until its bounded request and
final account comparison end. A network evidence retry can briefly
refuse removal until its bounded attempt ends. Files remain ordinary private
JSON files; there is no new database or dependency.

Tests cover case and issuer separation, SCIM provisioning and deactivation,
legacy credential and token invalidation, cookie bounds and MAC rotation, stale
account replacements, active journal retention, local erasure refusal, and
orphan cleanup. Platform CI builds both macOS and Windows shells. Active native
download authorization uses upstream VOT ADR-0064.
