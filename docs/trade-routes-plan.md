# Trade routes: address, identity, and permission

Status: implemented. Trade routes are managed under **Trade routes** on each
installation. Independent administration and the existing receive-link path are
supported. Shared organization administration and relay/pull transport remain
separate future capabilities.

## Set up a route

1. On the receiver, choose **Receive from another port**. Follow **Create a receive request and return here** to choose its local destination,
   byte limit and reception workflow. Continue back to Trade routes with the request selected, then convert it
   into a receiving endpoint. Choose internal/external, the metadata allowlist,
   forwarding permission and receiver notifications. Ordinary uploads to that
   request are then denied on both HTTP and QUIC.
2. Set the receiver's advertised address in This port. Create a one-time invitation
   expiring in one hour, one day or seven days. An optional exact sender fingerprint
   preapproves that identity; otherwise enrollment awaits receiver approval.
3. On the sender, choose **Send to another port** and preview the invitation, confirm its destination and fingerprint,
   choose a local route name and notification policy, and accept. The sender stores
   its credential privately. Check connection retries an interrupted enrollment.
4. Approve the incoming grant on the receiver when needed. Select the outgoing
   route by name in a sender workflow project. Scripts and agents can use the **Local connection ID** shown in the route's expandable details. Reverse sending
   requires a separate invitation in the other direction.
5. Check the route's recent deliveries for verified receipt, receiver processing or
   approval hold, and release. This is informational status; the sender's release
   choice continues to use destination receipt or local release with background copy.

Each tenant owns its directional routes. Multiple routes to a peer share its pinned
identity and configured address within that tenant. Address changes verify the same
key and require active jobs to finish or be cancelled first. Route credentials can
be rotated independently; interrupted rotations recover from a saved pending value.
Pausing or revoking stops new admissions, with an explicit finish-or-cancel choice
for admitted transfers. Cancellation remains permanent for those delivery legs even
if the reusable route is resumed. Relationship revocation does not delete received
files. A missing signing key on a paired installation stops startup until the key is
restored or the installation is explicitly re-enrolled.

Outgoing metadata is filtered before transmission. Signed ancestry containing keys
outside a downstream route's allowlist holds forwarding before any request is sent,
and the receiver re-checks the ancestry against its endpoint allowlist on admission.
Forwarding prohibition is signed and checked at every managed hop. Route notification
policies are captured per delivery; tenant defaults remain dynamic. Connection
monitoring checks outgoing enrolled routes once per minute, with four requests in
parallel; a route that keeps failing is retried with a doubling wait of up to 64
minutes until it answers again. Delivery listings show the most recent 50 operations
per route.

The design rationale below describes the implemented boundaries and the optional
capabilities deliberately left for separate work.

## What exists today

A Storage connection's **Local connection ID** names that connection on the
sending installation. It is used by projects and agents. It does not identify or
locate a remote installation.

Older receive-link connections under Storage can no longer be created or
edited, only disabled. New port-to-port sending goes through Trade routes: the
receiver converts a receive request into a receiving endpoint and issues an
invitation, and the sender accepts it. The receiving request chooses the
tenant, quota, and project; the sender cannot choose those by naming its own
tenant or project.

The existing receipt public key is also the port's custody-signing identity. It
is visible under System > Receipt verification and at GET /api/receipt-key.
Current routes bind the peer key per delivery after admission, retain signed
custody evidence, resume transfers, reject forwarding loops, and propagate signed
revocations. Trade routes add persistent peer approval and identity pinning. Organization
membership is still administered independently at each port.

## Connection setup

Expose a **This port** card with display name, advertised address, full identity
fingerprint, and copy buttons. Reuse the receipt-signing identity. A friendly
name or matching email domain is never proof that two installations share an
owner. Keep transport certificates separate from the displayed port identity.

A reusable connection needs three things:

| Item | Purpose | Example |
| --- | --- | --- |
| Port address | Reach the destination | https://nyc.studio.example |
| Port identity | Verify which installation answered | Pinned receipt-key fingerprint |
| Receiving permission | Authorize a specific delivery destination | Route invitation for “LA masters” |

Prefer **Paste route invitation** as the setup flow. The receiving administrator
creates a one-time, expiring invitation for a receiving endpoint. It contains the
address, expected identity, and a secret enrollment capability. The sender sees
the destination name, fingerprint, and permitted endpoint before accepting.
Redeeming an invitation binds the sending identity; the receiver either
preapproves that identity or explicitly approves the pending connection. A
self-signed invitation proves consistency, not organizational ownership; confirm
the fingerprint through the partner when the invitation's source is uncertain.

Offer **Enter port address** for discovery and testing, followed by an invitation
or approval step. Knowing an address or fingerprint never grants upload access.
Discovery publishes protocol versions and identity, not tenant/project catalogs.
Show only receiving endpoints granted to the authenticated peer. Secrets remain
private after enrollment and can be rotated or revoked independently per route.

Existing receive links remain useful for occasional exchanges. Label them as
receive-link connections; upgrading one to a persistent relationship requires
explicit pairing, rather than silently granting lasting trust.

## Internal and external routes

Use one transfer protocol and permission model. The relationship category sets
useful defaults and presentation, and is not itself an authorization grant.

| Behavior | Internal sites | External partners |
| --- | --- | --- |
| Address | Reachable private/VPN or public HTTPS address | Reachable HTTPS address, or agreed private network |
| Enrollment | Approved organization administrator pairs both ports | Each side approves its own side of the relationship |
| Receiving destination | Explicit local endpoint/project mapping | Explicit local endpoint/project mapping |
| Defaults | Reusable routes; automatic receipt into the selected workflow | Partner-specific quotas, metadata allowlist, forwarding off |
| Users and projects | Independent by default | Independent |
| Shared administration | Optional, separately granted later | None by default |

Do not require both ports to accept unsolicited inbound connections for one-way
sending: the sender connects to the receiver and polls status over that same
approved address. The receiving endpoint must be reachable from the sender.
Two outbound-only installations need a separately designed relay or pull mode;
an ID cannot solve that network constraint.

Start with one configured address per connection. Address edits require the same
pinned identity at the new endpoint and explicit approval of the edit. Unexpected
identity changes hold the route for review. A lost signing key requires
re-enrollment; do not silently create a replacement identity. Preserve identity
files during normal upgrades and backup recovery.

## Routes and deliveries

A connection identifies a peer. A **route** selects a permitted receiving endpoint
and direction. Several routes may use the same peer: “Dailies,” “Final masters,”
and “Returns” can have separate projects, quotas, schedules, and notifications.
Sending permission does not imply reverse permission. A bidirectional relationship
has two independently revocable directional grants, even if one setup wizard
creates both.

The receiver controls its tenant mapping, storage, retention, file and metadata
limits, malware/media checks, and approval rules. A sending project chooses its
allowed outgoing routes, required metadata, schedule, and release condition.
Source forwarding restrictions must be included in signed route terms; every
managed hop applies the intersection of those terms and its own rules. The
receiver cannot weaken an inherited restriction. This cannot control downloaded
or manually copied files outside managed routes.

Reuse the existing durable jobs and per-destination legs:

1. Validate source policy and approved route permission; freeze the manifest.
2. Receiver admits a stable operation under its local limits and policy.
3. Transfer verified files using QUIC when available, with HTTP fallback.
4. Commit a signed custody receipt with publication; retries recover that receipt.
5. Run the receiver's reception workflow and expose its separately authorized status.

Show **Received and verified**, **Processing/held for approval**, and **Released**
as separate statuses. A custody receipt does not mean a downstream workflow
finished or a human accepted the delivery. Retain the existing sender release
choice: wait for destination receipt, or release locally and copy in the
background. Add a distinct wait-for-receiver-release option only with an explicit
remote-status contract and timeout behavior.

Route cards show the peer name and address, pinned identity, relationship type,
direction, receiving endpoint, permission status, last contact, and failed jobs.
Connection status distinguishes pending approval, active, paused, unreachable,
identity mismatch, and revoked. Pausing and revoking permissions stop new
admissions; already admitted transfers follow an explicit finish-or-cancel policy.
Revoking a relationship does not implicitly delete previously received files.
Keep delivery revocation separate and report pending versus acknowledged status.

## Notifications and boundaries

Allow tenant defaults or destination/event overrides on routes, using the new
notification destination catalog. Copy a route's policy to each delivery leg when
it is created so later route edits do not silently change existing custom rules.
A tenant-default subscription continues to resolve the current tenant defaults.
Add connection approval, identity-change, and route failure/recovery events as
part of the route-management work. Each organization controls its own notification
channels; do not copy webhook credentials across ports.

No automatic database, user, secret, tenant-name, or project-policy replication.
If internal shared administration is desired, first define explicit organization
membership and administrator authority. Then support selected versioned policy
templates with a target-port preview and acceptance. Configuration synchronization
must have separate permissions and audit history from file transfer.

## Implementation order and acceptance

1. Clarify Local connection ID and Destination receive URL in the current form.
   Add This port identity/address display and connection-level identity pinning.
2. Add receiving endpoints, expiring invitations, mutual enrollment, scoped
   directional grants, and a dedicated Trade routes view. Reuse the current
   transfer worker, checkpoint, receipt, and revocation mechanisms.
3. Add per-route status, notifications, limits, and lifecycle actions. Migrate
   existing connections only through explicit enrollment.
4. Add optional internal organization administration if selected. Relay/pull
   transport is a separate capability driven by actual network requirements.

Before shipping, run two independent installations with separate tenants and
keys. Verify enrollment expiry/replay, wrong-peer rejection, cross-tenant denial,
identity/address changes, credential revocation, interrupted transfers, lost
completion responses, downstream approval holds, loop rejection, and offline
revocation recovery. Confirm that receiving files does not copy users or weaken
project policy, and that notifications stay within each side's chosen channels.
