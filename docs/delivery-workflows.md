# Delivery workflows

Delivery workflows add project policies, durable preparation, recipient evidence,
and storage integration to the existing verified transfer paths. Open
**Workflows** in the browser or either native app.
Agents use the scoped HTTP API, client CLI, or MCP tools described
in [Agent access](agents.md).

## What each client can do

| Capability | Browser | Windows/macOS | CLI/MCP |
| --- | --- | --- | --- |
| List projects and durable jobs | Yes | Yes | Yes |
| Create a job with required metadata and enrolled recipients | Yes | Yes | Yes |
| Schedule a start and acceptance deadline | Yes | Opens browser | Yes |
| Review a manifest and approve release | Human operator | Human operator | No agent approval |
| Retry or cancel a job | Yes | Yes | Yes |
| Configure project roles, templates, storage and webhooks | Administrator | Opens browser | Operator HTTP API |
| Inspect signed recipient evidence and events | Yes, with JSON export | Local recipient history; browser for server history | Yes |
| Verify downloaded bytes and explicitly accept | Choose and hash saved files | Automatic verification after download; explicit acceptance | `evidence` commands; no automatic MCP acceptance |

The native apps bundle the client CLI. Desktop **Settings > Agent access** also
includes the new job permissions. Updating the server alone does not update an
installed native application's screens or bundled MCP executable.

## Recipient verification and acceptance

An ordered manifest digest commits to every filename, VOT hash suite, object
root, file size, and file position. The server signs an authorization containing
that digest, the grant ID, server origin, recipient device public key, nonce,
and validity window. The recipient separately signs `verified` and `accepted`
statements. Changing either the manifest or statement kind invalidates its
signature. Verification never implies acceptance.

Native HTTP and QUIC receivers enqueue verification after VOT verification and
local publication, before reporting completion. The durable outbox is separate
from the transfer journal: retrying evidence does not download the payload
again. Submission runs in the background, in fair batches of 16 every minute.
A server must acknowledge the exact statement ID before its queued copy is
removed. A short CLI invocation may exit before the background request finishes;
`votport evidence retry` explicitly flushes a batch.

```sh
votport evidence device-key
votport evidence list
votport evidence retry
votport evidence accept VERIFICATION_ID
```

The browser stores a nonextractable device key and queued evidence in IndexedDB.
Ordinary download clicks do not prove saved bytes. After downloading, choose the
saved files in **Verify saved files and accept this delivery**. Votport hashes
all expected files before offering explicit acceptance. Browser and native
keys are separate. Clearing browser site data removes that browser's key and
local evidence history.

Native first-use key creation is coordinated across processes. A damaged or
unreadable existing key is reported instead of silently replacing the enrolled
identity; restore that key from backup to retain its enrollment and acceptance
authority.

Authorizations last seven days. Signed reports may arrive after the share is
revoked or expires, while their authorization remains valid. An already-recorded
statement can be acknowledged again after authorization expiry, so a lost
response does not leave a permanent retry. A new expired statement is rejected.
Server exports retain each distinct signed statement; duplicate submissions do
not create duplicate verification or acceptance events.

These signatures establish what the enrolled device attested to. The operator's
email-to-key enrollment supplies the identity mapping; a device signature alone
does not prove a person's email address or prevent a modified client from lying.

## Projects and release policy

Open **Workflows > Projects > New project** to create a project. The empty
project list also offers **Create project**. Administrators assign a library
directory to a project and grant `sender`,
`approver`, or `viewer` membership. An automation principal is
`automation:TOKEN_ID`, using the issued token's ID. Agents also need the matching
`jobs:read`, `jobs:create`, or `jobs:cancel` permission and a folder scope covering
the project's directory. An administrator may manage projects within their tenant.

Projects support required metadata, allowed recipient email domains, enrolled
recipient device keys, optional approval, sequence rules, media checks, malware
scanning, and export storage. If a project has enrolled recipients, each job must
select at least one. File access then requires proof of possession of a selected
key, including browser and native downloads.

Approval requires a different human operator from the submitter and binds the
exact manifest and project policy revision. Agents cannot approve. Policy changes
block further admissions for jobs prepared under the old revision; submit a new
job to use the new policy. Ordinary sharing cannot bypass a protected project
directory. Scope checks account for portable case and Unicode aliases.

HTTP metadata, files, ranges, bundles and download leases, plus QUIC ticket
issuance and session admission, enforce release and recipient policy. Rotating a
share invalidates its previous token and QUIC tickets. Already-admitted streams
may finish; previously delivered bytes cannot be recalled.

## Durable preparation, schedules and deadlines

Create a job with a stable `operation_id`. Repeating the same request under the
same actor returns the same job. Reusing that ID with different fields fails.
Jobs retain their request and policy revision across server restarts and recover
interrupted preparation or export. Recovery is bounded to five worker attempts per retry cycle; failed jobs remain visible and can be explicitly retried or cancelled.

States include `queued`, `preparing`, `awaiting_approval`, `exporting`, `ready`,
`retrying`, `failed`, `cancelled`, `retiring`, and `retired`. Download URLs are exposed only
for a released job under its current policy and grant lifecycle. A scheduled job
starts at or after `not_before`. When an acceptance deadline passes, a durable
`delivery_deadline_missed` event is emitted once if any selected recipient has
not accepted. For a job without selected recipients, any recorded acceptance
satisfies the deadline. Cancelled jobs do not escalate.

```json
{
  "operation_id": "episode-08-final-v3",
  "project_id": "broadcast",
  "label": "Episode 08 final",
  "metadata": { "client": "Example", "version": "v3" },
  "recipients": ["<enrolled 64-character device public key>"],
  "expires_days": 7
}
```

```sh
votport agent projects
votport agent create-job delivery.json
votport agent jobs --limit 50
votport agent job JOB_ID
votport agent job-evidence JOB_ID --limit 50
votport agent retry-job JOB_ID
votport agent cancel-job JOB_ID
votport agent events --limit 100
```

Optional `not_before` and `deadline` values are Unix seconds. Optional
`import: { "storage_id": "source", "prefix": "incoming/episode-08" }` selects
S3 objects instead of the project's library files. MCP `create_job` accepts the
same information using `import_storage_id` and `import_prefix` together.
Follow returned cursors even when a filtered job/event page is empty.

## Reception workflows and trade routes

Enable **Use this project for incoming files** in a project, then select it
under **Receive > After files arrive > Reception project**. Existing requests
also have a **Reception workflow** editor. The selection applies to subsequent
completed uploads. Required metadata and recipient selections belong to the
receiving project. Incomplete uploads remain visible without starting copies.

A complete upload queues its reception job in the same database transaction.
The worker snapshots verified files and applies the receiving project's checks,
approval and destination choices. Pending jobs protect source records against
deletion; after a snapshot is prepared, retention can remove the original.
Failures remain visible and can be retried or cancelled. Raw sharing cannot
bypass a reception job's release policy.

**Storage > Add storage > Destination type** offers S3, a shared folder, or
another Votport. A shared folder must already be mounted and visible to the
server process, including through a container mount when applicable. Votport
connections save the other port's receive URL and optional password privately.
**Test saved connection** checks access without sending files.

Select up to 16 destinations in **Workflows > Projects > Destinations**.
The release choice is explicit:

- **After all destinations finish** holds the local download link until each
  selected destination completes. This is the default.
- **After local checks and approval** releases the local link and copies in the
  background. A failed destination does not retract that local release.

Two destination legs can run concurrently. Completed legs are retained across
retries. Failed exports use persistent exponential backoff, with an initial
failure notification and signed events for the existing webhook queue. After
five worker attempts, explicit **Retry** starts another cycle. Native peer
transfers use QUIC when available and HTTP otherwise. Both reuse verified
receiver checkpoints. A receipt already committed at the receiver prevents a
lost completion response from creating another upload.

For a hypothetical LA and NYC installation, LA signs a source statement for
its frozen manifest. NYC verifies the arriving files and records its own signed
custody receipt in the upload completion transaction. Forwarding from NYC
includes the parent receipt's digest and its complete signed ancestry. Receivers
verify the chain and reject loops; a route allows at most eight sending ports.
**Workflows > Jobs > Download custody evidence** exports the peer receipt,
ancestors and any revocation acknowledgment. **Receive > Trade route > evidence**
exports evidence retained by the receiving port. File publication receipts
continue to identify their actual storage commit profile; custody signatures do
not add a power-loss guarantee to that profile.

Ports retain separate SQLite databases. The exchange includes file identities,
label, informational metadata and signed custody evidence. It does not copy
users, credentials, request links, tenant names, memberships or project policy.
The destination receive request selects its own tenant, quota and reception
project. An LA tenant does not create or select a same-named NYC tenant.

Cancelling, revoking or expiring the LA delivery queues a source-signed
revocation independently of payload work. NYC stops route-managed sharing and
forwarding and signs an acknowledgment. Subsequent managed ports receive their
own revocation requests. The UI distinguishes pending and acknowledged status;
an offline port retries with capped backoff until it responds. Already-downloaded
files, S3 exports, shared-folder copies and independent manual copies cannot be
recalled. Deleting a source tenant requires its outgoing route acknowledgments.
If a destination tenant was deleted first, its port can sign that the exact
route is absent without retaining the deleted tenant's metadata.

Internal organization routes with selected administration or policy syncing
are a later management feature. Current routes use the same independent
permission boundary for internal sites and external vendors.

## Storage, templates and quarantine

Open **Storage > Add storage** to connect Amazon S3 or an S3-compatible service.
Platform administrators configure the endpoint, bucket, region, root folder,
tenant access and optional SSE-KMS key. Enter an access key and secret in the
form, or select server credentials / IAM role. Saved credentials live in the
private server database and its backups; list and save responses never return
them. Editing a connection preserves its keys unless you explicitly replace
them or switch to server credentials. Keys and settings change atomically under
the same configuration revision.

**Test saved connection** checks bucket listing without writing objects. Exports
also need write permission and, when configured, permission to use the KMS key.
Choose connections under a project's **Destinations**, or choose S3 as a new delivery's source.

With server credentials selected, a storage ID `media` can use:

```sh
VOTPORT_STORAGE_MEDIA_ACCESS_KEY_ID=...
VOTPORT_STORAGE_MEDIA_SECRET_ACCESS_KEY=...
# Optional temporary-session credentials:
VOTPORT_STORAGE_MEDIA_SESSION_TOKEN=...
```

When explicit credentials are absent, the existing AWS credential provider chain
is used. HTTPS is required except for loopback test endpoints. The configured
SSE-KMS key is sent on export writes; the provider's IAM and KMS policies still
determine access. These settings do not configure a bucket retention policy.

Import persists the source inventory before downloading, uses version or ETag
conditions, enforces prefix boundaries and byte limits, and refuses changed
objects. Literal `%`, `#` and bracket characters remain literal object keys.
Storage access and configuration revision are checked during preparation,
approval and export. Retry uses the original inventory and policy.

Export streams multipart uploads while verifying each source against its frozen
VOT identity. A signed `complete.json` is published with create-only semantics
after all payload objects finish. Retrying a lost completion response accepts
only the identical completion document. Consumers should discover committed
packages through that document, rather than infer completion from partial object
listings. Object keys include the job and manifest. This is not S3 Object Lock;
configure retention or an independent archive if physically immutable storage is
required.

Sequence rules specify prefix, suffix, first/last frame and padding. Optional
media rules check the first video stream's codec, dimensions and rational frame
rate using `ffprobe`. `VOTPORT_FFPROBE` can name its executable. Required malware
scanning uses `clamdscan --fdpass`; `VOTPORT_CLAMDSCAN` can name its executable.
Install and operate the scanner daemon separately. Missing, failing or timed-out
checkers withhold release. Checks have a five-minute timeout per file and a
64 KiB output bound. Inspect job errors and retry after correcting the problem.

Media/scanning jobs, S3 imports and reception workflows use private snapshots. A global reservation
budget is controlled by `VOTPORT_WORKFLOW_SNAPSHOT_BYTES`, defaulting to four
times the maximum upload size. Private files are retired seven days after a
failed/cancelled job, or seven days after grant expiry/revocation. Job history,
evidence and events remain. Tenant deletion removes that tenant's records.

## Events, webhooks and MAM integration

`GET /api/workflows/events` returns paginated signed events visible to the caller.
Each includes the previous event hash for its tenant. Verify signatures against
a separately trusted server receipt public key. A complete tenant chain can be
checked for missing or reordered records; a project-filtered page may contain
intentional gaps.

The administrator webhook sends the signed event JSON with:

- `X-Votport-Event-Id`: event ID.
- `X-Votport-Timestamp`: Unix seconds for this attempt.
- `X-Votport-Signature`: `sha256=` followed by HMAC-SHA256 over
  `timestamp + "." + raw_body`, using the displayed secret as UTF-8 bytes.

Only 2xx acknowledges delivery; redirects are not followed. Attempts persist,
use bounded exponential retry, and become `dead` after 12 failures. Operators
can inspect attempts and replay individual events. Changing webhook configuration
rotates its secret, supersedes pending attempts under the old revision, and
starts automatic delivery from the new configuration's event. Explicit replay
can resend older events. Receivers must deduplicate by event ID/hash and tolerate
replay and out-of-order retries.

[The Node.js receiver example](../examples/delivery-event-receiver.mjs) uses only
the standard library. It validates HMAC freshness and the pinned Ed25519 issuer,
then atomically persists an event before acknowledging it. Run it behind your
HTTPS endpoint on a POSIX host with a precreated private event directory:

```sh
VOTPORT_EVENT_ISSUER='<trusted server receipt public key>' \
VOTPORT_WEBHOOK_SECRET='<displayed webhook signing secret>' \
VOTPORT_EVENT_DIRECTORY=/srv/mam-events PORT=8090 \
node examples/delivery-event-receiver.mjs
```

Consume the archived events from your MAM integration using job IDs to query
metadata, manifests, checks and recipient evidence. To verify an exported event
array, use the same issuer and run:

```sh
node examples/delivery-event-receiver.mjs verify events.json [previous-hash]
```

Signatures and chaining detect edits relative to a trusted key and checkpoint.
A local database and a signing key controlled by the same administrator are not
a tamper-proof archive. Preserve exported records and checkpoints independently
if administrator-resistant audit preservation is required. Azure/GCS adapters
and vendor-specific MAM connectors are deferred until a named integration is
needed.

## Transfer performance and validation

Ordinary governed library deliveries reuse the original files: they do not
require a second full payload copy. Existing VOT hashing and verification remain
in place. Source mutations fail verification instead of silently changing the
approved identity. Required snapshots try filesystem copy-on-write cloning before
bounded copying. Scanning, QC and cloud movement add their explicit preparation
work only when selected.

Verification authorization travels in the existing metadata response. HTTP
fallback reuses authorized metadata and cookies. Reporting adds a small durable
outbox write, with network submission outside transfer completion. Legacy folder
policy decisions are cached and invalidated transactionally when projects change,
so file requests do not repeatedly scan the package's file list.

Runnable checks include `scripts/delivery-performance.py` (creation through
verified CLI completion), `scripts/delivery-storage-e2e.py` (real S3 with injected
source/completion failures), and `scripts/delivery-browser-e2e.mjs` (project UI,
recipient access, saved-file verification and acceptance recovery). Use an
isolated instance and a dedicated data filesystem. Compare revisions on the same
rig and inspect variability; these scripts do not impose a zero-noise timing
gate. Unit/integration coverage also exercises signed-byte compatibility,
project authorization, rotation, queue fairness, retries, deadlines and retention.

On September 9, 2026, an isolated Ascii large VM (8 vCPU, 16 GiB) compared
baseline `b7d2735` with this implementation using alternating runs of the same
script and fixtures. Times include link/job preparation through verified CLI
completion. Each main comparison has two runs per revision; the governed-job
column has two runs with optional scanning, QC and storage movement disabled.

| Fixture / transport | Baseline median | Current median | Governed job median |
| --- | ---: | ---: | ---: |
| 2 GiB / HTTP | 8.004 s | 7.457 s | 6.961 s |
| 1,000 x 4 KiB / HTTP | 15.121 s | 15.720 s | 14.625 s |
| 2 GiB / QUIC | 13.834 s | 12.442 s | 12.880 s |
| 1,000 x 4 KiB / QUIC | 3.637 s | 5.188 s | 3.808 s |

The small-file QUIC result prompted four additional alternating pairs with a
1 MiB companion fixture. Its median was 2.825 s before and 2.579 s after; the
1 MiB median was 0.198 s before and 0.209 s after. The initial small-file slowdown
did not reproduce. The VM showed substantial timing variation, so these results
do not establish a universal speedup or a zero-regression guarantee. All payloads
were independently compared after transfer.

On September 10, 2026, reception routes were compared with `25230c1` on
Erebus using isolated NVMe fixtures and release binaries. Three alternating
runs per revision measured governed delivery preparation through CLI exit,
and fresh uploads from CLI start through completion. Every received file was
independently SHA-256 compared. No reception project was selected for these
ordinary-upload comparisons.

| Operation / fixture / transport | Baseline median | Reception routes median |
| --- | ---: | ---: |
| Delivery / 256 MiB / HTTP | 0.415 s | 0.420 s |
| Delivery / 1,000 x 4 KiB / HTTP | 6.388 s | 6.981 s |
| Delivery / 256 MiB / QUIC | 0.800 s | 0.826 s |
| Delivery / 1,000 x 4 KiB / QUIC | 1.485 s | 1.706 s |
| Upload / 256 MiB / HTTP | 0.764 s | 0.831 s |
| Upload / 1,000 x 4 KiB / HTTP | 3.995 s | 4.908 s |
| Upload / 256 MiB / QUIC | 0.816 s | 0.883 s |
| Upload / 1,000 x 4 KiB / QUIC | 4.634 s | 4.578 s |

The initial native small-file upload included a 37.796 s route-build outlier.
Four additional alternating pairs had medians of 5.666 s before and 3.990 s
after, with another 14.787 s route-build outlier. These variable samples do not
establish a speed improvement or rule out a latency regression. Reception
completion adds transactional queue work; copying, checks and network exports
run in the worker. Peer sends reuse prepared manifests and retained checkpoints.
The uncached proof builder now streams input in 1 MiB buffers instead of reading
the entire file into memory.
