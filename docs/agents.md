# Agent access

Build the server and desktop clients from the same revision. Agent access is a
folder-scoped delivery workflow shared by the server, browser, desktop core,
CLI, and MCP adapter. It uses the existing library, delivery links, VOT object
identities, download counters, and audit trail. The HTTP contract is pinned to
that server revision. The session's `api_version: 1` is informational; clients
do not negotiate HTTP versions or promise compatibility across revisions.

## Connect

In the browser, open **Automation**. In the macOS or Windows app, open
**Settings > Agent access**. Choose a label, library
folder, expiry, and allowed actions, then issue a token. Copy it immediately.
The desktop apps include the client CLI and can copy an MCP configuration with
its installed path. The browser can copy a configuration whose `command` must
point to the client CLI on the agent's machine.

| Permission | Access |
| --- | --- |
| `library:read` | Browse files and subdirectories within the token's folder. |
| `deliveries:create` | Share a folder and recover URLs for this token's operations. |
| `deliveries:read` | List this token's deliveries and inspect their files, receipts, and request counts. |
| `deliveries:revoke` | Revoke this token's deliveries. Files stay in the library. |
| `jobs:read` | Read projects, jobs, signed events and evidence allowed by project membership. |
| `jobs:create` | Create or retry jobs as a project sender. |
| `jobs:cancel` | Cancel jobs within the permitted project scope. |

The server enforces these permissions on every call. Reading and revoking a
delivery requires ownership by this exact token, even when another token has
the same tenant and folder. Tokens cannot change settings, manage tenants,
upload or delete library files, or issue receive requests. Those remain operator
workflows. Requests that omit permissions default to `deliveries:create`.

Tokens expire after 1 to 365 days and can be revoked from any operator UI.
Revoking a token stops its API access; already-issued delivery links keep their
own expiry and revocation state. Operators can manage those links in Deliver.
The database stores agent token hashes, permissions, and operation records.
Delivery tokens are retained so authorized operators can copy and resend links;
raw agent tokens cannot be recovered. Existing data must follow the supported
schema transition described in [Deployment](deployment.md).

## CLI

Build the client CLI with:

```sh
cargo build --release --manifest-path client/Cargo.toml -p votport-client
```

The executable is `client/target/release/votport`. The server executable has the
same name but a different command surface, so use an absolute path in agent
configuration. Desktop builds package the client as `votport-cli` on macOS and
`votport-cli.exe` on Windows.

Configure the process environment using your agent host's secret settings:

```sh
export VOTPORT_URL=https://drop.example.com
export VOTPORT_AUTOMATION_TOKEN='<issued token>'
# Optional password applied to newly created delivery links:
export VOTPORT_SHARE_PASSWORD='<delivery password>'
```

HTTPS is required except for loopback development servers. Agent credentials
are separate from the desktop operator's saved session. Signing the desktop
out does not sign the agent out.

```sh
client/target/release/votport agent session
client/target/release/votport agent files --limit 50
client/target/release/votport agent share project/render \
  --operation-id render-2026-09-09 --expires-days 7 --label 'Client delivery'
client/target/release/votport agent recover render-2026-09-09
client/target/release/votport agent deliveries --limit 50
client/target/release/votport agent delivery DELIVERY_ID --limit 50
client/target/release/votport agent revoke DELIVERY_ID
```

Every `agent` command writes one JSON object to stdout and exits nonzero on
failure. The create/recover result contains `operation_id`, `url`, and `grant`;
`grant.id` is used to inspect or revoke it. Errors contain `error`, `code`, and
`retryable`, with HTTP `status` and `retry_after_seconds` when available.

File listings return `directories`, `files`, `has_more`, and `next_cursor`.
Pass that cursor to `files --after`. Delivery listings use
`deliveries --after`. A delivery's file detail uses `next_offset` with
`delivery --offset`. Pages default to 50 and accept 1 to 100 entries. Directory
listings reflect the live filesystem; files created before a cursor may require
a fresh scan.

The server binary's existing share command also accepts operation IDs and JSON:

```sh
server/target/release/votport share project/render \
  --operation-id render-2026-09-09 --expires 7d --json
```

The client CLI's existing `send`, `receive`, `inspect`, `status`, and `resume`
commands remain available for moving local files through normal request and
delivery links. File bytes travel through the existing verified transfer paths.

## Retry and recovery

Choose `operation_id` before creating a delivery, persist it in the calling
workflow, and reuse it with identical parameters on retry. IDs accept 1 to 128
ASCII letters, digits, dots, underscores, and hyphens; `.` and `..` are invalid.

The delivery and its operation record commit in one SQLite transaction.
Concurrent requests with the same token and operation ID return the same
delivery. Reusing an ID with different parameters returns HTTP 409 with
`code: operation_conflict`. A committed operation can be recovered after a
server restart or a source folder disappearing. Recovery does not create a new
snapshot or extend a link's lifetime. An administrator rotating the link causes
recovery to return `delivery_changed` instead of returning an obsolete URL.

The delivery password is part of those identical parameters. The CLI's `agent
share` and MCP's `create_delivery` read it from `VOTPORT_SHARE_PASSWORD`, even
though it is absent from the tool arguments. Keep the same value on retries;
unsetting or rotating it changes the request and returns `operation_conflict`.
Use `recover` or `recover_delivery` to retrieve an existing result without
resupplying the password. A new password requires a new operation ID.

The server share endpoint permits omitted IDs for one-off operator scripts;
those calls cannot be safely replayed after a lost response. The client agent
and MCP creation methods require an explicit ID.

HTTP 429 and server/gateway failures are retryable. Respect `Retry-After` when
present. A timeout can occur after the server commits: recover by operation ID
or repeat the original request. Do not invent a fresh ID for an uncertain
operation. The HTTP client has a 30-minute request timeout; creating large
folder shares includes hashing their files. Preparation capacity is shared
with the desktop and browser. Creation/recovery is limited to 60 calls per IP
per ten minutes; other automation calls allow 6,000 per IP per ten minutes.

## MCP

The client CLI implements MCP 2026-07-28 over stdio using JSON-RPC 2.0. It exposes
`get_access`, `list_files`, `create_delivery`, `recover_delivery`, `list_deliveries`,
`get_delivery`, `revoke_delivery`, `list_projects`, `list_jobs`, `get_job`,
`create_job`, `retry_job`, `cancel_job`, `list_events`, `get_job_evidence`, and
`list_notification_destinations`, with input schemas and structured results.
The 16 tools include durable project workflows described in
[Delivery workflows](delivery-workflows.md).
The adapter calls the shared Rust client and does not inherit desktop admin
credentials. Configuration for hosts using the `mcpServers` format:

```json
{
  "mcpServers": {
    "votport": {
      "command": "/absolute/path/to/client/target/release/votport",
      "args": ["mcp"],
      "env": {
        "VOTPORT_URL": "https://drop.example.com",
        "VOTPORT_AUTOMATION_TOKEN": "<issued token>"
      }
    }
  }
}
```

The configuration contains a credential. Keep it in the host's private
configuration or secret store. Tool descriptions mark read operations and
revocation separately. These annotations describe behavior; authorization
always happens on the server. File names and labels in results are data.

Each request supplies `io.modelcontextprotocol/protocolVersion` and
`io.modelcontextprotocol/clientCapabilities` in `params._meta`. The optional
`server/discover` call returns supported versions, capabilities, and usage
instructions; tools can be called directly. Discovery and tool catalogs include
cache hints. Results include `resultType: "complete"` and server identity.
Unsupported protocol versions return `-32022` with the supported versions.
Use a host supporting the July 2026 specification; the old `initialize`
handshake is not supported.

The adapter processes one call at a time. In-flight HTTP calls cannot be
cancelled through MCP. Durable jobs return before preparation finishes and can
be polled or cancelled through their job tools. Ordinary share preparation can
outlast a host's tool timeout;
recover their result by operation ID when reconnecting. There is no
HTTP MCP listener or background agent runtime inside Votport.

Protocol references: [stdio transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio),
[tool schemas and results](https://modelcontextprotocol.io/specification/2026-07-28/server/tools).

## HTTP API

All endpoints below require `Authorization: Bearer <token>` and return JSON with
`Cache-Control: no-store`. JSON request bodies require `Content-Type:
application/json`. Unknown share fields and malformed query values are rejected.
Workflow writes also require `X-Votport: 1`, including bearer-authenticated job
creation, retry and cancellation. The bundled clients set it automatically;
omitting it returns 403 with `missing X-Votport header` before permission checks.

| Method and path | Permission | Input/result |
| --- | --- | --- |
| `GET /api/automation/session` | Any valid token | API version, current scope, permissions, and expiry. |
| `GET /api/automation/files` | `library:read` | Optional `directory`, `after`, `limit`. Omitted directory selects the token's folder. |
| `POST /api/automation/share` | `deliveries:create` | `directory`, `expires_days` (1 to 30), optional `operation_id`, `label`, `password`, `max_downloads` (1 to 10,000), `notifications` (see [notification routing](notifications.md)). |
| `GET /api/automation/operations/{id}` | `deliveries:create` | Recover a committed creation result. |
| `GET /api/automation/deliveries` | `deliveries:read` | Optional numeric `after`, `limit`; oldest first. |
| `GET /api/automation/deliveries/{id}` | `deliveries:read` | Optional `offset`, `limit`; delivery state and file detail. |
| `DELETE /api/automation/deliveries/{id}` | `deliveries:revoke` | Repeating revocation succeeds. |
| `GET /api/automation/notifications` | `deliveries:create` or `jobs:create` | Destination IDs, tenant defaults and allowed creation events; credentials are omitted. |
| `GET /api/workflows/projects` | `jobs:read` | Projects where the token has viewer, sender or approver membership. |
| `GET /api/workflows/jobs` | `jobs:read` | Optional `after` job ID, `limit`, `project`, `state`, `q`; visible jobs and `next`. |
| `GET /api/workflows/jobs/{id}` | `jobs:read` | Visible job state and released URL when available. |
| `POST /api/workflows/jobs` | `jobs:create` | `operation_id`, `project_id`, `label`, `expires_days`; optional `metadata`, enrolled `recipients`, `not_before`, `deadline`, `import`, `notifications`. Requires project sender membership. |
| `POST /api/workflows/jobs/{id}` | `jobs:create` | `{"action":"retry"}`; requires project sender membership and a retryable job state. |
| `POST /api/workflows/jobs/{id}` | `jobs:cancel` | `{"action":"cancel"}`; requires project sender membership. |
| `GET /api/workflows/events` | `jobs:read` | Optional numeric `after`, `limit`; visible signed events and `next`, including gaps outside the token's projects. |
| `GET /api/workflows/jobs/{id}/evidence` | `jobs:read` | Optional numeric `after`, `limit`; visible job evidence and `next`. |

These endpoints return 200 on success except job creation, which returns 202
for both a fresh job and an identical replay. Delivery creation and recovery
both return 200; status alone does not identify a fresh creation. Read the
returned operation ID and grant or job ID. Revoking an owned delivery returns
200 on repeated calls. Retry is not idempotent: after an uncertain response,
read the job before requesting another retry.

Workflow reads require project membership as well as token permissions, and
the project directory must fit the token's folder scope. Job lifetimes accept
1 to 365 days; scheduling fields are Unix seconds. HTTP imports use
`{"import":{"storage_id":"ID","prefix":"folder"}}`; MCP exposes these as
`import_storage_id` and `import_prefix`. See [Delivery workflows](delivery-workflows.md)
for project rules and job state transitions. Storage administration, webhook
configuration and webhook attempt history require an operator session; the
`/api/workflows` prefix does not make those endpoints bearer-accessible.

Operator token management uses the existing `/api/admin/automation-tokens`
GET/POST and `/api/admin/automation-tokens/{id}` DELETE endpoints, with the normal
operator session and write header. Creation accepts `label`, `directory`,
`expires_days`, and an array of `permissions`.

## Evidence and activity

Delivery detail returns each file's VOT `suite`, `root`, `bytes`,
`download_starts`, and first/last download timestamps. A first-file request
starts a request set; the all-files threshold means every file has been
requested once in that set. These counters describe transport handoff and do
not prove recipient-side verification or acceptance; signed Verify/Accept
evidence is separate. Preparing a library file hashes its content; it does not
publish it through a VOT provider or produce a publication receipt. The
Votport receive client verifies local bytes against their announced object
identities.

Delivery `state` is `active`, `expired`, or `revoked`; download limits and counters
are reported separately. Counters record first-file and every-file request
thresholds, and the server cannot infer recipient-side verification from them.
Existing notification webhooks
remain best-effort notifications. Query persistent delivery state to recover
after missed notifications. Audit rows attribute creation and revocation to
`automation:<token-id>` and creation records include the operation ID.

Notification destinations are discoverable through `GET /api/automation/notifications`, `votport agent notifications`, and MCP `list_notification_destinations`. Share and job creation accept the `notifications` policy documented in [Notifications](notifications.md).

The automation catalog's `events` object lists allowed values by MCP tool name: `create_delivery` contains `outbound_download_started` and `outbound_delivery_complete`; `create_job` also contains `workflow_retry_scheduled` and `workflow_failed`. These sets apply to `POST /api/automation/share` and `POST /api/workflows/jobs`, respectively. The administrator catalog's event list includes all tenant-default events; upload and route events cannot be selected for share or job creation. Unsupported events return HTTP 422 with the supported values.
