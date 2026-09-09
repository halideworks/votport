# Agent access

Build the server and desktop clients from the same revision. Agent access is a
folder-scoped delivery workflow shared by the server, browser, desktop core,
CLI, and MCP adapter. It uses the existing library, delivery links, VOT object
identities, download counters, and audit trail.

## Connect

In the browser, open **Deliver > Agent access and automation tokens**. In the
macOS or Windows app, open **Settings > Agent access**. Choose a label, library
folder, expiry, and allowed actions, then issue a token. Copy it immediately.
The desktop apps include the client CLI and can copy an MCP configuration with
its installed path. The browser can copy a configuration whose `command` must
point to the client CLI on the agent's machine.

| Permission | Access |
| --- | --- |
| `library:read` | Browse files and subdirectories within the token's folder. |
| `deliveries:create` | Share a folder and recover URLs for this token's operations. |
| `deliveries:read` | List this token's deliveries and inspect their files, receipts, and download starts. |
| `deliveries:revoke` | Revoke this token's deliveries. Files stay in the library. |

The server enforces these permissions on every call. Reading and revoking a
delivery requires ownership by this exact token, even when another token has
the same tenant and folder. Tokens cannot change settings, manage tenants,
upload or delete library files, or issue receive requests. Those remain operator
workflows. Requests that omit permissions default to `deliveries:create`.

Tokens expire after 1 to 365 days and can be revoked from any operator UI.
Revoking a token stops its API access; already-issued delivery links keep their
own expiry and revocation state. Operators can manage those links in Deliver.
The database stores token hashes, permissions, and operation records, without
raw agent tokens or delivery URLs. Schema 26 migrates existing development data
and preserves existing tokens with create-only permissions.

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
`get_delivery`, and `revoke_delivery`, with input schemas and structured results.
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
cancelled through MCP. Long preparations can outlast a host's tool timeout;
recover their result by operation ID when reconnecting. There is no
HTTP MCP listener or background agent runtime inside Votport.

Protocol references: [stdio transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio),
[tool schemas and results](https://modelcontextprotocol.io/specification/2026-07-28/server/tools).

## HTTP API

All endpoints below require `Authorization: Bearer <token>` and return JSON with
`Cache-Control: no-store`. JSON request bodies require `Content-Type:
application/json`. Unknown share fields and malformed query values are rejected.

| Method and path | Permission | Input/result |
| --- | --- | --- |
| `GET /api/automation/session` | Any valid token | API version, current scope, permissions, and expiry. |
| `GET /api/automation/files` | `library:read` | Optional `directory`, `after`, `limit`. Omitted directory selects the token's folder. |
| `POST /api/automation/share` | `deliveries:create` | `directory`, `expires_days` (1 to 30), optional `operation_id`, `label`, `password`, `max_downloads` (1 to 10,000), `notify_on_download`. |
| `GET /api/automation/operations/{id}` | `deliveries:create` | Recover a committed creation result. |
| `GET /api/automation/deliveries` | `deliveries:read` | Optional numeric `after`, `limit`; oldest first. |
| `GET /api/automation/deliveries/{id}` | `deliveries:read` | Optional `offset`, `limit`; delivery state and file detail. |
| `DELETE /api/automation/deliveries/{id}` | `deliveries:revoke` | Repeating revocation succeeds. |

Operator token management uses the existing `/api/admin/automation-tokens`
GET/POST and `/api/admin/automation-tokens/{id}` DELETE endpoints, with the normal
operator session and write header. Creation accepts `label`, `directory`,
`expires_days`, and an array of `permissions`.

## Evidence and activity

Delivery detail returns each file's VOT `suite`, `root`, `bytes`, base64 CBOR
`receipt_b64`, `download_starts`, and first/last download timestamps. Receipts
can be checked through `/api/verify` or the existing receipt library. A library
receipt attests to the source object; it does not establish that a remote
recipient finished downloading it. The normal Votport receive client verifies
local bytes against their announced object identities.

Delivery `state` is `active`, `expired`, or `revoked`; download limits and counters
are reported separately. Counters record download starts, and the server cannot
infer recipient-side verification from them. Existing notification webhooks
remain best-effort notifications. Query persistent delivery state to recover
after missed notifications. Audit rows attribute creation and revocation to
`automation:<token-id>` and creation records include the operation ID.
