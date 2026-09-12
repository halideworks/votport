# Workplace notifications

Open **Notifications** in the main navigation to manage destinations for the
current tenant. Tenant administrators can add multiple connections for each
service, rename them, replace credentials, test, disable, or delete them. Viewers
can inspect destinations and routing; auditors cannot access them. Switching
tenants switches the destination catalog. Tenant deletion removes its connections
and defaults, including stored credentials.

Each destination has a name and destination description. For Slack, Teams and
Google Chat, configure the real channel, chat, or space when creating the webhook
in that service. The description in Votport is a label, not a channel override.
Discord also accepts a thread ID; forum and media channels require a thread.
Email destinations have their own recipient lists and use the server SMTP relay.
JSON webhooks and ntfy support optional bearer tokens. Pushover destinations have
an application token and a user or group key. Credentials never appear in the
named-destination API responses, logs, or audit records. Blank credential fields
preserve saved values. A connection's service cannot be changed in place.

Administrators configuring destinations are trusted to choose network endpoints,
as with workflow storage and automation webhooks. URLs must be HTTP(S), with no
userinfo, fragments, or control characters. Redirects remain disabled. Tests send
only to the selected saved destination. The last accepted/failed attempt is shown
on its card. Acceptance by a webhook is not confirmation that a person saw it.

Receive creation and editing, delivery-link creation and editing, project
settings, workflow delivery creation, and receive workflow configuration use the
same notification editor:

- **Off** sends nothing.
- **Use tenant defaults** uses the current tenant's explicitly configured rules.
  The editor shows the matching destinations and events. Empty defaults send
  nothing. Changes to defaults affect subscribers immediately.
- **Choose destinations and events** subscribes to selected events at each named
  destination. Add a destination, expand its event summary, and select the events
  to send. Remove a destination to stop including it in that policy. Selecting
  one destination never subscribes to the other entries.
- Workflow deliveries and receive workflows can **Use project settings**. The
  project settings are captured when the job is created. Changing only a project's
  notifications does not invalidate existing downloads; it applies to future jobs.

The supported events are `upload_complete`, `upload_failed`,
`outbound_download_started`, `outbound_delivery_complete`,
`workflow_retry_scheduled`, and `workflow_failed`. Receive requests offer the two
upload events. Delivery links offer the two download events. Workflows offer
both download events and the retry/failure events. A first download that also
completes a delivery emits both subscribed events. An interrupted upload without
received bytes and a sender cancellation do not send failure notifications.

There are at most 100 named destinations per tenant and 32 destinations per
custom subscription. Notification delivery remains best effort, outside transfer
completion, with at most eight destinations in flight per event. A failed
connection does not prevent the other selected destinations from receiving their
messages. These notifications do not replace the signed, retrying delivery-event
webhook under Workflows.

## Named-destination API

Destination mutations require an administrator cookie and `X-Votport: 1`.
Read responses use `Cache-Control: no-store`.

- `GET /api/notifications`: tenant destinations, tenant
  defaults, event names, and latest destination outcomes. Credentials are omitted.
- `POST /api/notifications`: create or update a destination. Supply `label`,
  `channel`, `target`, `enabled`, and service fields `url`, `token`, `user`,
  `recipients`, or `thread_id`. For an update, also supply its `id` and `revision`;
  stale updates are rejected. `clear_token: true` removes an optional bearer token.
- `POST /api/notifications/{id}/test`: test the saved, enabled destination.
  Failures return 502.
- `DELETE /api/notifications/{id}` with `{"revision": N}`: delete a destination.
  References remain visibly unavailable and send nothing; they never fall back to
  another destination.
- `PUT /api/notifications/defaults`: save an `off` or `custom` notification policy.
- `GET /api/automation/notifications`: read the catalog with an automation bearer
  that has `deliveries:create` or `jobs:create` permission.

A notification policy has this shape:

```json
{
  "mode": "custom",
  "rules": [
    {"destination_id": "destination-id", "events": ["upload_complete"]},
    {"destination_id": "another-id", "events": ["upload_failed"]}
  ]
}
```

Set `notifications` on receive-link and outbound-grant creation requests, on
`POST /api/automation/share`, on workflow projects and job requests, and inside a
receive request's `workflow` object. PATCH an existing receive link or outbound
grant with `{"notifications": {...}}` as its single policy action. Server-side
validation restricts destinations to the tenant and events to the resource type.
An omitted notification policy sends nothing. Workflow deliveries may inherit the project’s policy.

`votport agent notifications` lists destinations. `votport agent share` accepts
`--notifications '{"mode":"default"}'` or a custom policy. MCP exposes
`list_notification_destinations`, and `create_delivery` and `create_job` accept a
`notifications` object. Job JSON files passed to `agent create-job` accept the
same object. Local desktop notification-center preferences still control alerts
on that device.

Existing workflow jobs also expose notification settings on their cards. These
edits apply to future events and the job's download link, including a link that
is still being prepared. They leave the original creation request unchanged, so
retries retain their identity. `PATCH /api/workflows/jobs/{id}/notifications`
accepts a policy directly, or JSON `null` to return to the job's captured request
and project settings. It requires project sender access (and `jobs:create` for
an automation bearer). Changing settings does not replay earlier events.

## Trade routes

Trade routes use the same tenant destination catalog for approval requests,
approval, identity changes, failures, recovery, and verified receipt. Configure
incoming notifications on the receiving endpoint and outgoing notifications when
accepting its invitation; each directional route also has its own editor. A route's
verified-receipt notification is independent of the Receive request's ordinary
upload notification policy. Custom rules are captured when each delivery leg is
created. Tenant-default subscriptions resolve the current defaults when sending.
Webhook credentials and recipient lists never travel in a route invitation.
