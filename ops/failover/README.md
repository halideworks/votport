# Failover automation

Two scripts and a compose example for the active-passive topologies in
`docs/deployment.md` (High availability). Both scripts take the stop, fence,
promote, and repoint steps as commands, so they drive docker compose over
ssh, a local process, or an orchestrator without changes.

| File | Use |
| --- | --- |
| `planned.sh` | Operator-run: drain the live instance, wait for uploads to finish, stop it, promote the standby, repoint the proxy, clear the drain on the new live. |
| `watch.sh` | Unattended: probe the live instance's `/healthz`; after a run of misses, fence it, promote the standby, repoint the proxy. One-shot, re-armed by a person. |
| `docker-compose.standby.yml` | Standby host compose file for the replicated topology, with `standby` and `live` profiles over one data volume. |

Both scripts wait for the promoted instance to report the receive-root
lease as its own on `/readyz` before repointing the proxy. If the old
instance is in fact still alive and renewing the lease, the promoted one
refuses to boot, the proxy stays on the old live, and the script reports
that instead of forcing anything: the lease is the fence of last resort. A
fence command that fails because the host is dead is logged and the
promotion proceeds. Every supplied command runs under `CMD_TIMEOUT` so a
wedged docker daemon cannot stall the failover; `planned.sh` defaults it to
600 s because it must exceed the container's `stop_grace_period` (a clean
stop waits for in-flight downloads), `watch.sh` to 120 s.

`LIVE_HOST_URL` and `NEW_LIVE_HOST_URL` are where `/healthz` and `/readyz`
are polled directly from the host running the script, bypassing the proxy (a
drained instance answers 503 there on purpose). Publish the container port on
a LAN address the script can reach, as `docker-compose.standby.yml` does, not
on loopback. `LIVE_URL` and `NEW_LIVE_URL` are the proxied https addresses
the admin API is used through; the admin cookie is `Secure`, so those must
be https.

Run `scripts/restart-e2e.mjs` in both modes before relying on either script;
it exercises the same sequence against the real binary. `DRY_RUN=1` on
either script prints every step and changes nothing (no sign-in, no drain).

## Planned failover

```sh
LIVE_URL=https://drop.example.com \
NEW_LIVE_URL=https://drop.example.com \
LIVE_HOST_URL=http://10.0.0.5:8103 \
NEW_LIVE_HOST_URL=http://10.0.0.6:8103 \
VOTPORT_ADMIN_PASSWORD=... \
LIVE_STOP_CMD='ssh live "cd /srv/votport && docker compose stop votport"' \
PROMOTE_CMD='ssh standby "cd /srv/votport && docker compose --profile standby stop && docker compose --profile live up -d"' \
REPOINT_CMD='ssh proxy "sed -i s/10.0.0.5/10.0.0.6/ /etc/caddy/Caddyfile && caddy reload --config /etc/caddy/Caddyfile"' \
ops/failover/planned.sh
```

Replica topology: `REPOINT_CMD` is required, because a replica-mode standby
is not in the proxy pool until promoted, and the final drain clear goes
through `NEW_LIVE_URL`. Shared-volume topology: `PROMOTE_CMD` starts
`votport` on the standby host over the same volumes and `REPOINT_CMD` can be
omitted when the proxy already pools both hosts. If the script aborts while
the old live is still running, its exit trap clears the drain there; if the
final clear on the new live fails, it says so and the drain is turned off by
hand on the System page. Clearing the drain writes the setting as a database
override, which is what the System page's toggle does too.

## Unattended failover

```sh
LIVE_HOST_URL=http://10.0.0.5:8103 \
NEW_LIVE_HOST_URL=http://10.0.0.6:8103 \
FENCE_CMD='ssh -o ConnectTimeout=5 live "cd /srv/votport && docker compose stop votport"' \
PROMOTE_CMD='ssh standby "cd /srv/votport && docker compose --profile standby stop && docker compose --profile live up -d"' \
REPOINT_CMD='ssh proxy "sed -i s/10.0.0.5/10.0.0.6/ /etc/caddy/Caddyfile && caddy reload --config /etc/caddy/Caddyfile"' \
INTERVAL=10 FAILURES=10 \
ops/failover/watch.sh
```

The watcher arms only after one successful probe, so a wrong URL cannot
fence a healthy instance. Ten misses at ten seconds (the defaults) is the
trigger: it clears the lease's 90 s staleness, so after a crash the promoted
instance boots on the first attempt rather than crash-looping under a
restart policy until the lease expires, and it also covers a live process
that is alive but unreachable from the watcher. Run the watcher somewhere
that is not the live host, and run one watcher only. After a promotion, clear
Drain for restart on the new live if it was on, and re-arm the watcher
against the new pair.
