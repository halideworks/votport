# Failover automation

Two scripts and a compose example for the active-passive topologies in
`docs/deployment.md` (High availability). Both scripts take the stop and
promote steps as commands, so they drive docker compose over ssh, a local
process, or an orchestrator without changes.

| File | Use |
| --- | --- |
| `planned.sh` | Operator-run: drain the live instance, wait for uploads to finish, stop it, promote the standby, clear the drain on the new live. |
| `watch.sh` | Unattended: probe the live instance's `/healthz`; after a run of misses, fence it and promote the standby. One-shot, re-armed by a person. |
| `docker-compose.standby.yml` | Standby host compose file for the replicated topology, with `standby` and `live` profiles over one data volume. |

Both scripts finish by waiting for the promoted instance to report the
receive-root lease as its own on `/readyz`. If the old instance is in fact
still alive and renewing the lease, the promoted one refuses to boot and the
script reports that instead of forcing anything; the lease is the fence of
last resort and `FENCE_CMD` should fail closed on a dead host (a short ssh
`ConnectTimeout`).

Run `scripts/restart-e2e.mjs` in both modes before relying on either script;
it exercises the same sequence against the real binary.

## Planned failover

```sh
LIVE_URL=https://drop.example.com \
NEW_LIVE_URL=https://drop.example.com \
LIVE_HOST_URL=http://10.0.0.5:8080 \
NEW_LIVE_HOST_URL=http://10.0.0.6:8080 \
VOTPORT_ADMIN_PASSWORD=... \
LIVE_STOP_CMD='ssh live "cd /srv/votport && docker compose stop votport"' \
PROMOTE_CMD='ssh standby "cd /srv/votport && docker compose --profile standby stop && docker compose --profile live up -d"' \
ops/failover/planned.sh
```

`LIVE_HOST_URL` and `NEW_LIVE_HOST_URL` are where `/readyz` is polled
directly, bypassing the proxy (a drained instance answers 503 there on
purpose). For the shared-volume topology `PROMOTE_CMD` starts `votport` on the
standby host over the same volumes. `DRY_RUN=1` prints the stop and promote
commands instead of running them.

## Unattended failover

```sh
LIVE_HOST_URL=http://10.0.0.5:8080 \
NEW_LIVE_HOST_URL=http://10.0.0.6:8080 \
FENCE_CMD='ssh -o ConnectTimeout=5 live "cd /srv/votport && docker compose stop votport" || true' \
PROMOTE_CMD='ssh standby "cd /srv/votport && docker compose --profile standby stop && docker compose --profile live up -d"' \
INTERVAL=10 FAILURES=6 \
ops/failover/watch.sh
```

Sixty seconds of misses (the defaults) is the trigger; the lease's 90 s
staleness then covers a live process that is alive but unreachable from the
watcher. Run the watcher somewhere that is not the live host, and run one
watcher only. After a promotion, point the proxy at the new live (for the
replicated topology it is not in the pool until then) and re-arm the watcher
against the new pair.
