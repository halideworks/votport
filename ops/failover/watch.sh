#!/usr/bin/env bash
# Unattended failover: watches the live instance's /healthz and, after
# FAILURES consecutive misses, fences it and promotes the standby. One-shot:
# after a promotion the script exits and a person re-arms it against the new
# pair, so a flapping network cannot ping-pong two instances.
#
#   LIVE_HOST_URL=http://10.0.0.5:8103 \
#   NEW_LIVE_HOST_URL=http://10.0.0.6:8103 \
#   FENCE_CMD='ssh -o ConnectTimeout=5 live "cd /srv/votport && docker compose stop votport"' \
#   UNFENCE_CMD='ssh -o ConnectTimeout=5 live "cd /srv/votport && docker compose start votport"' \
#   PROMOTE_CMD='ssh standby "cd /srv/votport && docker compose --profile standby stop && docker compose --profile live up -d"' \
#   REPOINT_CMD='ssh proxy "sed -i s/10.0.0.5/10.0.0.6/ /etc/caddy/Caddyfile && caddy reload --config /etc/caddy/Caddyfile"' \
#   ops/failover/watch.sh
#
# The watcher arms only after one successful probe, so a wrong URL cannot
# fence a healthy instance. A fence that fails (the host is dead) is logged
# and promotion proceeds, but a holder of the shared receive-root kernel
# lock prevents the new instance from booting. Heartbeat age cannot release
# that lock. Run one watcher, and not on the live host.
#
# A promote that fails after the fence is rolled back: UNFENCE_CMD (the
# inverse of FENCE_CMD) restarts the previously-live instance, the rollback
# is logged loudly, and the script exits non-zero. The proxy is never
# repointed before the promoted instance holds the lease, so a failed
# promote cannot leave traffic on the standby; if anything repointed it
# anyway, the script prints the reverse repoint (see README.md).
#
# Optional: INTERVAL (seconds between probes, default 10), FAILURES
# (consecutive misses before acting, default 10), READY_TIMEOUT
# (seconds to wait for the promoted instance, default 300), CMD_TIMEOUT
# (seconds each supplied command may take, default 120), DRY_RUN=1 (print
# every step, run nothing).
set -euo pipefail

# python3 parses the /readyz JSON that gates the repoint.
command -v python3 >/dev/null 2>&1 || {
  echo "python3 is required on the host running this script" >&2
  exit 1
}

: "${LIVE_HOST_URL:?LIVE_HOST_URL is required}"
: "${NEW_LIVE_HOST_URL:?NEW_LIVE_HOST_URL is required}"
: "${FENCE_CMD:?FENCE_CMD is required}"
: "${UNFENCE_CMD:?UNFENCE_CMD is required: the inverse of FENCE_CMD, run to restart the old live when a promote fails}"
: "${PROMOTE_CMD:?PROMOTE_CMD is required}"
REPOINT_CMD="${REPOINT_CMD:-}"
INTERVAL="${INTERVAL:-10}"
FAILURES="${FAILURES:-10}"
READY_TIMEOUT="${READY_TIMEOUT:-300}"
CMD_TIMEOUT="${CMD_TIMEOUT:-120}"
DRY_RUN="${DRY_RUN:-0}"

log() { printf '%s watch: %s\n' "$(date -u +%FT%TZ)" "$*"; }
run() {
  if [ -z "$1" ]; then
    return 0
  fi
  if [ "$DRY_RUN" = 1 ]; then
    log "would run: $1"
  else
    log "running: $1"
    timeout "$CMD_TIMEOUT" bash -c "$1" || {
      local status=$?
      log "command exited $status (124 is the ${CMD_TIMEOUT}s timeout)"
      return "$status"
    }
  fi
}
probe() { curl -fsS -m 5 -o /dev/null "$LIVE_HOST_URL/healthz"; }

if ! probe; then
  log "not armed: $LIVE_HOST_URL/healthz does not answer now; fix the URL or the network before watching"
  exit 2
fi

# A rehearsal must not wait for real misses: print the whole run here, while
# the live instance is still healthy, instead of after the probe loop.
if [ "$DRY_RUN" = 1 ]; then
  log "dry run: would watch $LIVE_HOST_URL/healthz every ${INTERVAL}s and act after $FAILURES consecutive misses"
  run "$FENCE_CMD"
  run "$PROMOTE_CMD"
  log "dry run: would wait up to ${READY_TIMEOUT}s for $NEW_LIVE_HOST_URL/readyz to report lease.mine true"
  run "$REPOINT_CMD"
  log "dry run: a failed promote would run UNFENCE_CMD to restart the old live, then exit non-zero"
  log "dry run complete; nothing was changed"
  exit 0
fi

misses=0
log "armed: watching $LIVE_HOST_URL/healthz every ${INTERVAL}s; acting after $FAILURES misses"
while :; do
  sleep "$INTERVAL"
  if probe; then
    if [ "$misses" -gt 0 ]; then
      log "live instance answered again after $misses misses"
    fi
    misses=0
  else
    misses=$((misses + 1))
    log "miss $misses of $FAILURES"
    if [ "$misses" -ge "$FAILURES" ]; then
      break
    fi
  fi
done

log "live instance unreachable; fencing"
run "$FENCE_CMD" || log "fence exited non-zero (host dead or unreachable); the lease is the fence of last resort, continuing"
log "promoting the standby"
if ! run "$PROMOTE_CMD"; then
  log "PROMOTE FAILED; rolling back: restarting the fenced live instance with UNFENCE_CMD"
  if ! run "$UNFENCE_CMD"; then
    log "the rollback restart failed as well; the site is down: run the inverse of FENCE_CMD by hand, then inspect $NEW_LIVE_HOST_URL/readyz and the receive root's .votport-lease before promoting again"
  fi
  log "the proxy was not repointed before the failed promote; if anything pointed it at the standby anyway, reverse that by hand: the inverse sed swaps the two addresses (for the example above, sed -i s/10.0.0.6/10.0.0.5/ /etc/caddy/Caddyfile && caddy reload --config /etc/caddy/Caddyfile); see ops/failover/README.md"
  exit 1
fi

# The proxy is repointed only once the promoted instance holds the lease:
# a false alarm (live healthy but unreachable from here) leaves the site
# on the old live, which the lease kept in charge.
log "waiting up to ${READY_TIMEOUT}s for $NEW_LIVE_HOST_URL to hold the lease"
deadline=$((SECONDS + READY_TIMEOUT))
while :; do
  body="$(curl -sS -m 5 "$NEW_LIVE_HOST_URL/readyz" 2>/dev/null || true)"
  mine="$(printf '%s' "$body" | python3 -c 'import json,sys
try:
    print(json.dumps(json.load(sys.stdin).get("lease", {}).get("mine")))
except Exception:
    print("null")')"
  if [ "$mine" = true ]; then
    if [ -n "$REPOINT_CMD" ]; then
      log "repointing the proxy"
      run "$REPOINT_CMD" || {
        log "promoted, but the repoint failed: $NEW_LIVE_HOST_URL holds the lease; repoint by hand, clear Drain for restart if it was on, and re-arm this watch"
        exit 1
      }
    fi
    log "promoted: $NEW_LIVE_HOST_URL holds the lease; clear Drain for restart if it was on, and re-arm this watch against the new pair"
    exit 0
  fi
  if [ "$SECONDS" -ge "$deadline" ]; then
    log "the promoted instance did not come up holding the lease (a live holder still renewing it refuses the boot); the proxy was not repointed; inspect $NEW_LIVE_HOST_URL/readyz and the receive root's .votport-lease"
    exit 1
  fi
  sleep 3
done
