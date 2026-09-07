#!/usr/bin/env bash
# Unattended failover: watches the live instance's /healthz and, after
# FAILURES consecutive misses, fences it and promotes the standby. One-shot:
# after a promotion the script exits and a person re-arms it against the new
# pair, so a flapping network cannot ping-pong two instances.
#
#   LIVE_HOST_URL=http://10.0.0.5:8103 \
#   NEW_LIVE_HOST_URL=http://10.0.0.6:8103 \
#   FENCE_CMD='ssh -o ConnectTimeout=5 live "cd /srv/votport && docker compose stop votport"' \
#   PROMOTE_CMD='ssh standby "cd /srv/votport && docker compose --profile standby stop && docker compose --profile live up -d"' \
#   REPOINT_CMD='ssh proxy "sed -i s/10.0.0.5/10.0.0.6/ /etc/caddy/Caddyfile && caddy reload --config /etc/caddy/Caddyfile"' \
#   ops/failover/watch.sh
#
# The watcher arms only after one successful probe, so a wrong URL cannot
# fence a healthy instance. A fence that fails (the host is dead) is logged
# and the promotion proceeds: the receive-root lease is the fence of last
# resort, and a live process that is in fact alive keeps renewing it, so the
# promoted instance refuses to boot and this script reports that rather
# than retries. Run one watcher, and not on the live host.
#
# Optional: INTERVAL (seconds between probes, default 10), FAILURES
# (consecutive misses before acting, default 10, so the trigger clears the
# lease's 90 s staleness on the first promotion attempt), READY_TIMEOUT
# (seconds to wait for the promoted instance, default 300), CMD_TIMEOUT
# (seconds each supplied command may take, default 120), DRY_RUN=1.
set -euo pipefail

: "${LIVE_HOST_URL:?LIVE_HOST_URL is required}"
: "${NEW_LIVE_HOST_URL:?NEW_LIVE_HOST_URL is required}"
: "${FENCE_CMD:?FENCE_CMD is required}"
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
    timeout "$CMD_TIMEOUT" bash -c "$1"
  fi
}
probe() { curl -fsS -m 5 -o /dev/null "$LIVE_HOST_URL/healthz"; }

if ! probe; then
  log "not armed: $LIVE_HOST_URL/healthz does not answer now; fix the URL or the network before watching"
  exit 2
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
run "$PROMOTE_CMD"
if [ -n "$REPOINT_CMD" ]; then
  log "repointing the proxy"
  run "$REPOINT_CMD"
fi
if [ "$DRY_RUN" = 1 ]; then
  log "dry run complete; nothing was changed"
  exit 0
fi

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
    log "promoted: $NEW_LIVE_HOST_URL holds the lease; clear Drain for restart if it was on, and re-arm this watch against the new pair"
    exit 0
  fi
  if [ "$SECONDS" -ge "$deadline" ]; then
    log "the promoted instance did not come up holding the lease (a live holder still renewing it refuses the boot); inspect $NEW_LIVE_HOST_URL/readyz and the receive root's .votport-lease"
    exit 1
  fi
  sleep 3
done
