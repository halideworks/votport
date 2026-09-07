#!/usr/bin/env bash
# Unattended failover: watches the live instance's /healthz and, after
# FAILURES consecutive misses, fences it and promotes the standby. One-shot:
# after a promotion the script exits and a person re-arms it against the new
# pair, so a flapping network cannot ping-pong two instances.
#
#   LIVE_HOST_URL=http://10.0.0.5:8080 \
#   NEW_LIVE_HOST_URL=http://10.0.0.6:8080 \
#   FENCE_CMD='ssh live "cd /srv/votport && docker compose stop votport" || true' \
#   PROMOTE_CMD='ssh standby "cd /srv/votport && docker compose --profile standby stop && docker compose --profile live up -d"' \
#   ops/failover/watch.sh
#
# FENCE_CMD should fail closed on a dead host (a short ssh ConnectTimeout);
# the receive-root lease is the fence of last resort: a live process that is
# actually alive keeps renewing it and the promoted instance refuses to
# boot, which this script reports rather than retries.
#
# Optional: INTERVAL (seconds between probes, default 10), FAILURES
# (consecutive misses before acting, default 6), READY_TIMEOUT (seconds to
# wait for the promoted instance, default 300), DRY_RUN=1.
set -euo pipefail

: "${LIVE_HOST_URL:?LIVE_HOST_URL is required}"
: "${NEW_LIVE_HOST_URL:?NEW_LIVE_HOST_URL is required}"
: "${FENCE_CMD:?FENCE_CMD is required}"
: "${PROMOTE_CMD:?PROMOTE_CMD is required}"
INTERVAL="${INTERVAL:-10}"
FAILURES="${FAILURES:-6}"
READY_TIMEOUT="${READY_TIMEOUT:-300}"
DRY_RUN="${DRY_RUN:-0}"

log() { printf '%s watch: %s\n' "$(date -u +%FT%TZ)" "$*"; }
run() {
  if [ "$DRY_RUN" = 1 ]; then
    log "would run: $*"
  else
    log "running: $*"
    bash -c "$*"
  fi
}

misses=0
log "watching $LIVE_HOST_URL/healthz every ${INTERVAL}s; acting after $FAILURES misses"
while :; do
  if curl -fsS -m 5 -o /dev/null "$LIVE_HOST_URL/healthz"; then
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
  sleep "$INTERVAL"
done

log "live instance unreachable; fencing"
run "$FENCE_CMD"
log "promoting the standby"
run "$PROMOTE_CMD"
if [ "$DRY_RUN" = 1 ]; then
  log "dry run complete"
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
    log "promoted: $NEW_LIVE_HOST_URL holds the lease; re-arm this watch against the new pair"
    exit 0
  fi
  if [ "$SECONDS" -ge "$deadline" ]; then
    log "the promoted instance did not come up holding the lease (a live holder still renewing it refuses the boot); inspect $NEW_LIVE_HOST_URL/readyz and the receive root's .votport-lease"
    exit 1
  fi
  sleep 3
done
