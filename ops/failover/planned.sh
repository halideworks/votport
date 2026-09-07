#!/usr/bin/env bash
# Planned failover: drain the live instance, wait for its uploads to finish,
# stop it, promote the standby, and clear the drain on the new live.
#
# Works for both topologies. The stop and promote steps are commands you
# supply, so the same script drives docker compose over ssh, a local
# process, or an orchestrator:
#
#   LIVE_URL=https://drop.example.com \
#   NEW_LIVE_URL=https://drop.example.com \
#   VOTPORT_ADMIN_PASSWORD=... \
#   LIVE_STOP_CMD='ssh live "cd /srv/votport && docker compose stop votport"' \
#   PROMOTE_CMD='ssh standby "cd /srv/votport && docker compose --profile standby stop && docker compose --profile live up -d"' \
#   ops/failover/planned.sh
#
# Shared-volume topology: PROMOTE_CMD starts votport on the standby host over
# the same three volumes (move the data volume in between if it is not
# already shared). Replica topology: PROMOTE_CMD stops `votport standby` and
# starts `votport` over its data directory; that boot applies the last copy.
#
# Optional: DRAIN_TIMEOUT (seconds to wait for sessions_active 0, default
# 1800), READY_TIMEOUT (seconds to wait for the new live, default 300),
# LIVE_HOST_URL (where to poll /readyz on the old live directly, default
# LIVE_URL), NEW_LIVE_HOST_URL (same for the new live, default NEW_LIVE_URL),
# DRY_RUN=1 to print the commands instead of running them.
set -euo pipefail

: "${LIVE_URL:?LIVE_URL is required}"
: "${NEW_LIVE_URL:?NEW_LIVE_URL is required}"
: "${VOTPORT_ADMIN_PASSWORD:?VOTPORT_ADMIN_PASSWORD is required}"
: "${LIVE_STOP_CMD:?LIVE_STOP_CMD is required}"
: "${PROMOTE_CMD:?PROMOTE_CMD is required}"
DRAIN_TIMEOUT="${DRAIN_TIMEOUT:-1800}"
READY_TIMEOUT="${READY_TIMEOUT:-300}"
LIVE_HOST_URL="${LIVE_HOST_URL:-$LIVE_URL}"
NEW_LIVE_HOST_URL="${NEW_LIVE_HOST_URL:-$NEW_LIVE_URL}"
DRY_RUN="${DRY_RUN:-0}"

log() { printf '%s failover: %s\n' "$(date -u +%FT%TZ)" "$*"; }
run() {
  if [ "$DRY_RUN" = 1 ]; then
    log "would run: $*"
  else
    log "running: $*"
    bash -c "$*"
  fi
}

jar="$(mktemp)"
trap 'rm -f "$jar"' EXIT

# Signs in with the local password and keeps the cookie in the jar.
login() {
  local url="$1"
  curl -fsS -c "$jar" -b "$jar" -H 'Content-Type: application/json' \
    -d "{\"password\":$(printf '%s' "$VOTPORT_ADMIN_PASSWORD" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')}" \
    "$url/api/admin/login" >/dev/null
}

# Sets the draining flag through the settings API.
set_drain() {
  local url="$1" value="$2"
  curl -fsS -c "$jar" -b "$jar" -H 'Content-Type: application/json' -H 'X-Votport: 1' \
    -X PUT -d "{\"draining\":$value}" "$url/api/admin/settings" >/dev/null
}

readyz_field() {
  local url="$1" field="$2"
  curl -sS "$url/readyz" | python3 -c "import json,sys
body=json.load(sys.stdin)
value=body
for key in '$field'.split('.'):
    value=value.get(key) if isinstance(value, dict) else None
print(json.dumps(value))"
}

log "signing in to $LIVE_URL"
login "$LIVE_URL"
log "draining $LIVE_URL"
set_drain "$LIVE_URL" true

log "waiting up to ${DRAIN_TIMEOUT}s for uploads to finish"
deadline=$((SECONDS + DRAIN_TIMEOUT))
while :; do
  active="$(readyz_field "$LIVE_HOST_URL" sessions_active)"
  if [ "$active" = 0 ]; then
    break
  fi
  if [ "$SECONDS" -ge "$deadline" ]; then
    log "still $active active sessions after ${DRAIN_TIMEOUT}s; clearing the drain and aborting"
    set_drain "$LIVE_URL" false
    exit 1
  fi
  log "$active active sessions"
  sleep 5
done

log "stopping the live instance"
run "$LIVE_STOP_CMD"
log "promoting the standby"
run "$PROMOTE_CMD"

if [ "$DRY_RUN" = 1 ]; then
  log "dry run complete"
  exit 0
fi

log "waiting up to ${READY_TIMEOUT}s for $NEW_LIVE_HOST_URL to hold the lease"
deadline=$((SECONDS + READY_TIMEOUT))
while :; do
  mine="$(readyz_field "$NEW_LIVE_HOST_URL" lease.mine 2>/dev/null || echo null)"
  if [ "$mine" = true ]; then
    break
  fi
  if [ "$SECONDS" -ge "$deadline" ]; then
    log "the new live instance did not come up holding the lease; inspect $NEW_LIVE_HOST_URL/readyz"
    exit 1
  fi
  sleep 3
done

# The drain setting travelled with the database (shared volume or replica),
# so the new live starts drained; clear it there.
log "signing in to $NEW_LIVE_URL and clearing the drain"
rm -f "$jar"
login "$NEW_LIVE_URL"
set_drain "$NEW_LIVE_URL" false
log "done: $NEW_LIVE_URL is live and accepting uploads"
