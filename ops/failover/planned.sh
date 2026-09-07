#!/usr/bin/env bash
# Planned failover: drain the live instance, wait for its uploads to finish,
# stop it, promote the standby, repoint the proxy, and clear the drain on
# the new live.
#
# Works for both topologies. The stop, promote, and repoint steps are
# commands you supply, so the same script drives docker compose over ssh, a
# local process, or an orchestrator:
#
#   LIVE_URL=https://drop.example.com \
#   NEW_LIVE_URL=https://drop.example.com \
#   LIVE_HOST_URL=http://10.0.0.5:8103 \
#   NEW_LIVE_HOST_URL=http://10.0.0.6:8103 \
#   VOTPORT_ADMIN_PASSWORD=... \
#   LIVE_STOP_CMD='ssh live "cd /srv/votport && docker compose stop votport"' \
#   PROMOTE_CMD='ssh standby "cd /srv/votport && docker compose --profile standby stop && docker compose --profile live up -d"' \
#   REPOINT_CMD='ssh proxy "sed -i s/10.0.0.5/10.0.0.6/ /etc/caddy/Caddyfile && caddy reload --config /etc/caddy/Caddyfile"' \
#   ops/failover/planned.sh
#
# Shared-volume topology: PROMOTE_CMD starts votport on the standby host over
# the same three volumes (move the data volume in between if it is not
# already shared) and REPOINT_CMD can be empty when the proxy already pools
# both hosts. Replica topology: PROMOTE_CMD stops `votport standby` and
# starts `votport` over its data directory (that boot applies the last
# copy), and REPOINT_CMD must make NEW_LIVE_URL reach the promoted host,
# because a replica-mode standby is not in the proxy pool until then.
#
# LIVE_HOST_URL and NEW_LIVE_HOST_URL are where /readyz is polled directly,
# bypassing the proxy (a drained instance answers 503 there on purpose).
# Optional: DRAIN_TIMEOUT (seconds to wait for sessions_active 0, default
# 1800), READY_TIMEOUT (seconds to wait for the new live to hold the lease,
# default 300), CMD_TIMEOUT (seconds each supplied command may take, default
# 120), DRY_RUN=1 to print every step without signing in, draining, or
# running anything.
#
# If the script aborts with the drain on, the EXIT trap clears it on the old
# live while that instance is still running; after the stop, a failed clear
# on the new live is reported and left for the operator.
set -euo pipefail

: "${LIVE_URL:?LIVE_URL is required}"
: "${NEW_LIVE_URL:?NEW_LIVE_URL is required}"
: "${LIVE_STOP_CMD:?LIVE_STOP_CMD is required}"
: "${PROMOTE_CMD:?PROMOTE_CMD is required}"
REPOINT_CMD="${REPOINT_CMD:-}"
DRAIN_TIMEOUT="${DRAIN_TIMEOUT:-1800}"
READY_TIMEOUT="${READY_TIMEOUT:-300}"
CMD_TIMEOUT="${CMD_TIMEOUT:-120}"
LIVE_HOST_URL="${LIVE_HOST_URL:-$LIVE_URL}"
NEW_LIVE_HOST_URL="${NEW_LIVE_HOST_URL:-$NEW_LIVE_URL}"
DRY_RUN="${DRY_RUN:-0}"

log() { printf '%s failover: %s\n' "$(date -u +%FT%TZ)" "$*"; }
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

if [ "$DRY_RUN" = 1 ]; then
  log "dry run: would sign in to $LIVE_URL and set draining"
  log "dry run: would poll $LIVE_HOST_URL/readyz until sessions_active is 0 (up to ${DRAIN_TIMEOUT}s)"
  run "$LIVE_STOP_CMD"
  run "$PROMOTE_CMD"
  run "$REPOINT_CMD"
  log "dry run: would wait for $NEW_LIVE_HOST_URL/readyz to report lease.mine true (up to ${READY_TIMEOUT}s)"
  log "dry run: would sign in to $NEW_LIVE_URL and clear draining"
  log "dry run complete; nothing was changed"
  exit 0
fi

: "${VOTPORT_ADMIN_PASSWORD:?VOTPORT_ADMIN_PASSWORD is required}"

jar="$(mktemp)"
drained=0
cleanup() {
  if [ "$drained" = 1 ]; then
    log "aborting with the drain on; clearing it on $LIVE_URL"
    set_drain "$LIVE_URL" false || log "could not clear the drain; clear it by hand on the System page"
  fi
  rm -f "$jar"
}
trap cleanup EXIT

# Signs in with the local password and keeps the cookie in the jar.
login() {
  local url="$1"
  curl -fsS -m 30 -c "$jar" -b "$jar" -H 'Content-Type: application/json' \
    -d "{\"password\":$(printf '%s' "$VOTPORT_ADMIN_PASSWORD" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')}" \
    "$url/api/admin/login" >/dev/null
}

# Sets the draining flag through the settings API.
set_drain() {
  local url="$1" value="$2"
  curl -fsS -m 30 -c "$jar" -b "$jar" -H 'Content-Type: application/json' -H 'X-Votport: 1' \
    -X PUT -d "{\"draining\":$value}" "$url/api/admin/settings" >/dev/null
}

# One field of /readyz as JSON, or null when the instance does not answer.
readyz_field() {
  local url="$1" field="$2"
  curl -sS -m 10 "$url/readyz" 2>/dev/null | python3 -c "import json,sys
try:
    value=json.load(sys.stdin)
except Exception:
    value=None
for key in '$field'.split('.'):
    value=value.get(key) if isinstance(value, dict) else None
print(json.dumps(value))" 2>/dev/null || echo null
}

log "signing in to $LIVE_URL"
login "$LIVE_URL"
log "draining $LIVE_URL"
set_drain "$LIVE_URL" true
drained=1

log "waiting up to ${DRAIN_TIMEOUT}s for uploads to finish"
deadline=$((SECONDS + DRAIN_TIMEOUT))
while :; do
  active="$(readyz_field "$LIVE_HOST_URL" sessions_active)"
  if [ "$active" = 0 ]; then
    break
  fi
  if [ "$SECONDS" -ge "$deadline" ]; then
    log "still $active active sessions after ${DRAIN_TIMEOUT}s; aborting (the trap clears the drain)"
    exit 1
  fi
  log "$active active sessions"
  sleep 5
done

log "stopping the live instance"
run "$LIVE_STOP_CMD"
# The old live is gone; the drain setting now lives in the copy the new
# live boots from and is cleared there below.
drained=0
log "promoting the standby"
run "$PROMOTE_CMD"
if [ -n "$REPOINT_CMD" ]; then
  log "repointing the proxy"
  run "$REPOINT_CMD"
fi

log "waiting up to ${READY_TIMEOUT}s for $NEW_LIVE_HOST_URL to hold the lease"
deadline=$((SECONDS + READY_TIMEOUT))
while :; do
  mine="$(readyz_field "$NEW_LIVE_HOST_URL" lease.mine)"
  if [ "$mine" = true ]; then
    break
  fi
  if [ "$SECONDS" -ge "$deadline" ]; then
    log "the new live instance did not come up holding the lease; inspect $NEW_LIVE_HOST_URL/readyz (a live holder still renewing the lease refuses the boot)"
    exit 1
  fi
  sleep 3
done

# The drain setting travelled with the database, so the new live starts
# drained; clear it there through the proxy address, since the admin cookie
# is Secure and only https carries it.
log "signing in to $NEW_LIVE_URL and clearing the drain"
rm -f "$jar"
jar="$(mktemp)"
if login "$NEW_LIVE_URL" && set_drain "$NEW_LIVE_URL" false; then
  log "done: $NEW_LIVE_URL is live and accepting uploads"
else
  log "promoted, but the drain could not be cleared at $NEW_LIVE_URL; turn Drain for restart off on its System page"
  exit 1
fi
