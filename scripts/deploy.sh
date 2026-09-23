#!/bin/bash
# Build, deploy and verify a votport server revision on this host.
#
# Usage: scripts/deploy.sh <git-sha-on-main>
#
# The script refuses to run against a revision that is not on origin/main, and
# refuses an override file whose shape it does not recognise, so the image pin
# and its rollback comment can never drift apart. Every run leaves an evidence
# directory beside the other deploy records.
set -Eeuo pipefail

# The production checkout when invoked from elsewhere (a worktree, a clone).
repo=${VOTPORT_DEPLOY_REPO:-$(cd "$(dirname "$0")/.." && pwd)}
override=$repo/docker-compose.override.yml
sha=${1:?usage: scripts/deploy.sh <git-sha-on-main>}
short=${sha:0:7}
image=votport-local:audit-$short
version=$(git -C "$repo" show "$sha:server/Cargo.toml" | awk -F'"' '/^version = /{print $2; exit}')
evidence="${TMPDIR:-/tmp}/votport-audit-deploy-$short-evidence"
host_port=$(docker port votport 2>/dev/null | awk -F' -> ' '/127.0.0.1/{split($2,a,":"); print a[length(a)]; exit}')

[ "$(git -C "$repo" merge-base --is-ancestor "$sha" origin/main && echo yes)" = yes ] || {
  echo "refusing: $sha is not on origin/main" >&2; exit 1; }
grep -q '^# Deployed main ' "$override" || {
  echo "refusing: $override does not start with a deployed-main comment" >&2; exit 1; }
previous_image=$(awk '/^    image: /{print $2}' "$override")
previous_main=$(awk '/^# Deployed main /{print $4}' "$override")

mkdir -p "$evidence"
echo "== build $image (version $version) =="
git -C "$repo" archive "$sha" | docker build -t "$image" \
  --build-arg "VOTPORT_VERSION=$version" \
  --build-arg "VOTPORT_REVISION=$sha" \
  - > "$evidence/image-build.log" 2>&1
image_id=$(docker image inspect "$image" --format '{{.Id}}')
echo "image $image_id"

echo "== pin $image (was $previous_image) =="
cp "$override" "$evidence/override-before.yml"
python3 - "$override" "$sha" "$short" "$previous_image" <<'PYEOF'
import sys
path, sha, short, previous = sys.argv[1:5]
lines = open(path).read().split('\n')
comment = image = False
for i, line in enumerate(lines):
    if line.startswith('# Deployed main '):
        lines[i] = f'# Deployed main {short} (from {sha}). Previous image: {previous}.'
        comment = True
    elif line.startswith('    image: votport-local:'):
        lines[i] = f'    image: votport-local:audit-{short}'
        image = True
if not (comment and image):
    sys.exit('override shape not recognised')
open(path, 'w').write('\n'.join(lines))
PYEOF
cp "$override" "$evidence/override-after.yml"

previous_schema=$(git -C "$repo" show "$previous_main:server/src/store.rs" 2>/dev/null | awk '/const SCHEMA_VERSION/{sub(";", "", $NF); print $NF; exit}' || true)
schema=$(git -C "$repo" show "$sha:server/src/store.rs" 2>/dev/null | awk '/const SCHEMA_VERSION/{sub(";", "", $NF); print $NF; exit}' || true)
base="http://127.0.0.1:${host_port:-8103}"

# From here on any failed check or command puts the previous image back, so a
# bad build never stays live. Across a schema change the old binary cannot
# open the migrated database, so that case stops and asks for a decision.
fail() {
  # set -E runs the trap inside command substitutions too; only the main
  # shell acts, after the failed substitution returns to it.
  [ "$BASH_SUBSHELL" -eq 0 ] || exit 1
  trap - ERR
  echo "VERIFY FAILED: $1" >&2
  if [ -z "$schema" ] || [ "$previous_schema" != "$schema" ]; then
    echo "NOT ROLLED BACK: $sha may have migrated the database from schema ${previous_schema:-unknown} to ${schema:-unknown}, which $previous_image cannot open; fix forward, or restore a pre-deploy backup before starting $previous_image" >&2
    exit 1
  fi
  echo "restoring $previous_image" >&2
  cp "$evidence/override-before.yml" "$override"
  docker compose up -d > "$evidence/rollback.log" 2>&1 || {
    echo "ROLLBACK FAILED: compose up; see $evidence/rollback.log" >&2
    exit 1
  }
  for _ in $(seq 1 90); do
    [ "$(docker inspect votport --format '{{.Config.Image}}')" = "$previous_image" ] \
      && curl -sf -m 2 "$base/healthz" >/dev/null && exit 1
    sleep 2
  done
  echo "ROLLBACK FAILED: $previous_image is not healthy; see $evidence/rollback.log" >&2
  exit 1
}
trap 'fail "command failed at line $LINENO"' ERR

echo "== deploy =="
cd "$repo"
docker compose up -d 2>&1 | tee "$evidence/compose-up.log" | tail -2

echo "== verify =="
# A schema migration can hold the listener for a while before it serves.
for _ in $(seq 1 90); do curl -sf -m 2 "$base/healthz" >/dev/null && break; sleep 2; done
docker inspect votport --format '{{.State.Status}}' | grep -qx running || fail "container not running"
[ "$(docker exec votport /app/votport --version)" = "votport $version ($sha)" ] || fail "binary version"
curl -sf -m 5 "$base/healthz" >/dev/null || fail healthz
# /readyz answers 503 while drained, which a drain-first upgrade boots into.
ready=$(curl -s -m 5 "$base/readyz")
printf '%s' "$ready" | grep -q '"healthy":true' || fail readyz
printf '%s' "$ready" | grep -q '"mine":true' || fail "lease not owned"
public_url=$(awk -F'"' '/VOTPORT_PUBLIC_URL/{print $2; exit}' "$repo/docker-compose.yml")
host=$(printf '%s' "$public_url" | sed -E 's#https://##')
code=$(curl -s --resolve "$host:443:127.0.0.1" -o /dev/null -w '%{http_code} %{ssl_verify_result}' -m 8 "https://$host/")
[ "$code" = "200 0" ] || fail "public path: $code"
served=$(curl -s --resolve "$host:443:127.0.0.1" -m 8 "https://$host/assets/object-card.js" | sha256sum | cut -d' ' -f1)
local=$(git -C "$repo" show "$sha:web/assets/object-card.js" | sha256sum | cut -d' ' -f1)
[ "$served" = "$local" ] || fail "served asset differs from repo"

cat > "$evidence/deploy-summary.txt" <<EOF
Deployed $(date -u +%FT%TZ): main $short (full $sha), version $version.
Image $image $image_id. Previous: $previous_image (main $previous_main).
Checks: container running; binary version and revision; healthz; readyz healthy+owned;
public path 200 with valid TLS; served object-card.js sha256 == repo.
Rollback: $previous_image remains on the host.
EOF
echo "== done: evidence in $evidence =="
