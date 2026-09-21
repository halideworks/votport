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

repo=$(cd "$(dirname "$0")/.." && pwd)
override=$repo/docker-compose.override.yml
sha=${1:?usage: scripts/deploy.sh <git-sha-on-main>}
short=${sha:0:7}
image=votport-local:audit-$short
version=$(awk -F'"' '/^version = /{print $2; exit}' "$repo/server/Cargo.toml")
evidence="/nvme-mirror/temp/claude/tmp/votport-audit-deploy-$short-evidence"
host_port=$(docker port votport 2>/dev/null | awk -F' -> ' '/127.0.0.1/{split($2,a,":"); print a[length(a)]; exit}')

[ "$(git -C "$repo" merge-base --is-ancestor "$sha" origin/main && echo yes)" = yes ] || {
  echo "refusing: $sha is not on origin/main" >&2; exit 1; }
grep -q '^# Deployed main ' "$override" || {
  echo "refusing: $override does not start with a deployed-main comment" >&2; exit 1; }
previous_image=$(awk '/^    image: /{print $2}' "$override")
previous_main=$(awk '/^# Deployed main /{print $4}' "$override")

mkdir -p "$evidence"
echo "== build $image (version $version) =="
docker build -t "$image" \
  --build-arg "VOTPORT_VERSION=$version" \
  --build-arg "VOTPORT_REVISION=$sha" \
  "$repo" > "$evidence/image-build.log" 2>&1
image_id=$(docker image inspect "$image" --format '{{.Id}}')
echo "image $image_id"

echo "== pin $image (was $previous_image) =="
cp "$override" "$evidence/override-before.yml"
python3 - "$override" "$sha" "$short" "$previous_image" <<'PYEOF'
import sys
path, sha, short, previous = sys.argv[1:5]
lines = open(path).read().split('\n')
for i, line in enumerate(lines):
    if line.startswith('# Deployed main '):
        lines[i] = f'# Deployed main {short} (from {sha}). Previous image: {previous}.'
        break
    if line.startswith('    image: votport-local:'):
        lines[i] = f'    image: votport-local:audit-{short}'
        break
else:
    sys.exit('override shape not recognised')
for line in lines:
    if line.startswith('    image: votport-local:') and not line.endswith(f'audit-{short}'):
        sys.exit('multiple image lines; refusing')
open(path, 'w').write('\n'.join(lines))
PYEOF
cp "$override" "$evidence/override-after.yml"

echo "== deploy =="
cd "$repo"
docker compose up -d 2>&1 | tee "$evidence/compose-up.log" | tail -2
sleep 8

echo "== verify =="
fail() { echo "VERIFY FAILED: $1" >&2; exit 1; }
docker inspect votport --format '{{.State.Status}}' | grep -qx running || fail "container not running"
docker logs votport 2>&1 | grep -a "revision=$sha" >/dev/null || fail "boot log revision stamp"
curl -sf -m 5 "http://127.0.0.1:${host_port:-8103}/healthz" >/dev/null || fail healthz
curl -sf -m 5 "http://127.0.0.1:${host_port:-8103}/readyz" | grep -q '"healthy":true' || fail readyz
curl -sf -m 5 "http://127.0.0.1:${host_port:-8103}/readyz" | grep -q '"mine":true' || fail "lease not owned"
public_url=$(awk -F'"' '/VOTPORT_PUBLIC_URL/{print $2; exit}' "$repo/docker-compose.yml")
host=$(printf '%s' "$public_url" | sed -E 's#https://##')
code=$(curl -s --resolve "$host:443:127.0.0.1" -o /dev/null -w '%{http_code} %{ssl_verify_result}' -m 8 "https://$host/")
[ "$code" = "200 0" ] || fail "public path: $code"
served=$(curl -s --resolve "$host:443:127.0.0.1" -m 8 "https://$host/assets/object-card.js" | sha256sum | cut -d' ' -f1)
local=$(sha256sum "$repo/web/assets/object-card.js" | cut -d' ' -f1)
[ "$served" = "$local" ] || fail "served asset differs from repo"

cat > "$evidence/deploy-summary.txt" <<EOF
Deployed $(date -u +%FT%TZ): main $short (full $sha), version $version.
Image $image $image_id. Previous: $previous_image (main $previous_main).
Checks: container running; revision stamp; healthz; readyz healthy+owned;
public path 200 with valid TLS; served object-card.js sha256 == repo.
Rollback: $previous_image remains on the host.
EOF
echo "== done: evidence in $evidence =="
