#!/usr/bin/env sh
# Builds vot-wasm and installs the bindings into web/assets/vendor/.
# Usage: scripts/build-wasm.sh [path-to-VOT-checkout]
# Requires: rustup target wasm32-unknown-unknown, wasm-bindgen-cli 0.2.126.
set -eu

here="$(cd "$(dirname "$0")/.." && pwd)"
vot="${1:-$here/..}"

if [ ! -f "$vot/crates/vot-wasm/Cargo.toml" ]; then
    echo "error: $vot is not a VOT checkout (pass one as the first argument)" >&2
    exit 2
fi

(cd "$vot" && cargo build --release \
    -p vot-wasm --target wasm32-unknown-unknown --locked)

mkdir -p "$here/web/assets/vendor"
wasm-bindgen --target web --no-typescript \
    --out-dir "$here/web/assets/vendor" \
    "$vot/target/wasm32-unknown-unknown/release/vot_wasm.wasm"

# Stamp the wasm URL in the loader so the binary is served immutable-cacheable
# (the server keys Cache-Control on a v= query; see /assets in server/src/app.rs).
# The loader itself stays unstamped: it is served no-cache and revalidates, so a
# rebuild changes the stamp browsers see.
# Guard the stamp before using it: sha256sum piped into cut hides its own
# failure from set -e, and an empty stamp would pass the self-referential
# grep below while writing an immutable URL that never changes.
wasm="$here/web/assets/vendor/vot_wasm_bg.wasm"
[ -f "$wasm" ] || { echo "error: $wasm missing after wasm-bindgen" >&2; exit 1; }
stamp="$(sha256sum "$wasm" | cut -c1-16)"
case "$stamp" in
    *[!0-9a-f]* | "") echo "error: bad wasm stamp '$stamp'" >&2; exit 1 ;;
esac
[ "${#stamp}" -eq 16 ] || { echo "error: bad wasm stamp '$stamp'" >&2; exit 1; }
sed -i "s|'vot_wasm_bg.wasm'|'vot_wasm_bg.wasm?v=$stamp'|" \
    "$here/web/assets/vendor/vot_wasm.js"
grep -q "vot_wasm_bg.wasm?v=$stamp" "$here/web/assets/vendor/vot_wasm.js" || {
    echo "error: failed to stamp vot_wasm_bg.wasm reference in vot_wasm.js" >&2
    exit 1
}

echo "installed: $here/web/assets/vendor"
