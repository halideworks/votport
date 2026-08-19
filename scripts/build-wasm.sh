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

echo "installed: $here/web/assets/vendor"
