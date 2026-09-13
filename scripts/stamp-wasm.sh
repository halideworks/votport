#!/bin/sh
# Usage: scripts/stamp-wasm.sh <wasm-bindgen output directory>
# The server serves v= URLs immutably, so the stamp must match the binary.
set -eu

vendor="${1:?pass the wasm-bindgen output directory}"
wasm="$vendor/vot_wasm_bg.wasm"
loader="$vendor/vot_wasm.js"
[ -f "$wasm" ] || { echo "error: $wasm missing after wasm-bindgen" >&2; exit 1; }
hash="$(sha256sum "$wasm")"
stamp="$(printf '%s' "$hash" | cut -c1-16)"
case "$stamp" in
    *[!0-9a-f]* | "") echo "error: bad wasm stamp '$stamp'" >&2; exit 1 ;;
esac
[ "${#stamp}" -eq 16 ] || { echo "error: bad wasm stamp '$stamp'" >&2; exit 1; }
sed -Ei "s|'vot_wasm_bg\.wasm(\?v=[0-9a-f]{16})?'|'vot_wasm_bg.wasm?v=$stamp'|" "$loader"
grep -Fq "'vot_wasm_bg.wasm?v=$stamp'" "$loader" || {
    echo "error: failed to stamp vot_wasm_bg.wasm reference in vot_wasm.js" >&2
    exit 1
}
