#!/bin/sh
# Builds the Rust core for the macOS shell: a release static library for the
# host architecture, the UniFFI Swift bindings, and the XCFramework the Swift
# package wraps. Run from anywhere; needs cargo 1.97, cmake (BoringSSL), and
# Xcode. A universal build (arm64 + x86_64) is a release concern, later.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
client="$here/.."
target="${CARGO_TARGET_DIR:-$client/target}"
package="$here/VotportCore"
cargo="${CARGO:-cargo}"

cd "$client"
"$cargo" build --release -p votport-client-core
"$cargo" run -q -p uniffi-bindgen -- generate \
    --library "$target/release/libvotport_client_core.dylib" \
    --language swift --out-dir "$target/bindings"

headers="$target/bindings/headers"
rm -rf "$headers" "$package/VotportCoreFFI.xcframework"
mkdir -p "$headers"
cp "$target/bindings/votport_client_coreFFI.h" "$headers/"
cp "$target/bindings/votport_client_coreFFI.modulemap" "$headers/module.modulemap"
xcodebuild -quiet -create-xcframework \
    -library "$target/release/libvotport_client_core.a" -headers "$headers" \
    -output "$package/VotportCoreFFI.xcframework"
mkdir -p "$package/Sources/VotportCore"
cp "$target/bindings/votport_client_core.swift" "$package/Sources/VotportCore/"
echo "core ready in $package"
