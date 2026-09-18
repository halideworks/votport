#!/bin/sh
# Builds the Rust core for the macOS shell: release static libraries for
# both Apple silicon and Intel lipoed into one universal XCFramework slice,
# the UniFFI Swift bindings, and the universal CLI the Swift package wraps.
# Run from anywhere; needs cargo 1.97, cmake (BoringSSL), and Xcode. It also
# stamps the app's version from the core's Cargo.toml into project.yml, so
# regeneration carries the number.
set -eu
# Match the deployment floor of the Swift app and its native dependencies.
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-14.0}"
here=$(cd "$(dirname "$0")" && pwd)
client="$here/.."
target="${CARGO_TARGET_DIR:-$client/target}"
package="$here/VotportCore"
cargo="${CARGO:-cargo}"

cd "$client"
"$cargo" build --locked --release -p votport-client-core -p votport-client --target aarch64-apple-darwin
"$cargo" build --locked --release -p votport-client-core -p votport-client --target x86_64-apple-darwin
"$cargo" run --locked -q -p uniffi-bindgen -- generate \
    --library "$target/aarch64-apple-darwin/release/libvotport_client_core.dylib" \
    --language swift --out-dir "$target/bindings"

# One version everywhere: the core's Cargo.toml is the source of truth, the
# same number the shells show as "Core" in Settings. The app's marketing
# version is stamped into the XcodeGen project here, so the bundle, the
# Windows manifests, and the core move together.
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' core/Cargo.toml | head -1)
case "$version" in
    "" | *[!0-9.]*) echo "error: no plain version in core/Cargo.toml" >&2; exit 1 ;;
esac
sed -i '' "s/^        MARKETING_VERSION: \".*\"/        MARKETING_VERSION: \"$version\"/" project.yml
grep -Fq "MARKETING_VERSION: \"$version\"" project.yml || {
    echo "error: failed to stamp MARKETING_VERSION in project.yml" >&2
    exit 1
}

universal="$target/universal"
mkdir -p "$universal"
lipo -create -output "$universal/libvotport_client_core.a" \
    "$target/aarch64-apple-darwin/release/libvotport_client_core.a" \
    "$target/x86_64-apple-darwin/release/libvotport_client_core.a"
lipo -create -output "$universal/votport" \
    "$target/aarch64-apple-darwin/release/votport" \
    "$target/x86_64-apple-darwin/release/votport"

headers="$target/bindings/headers"
rm -rf "$headers" "$package/VotportCoreFFI.xcframework"
mkdir -p "$headers"
cp "$target/bindings/votport_client_coreFFI.h" "$headers/"
cp "$target/bindings/votport_client_coreFFI.modulemap" "$headers/module.modulemap"
xcodebuild -quiet -create-xcframework \
    -library "$universal/libvotport_client_core.a" -headers "$headers" \
    -output "$package/VotportCoreFFI.xcframework"
mkdir -p "$package/Sources/VotportCore"
cp "$target/bindings/votport_client_core.swift" "$package/Sources/VotportCore/"
cp "$universal/votport" "$package/votport-cli"
echo "core ready in $package (version $version)"
