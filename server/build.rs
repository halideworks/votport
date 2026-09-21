//! Stamps the build instant so start-up can refuse a wall clock that reads
//! earlier than it: a dead RTC boots before chrony corrects it, and serving
//! from that state admits every expired credential (audit finding 407).
//!
//! Licensed under the VOTPORT PROPRIETARY LICENSE.

use std::path::PathBuf;

fn main() {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the build machine clock is before the epoch")
        .as_secs();
    // A source-tree file included by relative path: compile-time env
    // (rustc-env and OUT_DIR) is not replayed through every rustc wrapper
    // (the release image recompiles under cargo auditable after touching
    // sources), while a relative include! resolves without any env.
    let stamp: PathBuf =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("src/.build_stamp");
    std::fs::write(&stamp, format!("{seconds}\n")).expect("writing the build stamp");
    // The stamp is the build script's real output but lives in the source
    // tree (gitignored, so a fresh checkout has none) while its fingerprints
    // ride the target dir, which CI caches: a restored cache can believe the
    // script already ran on a tree that has no stamp, and the include! then
    // fails to compile. Tracking the stamp itself makes a missing file rerun
    // this script, which recreates it.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/.build_stamp");
}
