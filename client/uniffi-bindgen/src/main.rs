//! `cargo run -p uniffi-bindgen -- generate --library <built core> --language swift --out-dir <dir>`
fn main() {
    uniffi::uniffi_bindgen_main();
}
