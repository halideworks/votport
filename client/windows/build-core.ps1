# Builds the Rust core for the Windows shell: the release DLL and the
# UniFFI C# bindings, copied into the project. Run from anywhere; needs
# cargo 1.97, cmake and nasm (BoringSSL), libclang, and uniffi-bindgen-cs
# (cargo install uniffi-bindgen-cs --git https://github.com/NordSecurity/uniffi-bindgen-cs --tag v0.11.0+v0.31.0).
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$client = Resolve-Path "$here\.."
$target = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { "$client\target" }
$project = "$here\Votport"

Push-Location $client
try {
    cargo build --release -p votport-client-core
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
    uniffi-bindgen-cs --library "$target\release\votport_client_core.dll" --out-dir "$target\bindings-cs"
    if ($LASTEXITCODE -ne 0) { throw "uniffi-bindgen-cs failed" }
} finally {
    Pop-Location
}
New-Item -ItemType Directory -Force "$project\Generated" | Out-Null
Copy-Item "$target\bindings-cs\votport_client_core.cs" "$project\Generated\"
Copy-Item "$target\release\votport_client_core.dll" "$project\Generated\"
Write-Host "core ready in $project\Generated"
