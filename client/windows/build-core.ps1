# Builds the Rust core for the Windows shell: the release DLL and the
# UniFFI C# bindings, copied into the project. Run from anywhere; needs
# cargo 1.97, cmake and nasm (BoringSSL), libclang, and uniffi-bindgen-cs
# (cargo install uniffi-bindgen-cs --git https://github.com/NordSecurity/uniffi-bindgen-cs --rev e10ce410eb3a10cc19c7928b93ea8d84e038c034 --locked).
# -Arch arm64 builds the ARM64 core for a win-arm64 release; it does not
# touch the x64 files the development build links.
param(
    [ValidateSet("dev", "release")][string]$BuildProfile = "release",
    [ValidateSet("x64", "arm64")][string]$Arch = "x64"
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$client = Resolve-Path "$here\.."
$target = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { "$client\target" }
$project = "$here\Votport"
$outputProfile = if ($BuildProfile -eq "dev") { "debug" } else { $BuildProfile }
$rustTarget = @{ "x64" = "x86_64-pc-windows-msvc"; "arm64" = "aarch64-pc-windows-msvc" }[$Arch]

Push-Location $client
try {
    cargo build --locked --profile $BuildProfile -p votport-client-core -p votport-client --target $rustTarget
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
    # The bindings are architecture independent; generate them once, from the
    # x64 DLL.
    $bindingsLibrary = "$target\x86_64-pc-windows-msvc\$outputProfile\votport_client_core.dll"
    uniffi-bindgen-cs --library $bindingsLibrary --out-dir "$target\bindings-cs"
    if ($LASTEXITCODE -ne 0) { throw "uniffi-bindgen-cs failed" }
} finally {
    Pop-Location
}

# One version everywhere: the core's Cargo.toml is the source of truth, the
# same number the shells show as "Core" in Settings. The Windows manifests
# take the four-part form of it, stamped here so they move with the core.
$version = (Select-String -Path "$client\core\Cargo.toml" -Pattern '^version = "(.+)"$').Matches[0].Groups[1].Value
if ($version -notmatch '^[\d.]+$') { throw "no plain version in core\Cargo.toml" }
$fourPart = "$version.0"
# Anchor to the assembly identity so the XML declaration's own version
# attribute is never rewritten, and verify against the raw text so line
# endings and encoding cannot defeat the check.
$manifest = Get-Content "$project\app.manifest" -Raw
$manifest = $manifest -replace '(<assemblyIdentity version=")[\d.]+(")', "`${1}$fourPart`$2"
Set-Content -Path "$project\app.manifest" -Value $manifest -NoNewline
if (-not ((Get-Content "$project\app.manifest" -Raw).Contains("version=`"$fourPart`""))) {
    throw "failed to stamp $fourPart into app.manifest"
}
$appx = Get-Content "$project\Package.appxmanifest" -Raw
$appx = $appx -replace '(<Identity[^>]*Version=")[\d.]+(")', "`${1}$fourPart`$2"
Set-Content -Path "$project\Package.appxmanifest" -Value $appx -NoNewline
if (-not ((Get-Content "$project\Package.appxmanifest" -Raw).Contains("Version=`"$fourPart`""))) {
    throw "failed to stamp $fourPart into Package.appxmanifest"
}

New-Item -ItemType Directory -Force "$project\Generated" | Out-Null
if ($Arch -eq "x64") {
    # The development layout the project links by default.
    Copy-Item "$target\bindings-cs\votport_client_core.cs" "$project\Generated\"
    Copy-Item "$target\$rustTarget\$outputProfile\votport_client_core.dll" "$project\Generated\"
    Copy-Item "$target\$rustTarget\$outputProfile\votport.exe" "$project\Generated\votport-cli.exe"
} else {
    # The ARM64 core beside the x64 one, for a -r win-arm64 package.
    New-Item -ItemType Directory -Force "$project\Generated\arm64" | Out-Null
    Copy-Item "$target\$rustTarget\$outputProfile\votport_client_core.dll" "$project\Generated\arm64\"
    Copy-Item "$target\$rustTarget\$outputProfile\votport.exe" "$project\Generated\arm64\votport-cli.exe"
}
Write-Host "core ready in $project\Generated (arch $Arch, version $version)"
