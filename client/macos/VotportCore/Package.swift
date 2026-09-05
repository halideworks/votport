// swift-tools-version: 5.9
// The Rust core as a Swift package: the XCFramework wraps the static library
// and its C header, the VotportCore target is the UniFFI-generated Swift.
// Both are produced by ../build-core.sh and are not committed.
import PackageDescription

let package = Package(
    name: "VotportCore",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "VotportCore", targets: ["VotportCore"]),
    ],
    targets: [
        .binaryTarget(name: "VotportCoreFFI", path: "VotportCoreFFI.xcframework"),
        .target(name: "VotportCore", dependencies: ["VotportCoreFFI"]),
    ]
)
