// swift-tools-version: 6.0
import PackageDescription

// LeafKit: a thin wrapper around the leaf proxy engine.
//
// Leaf lives in its own package so SharedCore's `swift test` does not pull
// the ~200 MB binary artifact during resolution. Only the PacketTunnel
// extension links it. SPM downloads and checksum-verifies the xcframework at
// build time; it is not checked into git.
let package = Package(
    name: "LeafKit",
    platforms: [
        .iOS(.v18),
        .macOS(.v14),
    ],
    products: [
        .library(name: "LeafKit", targets: ["LeafKit"]),
    ],
    targets: [
        .binaryTarget(
            name: "leaf",
            url: "https://github.com/eycorsican/leaf/releases/download/v0.14.2/leaf.xcframework.zip",
            checksum: "a392d618646b08230fb70b3ec74de1855851e15c9c3185fae9469fe2037ad7d5"
        ),
        .target(
            name: "LeafKit",
            dependencies: ["leaf"],
            swiftSettings: [
                .swiftLanguageMode(.v6),
            ]
        ),
    ]
)
