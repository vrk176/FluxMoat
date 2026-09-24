// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SharedCore",
    platforms: [
        .iOS(.v18),
        .macOS(.v14),
    ],
    products: [
        .library(name: "SharedCore", targets: ["SharedCore"]),
    ],
    targets: [
        .target(
            name: "SharedCore",
            swiftSettings: [
                .swiftLanguageMode(.v6),
            ]
        ),
        .testTarget(
            name: "SharedCoreTests",
            dependencies: ["SharedCore"]
        ),
    ]
)
