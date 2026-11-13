// swift-tools-version:5.5
import PackageDescription

let package = Package(
    name: "fixture-app",
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", .exact("1.2.3")),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.4.0"),
        .package(url: "https://github.com/apple/swift-collections.git", .branch("release/1.0")),
        .package(url: "https://github.com/apple/swift-system.git", .revision("836bc4557b74fe6d2660218d56e3ce96aff76574")),
        .package(url: "https://github.com/apple/swift-algorithms.git", from: "1.0.0"),
    ],
    targets: [
        .executableTarget(
            name: "fixture-app",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "Collections", package: "swift-collections"),
                .product(name: "SystemPackage", package: "swift-system"),
                .product(name: "Algorithms", package: "swift-algorithms"),
            ]
        ),
    ]
)
