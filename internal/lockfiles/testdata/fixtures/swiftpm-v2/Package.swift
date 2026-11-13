// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "fixture-app",
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", exact: "1.6.1"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-collections.git", branch: "release/1.1"),
        .package(url: "https://github.com/apple/swift-system.git", revision: "c8a44d836fe7913603e246acab7c528c2e780168"),
        .package(url: "https://github.com/apple/swift-algorithms.git", from: "1.2.0"),
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
