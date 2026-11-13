// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "fixture-app",
    dependencies: [
        .package(id: "apple.swift-argument-parser", exact: "1.8.2"),
        .package(id: "apple.swift-log", from: "1.6.0"),
        .package(id: "apple.swift-algorithms", from: "1.2.0"),
    ],
    targets: [
        .executableTarget(
            name: "fixture-app",
            dependencies: [
                .product(name: "ArgumentParser", package: "apple.swift-argument-parser"),
                .product(name: "Logging", package: "apple.swift-log"),
                .product(name: "Algorithms", package: "apple.swift-algorithms"),
            ]
        ),
    ]
)
