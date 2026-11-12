#!/bin/sh
# swift — use the proxy as the Swift package registry (SwiftPM, SE-0292).
set -eu
echo "ECOTEST_CLIENT_VERSION=$(swift --version 2>/dev/null | awk '/Swift version/ { print $3; exit }')"

# SwiftPM accepts a registry only over HTTPS, so the proxy serves it over TLS.
# Trust the proxy's CA (a corporate CA in a real deployment) in the system
# store, which SwiftPM's HTTP client reads.
cp "$PT_CA_CERT" /usr/local/share/ca-certificates/pullthrough.crt
update-ca-certificates >/dev/null

# A dependency declared by registry identity (scope.name) is resolved from the
# package's registry; one declared by Git URL would be cloned instead.
# $PKG_PRODUCT is the library product the package vends.
mkdir app
cd app
cat > Package.swift <<PACKAGE
// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "ecotest",
    dependencies: [
        .package(id: "$PKG_NAME", exact: "$PKG_VERSION"),
    ],
    targets: [
        .executableTarget(name: "ecotest", dependencies: [
            .product(name: "$PKG_PRODUCT", package: "$PKG_NAME"),
        ]),
    ]
)
PACKAGE
mkdir -p Sources/ecotest
printf 'import %s\nprint("ok")\n' "$PKG_PRODUCT" > Sources/ecotest/main.swift

# `swift package-registry set` writes .swiftpm/configuration/registries.json
# (add --global for every package of the user). Resolving fetches the release
# metadata, the manifest and the source archive from the proxy; SwiftPM checks
# the archive against the checksum in the release metadata.
swift package-registry set "$MOUNT"
swift package resolve
swift run ecotest
