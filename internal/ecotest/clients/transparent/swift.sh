#!/bin/sh
# swift — resolve from the Tuist registry, intercepted by the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(swift --version 2>/dev/null | awk '/Swift version/ { print $3; exit }')"

# SwiftPM has no built-in registry: the package keeps the one it uses anyway,
# Tuist's public registry. SwiftPM's HTTP client reads the system trust store,
# so the proxy's CA is added to it; through a forward proxy it reads
# HTTPS_PROXY.
cp "$PT_CA_CERT" /usr/local/share/ca-certificates/pullthrough-intercept.crt
update-ca-certificates >/dev/null

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

swift package-registry set https://tuist.dev/api/registry/swift
swift package resolve
swift run ecotest
