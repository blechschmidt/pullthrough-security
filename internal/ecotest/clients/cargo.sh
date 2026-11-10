#!/bin/sh
# cargo — replace the crates.io source with the proxy's sparse registry.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(cargo --version | awk '{print $2}')"

# Source replacement in $CARGO_HOME/config.toml redirects every crates.io
# dependency to the proxy without touching any Cargo.toml. The trailing slash on
# the sparse+ URL is required. The proxy rewrites the registry's config.json so
# the .crate downloads come back through it as well.
export CARGO_HOME="$PWD/cargo-home"
mkdir -p "$CARGO_HOME"
cat > "$CARGO_HOME/config.toml" <<CONFIG
[source.crates-io]
replace-with = "pullthrough"

[source.pullthrough]
registry = "sparse+$MOUNT/"
CONFIG

mkdir -p app/src
cat > app/Cargo.toml <<MANIFEST
[package]
name = "ecotest"
version = "0.1.0"
edition = "2021"

[dependencies]
$PKG_NAME = "=$PKG_VERSION"
MANIFEST
echo 'fn main() {}' > app/src/main.rs

cd app
cargo fetch
