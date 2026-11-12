#!/bin/sh
# cargo — fetch crates from crates.io, intercepted by the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(cargo --version | awk '{print $2}')"

# No source replacement: cargo keeps crates.io (the sparse index at
# index.crates.io). It trusts the proxy's CA through CARGO_HTTP_CAINFO (or
# http.cainfo in config.toml); through a forward proxy it reads HTTPS_PROXY.
# The proxy points the index's config.json download URL at index.crates.io, so
# the .crate downloads are intercepted too.
export CARGO_HOME="$PWD/cargo-home"
export CARGO_HTTP_CAINFO="$PT_CA_CERT"

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
