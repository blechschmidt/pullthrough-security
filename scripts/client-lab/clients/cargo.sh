#!/bin/sh
# lab: client=cargo
# lab: image=rust:1-slim
# lab: modes=open
#
# cargo with source replacement in the user-level configuration. (cargo cannot
# present a token for crate downloads; see cargo-token.sh.)
set -eu
echo "LAB_CLIENT_VERSION=$(cargo --version | awk '{print $2}')"

# The user-level file is $CARGO_HOME/config.toml: ~/.cargo/config.toml unless
# CARGO_HOME is set — which it is in the official Rust image (/usr/local/cargo).
: "${CARGO_HOME:=$HOME/.cargo}"
mkdir -p "$CARGO_HOME"
cat > "$CARGO_HOME/config.toml" <<EOF
[source.crates-io]
replace-with = "proxy"

[source.proxy]
registry = "sparse+https://proxy.example.com/v1/crates/"

[http]
cainfo = "/etc/ssl/corp-ca.pem"
EOF

mkdir -p app/src && cd app
cat > Cargo.toml <<EOF
[package]
name = "lab"
version = "0.1.0"
edition = "2021"

[dependencies]
cfg-if = "=1.0.0"
EOF
echo 'fn main() {}' > src/main.rs
cargo fetch

# Cargo.lock keeps naming crates.io: source replacement does not change it.
grep -q 'source = "registry+https://github.com/rust-lang/crates.io-index"' Cargo.lock
if grep -q 'proxy.example.com' Cargo.lock; then echo "Cargo.lock names the proxy"; exit 1; fi
