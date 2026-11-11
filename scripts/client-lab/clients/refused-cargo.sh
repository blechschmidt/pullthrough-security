#!/bin/sh
# lab: client=cargo (a refused crate)
# lab: image=rust:1-slim
# lab: modes=open
#
# What cargo prints when the proxy refuses a crate (the lab's policy denies itoa).
set -eu
echo "LAB_CLIENT_VERSION=$(cargo --version | awk '{print $2}')"

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
itoa = "=1.0.11"
EOF
echo 'fn main() {}' > src/main.rs
if cargo fetch >fetch.log 2>&1; then
    echo "the refused crate was downloaded"; cat fetch.log; exit 1
fi
cat fetch.log
grep -q "403" fetch.log
