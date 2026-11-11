#!/bin/sh
# lab: client=cargo (--config flags)
# lab: image=rust:1-slim
# lab: modes=open
# lab: lookups=index.crates.io
#
# cargo without a configuration file, as in a CI job. The [source] table cannot
# be set through CARGO_* environment variables; --config flags can set it.
set -eu
echo "LAB_CLIENT_VERSION=$(cargo --version | awk '{print $2}')"

export CARGO_HTTP_CAINFO=/etc/ssl/corp-ca.pem

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

# Environment variables are NOT enough: cargo ignores them for [source] and
# goes to crates.io (the lookup this script declares), which this network does
# not reach.
if CARGO_SOURCE_CRATES_IO_REPLACE_WITH=proxy \
   CARGO_SOURCE_PROXY_REGISTRY="sparse+https://proxy.example.com/v1/crates/" \
   cargo fetch >env.log 2>&1; then
    echo "cargo honored CARGO_SOURCE_* variables (it did not use to)"; cat env.log; exit 1
fi
grep -q "index.crates.io" env.log

cargo --config 'source.crates-io.replace-with="proxy"' \
      --config 'source.proxy.registry="sparse+https://proxy.example.com/v1/crates/"' \
      fetch
