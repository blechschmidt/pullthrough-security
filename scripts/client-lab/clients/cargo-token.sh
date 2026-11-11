#!/bin/sh
# lab: client=cargo (with a token: refused)
# lab: image=rust:1-slim
# lab: modes=auth anon
#
# A LIMITATION, asserted. With access control on, cargo cannot fetch crates even
# with a token configured:
#
#   - cargo sends its token only after a 401. Where every request needs a token
#     (auth), it reads the index that way, but downloads crates WITHOUT the token,
#     because the registry's config.json does not declare "auth-required": the
#     download is answered 401.
#   - where an anonymous role exists (anon), a request without a token is
#     answered 403, not 401, and cargo never presents the token at all.
set -eu
echo "LAB_CLIENT_VERSION=$(cargo --version | awk '{print $2}')"

: "${CARGO_HOME:=$HOME/.cargo}"
mkdir -p "$CARGO_HOME"
cat > "$CARGO_HOME/config.toml" <<EOF
[source.crates-io]
replace-with = "proxy"

[source.proxy]
registry = "sparse+https://proxy.example.com/v1/crates/"

[registries.proxy]
index = "sparse+https://proxy.example.com/v1/crates/"
credential-provider = ["cargo:token"]
token = "Bearer ${PROXY_TOKEN}"

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

if cargo fetch >fetch.log 2>&1; then
    echo "cargo fetched a crate with a token: the limitation is gone — update docs/clients/cargo.md"
    cat fetch.log; exit 1
fi
cat fetch.log
if [ "$LAB_MODE" = auth ]; then
    # The index was read with the token; the download was refused.
    grep -q "Downloading crates" fetch.log
    grep -q "/download.*got 401" fetch.log
else
    grep -q "config.json.*got 403" fetch.log
fi
