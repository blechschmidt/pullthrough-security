#!/bin/sh
# lab: client=Bun
# lab: image=oven/bun:1.1
set -eu
echo "LAB_CLIENT_VERSION=$(bun --version)"

if [ -n "${PROXY_TOKEN:-}" ]; then
cat > bunfig.toml <<EOF
[install]
registry = { url = "https://proxy.example.com/v1/npm/", token = "${PROXY_TOKEN}" }
cafile = "/etc/ssl/corp-ca.pem"
EOF
else
cat > bunfig.toml <<EOF
[install]
registry = "https://proxy.example.com/v1/npm/"
cafile = "/etc/ssl/corp-ca.pem"
EOF
fi

echo '{"name":"lab","version":"1.0.0"}' > package.json
bun add is-number@7.0.0
test -d node_modules/is-number
