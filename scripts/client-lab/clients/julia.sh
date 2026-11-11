#!/bin/sh
# lab: client=Julia Pkg
# lab: image=julia:1.10
set -eu
echo "LAB_CLIENT_VERSION=$(julia --version | awk '{print $3}')"

export JULIA_PKG_SERVER=https://proxy.example.com/v1/julia
export JULIA_SSL_CA_ROOTS_PATH=/etc/ssl/corp-ca.pem
if [ -n "${PROXY_TOKEN:-}" ]; then
# Pkg keeps a server's token in a file named after the server's host.
mkdir -p ~/.julia/servers/proxy.example.com
cat > ~/.julia/servers/proxy.example.com/auth.toml <<EOF
access_token = "${PROXY_TOKEN}"
EOF
fi

julia -e 'using Pkg; Pkg.add(name="Example", version="0.5.3"); using Example; println(Example.hello("lab"))'

# Manifest.toml records UUIDs and tree hashes, no URL.
grep -q 'git-tree-sha1' ~/.julia/environments/v1.10/Manifest.toml
if grep -q 'proxy.example.com' ~/.julia/environments/v1.10/Manifest.toml; then echo "Manifest.toml names the proxy"; exit 1; fi
