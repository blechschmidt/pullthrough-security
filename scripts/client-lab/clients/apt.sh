#!/bin/sh
# lab: client=APT
# lab: image=debian:bookworm-slim
set -eu
echo "LAB_CLIENT_VERSION=$(apt-get --version | awk 'NR==1 {print $2}')"

# Replace the distribution's sources with the proxy (deb822 format).
rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*
cat > /etc/apt/sources.list.d/pullthrough.sources <<EOF
Types: deb
URIs: https://proxy.example.com/v1/debian
Suites: bookworm bookworm-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF
# The CA, for this host only. (A minimal image has no ca-certificates package,
# and does not need one for this.)
cat > /etc/apt/apt.conf.d/99pullthrough <<EOF
Acquire::https::proxy.example.com::CAInfo "/etc/ssl/corp-ca.pem";
EOF
if [ -n "${PROXY_TOKEN:-}" ]; then
cat > /etc/apt/auth.conf.d/pullthrough.conf <<EOF
machine proxy.example.com
login pullthrough
password ${PROXY_TOKEN}
EOF
chmod 600 /etc/apt/auth.conf.d/pullthrough.conf
fi

apt-get update
apt-get install -y --no-install-recommends hello
dpkg -s hello >/dev/null
apt-cache policy hello | grep -q "https://proxy.example.com/v1/debian bookworm/main"
