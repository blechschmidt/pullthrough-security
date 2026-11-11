#!/bin/sh
# lab: client=go
# lab: image=golang:1.24-alpine
set -eu
version=$(go env GOVERSION)
echo "LAB_CLIENT_VERSION=${version#go}"

go env -w GOPROXY=https://proxy.example.com/v1/goproxy
# The go command reads the CA bundle from SSL_CERT_FILE and credentials for the
# proxy's host from ~/.netrc.
export SSL_CERT_FILE=/etc/ssl/corp-ca.pem
if [ -n "${PROXY_TOKEN:-}" ]; then
cat > ~/.netrc <<EOF
machine proxy.example.com
  login pullthrough
  password ${PROXY_TOKEN}
EOF
chmod 600 ~/.netrc
fi
export GOFLAGS=-mod=mod GOTOOLCHAIN=local

mkdir app && cd app
go mod init example.com/lab >/dev/null 2>&1
go get rsc.io/quote@v1.5.2

# Checksum verification stayed on, against the database the proxy serves.
test "$(go env GOSUMDB)" = "sum.golang.org"
test -z "$(go env GONOSUMDB)"
grep -q '^rsc.io/quote v1.5.2 h1:' go.sum

if [ -n "${PROXY_TOKEN:-}" ]; then
    # The same without ~/.netrc: the credentials in the GOPROXY URL.
    rm ~/.netrc
    go clean -modcache
    export GOPROXY=https://pullthrough:${PROXY_TOKEN}@proxy.example.com/v1/goproxy
    go mod download rsc.io/quote@v1.5.2
fi
