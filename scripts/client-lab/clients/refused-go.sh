#!/bin/sh
# lab: client=go (a refused module)
# lab: image=golang:1.24-alpine
#
# What the go command prints when the proxy refuses a module (the lab's policy
# denies github.com/pkg/errors).
set -eu
version=$(go env GOVERSION)
echo "LAB_CLIENT_VERSION=${version#go}"

export GOPROXY=https://proxy.example.com/v1/goproxy
export SSL_CERT_FILE=/etc/ssl/corp-ca.pem
if [ -n "${PROXY_TOKEN:-}" ]; then
    export GOPROXY=https://pullthrough:${PROXY_TOKEN}@proxy.example.com/v1/goproxy
fi
export GOFLAGS=-mod=mod GOTOOLCHAIN=local

mkdir app && cd app
go mod init example.com/lab >/dev/null 2>&1
if go get github.com/pkg/errors@v0.9.1 >get.log 2>&1; then
    echo "the refused module was downloaded"; cat get.log; exit 1
fi
cat get.log
grep -q "403" get.log
