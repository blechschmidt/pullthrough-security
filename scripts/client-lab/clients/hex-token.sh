#!/bin/sh
# lab: client=mix (with a token: refused)
# lab: image=elixir:1.16-slim
# lab: modes=auth
#
# A LIMITATION, asserted: Mix has no credential setting for the download of Hex
# itself, so against a proxy that requires a token `mix local.hex` is answered
# 401 — and without Hex nothing else can be fetched. (Hex, once installed by
# other means, presents no credential to a mirror either: HEX_REPOS_KEY and
# HEX_API_KEY are not sent to HEX_MIRROR, and with HEX_TRUSTED_MIRROR Hex 2.7
# first exchanges the key at hex.pm. Tried by hand on the lab's network; this
# script cannot install Hex without the token it is about.)
set -eu
echo "LAB_CLIENT_VERSION=$(elixir --short-version)"

export HEX_MIRROR=https://proxy.example.com/v1/hex
export HEX_CACERTS_PATH=/etc/ssl/corp-ca.pem
mkdir -p /etc/ssl/certs
cat /etc/ssl/corp-ca.pem >> /etc/ssl/certs/ca-certificates.crt

if mix local.hex --force >local-hex.log 2>&1 && mix hex.info >/dev/null 2>&1; then
    echo "mix installed Hex from a proxy that requires a token: update docs/clients/hex.md"
    cat local-hex.log; exit 1
fi
cat local-hex.log
grep -q "401" local-hex.log
