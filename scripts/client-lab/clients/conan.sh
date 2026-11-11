#!/bin/sh
# lab: client=Conan 2
# lab: image=python:3.12-slim
# lab: modes=open anon
#
# Conan cannot present a proxy token (see docs/clients/conan.md). Where access
# control is on it therefore runs WITHOUT one, against a proxy that admits
# anonymous reads for the Conan upstream and for nothing else ("anon" mode).
set -eu
# The tool itself is installed with pip, through the proxy.
bootstrap_index=https://proxy.example.com/v1/pypi/simple/
if [ -n "${PROXY_TOKEN:-}" ]; then
    bootstrap_index=https://pullthrough:${PROXY_TOKEN}@proxy.example.com/v1/pypi/simple/
fi
pip install --quiet --disable-pip-version-check --root-user-action=ignore --timeout 120 \
    --cert /etc/ssl/corp-ca.pem --index-url "$bootstrap_index" conan
echo "LAB_CLIENT_VERSION=$(conan --version | awk '{print $3}')"

conan remote remove conancenter
conan remote add proxy https://proxy.example.com/v1/conancenter
# Conan reads its CA bundle from core.net.http:cacert_path.
echo "core.net.http:cacert_path=/etc/ssl/corp-ca.pem" >> "$(conan config home)/global.conf"

conan download zlib/1.3.1 --remote proxy --only-recipe
conan list "zlib/1.3.1" | grep -q "zlib/1.3.1"

if [ -n "${PROXY_TOKEN:-}" ]; then
    # Logging in is refused: the proxy serves no Conan login endpoint.
    if conan remote login proxy pullthrough -p "${PROXY_TOKEN}" >login.log 2>&1; then
        echo "conan remote login succeeded: update docs/clients/conan.md"; cat login.log; exit 1
    fi
    cat login.log
fi
