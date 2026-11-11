#!/bin/sh
# lab: client=Conan 2 (with a token: refused)
# lab: image=python:3.12-slim
# lab: modes=auth
#
# A LIMITATION, asserted: where every request needs a token, Conan cannot use
# the proxy — it has no way to present one, and logging in is refused.
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
echo "core.net.http:cacert_path=/etc/ssl/corp-ca.pem" >> "$(conan config home)/global.conf"

if conan remote login proxy pullthrough -p "${PROXY_TOKEN}" >login.log 2>&1; then
    echo "conan remote login succeeded: update docs/clients/conan.md"; cat login.log; exit 1
fi
cat login.log
if conan download zlib/1.3.1 --remote proxy --only-recipe </dev/null >download.log 2>&1; then
    echo "conan downloaded a recipe from a proxy that requires a token: update docs/clients/conan.md"
    cat download.log; exit 1
fi
cat download.log
