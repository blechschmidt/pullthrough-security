#!/bin/sh
# lab: client=pip (a refused package)
# lab: image=python:3.12-slim
#
# What pip prints when the proxy refuses a package (the lab's policy denies
# itsdangerous).
set -eu
echo "LAB_CLIENT_VERSION=$(pip --version | awk '{print $2}')"

export PIP_INDEX_URL=https://proxy.example.com/v1/pypi/simple/
export PIP_CERT=/etc/ssl/corp-ca.pem
if [ -n "${PROXY_TOKEN:-}" ]; then
    export PIP_INDEX_URL=https://pullthrough:${PROXY_TOKEN}@proxy.example.com/v1/pypi/simple/
fi

if pip install --no-cache-dir --disable-pip-version-check --root-user-action=ignore itsdangerous==2.2.0 >install.log 2>&1; then
    echo "the refused package was installed"; cat install.log; exit 1
fi
cat install.log
grep -q "403" install.log
