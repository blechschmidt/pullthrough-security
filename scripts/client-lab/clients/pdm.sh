#!/bin/sh
# lab: client=PDM
# lab: image=python:3.12-slim
set -eu
# The tool itself is installed with pip, through the proxy.
bootstrap_index=https://proxy.example.com/v1/pypi/simple/
if [ -n "${PROXY_TOKEN:-}" ]; then
    bootstrap_index=https://pullthrough:${PROXY_TOKEN}@proxy.example.com/v1/pypi/simple/
fi
pip install --quiet --disable-pip-version-check --root-user-action=ignore --timeout 120 \
    --cert /etc/ssl/corp-ca.pem --index-url "$bootstrap_index" pdm
echo "LAB_CLIENT_VERSION=$(pdm --version | awk '{print $3}')"

pdm config check_update false
pdm config pypi.url https://proxy.example.com/v1/pypi/simple/
pdm config pypi.ca_certs /etc/ssl/corp-ca.pem
if [ -n "${PROXY_TOKEN:-}" ]; then
    pdm config pypi.username pullthrough
    pdm config pypi.password "${PROXY_TOKEN}"
fi

mkdir project && cd project
pdm init --non-interactive --python "$(command -v python)" >/dev/null 2>&1
pdm add six==1.16.0
pdm run python -c "import six"

# pdm.lock records file names and hashes, not URLs.
if grep -q 'proxy.example.com' pdm.lock; then echo "pdm.lock names the proxy"; exit 1; fi
