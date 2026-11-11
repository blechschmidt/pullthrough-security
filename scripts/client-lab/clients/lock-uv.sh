#!/bin/sh
# lab: client=uv (an existing lock file, written against pypi.org)
# lab: image=python:3.12-slim
#
# Moving a project onto the proxy: its uv.lock names pypi.org as the registry
# and files.pythonhosted.org for every file. uv does not follow those URLs; it
# sees that the index changed and wants the lock file updated.
set -eu
# The tool itself is installed with pip, through the proxy.
bootstrap_index=https://proxy.example.com/v1/pypi/simple/
if [ -n "${PROXY_TOKEN:-}" ]; then
    bootstrap_index=https://pullthrough:${PROXY_TOKEN}@proxy.example.com/v1/pypi/simple/
fi
pip install --quiet --disable-pip-version-check --root-user-action=ignore --timeout 120 \
    --cert /etc/ssl/corp-ca.pem --index-url "$bootstrap_index" uv
echo "LAB_CLIENT_VERSION=$(uv --version | awk '{print $2}')"

export SSL_CERT_FILE=/etc/ssl/corp-ca.pem
export UV_DEFAULT_INDEX="$bootstrap_index"

# A lock file as pypi.org would have produced it.
mkdir project && cd project
uv init --name lab --no-workspace . >/dev/null 2>&1
uv add six==1.16.0 >/dev/null 2>&1
sed -i 's#https://proxy.example.com/v1/pypi/simple/#https://pypi.org/simple#g; s#https://proxy.example.com/v1/pypi/files/https/files.pythonhosted.org/#https://files.pythonhosted.org/#g' uv.lock
grep -q 'registry = "https://pypi.org/simple"' uv.lock
rm -rf .venv
uv cache clean >/dev/null 2>&1

# With the lock file frozen, uv refuses rather than fetch from pypi.org.
if uv sync --locked >locked.log 2>&1; then
    echo "uv installed a pypi.org lock file as it is: update docs/clients/pip.md"; cat locked.log; exit 1
fi
grep -q "needs to be updated" locked.log

# Re-locking moves it onto the proxy; versions and hashes stay as they are.
uv lock
uv sync --locked
grep -q 'registry = "https://proxy.example.com/v1/pypi/simple/"' uv.lock
grep -q 'name = "six"' uv.lock
grep -q 'version = "1.16.0"' uv.lock
