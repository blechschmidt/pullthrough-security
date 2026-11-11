#!/bin/sh
# lab: client=uv
# lab: image=python:3.12-slim
set -eu
# The tool itself is installed with pip, through the proxy.
bootstrap_index=https://proxy.example.com/v1/pypi/simple/
if [ -n "${PROXY_TOKEN:-}" ]; then
    bootstrap_index=https://pullthrough:${PROXY_TOKEN}@proxy.example.com/v1/pypi/simple/
fi
pip install --quiet --disable-pip-version-check --root-user-action=ignore --timeout 120 \
    --cert /etc/ssl/corp-ca.pem --index-url "$bootstrap_index" uv
echo "LAB_CLIENT_VERSION=$(uv --version | awk '{print $2}')"

# A default index in uv's user-level configuration replaces pypi.org.
mkdir -p ~/.config/uv
cat > ~/.config/uv/uv.toml <<EOF
[[index]]
name = "proxy"
url = "https://proxy.example.com/v1/pypi/simple/"
default = true
EOF
# uv reads the CA bundle from SSL_CERT_FILE, and an index's credentials from
# UV_INDEX_<NAME>_USERNAME / _PASSWORD.
export SSL_CERT_FILE=/etc/ssl/corp-ca.pem
if [ -n "${PROXY_TOKEN:-}" ]; then
    export UV_INDEX_PROXY_USERNAME=pullthrough
    export UV_INDEX_PROXY_PASSWORD="${PROXY_TOKEN}"
fi

mkdir project && cd project
uv init --name lab --no-workspace . >/dev/null 2>&1
uv add six==1.16.0
uv run python -c "import six"

# uv.lock records the index and the URL of every file: the proxy's.
grep -q 'registry = "https://proxy.example.com/v1/pypi/simple/"' uv.lock
! grep -q "${PROXY_TOKEN:-no-token-in-the-lock-file}" uv.lock

# Without a configuration file: the index in the environment.
cd .. && rm ~/.config/uv/uv.toml
unset UV_INDEX_PROXY_USERNAME UV_INDEX_PROXY_PASSWORD
export UV_DEFAULT_INDEX=https://proxy.example.com/v1/pypi/simple/
if [ -n "${PROXY_TOKEN:-}" ]; then
    export UV_DEFAULT_INDEX=https://pullthrough:${PROXY_TOKEN}@proxy.example.com/v1/pypi/simple/
fi
uv venv --quiet venv
VIRTUAL_ENV="$PWD/venv" uv pip install toml==0.10.2
