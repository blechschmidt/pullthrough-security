#!/bin/sh
# lab: client=Poetry
# lab: image=python:3.12-slim
set -eu
# The tool itself is installed with pip, through the proxy.
bootstrap_index=https://proxy.example.com/v1/pypi/simple/
if [ -n "${PROXY_TOKEN:-}" ]; then
    bootstrap_index=https://pullthrough:${PROXY_TOKEN}@proxy.example.com/v1/pypi/simple/
fi
pip install --quiet --disable-pip-version-check --root-user-action=ignore --timeout 120 \
    --cert /etc/ssl/corp-ca.pem --index-url "$bootstrap_index" poetry
echo "LAB_CLIENT_VERSION=$(poetry --version | awk '{print $3}' | tr -d ')')"

mkdir project && cd project
# A primary source in pyproject.toml replaces PyPI for the project.
cat > pyproject.toml <<EOF
[project]
name = "lab"
version = "0.1.0"
requires-python = ">=3.9"
dependencies = []

[tool.poetry]
package-mode = false

[[tool.poetry.source]]
name = "proxy"
url = "https://proxy.example.com/v1/pypi/simple/"
priority = "primary"
EOF
# The CA and the credentials are per source name, in Poetry's own configuration.
poetry config certificates.proxy.cert /etc/ssl/corp-ca.pem
if [ -n "${PROXY_TOKEN:-}" ]; then
    poetry config http-basic.proxy pullthrough "${PROXY_TOKEN}"
fi
poetry config virtualenvs.in-project true

poetry add six==1.16.0
poetry run python -c "import six"

# poetry.lock records the source by name and URL.
grep -q 'url = "https://proxy.example.com/v1/pypi/simple"' poetry.lock
