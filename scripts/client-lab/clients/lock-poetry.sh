#!/bin/sh
# lab: client=Poetry (an existing lock file, written against PyPI)
# lab: image=python:3.12-slim
#
# Moving a project onto the proxy: its poetry.lock names no source (PyPI is
# implied). With the proxy as the project's primary source, Poetry installs the
# locked packages from the proxy; the lock file needs no change.
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
poetry config certificates.proxy.cert /etc/ssl/corp-ca.pem
if [ -n "${PROXY_TOKEN:-}" ]; then
    poetry config http-basic.proxy pullthrough "${PROXY_TOKEN}"
fi
poetry config virtualenvs.in-project true

# A lock file as PyPI would have produced it: no [package.source] sections.
poetry add six==1.16.0 >/dev/null
python3 - <<'PY'
import re
lock = open("poetry.lock").read()
lock = re.sub(r'\n\[package\.source\]\ntype = "legacy"\nurl = "[^"]*"\nreference = "proxy"\n', "\n", lock)
open("poetry.lock", "w").write(lock)
PY
if grep -q "package.source" poetry.lock; then echo "poetry.lock still has a package source"; exit 1; fi
rm -rf .venv
poetry cache clear --all . --no-interaction >/dev/null 2>&1

poetry install --no-root
poetry run python -c "import six"
