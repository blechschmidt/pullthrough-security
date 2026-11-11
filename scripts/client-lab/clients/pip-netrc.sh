#!/bin/sh
# lab: client=pip (environment + ~/.netrc)
# lab: image=python:3.12-slim
#
# pip configured through the environment, with the token in ~/.netrc instead of
# in the index URL — nothing secret in pip.conf, the environment or a
# requirements file.
set -eu
echo "LAB_CLIENT_VERSION=$(pip --version | awk '{print $2}')"

export PIP_INDEX_URL=https://proxy.example.com/v1/pypi/simple/
export PIP_CERT=/etc/ssl/corp-ca.pem
if [ -n "${PROXY_TOKEN:-}" ]; then
cat > ~/.netrc <<EOF
machine proxy.example.com
  login pullthrough
  password ${PROXY_TOKEN}
EOF
chmod 600 ~/.netrc
fi

pip install --no-cache-dir --disable-pip-version-check --root-user-action=ignore six==1.16.0
pip show six >/dev/null
