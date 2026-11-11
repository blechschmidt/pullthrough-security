#!/bin/sh
# lab: client=npm (a refused package)
# lab: image=node:22-slim
#
# What npm prints when the proxy refuses a package (the lab's policy denies
# left-pad): the install fails with the proxy's 403.
set -eu
echo "LAB_CLIENT_VERSION=$(npm --version)"

cat > .npmrc <<EOF
registry=https://proxy.example.com/v1/npm/
cafile=/etc/ssl/corp-ca.pem
EOF
if [ -n "${PROXY_TOKEN:-}" ]; then
cat >> .npmrc <<EOF
//proxy.example.com/v1/npm/:_authToken=${PROXY_TOKEN}
EOF
fi

npm init --yes >/dev/null
if npm install --no-audit --no-fund left-pad@1.3.0 >install.log 2>&1; then
    echo "the refused package was installed"; cat install.log; exit 1
fi
cat install.log
grep -q "E403" install.log
