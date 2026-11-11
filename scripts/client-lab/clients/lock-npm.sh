#!/bin/sh
# lab: client=npm (an existing lock file, written against npmjs.org)
# lab: image=node:22-slim
#
# Moving a project onto the proxy: its package-lock.json names
# registry.npmjs.org for every tarball. npm replaces that host with the
# configured registry by itself (replace-registry-host, default "npmjs"), so the
# lock file needs no change.
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

# A lock file as npmjs.org would have produced it.
npm init --yes >/dev/null
npm install --no-audit --no-fund is-number@7.0.0 >/dev/null
sed -i 's#https://proxy.example.com/v1/npm/#https://registry.npmjs.org/#g' package-lock.json
grep -q '"resolved": "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz"' package-lock.json
rm -rf node_modules
npm cache clean --force >/dev/null 2>&1

# Installed through the proxy, and the lock file is left as it was.
npm ci --no-audit --no-fund
node -e "require('is-number')"
grep -q '"resolved": "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz"' package-lock.json
