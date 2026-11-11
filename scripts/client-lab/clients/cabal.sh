#!/bin/sh
# lab: client=cabal
# lab: image=haskell:9-slim
# lab: lookups=_mirrors.proxy.example.com
#
# cabal with the proxy as its Hackage repository. cabal asks DNS for mirrors of
# the repository's host (_mirrors.<host>), hence the declared lookup.
set -eu
echo "LAB_CLIENT_VERSION=$(cabal --numeric-version)"

# `secure: True` keeps cabal verifying Hackage's signed (TUF) metadata, which
# the proxy serves byte for byte, against the root keys built into cabal.
mkdir -p "$HOME/.config/cabal"
cat > "$HOME/.config/cabal/config" <<EOF
repository hackage.haskell.org
  url: https://proxy.example.com/v1/hackage/
  secure: True
EOF

# cabal downloads with curl, which reads the CA bundle from CURL_CA_BUNDLE.
export CURL_CA_BUNDLE=/etc/ssl/corp-ca.pem
if [ -n "${PROXY_TOKEN:-}" ]; then
# cabal has no credential setting the proxy can use (credentials in the URL are
# sent only in answer to a challenge the proxy does not send). curl reads
# ~/.curlrc, though: `netrc` makes it take the credentials for the proxy's host
# from ~/.netrc.
echo "netrc" > ~/.curlrc
cat > ~/.netrc <<EOF
machine proxy.example.com
  login pullthrough
  password ${PROXY_TOKEN}
EOF
chmod 600 ~/.netrc
fi

cabal update
cabal get split-0.2.5
test -d split-0.2.5
