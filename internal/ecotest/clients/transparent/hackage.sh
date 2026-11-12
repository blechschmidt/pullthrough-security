#!/bin/sh
# hackage — get packages from hackage.haskell.org with cabal, intercepted by the
# proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(cabal --numeric-version)"

# cabal keeps hackage.haskell.org. With `secure: True` it verifies Hackage's
# TUF metadata (served byte-exact by the proxy) against the root keys built into
# cabal-install. The proxy's CA goes into the system trust store, which cabal's
# HTTP transport reads; through a forward proxy it reads HTTPS_PROXY.
cp "$PT_CA_CERT" /usr/local/share/ca-certificates/pullthrough-intercept.crt
update-ca-certificates >/dev/null
mkdir -p "$HOME/.config/cabal"
cat > "$HOME/.config/cabal/config" <<CABALCONFIG
repository hackage.haskell.org
  url: https://hackage.haskell.org/
  secure: True
CABALCONFIG

cabal update
cabal get "$PKG_NAME-$PKG_VERSION"
test -d "$PKG_NAME-$PKG_VERSION"
