#!/bin/sh
# hackage — use the proxy as cabal's package repository.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(cabal --numeric-version)"

# A `repository` stanza in the cabal config replaces hackage.haskell.org. With
# `secure: True` cabal still verifies Hackage's TUF metadata (served byte-exact
# by the proxy) against the root keys built into cabal-install.
mkdir -p "$HOME/.config/cabal"
cat > "$HOME/.config/cabal/config" <<CABALCONFIG
repository hackage.haskell.org
  url: $MOUNT/
  secure: True
CABALCONFIG

cabal update
cabal get "$PKG_NAME-$PKG_VERSION"
test -d "$PKG_NAME-$PKG_VERSION"
