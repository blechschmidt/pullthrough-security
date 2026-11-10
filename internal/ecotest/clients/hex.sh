#!/bin/sh
# hex — mirror repo.hex.pm through the proxy with mix.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(elixir --short-version)"

# HEX_MIRROR replaces repo.hex.pm for registry resources and tarballs. The
# registry resources are served byte-exact, so mix still verifies their signature
# with hex.pm's public key.
export HEX_MIRROR="$MOUNT"
mix local.hex --force >/dev/null

cat > mix.exs <<MIXFILE
defmodule Ecotest.MixProject do
  use Mix.Project

  def project do
    [app: :ecotest, version: "0.1.0", deps: [{:$PKG_NAME, "$PKG_VERSION"}]]
  end
end
MIXFILE
mix deps.get
test -d "deps/$PKG_NAME"
