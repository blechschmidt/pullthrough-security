#!/bin/sh
# hex — get packages from repo.hex.pm with mix, intercepted by the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(elixir --short-version)"

# No HEX_MIRROR: mix keeps repo.hex.pm (and builds.hex.pm, where `mix
# local.hex` gets Hex itself). Mix verifies TLS against the system CA bundle
# Erlang reads (/etc/ssl/certs/ca-certificates.crt) — which this slim image does
# not ship, so the proxy's CA is written there; Hex reads HEX_CACERTS_PATH.
# Through a forward proxy both read HTTPS_PROXY. Registry resources are served
# byte-exact, so mix still verifies their signature with hex.pm's public key.
mkdir -p /etc/ssl/certs
cat "$PT_CA_CERT" >> /etc/ssl/certs/ca-certificates.crt
export HEX_CACERTS_PATH="$PT_CA_CERT"
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
