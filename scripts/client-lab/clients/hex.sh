#!/bin/sh
# lab: client=mix (Hex)
# lab: image=elixir:1.16-slim
# lab: modes=open
#
# mix with the proxy as the mirror of hex.pm. (Neither Mix nor Hex can present
# a token to the proxy; see hex-token.sh.)
set -eu
echo "LAB_CLIENT_VERSION=$(elixir --short-version)"

export HEX_MIRROR=https://proxy.example.com/v1/hex
# Hex reads its CA bundle from HEX_CACERTS_PATH.
export HEX_CACERTS_PATH=/etc/ssl/corp-ca.pem
# Mix — which downloads Hex itself, with `mix local.hex` — reads only the system
# trust store. Without the CA in it Mix prints a warning and SKIPS certificate
# verification for that download.
mkdir -p /etc/ssl/certs
cat /etc/ssl/corp-ca.pem >> /etc/ssl/certs/ca-certificates.crt

mix local.hex --force >local-hex.log 2>&1
cat local-hex.log
! grep -q "SSL peer verification will be skipped" local-hex.log

cat > mix.exs <<EOF
defmodule Lab.MixProject do
  use Mix.Project

  def project do
    [app: :lab, version: "0.1.0", deps: [{:jason, "1.4.1"}]]
  end
end
EOF
mix deps.get
test -d deps/jason

# mix.lock records names, versions and checksums, no URL.
grep -q '"jason": {:hex, :jason, "1.4.1"' mix.lock
! grep -q 'proxy.example.com' mix.lock
