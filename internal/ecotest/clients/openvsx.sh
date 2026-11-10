#!/bin/sh
# openvsx — download a VS Code extension through the proxy with the ovsx CLI.
set -eu

# The ovsx CLI is an npm package; fetch it through the proxy's npm upstream.
export npm_config_registry="$PROXY_URL/v1/npm/"
echo "ECOTEST_CLIENT_VERSION=$(npx --yes ovsx --version | awk 'NR==1 {print $NF}')"

# --registryUrl replaces open-vsx.org. (Editors use the same URL as their
# gallery service URL.) The proxy rewrites the download links in the metadata it
# serves, so the .vsix comes back through it.
# PKG_NAME is "<namespace>.<extension>".
npx --yes ovsx get "$PKG_NAME" --versionRange "$PKG_VERSION" --registryUrl "$MOUNT" -o extension.vsix
test -s extension.vsix
