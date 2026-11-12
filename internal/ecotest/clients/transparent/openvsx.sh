#!/bin/sh
# openvsx — download a VS Code extension from open-vsx.org with the ovsx CLI,
# intercepted by the proxy.
set -eu

# Node trusts the proxy's CA through NODE_EXTRA_CA_CERTS. npm reads HTTPS_PROXY
# by itself; for ovsx, NODE_USE_ENV_PROXY makes Node's own HTTP client read it
# too. The ovsx CLI comes from registry.npmjs.org, intercepted as well.
export NODE_EXTRA_CA_CERTS="$PT_CA_CERT" NODE_USE_ENV_PROXY=1
echo "ECOTEST_CLIENT_VERSION=$(npx --yes ovsx --version | awk 'NR==1 {print $NF}')"

# ovsx keeps its default registry, open-vsx.org. The proxy moves the download
# links in the metadata onto open-vsx.org, so the .vsix is intercepted too.
# PKG_NAME is "<namespace>.<extension>".
npx --yes ovsx get "$PKG_NAME" --versionRange "$PKG_VERSION" -o extension.vsix
test -s extension.vsix
