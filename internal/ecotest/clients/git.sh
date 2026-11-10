#!/bin/sh
# git — clone GitHub repositories through the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(git --version | awk '{print $3}')"

# url.<base>.insteadOf rewrites every https://github.com/ URL to the proxy's git
# upstream, so existing clone URLs, submodules and dependency manifests keep
# working unchanged.
git config --global url."$MOUNT/".insteadOf "https://github.com/"

# PKG_NAME is "<owner>/<repository>".
git clone "https://github.com/$PKG_NAME.git" repo
git -C repo log --oneline -1
