#!/bin/sh
# bazel — use the proxy as the Bzlmod module registry.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(bazel --version | awk '{print $2}')"

# --registry (persist it as `common --registry=...` in .bazelrc) replaces
# bcr.bazel.build. The proxy rewrites each module's source.json so the source
# archive (hosted on GitHub) comes back through it and is verified against the
# registry's integrity hash.
echo "common --registry=$MOUNT" > .bazelrc

cat > MODULE.bazel <<MODULE
module(name = "ecotest", version = "0.0.0")

bazel_dep(name = "$PKG_NAME", version = "$PKG_VERSION")
MODULE
touch BUILD.bazel

bazel fetch --repo="@$PKG_NAME"
