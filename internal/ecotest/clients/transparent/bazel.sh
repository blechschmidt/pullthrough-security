#!/bin/sh
# bazel — resolve Bzlmod modules from the Bazel Central Registry, intercepted by
# the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(bazel --version | awk '{print $2}')"

# No --registry: Bazel keeps bcr.bazel.build. Its downloader runs in Bazel's
# JVM, which trusts the proxy's CA through a trust store handed to it as a
# startup option; through a forward proxy it reads HTTPS_PROXY. The proxy points
# each module's source.json at bcr.bazel.build, so the source archives are
# intercepted (and verified against the registry's integrity hash) too.
keytool -importcert -noprompt -alias pullthrough -file "$PT_CA_CERT" \
    -keystore "$PWD/truststore.p12" -storetype PKCS12 -storepass changeit >/dev/null
cat > .bazelrc <<BAZELRC
startup --host_jvm_args=-Djavax.net.ssl.trustStore=$PWD/truststore.p12
startup --host_jvm_args=-Djavax.net.ssl.trustStorePassword=changeit
startup --host_jvm_args=-Djavax.net.ssl.trustStoreType=PKCS12
BAZELRC

cat > MODULE.bazel <<MODULE
module(name = "ecotest", version = "0.0.0")

bazel_dep(name = "$PKG_NAME", version = "$PKG_VERSION")
MODULE
touch BUILD.bazel

bazel fetch --repo="@$PKG_NAME"
