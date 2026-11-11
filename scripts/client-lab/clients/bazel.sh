#!/bin/sh
# lab: client=Bazel
# lab: image=gcr.io/bazel-public/bazel:7.4.1
# lab: entrypoint=sh
# lab: user=0
#
# Bazel (Bzlmod) with the proxy as its module registry.
set -eu
echo "LAB_CLIENT_VERSION=$(bazel --version | awk '{print $2}')"
export HOME=/root

if [ -n "${PROXY_TOKEN:-}" ]; then
# Bazel reads credentials for a host from ~/.netrc.
cat > ~/.netrc <<EOF
machine proxy.example.com
  login pullthrough
  password ${PROXY_TOKEN}
EOF
chmod 600 ~/.netrc
fi

# Bazel's server is a JVM, which does not read PEM bundles: add the CA to a copy
# of a JDK trust store and hand it to the server in .bazelrc. (The image has a
# Java runtime for keytool, and does not say where.)
JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64/jre
cp "$JAVA_HOME/lib/security/cacerts" /etc/ssl/corp-truststore.jks
keytool -importcert -noprompt -trustcacerts -alias corp-ca -file /etc/ssl/corp-ca.pem \
    -keystore /etc/ssl/corp-truststore.jks -storepass changeit

cat > .bazelrc <<EOF
common --registry=https://proxy.example.com/v1/bazel
startup --host_jvm_args=-Djavax.net.ssl.trustStore=/etc/ssl/corp-truststore.jks --host_jvm_args=-Djavax.net.ssl.trustStorePassword=changeit
EOF

cat > MODULE.bazel <<EOF
module(name = "lab", version = "0.0.0")

bazel_dep(name = "platforms", version = "0.0.10")
EOF
touch BUILD.bazel

bazel fetch --repo="@platforms"

# MODULE.bazel.lock records the registry URL of every file: the proxy's.
grep -q 'https://proxy.example.com/v1/bazel/modules/platforms/0.0.10/MODULE.bazel' MODULE.bazel.lock
