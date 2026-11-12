#!/bin/sh
# maven — resolve a project's dependencies from Maven Central, intercepted by
# the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(mvn -v | awk 'NR==1 {print $3}')"

# No mirror: Maven keeps its built-in central repository
# (repo.maven.apache.org/maven2). The JVM trusts the proxy's CA through a
# trust store; -Djavax.net.ssl.trustStore names one (importing the CA into the
# JDK's cacerts works as well).
keytool -importcert -noprompt -alias pullthrough -file "$PT_CA_CERT" \
    -keystore truststore.p12 -storetype PKCS12 -storepass changeit >/dev/null
export MAVEN_OPTS="-Djavax.net.ssl.trustStore=$PWD/truststore.p12 -Djavax.net.ssl.trustStorePassword=changeit -Djavax.net.ssl.trustStoreType=PKCS12"

# Maven does not read HTTPS_PROXY: through a forward proxy, settings.xml names
# it. (Without one — NAT mode — there is nothing to configure.)
if [ -n "${PT_INTERCEPT_PROXY:-}" ]; then
    hostport=${PT_INTERCEPT_PROXY#http://}
    cat > settings.xml <<SETTINGS
<settings>
  <proxies>
    <proxy>
      <id>pullthrough</id>
      <active>true</active>
      <protocol>http</protocol>
      <host>${hostport%:*}</host>
      <port>${hostport##*:}</port>
    </proxy>
  </proxies>
</settings>
SETTINGS
else
    echo '<settings/>' > settings.xml
fi

# A project that depends on the package. (`mvn dependency:get` resolves its
# artifact without the settings.xml proxy; a project's dependencies, which is
# what a build resolves, go through it.) PKG_NAME is "groupId:artifactId".
cat > pom.xml <<POM
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>ecotest</groupId>
  <artifactId>app</artifactId>
  <version>0.0.0</version>
  <dependencies>
    <dependency>
      <groupId>${PKG_NAME%%:*}</groupId>
      <artifactId>${PKG_NAME#*:}</artifactId>
      <version>$PKG_VERSION</version>
    </dependency>
  </dependencies>
</project>
POM
mvn --batch-mode --no-transfer-progress -s settings.xml -Dmaven.repo.local="$PWD/m2" \
    dependency:resolve -DexcludeTransitive=true
