#!/bin/sh
# lab: client=Maven
# lab: image=maven:3.9-eclipse-temurin-17
#
# Maven with a mirror of every repository in ~/.m2/settings.xml. Where the proxy
# asks for a token, it is sent as an Authorization header configured on the
# mirror's <server>.
set -eu
echo "LAB_CLIENT_VERSION=$(mvn -v | awk 'NR==1 {print $3}')"

# The JVM does not read PEM bundles: add the CA to a copy of the JDK's trust
# store and point Maven's JVM at it.
cp "$JAVA_HOME/lib/security/cacerts" /etc/ssl/corp-truststore.jks
keytool -importcert -noprompt -trustcacerts -alias corp-ca -file /etc/ssl/corp-ca.pem \
    -keystore /etc/ssl/corp-truststore.jks -storepass changeit
export MAVEN_OPTS="-Djavax.net.ssl.trustStore=/etc/ssl/corp-truststore.jks -Djavax.net.ssl.trustStorePassword=changeit"

mkdir -p ~/.m2
if [ -n "${PROXY_TOKEN:-}" ]; then
cat > ~/.m2/settings.xml <<EOF
<settings>
  <mirrors>
    <mirror>
      <id>pullthrough</id>
      <name>pull-through proxy</name>
      <url>https://proxy.example.com/v1/maven</url>
      <mirrorOf>*</mirrorOf>
    </mirror>
  </mirrors>
  <servers>
    <server>
      <id>pullthrough</id>
      <configuration>
        <httpHeaders>
          <property>
            <name>Authorization</name>
            <value>Bearer ${PROXY_TOKEN}</value>
          </property>
        </httpHeaders>
      </configuration>
    </server>
  </servers>
</settings>
EOF
else
cat > ~/.m2/settings.xml <<EOF
<settings>
  <mirrors>
    <mirror>
      <id>pullthrough</id>
      <name>pull-through proxy</name>
      <url>https://proxy.example.com/v1/maven</url>
      <mirrorOf>*</mirrorOf>
    </mirror>
  </mirrors>
</settings>
EOF
fi

mvn --batch-mode --no-transfer-progress dependency:get \
    -Dartifact=org.apache.commons:commons-lang3:3.14.0 -Dtransitive=false
test -s ~/.m2/repository/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar
