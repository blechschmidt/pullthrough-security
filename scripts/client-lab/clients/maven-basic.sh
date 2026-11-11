#!/bin/sh
# lab: client=Maven (user name + password)
# lab: image=maven:3.9-eclipse-temurin-17
# lab: modes=auth
#
# The <username>/<password> form of a Maven <server>. Maven presents them only
# in answer to a Basic challenge, which the proxy does not send — so they work
# only with preemptive authentication switched on.
set -eu
echo "LAB_CLIENT_VERSION=$(mvn -v | awk 'NR==1 {print $3}')"

cp "$JAVA_HOME/lib/security/cacerts" /etc/ssl/corp-truststore.jks
keytool -importcert -noprompt -trustcacerts -alias corp-ca -file /etc/ssl/corp-ca.pem \
    -keystore /etc/ssl/corp-truststore.jks -storepass changeit
export MAVEN_OPTS="-Djavax.net.ssl.trustStore=/etc/ssl/corp-truststore.jks -Djavax.net.ssl.trustStorePassword=changeit"

mkdir -p ~/.m2
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
      <username>pullthrough</username>
      <password>${PROXY_TOKEN}</password>
    </server>
  </servers>
</settings>
EOF

# Without preemptive authentication: 401.
if mvn --batch-mode --no-transfer-progress dependency:get \
    -Dartifact=org.apache.commons:commons-lang3:3.14.0 -Dtransitive=false >plain.log 2>&1; then
    echo "Maven authenticated without preemptive auth: update docs/clients/maven.md"; cat plain.log; exit 1
fi
grep -q "401" plain.log

mvn --batch-mode --no-transfer-progress -Daether.connector.http.preemptiveAuth=true dependency:get \
    -Dartifact=org.apache.commons:commons-lang3:3.14.0 -Dtransitive=false
test -s ~/.m2/repository/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar
