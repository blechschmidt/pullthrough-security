#!/bin/sh
# maven — mirror every repository through the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(mvn -v | awk 'NR==1 {print $3}')"

# A <mirror> with <mirrorOf>*</mirrorOf> in settings.xml (~/.m2/settings.xml)
# sends every repository request — Maven Central, plugin repositories — to the
# proxy, without touching any pom.xml.
cat > settings.xml <<SETTINGS
<settings>
  <mirrors>
    <mirror>
      <id>pullthrough</id>
      <name>pull-through proxy</name>
      <url>$MOUNT</url>
      <mirrorOf>*</mirrorOf>
    </mirror>
  </mirrors>
</settings>
SETTINGS

# PKG_NAME is "groupId:artifactId".
mvn --batch-mode --no-transfer-progress -s settings.xml -Dmaven.repo.local="$PWD/m2" \
    dependency:get -Dartifact="$PKG_NAME:$PKG_VERSION" -Dtransitive=false
