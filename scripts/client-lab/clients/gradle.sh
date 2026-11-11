#!/bin/sh
# lab: client=Gradle
# lab: image=gradle:8.10-jdk17
#
# Gradle with an init script that replaces every repository of every build on
# the machine — for plugins (the Plugin Portal, a Maven-layout repository behind
# an upstream of its own) and for dependencies.
set -eu
echo "LAB_CLIENT_VERSION=$(gradle --version | awk '/^Gradle/ {print $2}')"

# The JVM does not read PEM bundles: add the CA to a copy of the JDK's trust
# store and point Gradle's JVMs at it.
cp "$JAVA_HOME/lib/security/cacerts" /etc/ssl/corp-truststore.jks
keytool -importcert -noprompt -trustcacerts -alias corp-ca -file /etc/ssl/corp-ca.pem \
    -keystore /etc/ssl/corp-truststore.jks -storepass changeit
mkdir -p ~/.gradle/init.d
cat > ~/.gradle/gradle.properties <<EOF
systemProp.javax.net.ssl.trustStore=/etc/ssl/corp-truststore.jks
systemProp.javax.net.ssl.trustStorePassword=changeit
EOF

cat > ~/.gradle/init.d/pullthrough.init.gradle.kts <<'EOF'
// Every build on this machine resolves plugins and dependencies through the proxy.
val proxy = "https://proxy.example.com/v1"
val token: String? = System.getenv("PULLTHROUGH_TOKEN")

fun RepositoryHandler.pullthrough(upstream: String) = maven {
    name = "pullthrough-$upstream"
    url = uri("$proxy/$upstream")
    if (token != null) {
        // The proxy takes the token as a bearer credential, sent with every request.
        credentials(HttpHeaderCredentials::class) {
            name = "Authorization"
            value = "Bearer $token"
        }
        authentication { create<HttpHeaderAuthentication>("header") }
    }
}

settingsEvaluated {
    pluginManagement.repositories { clear(); pullthrough("gradle-plugins") }
}
allprojects {
    buildscript.repositories { clear(); pullthrough("gradle-plugins") }
    repositories { clear(); pullthrough("maven") }
    // A repository the build declares itself is replaced as well.
    repositories.whenObjectAdded {
        if (this is MavenArtifactRepository && !name.startsWith("pullthrough-")) {
            repositories.remove(this)
        }
    }
}
EOF
if [ -n "${PROXY_TOKEN:-}" ]; then
    export PULLTHROUGH_TOKEN="${PROXY_TOKEN}"
fi

mkdir app && cd app
echo 'rootProject.name = "lab"' > settings.gradle.kts
cat > build.gradle.kts <<'EOF'
plugins {
    java
    id("com.github.ben-manes.versions") version "0.51.0"
}
repositories { mavenCentral() }
dependencies { implementation("org.apache.commons:commons-lang3:3.14.0") }
tasks.register("resolveAll") {
    doLast { configurations["runtimeClasspath"].files.forEach { println("resolved " + it.name) } }
}
EOF
gradle --no-daemon --quiet resolveAll | tee resolve.log
grep -q "resolved commons-lang3-3.14.0.jar" resolve.log
