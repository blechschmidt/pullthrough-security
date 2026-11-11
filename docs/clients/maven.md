# Maven and Gradle

Send every repository request of a JVM build through the proxy. The examples
use the upstream names `maven` (Maven Central) and `gradle-plugins` (the Gradle
Plugin Portal); replace them with the names your operator gave the upstreams
([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `maven` |
| Package source | `https://proxy.example.com/v1/maven` (a Maven-layout repository) |
| Clients | Maven, Gradle |
| Tested | Maven 3.9: [in CI on every push](../ecosystem-tests-reference.md#maven) and in the [client lab](../client-lab.md). Gradle 8.10: in the client lab. sbt, Ivy and Leiningen: not tested. |

## Configure

### Maven

A mirror of every repository, in `~/.m2/settings.xml`. `<mirrorOf>*</mirrorOf>`
covers Maven Central and plugin repositories alike, and repositories that a
`pom.xml` declares, without touching any POM:

<!-- verified: ci:maven lab:maven -->

```xml
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
```

One mirror serves one upstream. A build that needs artifacts from a second
repository (a vendor's, your own) needs a second upstream and a mirror whose
`<mirrorOf>` names that repository's id, with `*,!that-id` on the first.

### Gradle

An init script replaces the repositories of every build on the machine — for
plugins (the Plugin Portal is a Maven-layout repository, behind an upstream of
its own) and for dependencies. `~/.gradle/init.d/pullthrough.init.gradle.kts`:

<!-- verified: lab:gradle -->

```kotlin
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
```

The lab build declares `mavenCentral()` and a plugin from the Plugin Portal;
both are resolved from the proxy. A single project can instead name the proxy
in its own `repositories { maven { url = uri("https://proxy.example.com/v1/maven") } }`
block.

## Authenticate

Only when the proxy has access control switched on.

**Maven** — the token as a request header, configured on the `<server>` whose
id is the mirror's:

<!-- verified: lab:maven -->

```xml
  <servers>
    <server>
      <id>pullthrough</id>
      <configuration>
        <httpHeaders>
          <property>
            <name>Authorization</name>
            <value>Bearer <token></value>
          </property>
        </httpHeaders>
      </configuration>
    </server>
  </servers>
```

The usual `<username>`/`<password>` form works only with preemptive
authentication switched on: Maven presents a user name and password in answer
to a `Basic` challenge, and the proxy challenges with `Bearer`.

<!-- verified: lab:maven-basic -->

```xml
    <server>
      <id>pullthrough</id>
      <username>pullthrough</username>
      <password><token></password>
    </server>
```

<!-- verified: lab:maven-basic -->

```sh
mvn --batch-mode --no-transfer-progress -Daether.connector.http.preemptiveAuth=true dependency:get \
    -Dartifact=org.apache.commons:commons-lang3:3.14.0 -Dtransitive=false
```

Without `-Daether.connector.http.preemptiveAuth=true` the same build fails
with `401`. (Maven reads standing command-line arguments from
`.mvn/maven.config`.)

**Gradle** — the init script above sends the token it finds in the
`PULLTHROUGH_TOKEN` environment variable as a bearer header:

<!-- verified: lab:gradle -->

```sh
export PULLTHROUGH_TOKEN="<token>"
```

## Trust a private CA

The JVM does not read PEM bundles. Add the CA to a copy of the JDK's trust
store:

<!-- verified: lab:maven lab:gradle -->

```sh
cp "$JAVA_HOME/lib/security/cacerts" /etc/ssl/corp-truststore.jks
keytool -importcert -noprompt -trustcacerts -alias corp-ca -file /etc/ssl/corp-ca.pem \
    -keystore /etc/ssl/corp-truststore.jks -storepass changeit
```

and point the build tool's JVM at it — **Maven**:

<!-- verified: lab:maven -->

```sh
export MAVEN_OPTS="-Djavax.net.ssl.trustStore=/etc/ssl/corp-truststore.jks -Djavax.net.ssl.trustStorePassword=changeit"
```

**Gradle**, in `~/.gradle/gradle.properties`:

<!-- verified: lab:gradle -->

```properties
systemProp.javax.net.ssl.trustStore=/etc/ssl/corp-truststore.jks
systemProp.javax.net.ssl.trustStorePassword=changeit
```

## Check that it works

<!-- verified: lab:maven -->

```sh
mvn --batch-mode --no-transfer-progress dependency:get \
    -Dartifact=org.apache.commons:commons-lang3:3.14.0 -Dtransitive=false
```

Without `--no-transfer-progress`, Maven prints `Downloading from pullthrough:`
for every artifact — the mirror's id. For Gradle, `--info` names the repository
each artifact is resolved from.

## Good to know

- **Maven's own plugins come through the mirror too** — the first build
  downloads several hundred artifacts through the proxy.
- **The Maven wrapper** downloads Maven itself from the `distributionUrl` in
  `.mvn/wrapper/maven-wrapper.properties`; Maven Central hosts those archives
  (`org/apache/maven/apache-maven/…`), so the proxy address works there (not
  tested). The **Gradle wrapper** downloads from `services.gradle.org`, which is
  not a Maven repository: that needs a [generic upstream](generic.md), or a
  distribution mirror of your own.
- **Snapshots**: non-timestamped `-SNAPSHOT` files are never cached;
  timestamped ones are.
- **Publishing does not go through the proxy** (`mvn deploy`,
  `gradle publish`): it is read-only.

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  maven:
    type: maven
    url: https://repo1.maven.org/maven2
  gradle-plugins:
    type: maven
    url: https://plugins.gradle.org/m2
```

Artifacts are verified against the strongest checksum sidecar the upstream
publishes (SHA-512, then SHA-256, SHA-1, MD5) and cached immutably;
`maven-metadata.xml` is served live. Details:
[backends: maven](../backends.md#maven).
