# gradle fixture — how it was generated

`gradle.lockfile` was written by real Gradle (2026-11-12, linux/amd64); it is not hand-made and must not be edited.

- Tool: Gradle 8.10.2 (Kotlin 1.9.24, Groovy 3.0.22), JVM Eclipse Adoptium 21.0.5+11-LTS
- Image: `gradle:8.10-jdk21` = `gradle@sha256:963d59f7f22767da4efbcf46b661361b61af5fb88b0309da1071c4234c647eba`
- Inputs: `settings.gradle`, `build.gradle` (Groovy DSL, `java` plugin, `mavenCentral()`, `dependencyLocking { lockAllConfigurations() }`)

Command (dependency resolution only, nothing compiled):

    docker run --rm -v /mnt/HC_Volume_106716549/pt178/jvm:/work -w /work/gradle \
      -e GRADLE_USER_HOME=/work/cache/gradle-home gradle:8.10-jdk21 \
      sh -c 'gradle --version --no-daemon && gradle dependencies --write-locks --no-daemon --console=plain'

Notable features of `gradle.lockfile`:

- Only `gradle.lockfile` was written: no `settings-gradle.lockfile` / `buildscript-gradle.lockfile` (settings and buildscript classpaths are neither locked nor non-empty).
- Three `#` comment header lines, then one `group:name:version=conf1,conf2,...` line per module, sorted lexicographically by the whole line.
- 7 modules: 3 declared (slf4j-api 2.0.13, jackson-databind 2.17.2, junit 4.13.2) and 4 transitive (jackson-annotations 2.17.2, jackson-core 2.17.2, jackson-bom 2.17.2, hamcrest-core 1.3).
- The lock file does not say which modules are declared and which are transitive.
- `com.fasterxml.jackson:jackson-bom:2.17.2` is a BOM/platform (pulled in through Gradle Module Metadata) and is locked like any other module.
- Test-only modules (junit, hamcrest-core) list only `testCompileClasspath,testRuntimeClasspath`; main modules list all four classpaths.
- Last line `empty=annotationProcessor,testAnnotationProcessor` names locked configurations that resolved to nothing; it is not a module.
- No hashes, no repository URLs.
- LF line endings, trailing newline.
