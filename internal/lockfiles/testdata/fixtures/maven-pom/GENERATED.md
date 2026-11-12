# maven-pom

Hand-written: a Spring Boot style POM. Read: the parent, plain dependencies with literal and
property versions (including a property defined through another property and ${project.*}), a
test-scoped dependency, an imported BOM, plugins (one without a groupId: org.apache.maven.plugins)
and a plugin's dependency, and a profile's dependency. Warned about: a version managed by the BOM, a
range, a SNAPSHOT, a property not defined in the file, a plugin without a version.
