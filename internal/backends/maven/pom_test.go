package maven

import "testing"

const fullPOM = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.google.guava</groupId>
  <artifactId>guava</artifactId>
  <version>31.1-jre</version>
  <packaging>jar</packaging>
  <licenses>
    <license>
      <name>Apache License, Version 2.0</name>
      <url>https://www.apache.org/licenses/LICENSE-2.0.txt</url>
    </license>
  </licenses>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>failureaccess</artifactId>
      <version>1.0.1</version>
    </dependency>
    <dependency>
      <groupId>org.checkerframework</groupId>
      <artifactId>checker-qual</artifactId>
      <version>3.12.0</version>
      <scope>provided</scope>
      <optional>true</optional>
    </dependency>
  </dependencies>
</project>`

func TestParsePOMFull(t *testing.T) {
	p, err := ParsePOM([]byte(fullPOM))
	if err != nil {
		t.Fatalf("ParsePOM: %v", err)
	}
	if p.Coordinate() != "com.google.guava:guava" {
		t.Errorf("Coordinate = %q", p.Coordinate())
	}
	if p.Version != "31.1-jre" {
		t.Errorf("Version = %q", p.Version)
	}
	if p.Packaging != "jar" {
		t.Errorf("Packaging = %q", p.Packaging)
	}
	if len(p.Licenses) != 1 || p.Licenses[0].Name != "Apache License, Version 2.0" {
		t.Errorf("Licenses = %+v", p.Licenses)
	}
	if len(p.Dependencies) != 2 {
		t.Fatalf("Dependencies = %d, want 2", len(p.Dependencies))
	}
	if d := p.Dependencies[1]; d.Scope != "provided" || !d.Optional {
		t.Errorf("dependency[1] = %+v", d)
	}
}

func TestParsePOMParentInheritance(t *testing.T) {
	const childPOM = `<project>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.1.0</version>
  </parent>
  <artifactId>my-service</artifactId>
</project>`
	p, err := ParsePOM([]byte(childPOM))
	if err != nil {
		t.Fatalf("ParsePOM: %v", err)
	}
	// groupId and version are inherited from the parent.
	if p.GroupID != "org.springframework.boot" {
		t.Errorf("inherited GroupID = %q", p.GroupID)
	}
	if p.Version != "3.1.0" {
		t.Errorf("inherited Version = %q", p.Version)
	}
	if p.ArtifactID != "my-service" {
		t.Errorf("ArtifactID = %q", p.ArtifactID)
	}
	// Default packaging is "jar" when unspecified.
	if p.Packaging != "jar" {
		t.Errorf("default Packaging = %q", p.Packaging)
	}
}

func TestPOMMatchesPath(t *testing.T) {
	p, err := ParsePOM([]byte(fullPOM))
	if err != nil {
		t.Fatalf("ParsePOM: %v", err)
	}
	if !p.matchesPath("com.google.guava", "guava", "31.1-jre") {
		t.Error("expected POM to match its own path coordinate")
	}
	if p.matchesPath("evil.group", "guava", "31.1-jre") {
		t.Error("expected mismatch on groupId")
	}
	if p.matchesPath("com.google.guava", "not-guava", "31.1-jre") {
		t.Error("expected mismatch on artifactId")
	}
}

func TestPOMMatchesPathUnresolvedProperty(t *testing.T) {
	const propPOM = `<project>
  <groupId>com.example</groupId>
  <artifactId>lib</artifactId>
  <version>${revision}</version>
</project>`
	p, err := ParsePOM([]byte(propPOM))
	if err != nil {
		t.Fatalf("ParsePOM: %v", err)
	}
	// An unresolved property version cannot be compared, so it is treated as a
	// match (the path version remains authoritative).
	if !p.matchesPath("com.example", "lib", "1.2.3") {
		t.Error("unresolved property version should not be flagged as a mismatch")
	}
}

func TestParsePOMRejectsGarbage(t *testing.T) {
	if _, err := ParsePOM([]byte("definitely not xml")); err == nil {
		t.Error("expected error for malformed XML")
	}
	if _, err := ParsePOM([]byte(`<metadata></metadata>`)); err == nil {
		t.Error("expected error for wrong root element")
	}
}
