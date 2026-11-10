package maven

import "testing"

const releaseMetadataXML = `<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>com.google.guava</groupId>
  <artifactId>guava</artifactId>
  <versioning>
    <latest>31.1-jre</latest>
    <release>31.1-jre</release>
    <versions>
      <version>30.0-jre</version>
      <version>31.0-jre</version>
      <version>31.1-jre</version>
    </versions>
    <lastUpdated>20220215120000</lastUpdated>
  </versioning>
</metadata>`

const snapshotMetadataXML = `<?xml version="1.0" encoding="UTF-8"?>
<metadata modelVersion="1.1.0">
  <groupId>com.example</groupId>
  <artifactId>lib</artifactId>
  <version>1.0-SNAPSHOT</version>
  <versioning>
    <snapshot>
      <timestamp>20231010.123456</timestamp>
      <buildNumber>7</buildNumber>
    </snapshot>
    <lastUpdated>20231010123456</lastUpdated>
    <snapshotVersions>
      <snapshotVersion>
        <extension>jar</extension>
        <value>1.0-20231010.123456-7</value>
        <updated>20231010123456</updated>
      </snapshotVersion>
      <snapshotVersion>
        <classifier>sources</classifier>
        <extension>jar</extension>
        <value>1.0-20231010.123456-7</value>
        <updated>20231010123456</updated>
      </snapshotVersion>
      <snapshotVersion>
        <extension>pom</extension>
        <value>1.0-20231010.123456-7</value>
        <updated>20231010123456</updated>
      </snapshotVersion>
    </snapshotVersions>
  </versioning>
</metadata>`

func TestParseReleaseMetadata(t *testing.T) {
	m, err := ParseMetadata([]byte(releaseMetadataXML))
	if err != nil {
		t.Fatalf("ParseMetadata: %v", err)
	}
	if m.GroupID != "com.google.guava" || m.ArtifactID != "guava" {
		t.Errorf("GA = %s:%s", m.GroupID, m.ArtifactID)
	}
	if m.Latest != "31.1-jre" || m.Release != "31.1-jre" {
		t.Errorf("latest=%q release=%q", m.Latest, m.Release)
	}
	if len(m.Versions) != 3 || m.Versions[2] != "31.1-jre" {
		t.Errorf("versions = %v", m.Versions)
	}
	if m.Snapshot != nil {
		t.Errorf("release metadata should not carry a snapshot block: %+v", m.Snapshot)
	}
}

func TestParseSnapshotMetadata(t *testing.T) {
	m, err := ParseMetadata([]byte(snapshotMetadataXML))
	if err != nil {
		t.Fatalf("ParseMetadata: %v", err)
	}
	if m.Snapshot == nil {
		t.Fatal("expected a snapshot block")
	}
	if m.Snapshot.Timestamp != "20231010.123456" || m.Snapshot.BuildNumber != 7 {
		t.Errorf("snapshot = %+v", m.Snapshot)
	}
	if len(m.SnapshotVersions) != 3 {
		t.Fatalf("snapshotVersions = %d, want 3", len(m.SnapshotVersions))
	}
}

func TestResolveSnapshotFromSnapshotVersions(t *testing.T) {
	m, err := ParseMetadata([]byte(snapshotMetadataXML))
	if err != nil {
		t.Fatalf("ParseMetadata: %v", err)
	}
	// Main jar.
	if got, ok := m.ResolveSnapshot("lib", "1.0-SNAPSHOT", "", "jar"); !ok || got != "lib-1.0-20231010.123456-7.jar" {
		t.Errorf("ResolveSnapshot(main jar) = %q, ok=%v", got, ok)
	}
	// Sources classifier.
	if got, ok := m.ResolveSnapshot("lib", "1.0-SNAPSHOT", "sources", "jar"); !ok || got != "lib-1.0-20231010.123456-7-sources.jar" {
		t.Errorf("ResolveSnapshot(sources) = %q, ok=%v", got, ok)
	}
	// POM.
	if got, ok := m.ResolveSnapshot("lib", "1.0-SNAPSHOT", "", "pom"); !ok || got != "lib-1.0-20231010.123456-7.pom" {
		t.Errorf("ResolveSnapshot(pom) = %q, ok=%v", got, ok)
	}
}

func TestResolveSnapshotFallbackToSnapshotBlock(t *testing.T) {
	// Metadata with only the <snapshot> block (no explicit snapshotVersions).
	const xml = `<metadata>
  <groupId>com.example</groupId>
  <artifactId>lib</artifactId>
  <version>2.0-SNAPSHOT</version>
  <versioning>
    <snapshot>
      <timestamp>20240101.010101</timestamp>
      <buildNumber>3</buildNumber>
    </snapshot>
  </versioning>
</metadata>`
	m, err := ParseMetadata([]byte(xml))
	if err != nil {
		t.Fatalf("ParseMetadata: %v", err)
	}
	got, ok := m.ResolveSnapshot("lib", "2.0-SNAPSHOT", "", "jar")
	if !ok || got != "lib-2.0-20240101.010101-3.jar" {
		t.Errorf("ResolveSnapshot = %q, ok=%v", got, ok)
	}
}

func TestResolveSnapshotNoData(t *testing.T) {
	m := &Metadata{ArtifactID: "lib"}
	if _, ok := m.ResolveSnapshot("lib", "1.0-SNAPSHOT", "", "jar"); ok {
		t.Error("expected ok=false when no snapshot data present")
	}
}

func TestParseMetadataRejectsGarbage(t *testing.T) {
	if _, err := ParseMetadata([]byte("not xml at all <<<")); err == nil {
		t.Error("expected error for malformed XML")
	}
	if _, err := ParseMetadata([]byte(`<project><groupId>x</groupId></project>`)); err == nil {
		t.Error("expected error for wrong root element")
	}
}
