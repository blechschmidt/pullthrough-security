package maven

import "testing"

func TestClassifyArtifact(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		wantKind   resourceKind
		group      string
		artifact   string
		version    string
		classifier string
		ext        string
		cacheable  bool
		verify     bool
	}{
		{
			name:      "release jar",
			path:      "/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar",
			wantKind:  kindArtifact,
			group:     "com.google.guava",
			artifact:  "guava",
			version:   "31.1-jre",
			ext:       "jar",
			cacheable: true,
			verify:    true,
		},
		{
			name:      "release pom",
			path:      "/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.pom",
			wantKind:  kindArtifact,
			group:     "org.apache.commons",
			artifact:  "commons-lang3",
			version:   "3.12.0",
			ext:       "pom",
			cacheable: true,
			verify:    true,
		},
		{
			name:       "sources classifier",
			path:       "/com/google/guava/guava/31.1-jre/guava-31.1-jre-sources.jar",
			wantKind:   kindArtifact,
			group:      "com.google.guava",
			artifact:   "guava",
			version:    "31.1-jre",
			classifier: "sources",
			ext:        "jar",
			cacheable:  true,
			verify:     true,
		},
		{
			name:      "gradle module metadata",
			path:      "/com/example/lib/1.0/lib-1.0.module",
			wantKind:  kindArtifact,
			group:     "com.example",
			artifact:  "lib",
			version:   "1.0",
			ext:       "module",
			cacheable: true,
			verify:    true,
		},
		{
			name:      "war artifact",
			path:      "/com/example/app/2.0/app-2.0.war",
			wantKind:  kindArtifact,
			group:     "com.example",
			artifact:  "app",
			version:   "2.0",
			ext:       "war",
			cacheable: true,
			verify:    true,
		},
		{
			name:      "sha1 checksum sidecar",
			path:      "/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar.sha1",
			wantKind:  kindChecksum,
			group:     "com.google.guava",
			artifact:  "guava",
			version:   "31.1-jre",
			ext:       "jar",
			cacheable: true,
			verify:    false,
		},
		{
			name:      "sha256 checksum sidecar",
			path:      "/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar.sha256",
			wantKind:  kindChecksum,
			group:     "com.google.guava",
			artifact:  "guava",
			version:   "31.1-jre",
			ext:       "jar",
			cacheable: true,
		},
		{
			name:      "asc signature sidecar",
			path:      "/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar.asc",
			wantKind:  kindSignature,
			group:     "com.google.guava",
			artifact:  "guava",
			version:   "31.1-jre",
			ext:       "jar",
			cacheable: true,
		},
		{
			name:      "release metadata",
			path:      "/com/google/guava/guava/maven-metadata.xml",
			wantKind:  kindMetadata,
			group:     "com.google.guava",
			artifact:  "guava",
			version:   "",
			cacheable: false,
		},
		{
			name:      "release metadata checksum",
			path:      "/com/google/guava/guava/maven-metadata.xml.sha1",
			wantKind:  kindMetadataChecksum,
			group:     "com.google.guava",
			artifact:  "guava",
			version:   "",
			cacheable: false,
		},
		{
			name:      "snapshot metadata",
			path:      "/com/example/lib/1.0-SNAPSHOT/maven-metadata.xml",
			wantKind:  kindMetadata,
			group:     "com.example",
			artifact:  "lib",
			version:   "1.0-SNAPSHOT",
			cacheable: false,
		},
		{
			name:      "non-timestamped snapshot jar is mutable",
			path:      "/com/example/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar",
			wantKind:  kindArtifact,
			group:     "com.example",
			artifact:  "lib",
			version:   "1.0-SNAPSHOT",
			ext:       "jar",
			cacheable: false,
			verify:    true,
		},
		{
			name:      "timestamped snapshot jar is immutable",
			path:      "/com/example/lib/1.0-SNAPSHOT/lib-1.0-20231010.123456-7.jar",
			wantKind:  kindArtifact,
			group:     "com.example",
			artifact:  "lib",
			version:   "1.0-SNAPSHOT",
			ext:       "jar",
			cacheable: true,
			verify:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, ok := classify(tt.path)
			if !ok {
				t.Fatalf("classify(%q) returned ok=false", tt.path)
			}
			if res.kind != tt.wantKind {
				t.Errorf("kind = %v, want %v", res.kind, tt.wantKind)
			}
			if res.groupID != tt.group {
				t.Errorf("groupID = %q, want %q", res.groupID, tt.group)
			}
			if res.artifactID != tt.artifact {
				t.Errorf("artifactID = %q, want %q", res.artifactID, tt.artifact)
			}
			if res.version != tt.version {
				t.Errorf("version = %q, want %q", res.version, tt.version)
			}
			if tt.classifier != "" && res.classifier != tt.classifier {
				t.Errorf("classifier = %q, want %q", res.classifier, tt.classifier)
			}
			if tt.ext != "" && res.ext != tt.ext {
				t.Errorf("ext = %q, want %q", res.ext, tt.ext)
			}
			if res.cacheable() != tt.cacheable {
				t.Errorf("cacheable() = %v, want %v", res.cacheable(), tt.cacheable)
			}
			if res.verifiableArtifact() != tt.verify {
				t.Errorf("verifiableArtifact() = %v, want %v", res.verifiableArtifact(), tt.verify)
			}
		})
	}
}

func TestClassifyRejectsBadPaths(t *testing.T) {
	bad := []string{
		"",
		"/",
		"/onlygroup",                 // too few segments
		"/g/a/v/../../../etc/passwd", // traversal
		"/com/example/lib/1.0/wrongprefix-1.0.jar", // filename != artifactId prefix
		"/com/example/lib/1.0/lib-1.0",             // no extension
	}
	for _, p := range bad {
		if res, ok := classify(p); ok {
			t.Errorf("classify(%q) = %+v, want ok=false", p, res)
		}
	}
}

func TestCoordinateName(t *testing.T) {
	res, ok := classify("/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar")
	if !ok {
		t.Fatal("classify failed")
	}
	if got, want := res.coordinateName(), "com.google.guava:guava"; got != want {
		t.Errorf("coordinateName() = %q, want %q", got, want)
	}
}
