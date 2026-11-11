package backends

import "testing"

func TestArtifactClassString(t *testing.T) {
	for class, want := range map[ArtifactClass]string{
		ArtifactUnclassified: "unclassified",
		ArtifactMetadata:     "metadata",
		ArtifactPayload:      "payload",
		ArtifactClass(200):   "unclassified",
	} {
		if got := class.String(); got != want {
			t.Errorf("ArtifactClass(%d).String() = %q, want %q", class, got, want)
		}
	}
}

// The zero Artifact must be "unclassified": a backend that forgets to classify
// a path leaves the decision to the bytes instead of declaring it metadata.
func TestArtifactZeroValueIsUnclassified(t *testing.T) {
	var r Resolved
	if r.Artifact.Class != ArtifactUnclassified {
		t.Fatalf("zero Resolved.Artifact.Class = %v, want unclassified", r.Artifact.Class)
	}
	if r.Artifact.Kind != "" || r.Artifact.Filename != "" {
		t.Fatalf("zero Resolved.Artifact = %+v, want empty kind and filename", r.Artifact)
	}
}

func TestArtifactConstructors(t *testing.T) {
	cases := []struct {
		name string
		got  Artifact
		want Artifact
	}{
		{"Payload", Payload(), Artifact{Class: ArtifactPayload}},
		{"PayloadNamed", PayloadNamed("demo-1.0.0.crate"), Artifact{Class: ArtifactPayload, Filename: "demo-1.0.0.crate"}},
		{"PayloadFile", PayloadFile(), Artifact{Class: ArtifactPayload, Kind: KindFile}},
		{"Metadata", Metadata(), Artifact{Class: ArtifactMetadata}},
		{"MetadataArchive", MetadataArchive(), Artifact{Class: ArtifactMetadata, Kind: KindIndexArchive}},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s() = %+v, want %+v", c.name, c.got, c.want)
		}
	}
}

func TestResolvedArtifactFilename(t *testing.T) {
	for raw, want := range map[string]string{
		"https://registry.npmjs.org/demo/-/demo-1.0.0.tgz":           "demo-1.0.0.tgz",
		"https://files.example/packages/demo-1.0.0.whl?sig=abc#frag": "demo-1.0.0.whl",
		"https://crates.io/api/v1/crates/demo/1.0.0/download":        "download",
		"https://host/":   "",
		"":                "",
		"::not a url::/x": "x",
	} {
		if got := (&Resolved{UpstreamURL: raw}).ArtifactFilename(); got != want {
			t.Errorf("ArtifactFilename(%q) = %q, want %q", raw, got, want)
		}
	}

	// An explicit name wins over the URL: a crate's upstream URL ends in
	// "download", which says nothing about the format.
	named := &Resolved{
		UpstreamURL: "https://crates.io/api/v1/crates/demo/1.0.0/download",
		Artifact:    PayloadNamed("demo-1.0.0.crate"),
	}
	if got := named.ArtifactFilename(); got != "demo-1.0.0.crate" {
		t.Errorf("explicit Artifact.Filename ignored: got %q", got)
	}

	var none *Resolved
	if got := none.ArtifactFilename(); got != "" {
		t.Errorf("nil Resolved: got %q, want empty", got)
	}
}
