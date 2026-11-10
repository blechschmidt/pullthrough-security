package composer

import "testing"

func TestParseMetadataPlain(t *testing.T) {
	md, err := ParseMetadata([]byte(metadataFixture))
	if err != nil {
		t.Fatalf("ParseMetadata: %v", err)
	}
	versions := md.Packages["monolog/monolog"]
	if len(versions) != 2 {
		t.Fatalf("parsed %d versions, want 2", len(versions))
	}
	if versions[0].Version != "3.2.0" || versions[0].Dist.Reference != "ref320" {
		t.Errorf("version[0] = %+v", versions[0])
	}
	v, ok := md.FindByReference("ref310")
	if !ok || v.Version != "3.1.0" {
		t.Errorf("FindByReference(ref310) = %+v,%v", v, ok)
	}
	if cs, ok := v.Checksum(); !ok || cs.hex != "1111111111111111111111111111111111111111" {
		t.Errorf("checksum = %+v,%v", cs, ok)
	}
}

func TestParseMetadataMinifiedExpansion(t *testing.T) {
	md, err := ParseMetadata([]byte(minifiedFixture))
	if err != nil {
		t.Fatalf("ParseMetadata: %v", err)
	}
	versions := md.Packages["vendor/pkg"]
	if len(versions) != 2 {
		t.Fatalf("parsed %d versions, want 2", len(versions))
	}

	// First version: complete, with its license.
	if versions[0].Version != "2.0.0" {
		t.Errorf("version[0] = %q", versions[0].Version)
	}
	if len(versions[0].License) != 1 || versions[0].License[0] != "Apache-2.0" {
		t.Errorf("version[0] license = %v", versions[0].License)
	}

	// Second version: inherits "name" from the first (delta only changed
	// version/license/dist), and "__unset" removed the license.
	if versions[1].Name != "vendor/pkg" {
		t.Errorf("version[1] name not inherited: %q", versions[1].Name)
	}
	if versions[1].Version != "1.9.0" {
		t.Errorf("version[1] version = %q", versions[1].Version)
	}
	if len(versions[1].License) != 0 {
		t.Errorf("version[1] license should be unset, got %v", versions[1].License)
	}
	if versions[1].Dist.Reference != "rB" {
		t.Errorf("version[1] dist reference = %q", versions[1].Dist.Reference)
	}
}

func TestParseMetadataMalformedDistTolerated(t *testing.T) {
	doc := `{"packages":{"a/b":[{"version":"1.0.0","dist":"not-an-object"}]}}`
	md, err := ParseMetadata([]byte(doc))
	if err != nil {
		t.Fatalf("ParseMetadata: %v", err)
	}
	v := md.Packages["a/b"][0]
	if v.Version != "1.0.0" {
		t.Errorf("version = %q", v.Version)
	}
	if _, ok := v.Checksum(); ok {
		t.Error("malformed dist should yield no checksum")
	}
}

func TestParseMetadataInvalidJSON(t *testing.T) {
	if _, err := ParseMetadata([]byte("not json")); err == nil {
		t.Error("invalid JSON should error")
	}
}

func TestParseMetadataTooLarge(t *testing.T) {
	big := make([]byte, maxMetadataBytes+1)
	if _, err := ParseMetadata(big); err == nil {
		t.Error("oversized metadata should be rejected")
	}
}

func TestParseRoot(t *testing.T) {
	root, err := ParseRoot([]byte(`{"metadata-url":"/p2/%package%.json","providers-url":"/p/%package%$%hash%.json"}`))
	if err != nil {
		t.Fatalf("ParseRoot: %v", err)
	}
	if root.MetadataURL != "/p2/%package%.json" {
		t.Errorf("metadata-url = %q", root.MetadataURL)
	}
	if root.ProvidersURL != "/p/%package%$%hash%.json" {
		t.Errorf("providers-url = %q", root.ProvidersURL)
	}
}
