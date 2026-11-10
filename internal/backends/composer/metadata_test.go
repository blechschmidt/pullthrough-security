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
	v, ok := md.FindDist("monolog/monolog", "3.1.0", "ref310", "zip")
	if !ok || v.Version != "3.1.0" {
		t.Errorf("FindDist(3.1.0, ref310) = %+v,%v", v, ok)
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

// A minified version that does not repeat "dist" inherits the previous one's, and
// "dist":"__unset" removes it. Real Packagist documents do both.
func TestParseMetadataInheritedAndUnsetDist(t *testing.T) {
	md, err := ParseMetadata([]byte(inheritedDistFixture))
	if err != nil {
		t.Fatalf("ParseMetadata: %v", err)
	}
	versions := md.Packages["ralouphie/getallheaders"]
	if len(versions) != 4 {
		t.Fatalf("parsed %d versions, want 4", len(versions))
	}
	if versions[1].Version != "dev-master" || versions[1].Dist.Reference != "120b605dfeb996808c31b6477290a714d356e822" {
		t.Errorf("dev-master should inherit dev-develop's dist, got %+v", versions[1])
	}
	if versions[3].Version != "dev-no-dist" || versions[3].Dist.URL != "" {
		t.Errorf("dev-no-dist should have no dist, got %+v", versions[3])
	}
}

// The delta encoding is only in force for the exact marker Composer tests for; a
// near-miss marker means every object stands alone.
func TestParseMetadataMinifiedMarkerIsExact(t *testing.T) {
	doc := `{"minified":"Composer/2.0","packages":{"a/b":[
	  {"version":"2.0.0","dist":{"type":"zip","url":"https://example.test/2.zip","reference":"r2"}},
	  {"version":"1.0.0"}
	]}}`
	md, err := ParseMetadata([]byte(doc))
	if err != nil {
		t.Fatalf("ParseMetadata: %v", err)
	}
	if got := md.Packages["a/b"][1].Dist.URL; got != "" {
		t.Errorf("second version must not inherit a dist without the exact marker, got %q", got)
	}
	if _, ok := md.FindDist("a/b", "1.0.0", "r2", "zip"); ok {
		t.Error("FindDist must not find an inherited dist without the exact marker")
	}
}

// A Composer client iterates a version collection with a PHP foreach, which
// accepts an object as readily as an array; the proxy must see the same versions.
func TestParseMetadataObjectVersionCollection(t *testing.T) {
	doc := `{"packages":{"a/b":{
	  "2.0.0":{"version":"2.0.0","dist":{"type":"zip","url":"https://example.test/2.zip","reference":"r2"}},
	  "1.0.0":{"version":"1.0.0","dist":{"type":"zip","url":"https://example.test/1.zip","reference":"r1"}},
	  "2.0.0":{"version":"2.0.0","dist":{"type":"zip","url":"https://example.test/2b.zip","reference":"r2b"}}
	}}}`
	md, err := ParseMetadata([]byte(doc))
	if err != nil {
		t.Fatalf("ParseMetadata: %v", err)
	}
	versions := md.Packages["a/b"]
	if len(versions) != 2 {
		t.Fatalf("parsed %d versions, want 2 (a repeated key keeps one entry)", len(versions))
	}
	// The repeated key keeps its first position and takes the last value.
	if versions[0].Version != "2.0.0" || versions[0].Dist.Reference != "r2b" || versions[1].Version != "1.0.0" {
		t.Errorf("versions = %+v", versions)
	}
}

// PHP encodes an empty map as "[]"; such a document simply has no packages.
func TestParseMetadataEmptyPackagesArray(t *testing.T) {
	for _, doc := range []string{`{"packages":[]}`, `{"packages":{}}`, `{}`, `{"packages":null}`, `{"packages":{"a/b":[]}}`} {
		md, err := ParseMetadata([]byte(doc))
		if err != nil {
			t.Errorf("ParseMetadata(%s): %v", doc, err)
			continue
		}
		if len(md.Packages["a/b"]) != 0 {
			t.Errorf("ParseMetadata(%s) found versions", doc)
		}
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

// parseDist reads a dist the way a Composer client does: exact, case-sensitive
// keys and string values only. Anything a client could not download is not a dist.
func TestParseDist(t *testing.T) {
	d, ok := parseDist([]byte(`{"type":"zip","url":"https://example.test/a.zip","reference":"abc","shasum":"0000000000000000000000000000000000000000"}`))
	if !ok || d.Type != "zip" || d.URL != "https://example.test/a.zip" || d.Reference != "abc" || d.Shasum == "" {
		t.Errorf("parseDist = %+v, %v", d, ok)
	}

	// An absent or null reference is "no reference", not an error.
	for _, raw := range []string{
		`{"type":"zip","url":"https://example.test/a.zip"}`,
		`{"type":"zip","url":"https://example.test/a.zip","reference":null,"shasum":null}`,
	} {
		d, ok := parseDist([]byte(raw))
		if !ok || d.Reference != "" || d.Shasum != "" {
			t.Errorf("parseDist(%s) = %+v, %v", raw, d, ok)
		}
	}

	// A differently-cased key is a different key: only "url" is the URL.
	d, ok = parseDist([]byte(`{"type":"zip","url":"https://good.test/a.zip","URL":"https://evil.test/a.zip","Url":"https://evil.test/b.zip"}`))
	if !ok || d.URL != "https://good.test/a.zip" {
		t.Errorf("parseDist must read the exact \"url\" key, got %+v, %v", d, ok)
	}

	for _, raw := range []string{
		``,
		`null`,
		`"__unset"`,
		`[]`,
		`{}`,
		`{"type":"zip"}`,                        // no url
		`{"url":"https://example.test/a.zip"}`,  // no type
		`{"type":"","url":"https://x.test/a"}`,  // empty type
		`{"type":"zip","url":""}`,               // empty url
		`{"type":"zip","url":42}`,               // url is not a string
		`{"type":["zip"],"url":"https://x/a"}`,  // type is not a string
		`{"type":"zip","URL":"https://x.test"}`, // wrong-case url only
		`{"type":"zip","url":"https://x.test/a","reference":1234}`, // reference is not a string
	} {
		if d, ok := parseDist([]byte(raw)); ok {
			t.Errorf("parseDist(%s) unexpectedly ok: %+v", raw, d)
		}
	}
}

// FindDist only honors a version/reference/type triple that one and the same
// metadata entry lists.
func TestFindDistRequiresMatchingEntry(t *testing.T) {
	md, err := ParseMetadata([]byte(metadataFixture))
	if err != nil {
		t.Fatalf("ParseMetadata: %v", err)
	}
	if _, ok := md.FindDist("monolog/monolog", "3.2.0", "ref320", "zip"); !ok {
		t.Fatal("the listed triple must be found")
	}
	misses := []struct{ name, version, token, distType string }{
		{"monolog/monolog", "3.2.0", "ref310", "zip"}, // another version's reference
		{"monolog/monolog", "3.1.0", "ref320", "zip"}, // another version's reference
		{"monolog/monolog", "3.2.0", "nope", "zip"},   // unlisted reference
		{"monolog/monolog", "9.9.9", "ref320", "zip"}, // unlisted version
		{"monolog/monolog", "3.2.0", "ref320", "tar"}, // wrong type
		{"monolog/monolog", "3.2.0", "", "zip"},       // no token
		{"monolog/monolog", "", "ref320", "zip"},      // no version
		{"other/pkg", "3.2.0", "ref320", "zip"},       // another package
		{"Monolog/Monolog", "3.2.0", "ref320", "zip"}, // names are matched exactly
	}
	for _, m := range misses {
		if v, ok := md.FindDist(m.name, m.version, m.token, m.distType); ok {
			t.Errorf("FindDist(%q, %q, %q, %q) unexpectedly found %+v", m.name, m.version, m.token, m.distType, v)
		}
	}
	var none *Metadata
	if _, ok := none.FindDist("monolog/monolog", "3.2.0", "ref320", "zip"); ok {
		t.Error("a nil Metadata lists nothing")
	}
}

// A dist without a reference, or with a reference a URL path cannot carry, is
// found through its token.
func TestFindDistByReferenceToken(t *testing.T) {
	doc := `{"packages":{"a/b":[
	  {"version":"1.0.0","dist":{"type":"zip","url":"https://example.test/1.zip"}},
	  {"version":"2.0.0","dist":{"type":"zip","url":"https://example.test/2.zip","reference":"refs/tags/v2"}}
	]}}`
	md, err := ParseMetadata([]byte(doc))
	if err != nil {
		t.Fatalf("ParseMetadata: %v", err)
	}
	if v, ok := md.FindDist("a/b", "1.0.0", noReferenceToken, "zip"); !ok || v.Dist.URL != "https://example.test/1.zip" {
		t.Errorf("reference-less dist = %+v, %v", v, ok)
	}
	if v, ok := md.FindDist("a/b", "2.0.0", referenceToken("refs/tags/v2"), "zip"); !ok || v.Dist.URL != "https://example.test/2.zip" {
		t.Errorf("hashed-reference dist = %+v, %v", v, ok)
	}
	// The placeholder does not stand in for a real reference.
	if _, ok := md.FindDist("a/b", "2.0.0", noReferenceToken, "zip"); ok {
		t.Error("the placeholder must not match a dist that declares a reference")
	}
}

func TestParseMetadataInvalidJSON(t *testing.T) {
	for _, doc := range []string{"not json", "", "null", "[]", `"string"`, "42"} {
		if _, err := ParseMetadata([]byte(doc)); err == nil {
			t.Errorf("ParseMetadata(%q) should error", doc)
		}
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
