package mirror

import (
	"strings"
	"testing"
)

func TestParsePrewarmManifest(t *testing.T) {
	const y = `
packages:
  - upstream: npm
    path: /lodash/-/lodash-4.17.21.tgz
  - upstream: pip
    path: /packages/source/r/requests/requests-2.31.0.tar.gz
images:
  - upstream: dockerhub
    path: /v2/library/alpine/manifests/3.19
`
	m, err := ParsePrewarmManifest(strings.NewReader(y))
	if err != nil {
		t.Fatalf("ParsePrewarmManifest: %v", err)
	}
	entries := m.Entries()
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}
	// Packages come before images, in order.
	if entries[0].Upstream != "npm" || entries[2].Upstream != "dockerhub" {
		t.Errorf("unexpected ordering: %+v", entries)
	}
}

func TestParsePrewarmManifestEmpty(t *testing.T) {
	if _, err := ParsePrewarmManifest(strings.NewReader("packages: []\n")); err == nil {
		t.Fatal("expected error for empty manifest")
	}
}

func TestParsePrewarmManifestMissingPath(t *testing.T) {
	const y = `
packages:
  - upstream: npm
`
	if _, err := ParsePrewarmManifest(strings.NewReader(y)); err == nil {
		t.Fatal("expected error for entry with empty path")
	}
}

func TestParsePrewarmManifestUnknownField(t *testing.T) {
	const y = `
packages:
  - upstream: npm
    path: /x
    bogus: true
`
	if _, err := ParsePrewarmManifest(strings.NewReader(y)); err == nil {
		t.Fatal("expected error for unknown field")
	}
}
