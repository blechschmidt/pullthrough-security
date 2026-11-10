package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateReferenceDeterministic(t *testing.T) {
	if GenerateReference() != GenerateReference() {
		t.Fatalf("reference generation must be deterministic")
	}
}

func TestGenerateReferenceCoversSurface(t *testing.T) {
	ref := GenerateReference()
	for _, want := range []string{
		"## `server`",
		"`server.httpAddr`",
		"`cache.backend`",
		"`upstreams.<string>.type`",
		"`coordination.mode`",
	} {
		if !strings.Contains(ref, want) {
			t.Errorf("reference is missing %q", want)
		}
	}
	if n := referenceFieldCount(); n < 200 {
		t.Fatalf("expected the reference to document the large config surface, got %d leaf settings", n)
	}
}

// TestReferenceFileUpToDate is the in-test twin of `make config-reference-check`:
// it fails if the committed docs/configuration-reference.md no longer matches the
// generator output, so a struct change without a docs regen is caught by `go
// test` too (not only in CI).
func TestReferenceFileUpToDate(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "configuration-reference.md")
	committed, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("committed reference not found (%v); run `make config-reference-gen`", err)
	}
	if string(committed) != GenerateReference() {
		t.Fatalf("%s is stale; run `make config-reference-gen` and commit the result", path)
	}
}
