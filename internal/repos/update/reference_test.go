package update

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

var updateDoc = flag.Bool("update", false, "rewrite the generated part of docs/repositories.md")

// TestRepositoriesDocIsCurrent holds the format table of
// docs/repositories.md#maintenance-updates to the catalog.
func TestRepositoriesDocIsCurrent(t *testing.T) {
	path := filepath.Join("..", "..", "..", "docs", "repositories.md")
	doc, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := SpliceReference(string(doc), GenerateReference())
	if err != nil {
		t.Fatal(err)
	}
	if updated == string(doc) {
		return
	}
	if *updateDoc {
		if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatalf("%s is stale; run go test ./internal/repos/update -run TestRepositoriesDocIsCurrent -update", path)
}

// TestCatalogCoversEveryParser holds the catalog to the lock-file parsers: a
// format added to internal/lockfiles needs a decision here.
func TestCatalogCoversEveryParser(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range lockfiles.DefaultRegistry().All() {
		key := p.Type() + "/" + p.Format()
		seen[key] = true
		if _, ok := Format(key); !ok {
			t.Errorf("%s has no entry in the update catalog (internal/repos/update/catalog.go)", key)
		}
	}
	for _, f := range Formats() {
		if !seen[f.Type+"/"+f.Format] {
			t.Errorf("%s/%s is in the update catalog but no parser reads it", f.Type, f.Format)
		}
	}
}
