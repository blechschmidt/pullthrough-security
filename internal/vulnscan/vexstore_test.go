package vulnscan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

const openVEXNotAffected = `{
	"@context": "https://openvex.dev/ns/v0.2.0",
	"timestamp": "2026-01-01T00:00:00Z",
	"statements": [{
		"vulnerability": {"name": "CVE-2026-1111"},
		"products": [{"@id": "pkg:npm/lodash@4.17.20"}],
		"status": "not_affected",
		"justification": "vulnerable_code_not_present"
	}]
}`

func TestVEXStore_LoadDir_SkipsMalformed(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "good.json", openVEXNotAffected)
	writeFile(t, dir, "bad.json", `{not valid json`)
	writeFile(t, dir, "unknown.json", `{"foo": "bar"}`)
	writeFile(t, dir, "ignored.txt", openVEXNotAffected) // not a VEX file extension

	store := NewVEXStore(nil)
	if err := store.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	stats := store.Stats()
	if stats.Documents != 1 {
		t.Errorf("documents = %d, want 1", stats.Documents)
	}
	if stats.Malformed != 2 {
		t.Errorf("malformed = %d, want 2 (bad.json + unknown.json)", stats.Malformed)
	}
	if stats.Statements != 1 {
		t.Errorf("statements = %d, want 1", stats.Statements)
	}
}

func TestVEXStore_LoadDir_NonexistentIsError(t *testing.T) {
	store := NewVEXStore(nil)
	if err := store.LoadDir("/no/such/dir/at/all"); err == nil {
		t.Error("expected error for non-existent directory")
	}
}

func TestVEXStore_Match(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "v.json", openVEXNotAffected)
	store := NewVEXStore(nil)
	if err := store.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	art := Artifact{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}
	finding := Vulnerability{ID: "CVE-2026-1111", Component: "pkg:npm/lodash@4.17.20", Package: "lodash", Version: "4.17.20"}
	st, ok := store.Match(art, finding)
	if !ok {
		t.Fatal("expected a match")
	}
	if st.Status != VEXNotAffected {
		t.Errorf("status = %q", st.Status)
	}
}

// fakeFetcher is a per-artifact VEXFetcher returning canned statements.
type fakeFetcher struct {
	stmts []VEXStatement
	calls int
	err   error
}

func (f *fakeFetcher) FetchVEX(ctx context.Context, art Artifact) ([]VEXStatement, error) {
	f.calls++
	return f.stmts, f.err
}

func TestVEXStore_Fetcher(t *testing.T) {
	fetcher := &fakeFetcher{stmts: []VEXStatement{{
		Vulnerability: "CVE-2026-7777",
		Status:        VEXNotAffected,
		Products:      []VEXProductRef{newProductRef("pkg:npm/express@4.0.0", "")},
	}}}
	store := NewVEXStore(nil, WithVEXFetcher(fetcher))
	art := Artifact{Ecosystem: "npm", Name: "express", Version: "4.0.0", Digest: "sha256:e"}

	stmts := store.statementsFor(context.Background(), art)
	if len(stmts) != 1 {
		t.Fatalf("got %d statements from fetcher", len(stmts))
	}
	// Second call within TTL should be cached (no extra fetch).
	store.statementsFor(context.Background(), art)
	if fetcher.calls != 1 {
		t.Errorf("fetcher called %d times, want 1 (cached)", fetcher.calls)
	}
}

func TestVEXStore_OfflineIgnoresFetcher(t *testing.T) {
	fetcher := &fakeFetcher{stmts: []VEXStatement{{Vulnerability: "CVE-X", Status: VEXFixed}}}
	store := NewVEXStore(nil, WithVEXFetcher(fetcher), WithVEXOffline(true))
	art := Artifact{Ecosystem: "npm", Name: "express", Version: "4.0.0", Digest: "sha256:e"}
	stmts := store.statementsFor(context.Background(), art)
	if len(stmts) != 0 {
		t.Errorf("offline store should not consult the fetcher; got %d statements", len(stmts))
	}
	if fetcher.calls != 0 {
		t.Errorf("offline store called the fetcher %d times", fetcher.calls)
	}
}
