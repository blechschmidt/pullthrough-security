package prewarm

import (
	"path/filepath"
	"testing"
	"time"
)

func TestHistoryObserveAggregates(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h := NewHistory(100, func() time.Time { return base })

	h.Observe(PullEvent{Backend: "pip", Ecosystem: "pip", Name: "foo", Version: "1.2.3", Path: "/v1/pip/foo-1.2.3.tar.gz", Tenant: "acme", At: base})
	h.Observe(PullEvent{Backend: "pip", Ecosystem: "pip", Name: "foo", Version: "1.2.3", Path: "/v1/pip/foo-1.2.3.tar.gz", Tenant: "acme", At: base.Add(time.Minute)})
	h.Observe(PullEvent{Backend: "pip", Ecosystem: "pip", Name: "foo", Version: "1.2.2", Path: "/v1/pip/foo-1.2.2.tar.gz", At: base.Add(2 * time.Minute)})

	snap := h.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("want 1 coordinate, got %d", len(snap))
	}
	cs := snap[0]
	if cs.Pulls != 3 {
		t.Errorf("want 3 pulls, got %d", cs.Pulls)
	}
	if cs.Tenant != "acme" {
		t.Errorf("want tenant acme, got %q", cs.Tenant)
	}
	if len(cs.Versions) != 2 {
		t.Fatalf("want 2 versions, got %d", len(cs.Versions))
	}
	// Versions sorted ascending by string.
	if cs.Versions[0].Version != "1.2.2" || cs.Versions[1].Version != "1.2.3" {
		t.Errorf("unexpected version ordering: %+v", cs.Versions)
	}
	if cs.Versions[1].Pulls != 2 {
		t.Errorf("want 2 pulls for 1.2.3, got %d", cs.Versions[1].Pulls)
	}
}

func TestHistoryIgnoresIncompleteEvents(t *testing.T) {
	h := NewHistory(100, nil)
	h.Observe(PullEvent{Name: "foo"})    // no backend
	h.Observe(PullEvent{Backend: "pip"}) // no name
	if got := h.Len(); got != 0 {
		t.Fatalf("want 0 records, got %d", got)
	}
}

func TestHistoryEviction(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h := NewHistory(2, nil)
	h.Observe(PullEvent{Backend: "pip", Name: "a", At: base})
	h.Observe(PullEvent{Backend: "pip", Name: "b", At: base.Add(time.Minute)})
	h.Observe(PullEvent{Backend: "pip", Name: "c", At: base.Add(2 * time.Minute)})

	if got := h.Len(); got != 2 {
		t.Fatalf("want 2 records after eviction, got %d", got)
	}
	// "a" (oldest lastPull) should have been evicted.
	for _, cs := range h.Snapshot() {
		if cs.Name == "a" {
			t.Errorf("expected least-recently-pulled coordinate 'a' to be evicted")
		}
	}
}

func TestHistoryPersistRoundTrip(t *testing.T) {
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	h := NewHistory(100, func() time.Time { return base })
	h.Observe(PullEvent{Backend: "npm", Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Path: "/v1/npm/left-pad/-/left-pad-1.3.0.tgz", Tenant: "team1", At: base})

	path := filepath.Join(t.TempDir(), "hist.json")
	if err := h.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	h2 := NewHistory(100, func() time.Time { return base })
	if err := h2.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	snap := h2.Snapshot()
	if len(snap) != 1 || snap[0].Name != "left-pad" || snap[0].Tenant != "team1" {
		t.Fatalf("round-trip mismatch: %+v", snap)
	}
	if len(snap[0].Versions) != 1 || snap[0].Versions[0].Path != "/v1/npm/left-pad/-/left-pad-1.3.0.tgz" {
		t.Fatalf("version round-trip mismatch: %+v", snap[0].Versions)
	}
}

func TestHistoryLoadMissingFileIsOK(t *testing.T) {
	h := NewHistory(100, nil)
	if err := h.Load(filepath.Join(t.TempDir(), "does-not-exist.json")); err != nil {
		t.Fatalf("Load of missing file should be a no-op, got %v", err)
	}
}
