package findings

import (
	"testing"
	"time"
)

func mkDoc(tenant, name, version string) Document {
	return Document{
		Tenant:   tenant,
		Artifact: Artifact{Name: name, Version: version, Coordinate: coordinate(name, version)},
		Findings: []Finding{{RuleID: RuleVulnerableDependency, Gate: GateVulnscan, Severity: SeverityHigh, Level: LevelError, Title: "x"}},
	}
}

func TestStoreRecordAndGet(t *testing.T) {
	clk := time.Date(2026, 6, 20, 0, 0, 0, 0, time.UTC)
	s := NewStore(StoreOptions{Now: func() time.Time { return clk }})

	s.Record(mkDoc("acme", "lodash", "4.17.21"))

	// Exact coordinate.
	if d, ok := s.Get("acme", "lodash@4.17.21"); !ok || d.Artifact.Name != "lodash" {
		t.Fatalf("exact coordinate lookup failed: ok=%v", ok)
	}
	// Bare name.
	if _, ok := s.Get("acme", "lodash"); !ok {
		t.Fatal("bare-name lookup failed")
	}
	// Wrong tenant.
	if _, ok := s.Get("other", "lodash"); ok {
		t.Fatal("cross-tenant lookup should miss")
	}
	// Empty tenant matches any.
	if _, ok := s.Get("", "lodash"); !ok {
		t.Fatal("empty-tenant lookup should match")
	}
	// Stamped GeneratedAt.
	d, _ := s.Get("acme", "lodash")
	if !d.GeneratedAt.Equal(clk) {
		t.Errorf("GeneratedAt not stamped: %v", d.GeneratedAt)
	}
}

func TestStoreLatestVersionWins(t *testing.T) {
	var now time.Time
	s := NewStore(StoreOptions{Now: func() time.Time { return now }})
	now = time.Unix(100, 0)
	s.Record(mkDoc("acme", "pkg", "1.0.0"))
	now = time.Unix(200, 0)
	s.Record(mkDoc("acme", "pkg", "2.0.0"))

	d, ok := s.Get("acme", "pkg")
	if !ok {
		t.Fatal("lookup failed")
	}
	if d.Artifact.Version != "2.0.0" {
		t.Errorf("bare-name lookup should return latest version, got %s", d.Artifact.Version)
	}
	// Both exact coordinates are still addressable.
	if _, ok := s.Get("acme", "pkg@1.0.0"); !ok {
		t.Error("older version should remain addressable by exact coordinate")
	}
}

func TestStoreEviction(t *testing.T) {
	var n int64
	s := NewStore(StoreOptions{MaxEntries: 2, Now: func() time.Time { n++; return time.Unix(n, 0) }})
	s.Record(mkDoc("t", "a", "1"))
	s.Record(mkDoc("t", "b", "1"))
	s.Record(mkDoc("t", "c", "1"))
	if s.Len() != 2 {
		t.Fatalf("store should be bounded to 2, got %d", s.Len())
	}
	// Oldest (a) evicted.
	if _, ok := s.Get("t", "a"); ok {
		t.Error("oldest entry should have been evicted")
	}
	if _, ok := s.Get("t", "c"); !ok {
		t.Error("newest entry should be retained")
	}
}

func TestStoreDocumentsFilter(t *testing.T) {
	var n int64
	s := NewStore(StoreOptions{Now: func() time.Time { n++; return time.Unix(n, 0) }})
	s.Record(mkDoc("acme", "lodash", "1"))
	s.Record(mkDoc("acme", "left-pad", "1"))
	s.Record(mkDoc("other", "lodash", "1"))

	all := s.Documents("acme", "")
	if len(all) != 2 {
		t.Fatalf("want 2 acme docs, got %d", len(all))
	}
	// Most-recent first.
	if all[0].Artifact.Name != "left-pad" {
		t.Errorf("expected most-recent (left-pad) first, got %s", all[0].Artifact.Name)
	}
	if got := s.Documents("acme", "pad"); len(got) != 1 {
		t.Errorf("substring filter should return 1, got %d", len(got))
	}
}

func TestStoreNilSafe(t *testing.T) {
	var s *Store
	s.Record(mkDoc("t", "a", "1")) // must not panic
	if _, ok := s.Get("t", "a"); ok {
		t.Error("nil store Get should miss")
	}
	if s.Len() != 0 {
		t.Error("nil store Len should be 0")
	}
}

func TestStoreDropsUnaddressable(t *testing.T) {
	s := NewStore(StoreOptions{})
	s.Record(Document{Tenant: "t"}) // no name/coordinate
	if s.Len() != 0 {
		t.Error("document with no coordinate should be dropped")
	}
}
