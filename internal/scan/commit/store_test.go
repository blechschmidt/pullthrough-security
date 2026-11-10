package commit

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func testVerdict() *Verdict {
	return &Verdict{
		SHA:       "0123456789abcdef",
		RiskScore: 42,
		Malicious: false,
		Findings:  []Finding{{Category: CategorySecret, Severity: "high", Title: "key", Detail: "found a key"}},
		Rationale: "looks ok",
		ScannedAt: time.Now().UTC().Truncate(time.Second),
	}
}

func TestMemoryStoreRoundTrip(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	if _, err := s.Get(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(missing) err = %v, want ErrNotFound", err)
	}
	v := testVerdict()
	if err := s.Put(ctx, v); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(ctx, v.SHA)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.RiskScore != v.RiskScore || got.SHA != v.SHA {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	// Mutating the returned copy must not affect the stored value.
	got.RiskScore = 0
	again, _ := s.Get(ctx, v.SHA)
	if again.RiskScore != 42 {
		t.Errorf("stored verdict was mutated through returned copy: %d", again.RiskScore)
	}
}

func TestFileStoreRoundTripAndAtomicity(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	ctx := context.Background()
	v := testVerdict()
	if err := s.Put(ctx, v); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(ctx, v.SHA)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.RiskScore != 42 || len(got.Findings) != 1 {
		t.Errorf("unexpected verdict: %+v", got)
	}

	// A fresh store over the same dir must see the persisted verdict (durability).
	s2, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, err := s2.Get(ctx, v.SHA); err != nil {
		t.Errorf("reopened store lost verdict: %v", err)
	}
}

func TestFileStoreRejectsPathTraversal(t *testing.T) {
	s, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	ctx := context.Background()
	for _, bad := range []string{"../escape", "a/b", "..", "sha;rm-rf", "", "g123"} {
		if _, err := s.path(bad); err == nil {
			t.Errorf("path(%q) accepted a non-hex sha; path traversal possible", bad)
		}
		if _, err := s.Get(ctx, bad); err == nil {
			t.Errorf("Get(%q) accepted invalid sha", bad)
		}
	}
	// Confirm a normal hex sha resolves under the store dir.
	p, err := s.path("abc1234")
	if err != nil {
		t.Fatalf("valid sha rejected: %v", err)
	}
	if filepath.Dir(p) != s.dir {
		t.Errorf("path %q escaped store dir %q", p, s.dir)
	}
}
