package watch

import (
	"context"
	"testing"
	"time"
)

func testStateStore(t *testing.T, s StateStore) {
	t.Helper()
	ctx := context.Background()

	// Absent cursor => zero value, no error.
	c, err := s.Load(ctx, "repo-a")
	if err != nil {
		t.Fatalf("Load absent: %v", err)
	}
	if c.Repo != "" || len(c.Tips) != 0 {
		t.Fatalf("absent cursor not zero: %+v", c)
	}

	cur := Cursor{
		Repo:         "repo-a",
		Tips:         map[string]string{"refs/heads/main": "abc"},
		Signature:    "sig1",
		ScannedCount: 3,
		LastScanAt:   time.Now().UTC().Truncate(time.Second),
	}
	if err := s.Save(ctx, cur); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := s.Load(ctx, "repo-a")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Tips["refs/heads/main"] != "abc" || got.Signature != "sig1" || got.ScannedCount != 3 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}

	// Mutating the returned map must not affect the stored cursor (Memory store).
	got.Tips["refs/heads/main"] = "mutated"
	again, _ := s.Load(ctx, "repo-a")
	if again.Tips["refs/heads/main"] != "abc" {
		t.Fatalf("stored cursor was mutated via returned map")
	}

	if err := s.Save(ctx, Cursor{Repo: "repo-b", Tips: map[string]string{"refs/heads/x": "d"}}); err != nil {
		t.Fatal(err)
	}
	list, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 || list[0].Repo != "repo-a" || list[1].Repo != "repo-b" {
		t.Fatalf("List = %+v, want [repo-a repo-b]", list)
	}

	if err := s.Save(ctx, Cursor{}); err == nil {
		t.Fatalf("expected error saving cursor without repo")
	}
}

func TestMemoryStateStore(t *testing.T) {
	testStateStore(t, NewMemoryStateStore())
}

func TestFileStateStore(t *testing.T) {
	s, err := NewFileStateStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStateStore: %v", err)
	}
	defer s.Close()
	testStateStore(t, s)
}

func TestFileStateStorePersistsAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	s1, err := NewFileStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.Save(context.Background(), Cursor{Repo: "r", Tips: map[string]string{"refs/heads/main": "zzz"}, Signature: "s"}); err != nil {
		t.Fatal(err)
	}
	s1.Close()

	s2, err := NewFileStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, err := s2.Load(context.Background(), "r")
	if err != nil {
		t.Fatal(err)
	}
	if got.Tips["refs/heads/main"] != "zzz" {
		t.Fatalf("cursor did not persist: %+v", got)
	}
}

func TestFileStateStoreRejectsUnsafeRepoName(t *testing.T) {
	s, err := NewFileStateStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, bad := range []string{"../escape", "a/b", ".hidden", "with space"} {
		if err := s.Save(context.Background(), Cursor{Repo: bad, Tips: map[string]string{}}); err == nil {
			t.Fatalf("expected rejection of unsafe repo name %q", bad)
		}
	}
}
