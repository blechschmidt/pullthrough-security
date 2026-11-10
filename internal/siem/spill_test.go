package siem

import (
	"path/filepath"
	"testing"
)

func TestSpillPushPopFIFO(t *testing.T) {
	q, err := openSpill(filepath.Join(t.TempDir(), "spill.log"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer q.close()

	for i := 0; i < 5; i++ {
		ev := sampleEvent(SeverityHigh)
		ev.Name = string(rune('A' + i))
		if err := q.push(ev); err != nil {
			t.Fatalf("push: %v", err)
		}
	}
	if q.len() != 5 {
		t.Fatalf("len = %d, want 5", q.len())
	}
	got, err := q.pop(3)
	if err != nil {
		t.Fatalf("pop: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("popped %d, want 3", len(got))
	}
	if got[0].Name != "A" || got[2].Name != "C" {
		t.Fatalf("FIFO order wrong: %q %q", got[0].Name, got[2].Name)
	}
	if q.len() != 2 {
		t.Fatalf("len after pop = %d, want 2", q.len())
	}
	rest, _ := q.pop(10)
	if len(rest) != 2 || rest[0].Name != "D" || rest[1].Name != "E" {
		t.Fatalf("remaining wrong: %+v", rest)
	}
	if q.len() != 0 {
		t.Fatalf("len after full drain = %d, want 0", q.len())
	}
	// Empty pop is fine.
	if more, _ := q.pop(1); len(more) != 0 {
		t.Fatalf("pop on empty returned %d", len(more))
	}
}

func TestSpillByteBudget(t *testing.T) {
	// Budget large enough for ~2 events, so the 3rd+ is rejected.
	ev := sampleEvent(SeverityHigh)
	q, err := openSpill(filepath.Join(t.TempDir(), "spill.log"), 400)
	if err != nil {
		t.Fatal(err)
	}
	defer q.close()

	pushed := 0
	for i := 0; i < 20; i++ {
		if err := q.push(ev); err == errSpillFull {
			break
		} else if err != nil {
			t.Fatalf("push: %v", err)
		}
		pushed++
	}
	if pushed == 0 || pushed >= 20 {
		t.Fatalf("expected the byte budget to bound pushes, got %d", pushed)
	}
	if q.len() != pushed {
		t.Fatalf("len = %d, want %d", q.len(), pushed)
	}
}

func TestSpillSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spill.log")
	q, err := openSpill(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := q.push(sampleEvent(SeverityHigh)); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.close(); err != nil {
		t.Fatal(err)
	}

	// Reopen: the pending events should be recovered.
	q2, err := openSpill(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer q2.close()
	if q2.len() != 3 {
		t.Fatalf("recovered len = %d, want 3", q2.len())
	}
	got, _ := q2.pop(3)
	if len(got) != 3 {
		t.Fatalf("recovered pop = %d, want 3", len(got))
	}
}
