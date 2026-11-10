package otlplog

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func TestSpillPushPopFIFO(t *testing.T) {
	q, err := openSpill(filepath.Join(t.TempDir(), "s.ndjson"), 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer q.close()

	for i := 0; i < 5; i++ {
		if err := q.push(rec(string(rune('a' + i)))); err != nil {
			t.Fatalf("push: %v", err)
		}
	}
	if q.len() != 5 {
		t.Fatalf("len = %d, want 5", q.len())
	}
	out, err := q.pop(3)
	if err != nil {
		t.Fatalf("pop: %v", err)
	}
	if len(out) != 3 || out[0].Body != "a" || out[2].Body != "c" {
		t.Fatalf("unexpected pop order: %+v", out)
	}
	if q.len() != 2 {
		t.Errorf("len after pop = %d, want 2", q.len())
	}
}

func TestSpillByteBudget(t *testing.T) {
	big := rec("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	// Size the budget to exactly one serialized record so the first push fits and
	// the second exceeds the budget.
	line, err := json.Marshal(big)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	budget := int64(len(line) + 1) // +1 for the trailing newline

	q, err := openSpill(filepath.Join(t.TempDir(), "s.ndjson"), budget)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer q.close()

	if err := q.push(big); err != nil {
		t.Fatalf("first push should fit: %v", err)
	}
	if err := q.push(big); err != errSpillFull {
		t.Fatalf("second push err = %v, want errSpillFull", err)
	}
}

func TestSpillRecoverAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.ndjson")
	q, err := openSpill(path, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := q.push(rec("r")); err != nil {
			t.Fatalf("push: %v", err)
		}
	}
	if err := q.close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	q2, err := openSpill(path, 0)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer q2.close()
	if q2.len() != 3 {
		t.Fatalf("recovered len = %d, want 3", q2.len())
	}
	out, err := q2.pop(10)
	if err != nil {
		t.Fatalf("pop: %v", err)
	}
	if len(out) != 3 {
		t.Errorf("popped %d, want 3", len(out))
	}
}

func TestSpillCompactionBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.ndjson")
	q, err := openSpill(path, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer q.close()

	// Churn well past the half-file compaction trigger; the queue must stay
	// consistent and eventually drain to zero.
	for round := 0; round < 20; round++ {
		for i := 0; i < 10; i++ {
			if err := q.push(LogRecord{Time: time.Unix(0, int64(round*10+i)), Body: "r"}); err != nil {
				t.Fatalf("push: %v", err)
			}
		}
		if _, err := q.pop(10); err != nil {
			t.Fatalf("pop: %v", err)
		}
	}
	if _, err := q.pop(1000); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if q.len() != 0 {
		t.Errorf("final len = %d, want 0", q.len())
	}
}
