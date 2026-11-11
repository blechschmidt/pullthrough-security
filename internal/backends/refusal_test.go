package backends

import (
	"context"
	"reflect"
	"testing"
)

// A backend that runs a gate of its own reports the gate's refusal through the
// request context; whoever records the request (the download log) hears it. A
// context nobody is listening on makes the report a no-op.
func TestRecordRefusal(t *testing.T) {
	var heard []string
	ctx := WithRefusalRecorder(context.Background(), func(gate string) { heard = append(heard, gate) })

	RecordRefusal(ctx, "lfs-content")
	// The recorder travels with contexts derived from the request's.
	derived, cancel := context.WithCancel(ctx)
	defer cancel()
	RecordRefusal(derived, "another-gate")
	if want := []string{"lfs-content", "another-gate"}; !reflect.DeepEqual(heard, want) {
		t.Fatalf("the recorder heard %v, want %v", heard, want)
	}

	// No recorder: nothing happens, and nothing panics.
	RecordRefusal(context.Background(), "lfs-content")
	if len(heard) != 2 {
		t.Fatalf("a context without a recorder reached one: %v", heard)
	}
}
