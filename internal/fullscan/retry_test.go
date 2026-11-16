package fullscan

// A failed attempt is retried with backoff; after MaxAttempts the artifact is
// counted as an error until the next sweep queues it again.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
)

type flakyScanner struct {
	*gateScanner
	mu    sync.Mutex
	fails map[string]int
}

func (f *flakyScanner) Scan(ctx context.Context, a Artifact, opts ScanOptions) (Reading, error) {
	f.mu.Lock()
	n := f.fails[a.Key]
	if n != 0 {
		if n > 0 {
			f.fails[a.Key] = n - 1
		}
		f.mu.Unlock()
		return Reading{}, errors.New("provider exploded\nwith a newline")
	}
	f.mu.Unlock()
	return f.gateScanner.Scan(ctx, a, opts)
}

func TestFailedAttemptsAreRetriedThenGivenUpUntilTheNextSweep(t *testing.T) {
	ctx := context.Background()
	fc := newFakeCache()
	fc.put(objectKey("ok"), "npm", objectPath("ok"), "", tarball("ok", false), time.Now())
	fc.put(objectKey("bad"), "npm", objectPath("bad"), "", tarball("bad", false), time.Now())
	provider := &pkgscantest.Provider{}
	gs := &gateScanner{svc: newGate(t, "mock-model", llmpkgscan.NewMemoryStore(0), provider, llmpkgscan.ActionBlock), cache: fc}
	fs := &flakyScanner{gateScanner: gs, fails: map[string]int{objectKey("ok"): 2, objectKey("bad"): -1}}
	s := startService(t, testOptions(t.TempDir()), fs, fc)
	waitFor(t, "ok scanned, bad given up", func() bool {
		u := upstreamStatus(t, s, "npm")
		return u.Scanned == 1 && u.Errors == 1
	})
	s.mu.Lock()
	bad := *s.items[objectKey("bad")]
	ok := *s.items[objectKey("ok")]
	s.mu.Unlock()
	if bad.State != StateError || bad.Attempts != 5 || strings.ContainsAny(bad.LastError, "\n\r") || !strings.Contains(bad.LastError, "provider exploded") {
		t.Fatalf("the failing artifact: state %s, %d attempts, error %q", bad.State, bad.Attempts, bad.LastError)
	}
	if ok.State != StateScanned || ok.Attempts != 0 {
		t.Fatalf("the artifact that failed twice: state %s, %d attempts", ok.State, ok.Attempts)
	}
	u := upstreamStatus(t, s, "npm")
	if u.Counters.Errors != 7 || u.OldestUnscanned == nil || u.OldestUnscanned.State != StateError {
		t.Fatalf("counters %+v, oldest unscanned %+v", u.Counters, u.OldestUnscanned)
	}
	// The next sweep queues it again (5 more attempts).
	fs.mu.Lock()
	fs.fails[objectKey("bad")] = 0
	fs.mu.Unlock()
	if err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bad scanned after the sweep", func() bool { return upstreamStatus(t, s, "npm").Scanned == 2 })
}
