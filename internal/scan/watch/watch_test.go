package watch

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
)

// fakeScanner records scanned SHAs and returns a configurable verdict.
type fakeScanner struct {
	mu        sync.Mutex
	sig       string
	scanned   []string
	malicious map[string]bool
	sev       map[string]string // sha -> highest severity
	failSHA   map[string]bool
}

func newFakeScanner(sig string) *fakeScanner {
	return &fakeScanner{
		sig:       sig,
		malicious: map[string]bool{},
		sev:       map[string]string{},
		failSHA:   map[string]bool{},
	}
}

func (f *fakeScanner) Signature() string { return f.sig }

func (f *fakeScanner) Scan(_ context.Context, c *commit.Commit) (*commit.Verdict, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failSHA[c.SHA] {
		return nil, fmt.Errorf("scan failed for %s", c.SHA)
	}
	f.scanned = append(f.scanned, c.SHA)
	v := &commit.Verdict{
		SHA:       c.SHA,
		CacheKey:  cacheKeyOf(c.SHA, f.sig),
		Malicious: f.malicious[c.SHA],
	}
	if sev := f.sev[c.SHA]; sev != "" {
		v.Findings = append(v.Findings, commit.Finding{Severity: sev, Title: "x"})
	}
	return v, nil
}

func (f *fakeScanner) scannedList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]string(nil), f.scanned...)
	return out
}

// fakeSource returns a fixed sequence of batches, one per call, keyed by repo.
type fakeSource struct {
	mu       sync.Mutex
	batches  map[string][]*Batch
	calls    map[string]int
	lastHint map[string]*UpdateHint
}

func newFakeSource() *fakeSource {
	return &fakeSource{batches: map[string][]*Batch{}, calls: map[string]int{}, lastHint: map[string]*UpdateHint{}}
}

func (s *fakeSource) queue(repo string, b *Batch) {
	s.batches[repo] = append(s.batches[repo], b)
}

func (s *fakeSource) NewCommits(_ context.Context, repo RepoRef, known map[string]string, hint *UpdateHint, limit int) (*Batch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastHint[repo.Name] = hint
	// Baseline sentinel: return the configured baseline tips (first queued batch's
	// Tips) without commits.
	if _, ok := known["__skip__"]; ok {
		if len(s.batches[repo.Name]) > 0 {
			return &Batch{Tips: s.batches[repo.Name][0].Tips}, nil
		}
		return &Batch{Tips: map[string]string{"refs/heads/main": "base"}}, nil
	}
	i := s.calls[repo.Name]
	s.calls[repo.Name]++
	if i >= len(s.batches[repo.Name]) {
		return &Batch{Tips: known}, nil
	}
	return s.batches[repo.Name][i], nil
}

// recordObserver collects scan events.
type recordObserver struct {
	mu     sync.Mutex
	events []ScanEvent
}

func (o *recordObserver) ObserveScan(_ context.Context, ev ScanEvent) {
	o.mu.Lock()
	o.events = append(o.events, ev)
	o.mu.Unlock()
}

func (o *recordObserver) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.events)
}

func mkCommit(sha string) *commit.Commit { return &commit.Commit{SHA: sha} }

func newTestService(t *testing.T, cfg Config, sc Scanner, src CommitSource, obs Observer) *Service {
	t.Helper()
	st := NewMemoryStateStore()
	svc, err := NewService(sc, src, st, obs, cfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func TestProcessRepoScansNewCommits(t *testing.T) {
	sc := newFakeScanner("sig1")
	src := newFakeSource()
	repo := RepoRef{Name: "r1", URL: "https://example.com/r1.git"}
	src.queue("r1", &Batch{
		Commits: []*commit.Commit{mkCommit("a"), mkCommit("b")},
		Tips:    map[string]string{"refs/heads/main": "b"},
	})
	obs := &recordObserver{}
	svc := newTestService(t, Config{Repos: []RepoRef{repo}, Backfill: true}, sc, src, obs)

	res, err := svc.processRepo(context.Background(), repo, nil, false)
	if err != nil {
		t.Fatalf("processRepo: %v", err)
	}
	if res.Scanned != 2 {
		t.Fatalf("scanned = %d, want 2", res.Scanned)
	}
	if got := sc.scannedList(); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("scanned order = %v, want [a b]", got)
	}
	if obs.count() != 2 {
		t.Fatalf("observer events = %d, want 2", obs.count())
	}

	// Cursor advanced and signature stamped.
	cur, _ := svc.state.Load(context.Background(), "r1")
	if cur.Tips["refs/heads/main"] != "b" {
		t.Fatalf("cursor tip = %q, want b", cur.Tips["refs/heads/main"])
	}
	if cur.Signature != "sig1" {
		t.Fatalf("cursor signature = %q, want sig1", cur.Signature)
	}
	if cur.ScannedCount != 2 {
		t.Fatalf("scannedCount = %d, want 2", cur.ScannedCount)
	}
}

func TestProcessRepoBaselineSkipsHistory(t *testing.T) {
	sc := newFakeScanner("sig1")
	src := newFakeSource()
	repo := RepoRef{Name: "r1", URL: "u"}
	// First queued batch provides the baseline tips.
	src.queue("r1", &Batch{Tips: map[string]string{"refs/heads/main": "base"}})
	obs := &recordObserver{}
	// Backfill disabled => first sighting only baselines.
	svc := newTestService(t, Config{Repos: []RepoRef{repo}, Backfill: false}, sc, src, obs)

	res, err := svc.processRepo(context.Background(), repo, nil, false)
	if err != nil {
		t.Fatalf("processRepo: %v", err)
	}
	if res.Scanned != 0 {
		t.Fatalf("scanned = %d, want 0 (baseline)", res.Scanned)
	}
	cur, _ := svc.state.Load(context.Background(), "r1")
	if cur.Tips["refs/heads/main"] != "base" {
		t.Fatalf("baseline tip = %q, want base", cur.Tips["refs/heads/main"])
	}
	if cur.Signature != "sig1" {
		t.Fatalf("signature not stamped on baseline")
	}
}

func TestRescanOnSignatureChange(t *testing.T) {
	sc := newFakeScanner("sig1")
	src := newFakeSource()
	repo := RepoRef{Name: "r1", URL: "u"}
	obs := &recordObserver{}
	svc := newTestService(t, Config{Repos: []RepoRef{repo}, Backfill: true}, sc, src, obs)

	// Cycle 1: scan a,b under sig1.
	src.queue("r1", &Batch{Commits: []*commit.Commit{mkCommit("a"), mkCommit("b")}, Tips: map[string]string{"refs/heads/main": "b"}})
	if _, err := svc.processRepo(context.Background(), repo, nil, false); err != nil {
		t.Fatal(err)
	}

	// Signature changes (new model/detector version). The next cycle must
	// re-enumerate from scratch (known=nil) and re-scan.
	sc.sig = "sig2"
	var capturedKnown map[string]string
	src.queue("r1", &Batch{Commits: []*commit.Commit{mkCommit("a"), mkCommit("b")}, Tips: map[string]string{"refs/heads/main": "b"}})
	// Intercept the known map by wrapping: re-run and inspect via lastHint not
	// available; instead assert rescan flag and that commits were re-scanned.
	res, err := svc.processRepo(context.Background(), repo, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	_ = capturedKnown
	if !res.Rescan {
		t.Fatalf("expected rescan flag set after signature change")
	}
	if res.Scanned != 2 {
		t.Fatalf("rescan scanned = %d, want 2", res.Scanned)
	}
	cur, _ := svc.state.Load(context.Background(), "r1")
	if cur.Signature != "sig2" {
		t.Fatalf("cursor signature after rescan = %q, want sig2", cur.Signature)
	}
}

func TestProcessRepoScanErrorStopsAndPersists(t *testing.T) {
	sc := newFakeScanner("sig1")
	sc.failSHA["b"] = true
	src := newFakeSource()
	repo := RepoRef{Name: "r1", URL: "u"}
	src.queue("r1", &Batch{
		Commits: []*commit.Commit{mkCommit("a"), mkCommit("b"), mkCommit("c")},
		Tips:    map[string]string{"refs/heads/main": "c"},
	})
	obs := &recordObserver{}
	svc := newTestService(t, Config{Repos: []RepoRef{repo}, Backfill: true}, sc, src, obs)

	res, err := svc.processRepo(context.Background(), repo, nil, false)
	if err != nil {
		t.Fatalf("processRepo returned error, want nil (error should be swallowed): %v", err)
	}
	// 'a' scanned, 'b' failed -> stop; 'c' not scanned.
	if res.Scanned != 1 {
		t.Fatalf("scanned = %d, want 1", res.Scanned)
	}
	if !res.Truncated {
		t.Fatalf("expected truncated after scan error")
	}
	if svc.Snapshot().Errors == 0 {
		t.Fatalf("expected error counter incremented")
	}
}

func TestFlaggedCounting(t *testing.T) {
	sc := newFakeScanner("sig1")
	sc.malicious["a"] = true
	sc.sev["b"] = "high"
	sc.sev["c"] = "low"
	src := newFakeSource()
	repo := RepoRef{Name: "r1", URL: "u"}
	src.queue("r1", &Batch{
		Commits: []*commit.Commit{mkCommit("a"), mkCommit("b"), mkCommit("c")},
		Tips:    map[string]string{"refs/heads/main": "c"},
	})
	svc := newTestService(t, Config{Repos: []RepoRef{repo}, Backfill: true}, sc, src, nil)
	res, err := svc.processRepo(context.Background(), repo, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	// a (malicious) + b (high) flagged; c (low) not.
	if res.Flagged != 2 {
		t.Fatalf("flagged = %d, want 2", res.Flagged)
	}
}

func TestBackfillUnknownRepo(t *testing.T) {
	sc := newFakeScanner("sig1")
	src := newFakeSource()
	svc := newTestService(t, Config{}, sc, src, nil)
	if _, err := svc.Backfill(context.Background(), "nope"); err == nil {
		t.Fatalf("expected error backfilling unwatched repo")
	}
}

func TestRepoValidation(t *testing.T) {
	sc := newFakeScanner("s")
	src := newFakeSource()
	st := NewMemoryStateStore()
	if _, err := NewService(sc, src, st, nil, Config{Repos: []RepoRef{{URL: "u"}}}); err == nil {
		t.Fatalf("expected error for repo without name")
	}
	if _, err := NewService(sc, src, st, nil, Config{Repos: []RepoRef{{Name: "a"}}}); err == nil {
		t.Fatalf("expected error for repo without url")
	}
	if _, err := NewService(sc, src, st, nil, Config{Repos: []RepoRef{{Name: "a", URL: "u"}, {Name: "a", URL: "v"}}}); err == nil {
		t.Fatalf("expected error for duplicate repo name")
	}
}
