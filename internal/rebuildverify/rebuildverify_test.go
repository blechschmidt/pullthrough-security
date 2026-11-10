package rebuildverify

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeBuilder is a deterministic test builder returning a configured digest/err.
type fakeBuilder struct {
	ecos   []string
	digest string
	err    error
	calls  int
	mu     sync.Mutex
}

func (b *fakeBuilder) Name() string { return "fake" }

func (b *fakeBuilder) Supports(ecosystem string) bool {
	for _, e := range b.ecos {
		if e == ecosystem {
			return true
		}
	}
	return false
}

func (b *fakeBuilder) Build(ctx context.Context, bc BuildContext) (BuildOutput, error) {
	b.mu.Lock()
	b.calls++
	b.mu.Unlock()
	if b.err != nil {
		return BuildOutput{}, b.err
	}
	return BuildOutput{Digest: b.digest}, nil
}

func newTestService(t *testing.T, cfg Config, b Builder) *Service {
	t.Helper()
	cfg.Enabled = true
	if b != nil {
		cfg.Registry = NewRegistry(b)
	}
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func TestVerify_Reproducible(t *testing.T) {
	digest := "sha256:" + repeat("a", 64)
	svc := newTestService(t, Config{}, &fakeBuilder{ecos: []string{"go"}, digest: digest})
	res := svc.Verify(context.Background(), Request{
		Coordinate: Coordinate{Ecosystem: "go", Name: "x", Version: "1.0.0", Digest: digest},
		Source:     Source{CommitSHA: "abc123", RepoDir: "/tmp/repo"},
	})
	if res.Verdict != VerdictReproducible {
		t.Fatalf("verdict = %q, want reproducible (reason=%s)", res.Verdict, res.Reason)
	}
	if !res.Reproducible || res.Mismatch || !res.Done {
		t.Fatalf("flags wrong: %+v", res)
	}
}

func TestVerify_Mismatch(t *testing.T) {
	svc := newTestService(t, Config{}, &fakeBuilder{ecos: []string{"go"}, digest: "sha256:" + repeat("b", 64)})
	res := svc.Verify(context.Background(), Request{
		Coordinate: Coordinate{Ecosystem: "go", Name: "x", Version: "1.0.0", Digest: "sha256:" + repeat("a", 64)},
		Source:     Source{CommitSHA: "abc123", RepoDir: "/tmp/repo"},
	})
	if res.Verdict != VerdictMismatch {
		t.Fatalf("verdict = %q, want mismatch", res.Verdict)
	}
	if !res.Mismatch {
		t.Fatalf("Mismatch flag not set: %+v", res)
	}
}

func TestVerify_Unattested(t *testing.T) {
	svc := newTestService(t, Config{}, &fakeBuilder{ecos: []string{"go"}, digest: "sha256:" + repeat("a", 64)})
	res := svc.Verify(context.Background(), Request{
		Coordinate: Coordinate{Ecosystem: "go", Name: "x", Version: "1.0.0", Digest: "sha256:" + repeat("a", 64)},
		// no CommitSHA
	})
	if res.Verdict != VerdictUnattested {
		t.Fatalf("verdict = %q, want unattested", res.Verdict)
	}
}

func TestVerify_UnsupportedNoBuilder(t *testing.T) {
	svc := newTestService(t, Config{}, &fakeBuilder{ecos: []string{"go"}, digest: "x"})
	res := svc.Verify(context.Background(), Request{
		Coordinate: Coordinate{Ecosystem: "npm", Name: "x", Version: "1.0.0", Digest: "sha256:" + repeat("a", 64)},
		Source:     Source{CommitSHA: "abc"},
	})
	if res.Verdict != VerdictUnsupported {
		t.Fatalf("verdict = %q, want unsupported", res.Verdict)
	}
}

func TestVerify_BuilderToolchainUnavailableFailsOpen(t *testing.T) {
	svc := newTestService(t, Config{}, &fakeBuilder{ecos: []string{"go"}, err: ErrToolchainUnavailable})
	res := svc.Verify(context.Background(), Request{
		Coordinate: Coordinate{Ecosystem: "go", Name: "x", Version: "1.0.0", Digest: "sha256:" + repeat("a", 64)},
		Source:     Source{CommitSHA: "abc", RepoDir: "/tmp/repo"},
	})
	if res.Verdict != VerdictUnsupported {
		t.Fatalf("verdict = %q, want unsupported (fail-open)", res.Verdict)
	}
}

func TestVerify_BuilderErrorFailsOpen(t *testing.T) {
	svc := newTestService(t, Config{}, &fakeBuilder{ecos: []string{"go"}, err: errors.New("boom")})
	res := svc.Verify(context.Background(), Request{
		Coordinate: Coordinate{Ecosystem: "go", Name: "x", Version: "1.0.0", Digest: "sha256:" + repeat("a", 64)},
		Source:     Source{CommitSHA: "abc", RepoDir: "/tmp/repo"},
	})
	if res.Verdict != VerdictUnsupported {
		t.Fatalf("verdict = %q, want unsupported", res.Verdict)
	}
	if svc.Metrics().BuildErrors != 1 {
		t.Fatalf("build errors = %d, want 1", svc.Metrics().BuildErrors)
	}
}

func TestObserve_AsyncCachesResult(t *testing.T) {
	digest := "sha256:" + repeat("c", 64)
	b := &fakeBuilder{ecos: []string{"go"}, digest: digest}
	var hookCount int
	var hookMu sync.Mutex
	svc := newTestService(t, Config{Async: true, MaxConcurrent: 1, OnResult: func(r Result) {
		hookMu.Lock()
		hookCount++
		hookMu.Unlock()
	}}, b)

	req := Request{
		Coordinate: Coordinate{Ecosystem: "go", Name: "x", Version: "1.0.0", Digest: digest},
		Source:     Source{CommitSHA: "abc", RepoDir: "/tmp/repo"},
	}
	first := svc.Observe(context.Background(), req)
	if !first.Pending {
		t.Fatalf("first observe should be pending, got %+v", first)
	}

	// Wait for the async build to land in the cache.
	deadline := time.Now().Add(2 * time.Second)
	var got Result
	for time.Now().Before(deadline) {
		if r, ok := svc.Lookup(req); ok {
			got = r
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got.Verdict != VerdictReproducible {
		t.Fatalf("cached verdict = %q, want reproducible", got.Verdict)
	}
	// A second observe is a cache hit.
	second := svc.Observe(context.Background(), req)
	if second.Pending || second.Verdict != VerdictReproducible {
		t.Fatalf("second observe = %+v, want cached reproducible", second)
	}
	if svc.Metrics().CacheHits != 1 {
		t.Fatalf("cache hits = %d, want 1", svc.Metrics().CacheHits)
	}
	hookMu.Lock()
	hc := hookCount
	hookMu.Unlock()
	if hc != 1 {
		t.Fatalf("hook fired %d times, want 1", hc)
	}
}

func TestGate_EnforceBlocksConfirmedMismatch(t *testing.T) {
	svc := newTestService(t, Config{Mode: ModeEnforce}, &fakeBuilder{ecos: []string{"go"}, digest: "sha256:" + repeat("b", 64)})
	res := svc.Verify(context.Background(), Request{
		Coordinate: Coordinate{Ecosystem: "go", Name: "x", Version: "1.0.0", Digest: "sha256:" + repeat("a", 64)},
		Source:     Source{CommitSHA: "abc", RepoDir: "/tmp/repo"},
	})
	d := svc.Gate(res, "")
	if !d.Block {
		t.Fatalf("enforce mode should block a confirmed mismatch: %+v", d)
	}
}

func TestGate_ObserveDoesNotBlock(t *testing.T) {
	svc := newTestService(t, Config{Mode: ModeObserve}, &fakeBuilder{ecos: []string{"go"}, digest: "sha256:" + repeat("b", 64)})
	res := svc.Verify(context.Background(), Request{
		Coordinate: Coordinate{Ecosystem: "go", Name: "x", Version: "1.0.0", Digest: "sha256:" + repeat("a", 64)},
		Source:     Source{CommitSHA: "abc", RepoDir: "/tmp/repo"},
	})
	if svc.Gate(res, "").Block {
		t.Fatalf("observe mode must not block")
	}
}

func TestGate_TenantEnforceOverride(t *testing.T) {
	svc := newTestService(t, Config{Mode: ModeObserve, Tenants: map[string]TenantConfig{"team-a": {Mode: ModeEnforce}}},
		&fakeBuilder{ecos: []string{"go"}, digest: "sha256:" + repeat("b", 64)})
	res := svc.Verify(context.Background(), Request{
		Coordinate: Coordinate{Ecosystem: "go", Name: "x", Version: "1.0.0", Digest: "sha256:" + repeat("a", 64)},
		Source:     Source{CommitSHA: "abc", RepoDir: "/tmp/repo"},
		Tenant:     "team-a",
	})
	if !svc.Gate(res, "team-a").Block {
		t.Fatalf("tenant override to enforce should block")
	}
	if svc.Gate(res, "team-b").Block {
		t.Fatalf("other tenant should remain observe")
	}
}

func TestMetrics_ByEcosystem(t *testing.T) {
	svc := newTestService(t, Config{}, &fakeBuilder{ecos: []string{"go"}, digest: "sha256:" + repeat("a", 64)})
	svc.Verify(context.Background(), Request{
		Coordinate: Coordinate{Ecosystem: "go", Name: "x", Version: "1.0.0", Digest: "sha256:" + repeat("a", 64)},
		Source:     Source{CommitSHA: "abc", RepoDir: "/tmp/repo"},
	})
	m := svc.Metrics()
	if m.Reproducible != 1 || m.Verifications != 1 {
		t.Fatalf("metrics wrong: %+v", m)
	}
	if m.ByEcosystem["go"].Reproducible != 1 {
		t.Fatalf("per-eco metrics wrong: %+v", m.ByEcosystem)
	}
}

func TestLocator_AirGapUnresolvedIsUnsupported(t *testing.T) {
	cfg := Config{Locator: stubLocator{resolved: false}}
	svc := newTestService(t, cfg, &fakeBuilder{ecos: []string{"go"}, digest: "sha256:" + repeat("a", 64)})
	res := svc.Verify(context.Background(), Request{
		Coordinate: Coordinate{Ecosystem: "go", Name: "x", Version: "1.0.0", Digest: "sha256:" + repeat("a", 64)},
		Source:     Source{CommitSHA: "abc", RepositoryURL: "https://example.com/x"},
	})
	if res.Verdict != VerdictUnsupported {
		t.Fatalf("unresolved repo should be unsupported (fail-open), got %q", res.Verdict)
	}
}

func TestParseDigest(t *testing.T) {
	cases := []struct {
		in   string
		ok   bool
		want string
	}{
		{"sha256:" + repeat("A", 64), true, "sha256:" + repeat("a", 64)},
		{repeat("a", 64), true, "sha256:" + repeat("a", 64)},
		{"  \"sha256:" + repeat("a", 64) + "\"  ", true, "sha256:" + repeat("a", 64)},
		{"sha512:" + repeat("a", 128), true, "sha512:" + repeat("a", 128)},
		{"sha256:tooshort", false, ""},
		{"sha256:" + repeat("a", 63), false, ""},
		{"", false, ""},
		{"not-a-digest", false, ""},
		{"sha256:", false, ""},
		{"custom:" + repeat("a", 10), true, "custom:" + repeat("a", 10)},
		{"custom:" + repeat("a", 11), false, ""}, // odd length unknown algo
	}
	for _, c := range cases {
		got, ok := NormalizeDigest(c.in)
		if ok != c.ok {
			t.Errorf("NormalizeDigest(%q) ok=%v, want %v", c.in, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("NormalizeDigest(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBuiltinBuildersAirGapAware(t *testing.T) {
	// A built-in builder whose toolchain is absent yields ErrToolchainUnavailable
	// (skip/fail-open), never a mismatch.
	b := &toolchainBuilder{name: "go", ecos: []string{"go"}, binaries: []string{"definitely-not-a-real-binary-xyz"}, label: "Go module"}
	_, err := b.Build(context.Background(), BuildContext{Coordinate: Coordinate{Ecosystem: "go"}})
	if !errors.Is(err, ErrToolchainUnavailable) {
		t.Fatalf("absent toolchain should be ErrToolchainUnavailable, got %v", err)
	}
}

func TestStubBuilderUnsupported(t *testing.T) {
	b := NewStubBuilder("stub", "rust")
	if !b.Supports("rust") {
		t.Fatal("stub should support rust")
	}
	_, err := b.Build(context.Background(), BuildContext{Coordinate: Coordinate{Ecosystem: "rust"}})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("stub build should be ErrUnsupported, got %v", err)
	}
}

func TestConfigValidate(t *testing.T) {
	if _, err := NewService(Config{Enabled: true, Mode: "bogus"}); err == nil {
		t.Fatal("invalid mode should fail validation")
	}
	if _, err := NewService(Config{Enabled: true, Tenants: map[string]TenantConfig{"t": {Mode: "bad"}}}); err == nil {
		t.Fatal("invalid tenant mode should fail validation")
	}
}

func TestNilServiceSafe(t *testing.T) {
	var s *Service
	if s.Enabled() {
		t.Fatal("nil service must not be enabled")
	}
	if s.Mode() != ModeObserve {
		t.Fatal("nil service mode should be observe")
	}
	_ = s.Metrics()
	_ = s.Status(0)
	if d := s.Gate(Result{Done: true, Verdict: VerdictMismatch}, ""); d.Block {
		t.Fatal("nil service must not block")
	}
}

// stubLocator is a test RepoLocator.
type stubLocator struct {
	resolved bool
	dir      string
	err      error
}

func (l stubLocator) Locate(ctx context.Context, repoURL string) (string, bool, bool, error) {
	return l.dir, l.resolved, false, l.err
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
