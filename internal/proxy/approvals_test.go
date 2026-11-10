package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/approvals"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/malfeed"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// newApprovalsGateway builds a gateway with a known-malicious gate and the
// break-glass approval workflow wired in, so the pull path consults active
// approvals before returning a block.
func newApprovalsGateway(t *testing.T, upstreamURL string, mf *malfeed.Service, ap *approvals.Service) *Gateway {
	t.Helper()
	registry := backends.NewRegistry()
	b, err := httpbackend.New(httpbackend.Options{
		Name:        "npm",
		BaseURL:     upstreamURL,
		Client:      upstream.NewWithHTTPClient(http.DefaultClient, "test/1"),
		Cacheable:   func(r *backends.Request) bool { return strings.Contains(r.Path, "/-/") },
		Coordinator: tarballCoordinator,
	})
	if err != nil {
		t.Fatalf("httpbackend.New: %v", err)
	}
	if err := registry.Register(b); err != nil {
		t.Fatalf("Register: %v", err)
	}
	g, err := New(Dependencies{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:      cache.NewMemoryCache(),
		Backends:   registry,
		Malfeed:    mf,
		Approvals:  ap,
		Ecosystems: map[string]string{"npm": "npm"},
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

// TestBreakGlassGrantServeExpireReblock exercises the full human-in-the-loop
// lifecycle through a real admission gate (malfeed): a block opens a pending
// review, an operator grants a time-boxed exception, the artifact then serves,
// the grant expires, and the artifact is re-blocked.
func TestBreakGlassGrantServeExpireReblock(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	mf := malfeed.NewService(malfeed.Config{
		InitialEntries: []malfeed.Entry{{
			ID: "MAL-2024-9999", Ecosystem: "npm", Name: "evil-stealer", AllVersions: true, Source: "test",
		}},
		InitialLoaded: true,
	})
	defer mf.Close()

	clock := &gwClock{t: time.Unix(1_700_000_000, 0).UTC()}
	ap, err := approvals.New(approvals.Config{Enabled: true, RequiredApprovers: 1, GrantTTL: time.Hour},
		slog.New(slog.NewTextHandler(io.Discard, nil)), approvals.WithClock(clock.now))
	if err != nil {
		t.Fatalf("approvals.New: %v", err)
	}

	g := newApprovalsGateway(t, srv.URL, mf, ap)
	const path = "/v1/npm/evil-stealer/-/evil-stealer-1.0.0.tgz"
	pull := func() *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		return rr
	}

	// 1. First pull: blocked, and a pending review is opened.
	if rr := pull(); rr.Code != http.StatusForbidden {
		t.Fatalf("first pull status = %d, want 403", rr.Code)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatal("blocked pull must not reach upstream")
	}
	pending := ap.Pending()
	if len(pending) != 1 {
		t.Fatalf("pending reviews = %d, want 1", len(pending))
	}
	reqID := pending[0].ID

	// 2. Operator grants a break-glass exception.
	if _, err := ap.Approve(context.Background(), reqID, approvals.ApproveInput{
		Approver: "ops-alice", Justification: "false positive, urgent deploy",
	}); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	// 3. Next pull serves under the grant.
	rr := pull()
	if rr.Code != http.StatusOK {
		t.Fatalf("under-grant pull status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-Approval-Decision") != "break-glass" {
		t.Errorf("missing X-Approval-Decision=break-glass header")
	}
	if rr.Header().Get("X-Approval-Request") != reqID {
		t.Errorf("X-Approval-Request = %q, want %q", rr.Header().Get("X-Approval-Request"), reqID)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("upstream hits = %d, want 1 (artifact fetched under grant)", atomic.LoadInt32(&hits))
	}

	// 4. Grant expires: the next pull is re-blocked and a fresh review opens.
	clock.advance(time.Hour + time.Minute)
	if rr := pull(); rr.Code != http.StatusForbidden {
		t.Fatalf("post-expiry pull status = %d, want 403 (re-blocked)", rr.Code)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("upstream hits = %d, want still 1 (re-blocked, not re-fetched)", atomic.LoadInt32(&hits))
	}
	snap := ap.Snapshot()
	if snap.ExpiredTotal != 1 {
		t.Errorf("expiredTotal = %d, want 1", snap.ExpiredTotal)
	}
	if snap.BreakGlassServesTotal != 1 {
		t.Errorf("breakGlassServes = %d, want 1", snap.BreakGlassServesTotal)
	}
	if snap.Open != 1 {
		t.Errorf("open reviews = %d, want 1 (fresh review after expiry)", snap.Open)
	}
}

// gwClock is a deterministic, advanceable clock for the gateway approvals test.
type gwClock struct{ t time.Time }

func (c *gwClock) now() time.Time          { return c.t }
func (c *gwClock) advance(d time.Duration) { c.t = c.t.Add(d) }
