package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/reposcore"
)

// stubLocator returns a fixed directory regardless of URL.
type stubLocator struct {
	dir      string
	resolved bool
}

func (l stubLocator) Locate(ctx context.Context, repoURL string) (string, bool, bool, error) {
	return l.dir, l.resolved, false, nil
}

func newRepoScoreGateway(t *testing.T, svc *reposcore.Service) *Gateway {
	t.Helper()
	g, err := New(Dependencies{
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:     cache.NewMemoryCache(),
		Backends:  backends.NewRegistry(),
		RepoScore: svc,
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

// TestRepoScoreGateRecordsSignal verifies the gate folds a repo-health signal
// into the per-request accumulator when a provenance repository URL is present,
// and that it is a non-blocking signal provider (always returns true).
func TestRepoScoreGateRecordsSignal(t *testing.T) {
	// An unresolved locator (air-gapped, repo not mirrored) still produces an
	// evaluated-but-unresolved signal and never blocks.
	svc, err := reposcore.New(reposcore.Config{
		Enabled: true,
		Locator: stubLocator{resolved: false},
		Now:     func() time.Time { return time.Unix(1_700_000_000, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	g := newRepoScoreGateway(t, svc)

	in := policyengine.Input{
		Artifact:   policyengine.ArtifactInput{Ecosystem: "npm", Name: "pkg", Version: "1.0.0"},
		Provenance: &policyengine.ProvenanceInput{Found: true, RepositoryURL: "https://github.com/acme/widget", CommitSHA: "abc123"},
	}
	r := reqWithSignals(in)
	rr := httptest.NewRecorder()

	if ok := g.gateRepoScore(rr, r, "npm", "npm"); !ok {
		t.Fatal("repo-score gate must never block")
	}

	s := signalsFrom(r.Context())
	if s == nil || s.input.RepoHealth == nil {
		t.Fatal("expected a RepoHealth signal recorded on the accumulator")
	}
	if !s.input.RepoHealth.Evaluated {
		t.Error("expected the recorded signal to be marked evaluated")
	}
	if s.input.RepoHealth.Resolved {
		t.Error("expected the signal to be unresolved (no clone available)")
	}
}

// TestRepoScoreGateNoProvenanceNoSignal verifies the gate is inert when there is
// no associated repository to score.
func TestRepoScoreGateNoProvenanceNoSignal(t *testing.T) {
	svc, err := reposcore.New(reposcore.Config{
		Enabled: true,
		Locator: stubLocator{resolved: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	g := newRepoScoreGateway(t, svc)

	r := reqWithSignals(policyengine.Input{
		Artifact: policyengine.ArtifactInput{Ecosystem: "npm", Name: "pkg", Version: "1.0.0"},
	})
	if ok := g.gateRepoScore(httptest.NewRecorder(), r, "npm", "npm"); !ok {
		t.Fatal("gate must return true")
	}
	if s := signalsFrom(r.Context()); s != nil && s.input.RepoHealth != nil {
		t.Error("expected no RepoHealth signal without a repository URL")
	}
}

// TestRepoScoreGateDisabled verifies a nil/disabled service is a no-op.
func TestRepoScoreGateDisabled(t *testing.T) {
	g := newRepoScoreGateway(t, nil)
	r := reqWithSignals(policyengine.Input{
		Provenance: &policyengine.ProvenanceInput{Found: true, RepositoryURL: "https://x/y"},
	})
	if ok := g.gateRepoScore(httptest.NewRecorder(), r, "npm", "npm"); !ok {
		t.Fatal("disabled gate must return true")
	}
}
