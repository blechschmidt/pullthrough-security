//go:build integration
// +build integration

package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/depfirewall"
	"github.com/blechschmidt/pullthrough-security/internal/dossier"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/malfeed"
	"github.com/blechschmidt/pullthrough-security/internal/proxy"
	"github.com/blechschmidt/pullthrough-security/internal/riskscore"
	"github.com/blechschmidt/pullthrough-security/internal/testset"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// discardLogger is a no-op logger for the harness gateways; the suite asserts on
// HTTP verdicts and recorded state, not log output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// artifactBody returns the deterministic bytes the recorded upstream serves for
// an artifact at the given upstream (rest) path. Keying the body on the path
// makes the body — and therefore its digest — reproducible across the backend's
// digest annotation and the upstream's response, so content-digest verification
// has something real to verify.
func artifactBody(restPath string) []byte {
	return []byte("pullthrough-e2e-artifact::" + restPath + "\n")
}

// indexBody returns the bytes the recorded upstream serves for a metadata/index
// resource. Index documents are served live (non-cacheable) so the exact bytes
// are immaterial; they only need to be non-empty and routed.
func indexBody(restPath string) []byte {
	return []byte("pullthrough-e2e-index::" + restPath + "\n")
}

// sha256Digest renders the "sha256:<hex>" digest the gateway's fill-time verifier
// expects.
func sha256Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// recordedUpstream is a deterministic, replayed upstream: it serves the recorded
// body for any registered rest path (ignoring the query string) and counts how
// many times each path was fetched, so the suite can prove a cached artifact is
// served on a repeat pull without a second upstream hit. Unregistered paths 404
// so a mis-wired route surfaces as a gateway error rather than a silent success.
type recordedUpstream struct {
	mu     sync.Mutex
	hits   map[string]int
	bodies map[string][]byte // rest path -> recorded bytes
}

func newRecordedUpstream() *recordedUpstream {
	return &recordedUpstream{hits: map[string]int{}, bodies: map[string][]byte{}}
}

func (u *recordedUpstream) record(restPath string, body []byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.bodies[restPath] = body
}

func (u *recordedUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	body, ok := u.bodies[r.URL.Path]
	if ok {
		u.hits[r.URL.Path]++
	}
	u.mu.Unlock()
	if !ok {
		http.Error(w, "not recorded", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(body)
}

func (u *recordedUpstream) count(restPath string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hits[restPath]
}

// recordingBackend decorates a real generic httpbackend.Backend (the shared
// substrate every HTTP ecosystem reuses) with the one thing the generic backend
// cannot derive on its own for a synthetic fixture: the expected content digest.
// Attaching Resolved.Digest is what engages the gateway's fill-time content
// verifier, so the suite exercises digest/content verification end-to-end. In
// tamper mode it deliberately reports a digest that does not match the bytes the
// upstream serves, so the verifier must reject the fill.
type recordingBackend struct {
	*httpbackend.Backend
	artifactRest map[string]bool // rest paths that are cacheable artifacts
	tamper       bool
}

func (b *recordingBackend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	res, err := b.Backend.Resolve(ctx, req)
	if err != nil {
		return res, err
	}
	rest := strings.SplitN(req.Path, "?", 2)[0]
	if b.artifactRest[rest] {
		body := artifactBody(rest)
		if b.tamper {
			// Report a digest for different bytes than the upstream will serve, so
			// the fill-time verifier detects the mismatch and fails the cache Put.
			res.Digest = sha256Digest([]byte("tampered::" + rest))
		} else {
			res.Digest = sha256Digest(body)
		}
	}
	return res, nil
}

// pullMethod returns a pull's effective HTTP method (GET when unset), mirroring
// the unexported testset.Pull.method helper.
func pullMethod(p testset.Pull) string {
	if p.Method == "" {
		return http.MethodGet
	}
	return p.Method
}

// restOf strips the "/v1/<backend>/" mount from a gateway pull path, yielding the
// upstream (rest) path the backend and the recorded upstream key on. Any query
// string is preserved on the returned gateway path but not on the rest key.
func restOf(backend, pullPath string) string {
	mount := "/v1/" + backend + "/"
	rest := strings.TrimPrefix(pullPath, mount)
	rest = "/" + strings.TrimLeft(rest, "/")
	return strings.SplitN(rest, "?", 2)[0]
}

// scenario is a fully-wired, single-backend in-process environment for one
// fixture: a gateway fronting the recording backend pointed at a freshly-started
// recorded upstream, with the SARIF findings store, risk engine, vulnerability
// scanner, dependency firewall and known-malicious gate attached, plus a dossier
// builder reading the same stores.
type scenario struct {
	fixture testset.Fixture
	gateway *proxy.Gateway
	handler http.Handler
	up      *recordedUpstream
	store   *findings.Store
	risk    *riskscore.Engine
	vuln    *vulnscan.Service
	dossier *dossier.Builder
	cleanup func()
}

// scenarioConfig tunes how a scenario's gateway is wired so the same fixture can
// be driven through the clean allow path and through forced-block / tamper
// variants.
type scenarioConfig struct {
	// riskBlock, when true, configures the risk engine with a block-at-low
	// threshold so every artifact trips the risk gate (a forced block whose SARIF
	// explains the refusal). When false the engine is observe-only.
	riskBlock bool
	// malfeedCoord, when set, seeds the known-malicious feed with this fixture's
	// coordinate so the coordinate gate hard-blocks the pull before any fetch.
	malfeedCoord bool
	// tamper, when true, makes the backend report a mismatching digest so the
	// fill-time content verifier must reject the artifact.
	tamper bool
}

// noopScanner is an offline vulnerability scanner that resolves every SBOM to no
// findings, so the vuln gate generates an SBOM and returns a clean verdict
// without any network access.
type noopScanner struct{}

func (noopScanner) Name() string { return "e2e-noop" }
func (noopScanner) Scan(context.Context, *vulnscan.SBOM) ([]vulnscan.Vulnerability, error) {
	return nil, nil
}

// buildScenario wires a scenario for the fixture under the given config.
func buildScenario(f testset.Fixture, cfg scenarioConfig) (*scenario, error) {
	up := newRecordedUpstream()
	srv := httptest.NewServer(up)

	// Classify the fixture's pulls and record a body for each resource.
	artifactRest := map[string]bool{}
	for _, p := range f.Pulls {
		if pullMethod(p) != http.MethodGet {
			continue // non-GET (git pack negotiation) is not driven here
		}
		rest := restOf(f.Backend, p.Path)
		if p.Kind == testset.KindArtifact {
			artifactRest[rest] = true
			up.record(rest, artifactBody(rest))
		} else {
			up.record(rest, indexBody(rest))
		}
	}

	cacheable := func(r *backends.Request) bool {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			return false
		}
		return artifactRest[strings.SplitN(r.Path, "?", 2)[0]]
	}
	coordinator := func(r *backends.Request) (backends.Coordinate, bool) {
		if artifactRest[strings.SplitN(r.Path, "?", 2)[0]] {
			return backends.Coordinate{Name: f.Dep.Name, Version: f.Dep.Version}, true
		}
		return backends.Coordinate{}, false
	}

	inner, err := httpbackend.New(httpbackend.Options{
		Name:        f.Backend,
		BaseURL:     srv.URL,
		Client:      upstream.NewWithHTTPClient(http.DefaultClient, "e2e/1"),
		Cacheable:   cacheable,
		Coordinator: coordinator,
	})
	if err != nil {
		srv.Close()
		return nil, err
	}
	backend := &recordingBackend{Backend: inner, artifactRest: artifactRest, tamper: cfg.tamper}

	registry := backends.NewRegistry()
	if err := registry.Register(backend); err != nil {
		srv.Close()
		return nil, err
	}

	store := findings.NewStore(findings.StoreOptions{})

	threshold := riskscore.Threshold{Band: riskscore.BandHigh, Action: riskscore.ThresholdOff}
	if cfg.riskBlock {
		threshold = riskscore.Threshold{Band: riskscore.BandLow, Action: riskscore.ThresholdBlock}
	}
	risk, err := riskscore.New(riskscore.Config{Enabled: true, Threshold: threshold})
	if err != nil {
		srv.Close()
		return nil, err
	}

	// A no-op offline scanner: the vuln gate builds an SBOM from the cached bytes
	// and returns clean; fail-open so synthetic (non-archive) bytes never block.
	vuln, err := vulnscan.NewService(vulnscan.Config{FailOnError: false}, noopScanner{}, discardLogger())
	if err != nil {
		srv.Close()
		return nil, err
	}

	fw, err := depfirewall.NewService(depfirewall.Config{DefaultAction: depfirewall.ActionAllow})
	if err != nil {
		srv.Close()
		return nil, err
	}

	var mf *malfeed.Service
	if cfg.malfeedCoord {
		mf = malfeed.NewService(malfeed.Config{
			InitialEntries: []malfeed.Entry{{
				ID:          "MAL-E2E-0001",
				Ecosystem:   f.Backend,
				Name:        f.Dep.Name,
				AllVersions: true,
				Summary:     "e2e forced known-malicious block",
				Source:      "e2e-bundle",
			}},
			InitialLoaded: true,
		})
	} else {
		// An empty, loaded feed: the gate runs and admits (exercised, not blocking).
		mf = malfeed.NewService(malfeed.Config{InitialLoaded: true})
	}

	deps := proxy.Dependencies{
		Logger:          discardLogger(),
		Cache:           cache.NewMemoryCache(),
		Backends:        registry,
		Ecosystems:      map[string]string{f.Backend: f.Backend},
		Findings:        store,
		RiskScore:       risk,
		Vulnerabilities: vuln,
		DepFirewall:     fw,
		Malfeed:         mf,
	}
	gw, err := proxy.New(deps, proxy.Options{HTTPAddr: ":0"})
	if err != nil {
		srv.Close()
		return nil, err
	}

	db := dossier.New(dossier.Config{}, dossier.Providers{
		Findings: store,
		Risk:     risk,
		Vuln:     vuln,
	})

	return &scenario{
		fixture: f,
		gateway: gw,
		handler: gw.Handler(),
		up:      up,
		store:   store,
		risk:    risk,
		vuln:    vuln,
		dossier: db,
		cleanup: srv.Close,
	}, nil
}

// get issues a client-style GET against the gateway and returns the recorder.
func (s *scenario) get(ctx context.Context, pullPath string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, pullPath, nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return rec
}

// artifactPull returns the fixture's artifact pull, or ok=false (git has none).
func artifactPull(f testset.Fixture) (testset.Pull, bool) {
	for _, p := range f.Pulls {
		if p.Kind == testset.KindArtifact && pullMethod(p) == http.MethodGet {
			return p, true
		}
	}
	return testset.Pull{}, false
}

// indexPull returns the fixture's first GET index pull, or ok=false.
func indexPull(f testset.Fixture) (testset.Pull, bool) {
	for _, p := range f.Pulls {
		if p.Kind == testset.KindIndex && pullMethod(p) == http.MethodGet {
			return p, true
		}
	}
	return testset.Pull{}, false
}
