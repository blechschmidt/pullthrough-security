// Package rebuildverify implements a reproducible-build verification gate (Task
// 68). For a package coordinate that the provenance subsystem (Task 8) and
// reposcore/provgraph have already mapped to a source Git commit, it performs a
// deterministic rebuild-from-source and compares the rebuilt artifact's
// byte/normalized digest against the upstream-served artifact.
//
// The subsystem is deliberately decoupled and air-gap-aware:
//
//   - The actual rebuild is delegated to a pluggable, sandboxed Builder (see
//     builder.go). The package ships toolchain-gated stub builders for the
//     ecosystems with reproducible toolchains (Go modules, npm with scripts
//     disabled, Python sdists/wheels, container images via buildkit) that skip
//     gracefully when the toolchain is unavailable, so a production operator can
//     register a real sandboxed builder without changing the wiring.
//
//   - Source-commit resolution and the upstream artifact bytes are supplied by
//     the caller (the proxy gate), so the package imports neither provenance nor
//     the cache and stays trivially unit-testable.
//
//   - Verification is asynchronous and non-blocking by default: the gate kicks
//     off a bounded background rebuild and serves the artifact immediately;
//     results are cached per (coordinate, digest) so a subsequent pull observes
//     the verdict. An optional enforce mode quarantines on a confirmed mismatch
//     (composing with the break-glass workflow).
//
// The verdict — reproducible | mismatch | unsupported | unattested — feeds the
// policy-as-code engine and the unified risk score as a new admission signal,
// and a confirmed mismatch surfaces as a SARIF finding and an EventRebuildVerify
// notification.
//
// All exported methods are safe for concurrent use and on a nil *Service.
package rebuildverify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Verdict is the terminal outcome of a reproducible-build verification.
type Verdict string

const (
	// VerdictReproducible: the rebuilt artifact's digest matched the
	// upstream-served artifact — the upstream binary provably derives from the
	// attested source commit.
	VerdictReproducible Verdict = "reproducible"
	// VerdictMismatch: the rebuilt artifact's digest did NOT match the upstream
	// artifact — the served binary does not derive from the attested source, a
	// strong supply-chain-tampering indicator.
	VerdictMismatch Verdict = "mismatch"
	// VerdictUnsupported: verification could not be performed — no builder for the
	// ecosystem, the build toolchain is unavailable (air-gapped), or the source
	// repository could not be located offline. The subsystem fails open.
	VerdictUnsupported Verdict = "unsupported"
	// VerdictUnattested: the artifact has no source-commit provenance association
	// to rebuild from, so there is nothing to verify against.
	VerdictUnattested Verdict = "unattested"
)

// Valid reports whether v is one of the four canonical verdicts.
func (v Verdict) Valid() bool {
	switch v {
	case VerdictReproducible, VerdictMismatch, VerdictUnsupported, VerdictUnattested:
		return true
	default:
		return false
	}
}

// Coordinate identifies the artifact under verification and the upstream-served
// digest that the rebuild is compared against.
type Coordinate struct {
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name,omitempty"`
	Version   string `json:"version,omitempty"`
	// Digest is the upstream-served artifact's content digest ("sha256:...").
	Digest string `json:"digest,omitempty"`
}

// String renders the canonical "name@version" coordinate, falling back to the
// digest when the version is unknown.
func (c Coordinate) String() string {
	switch {
	case c.Name != "" && c.Version != "":
		return c.Name + "@" + c.Version
	case c.Name != "":
		return c.Name
	default:
		return c.Digest
	}
}

// Source is the attested source revision the artifact is rebuilt from.
type Source struct {
	CommitSHA     string `json:"commitSha,omitempty"`
	RepositoryURL string `json:"repositoryUrl,omitempty"`
	// Confidence mirrors the provenance association confidence
	// (attested|claimed|heuristic).
	Confidence string `json:"confidence,omitempty"`
	// RepoDir, when set by the caller, is a pre-located local clone of the source
	// repository; otherwise the Service locates it via its RepoLocator.
	RepoDir string `json:"-"`
}

// Request is a single verification request.
type Request struct {
	Coordinate Coordinate
	Source     Source
	Tenant     string
	Backend    string
	// Upstream optionally opens the upstream-served artifact bytes so a builder can
	// compute a normalized upstream digest for content-rather-than-address
	// comparison. It may be nil.
	Upstream func() (io.ReadCloser, error)
}

// cacheKey is the per-(coordinate,digest) result cache key.
func (r Request) cacheKey() string {
	digest := strings.TrimSpace(r.Coordinate.Digest)
	if digest == "" {
		digest = r.Coordinate.String()
	}
	return strings.ToLower(strings.TrimSpace(r.Coordinate.Ecosystem)) + "|" +
		r.Coordinate.Name + "|" + r.Coordinate.Version + "|" + digest
}

// Result is the outcome of a verification.
type Result struct {
	Ecosystem      string        `json:"ecosystem,omitempty"`
	Coordinate     string        `json:"coordinate,omitempty"`
	Name           string        `json:"name,omitempty"`
	Version        string        `json:"version,omitempty"`
	Tenant         string        `json:"tenant,omitempty"`
	Verdict        Verdict       `json:"verdict"`
	Reproducible   bool          `json:"reproducible"`
	Mismatch       bool          `json:"mismatch"`
	CommitSHA      string        `json:"commitSha,omitempty"`
	RepositoryURL  string        `json:"repositoryUrl,omitempty"`
	Confidence     string        `json:"confidence,omitempty"`
	Builder        string        `json:"builder,omitempty"`
	UpstreamDigest string        `json:"upstreamDigest,omitempty"`
	RebuiltDigest  string        `json:"rebuiltDigest,omitempty"`
	Reason         string        `json:"reason,omitempty"`
	Pending        bool          `json:"pending,omitempty"`
	Done           bool          `json:"done"`
	Online         bool          `json:"online,omitempty"`
	DurationMS     int64         `json:"durationMs,omitempty"`
	ComputedAt     time.Time     `json:"computedAt,omitempty"`
	duration       time.Duration `json:"-"`
}

// Service is the reproducible-build verification subsystem.
type Service struct {
	cfg      Config
	registry *Registry
	locator  RepoLocator
	limiter  Limiter
	onResult func(Result)
	now      func() time.Time
	logger   *slog.Logger

	store  *resultStore
	recent *recentRing
	sem    chan struct{}

	mu       sync.Mutex
	inflight map[string]struct{}
	byEco    map[string]*VerdictCounts

	verifications atomic.Uint64
	reproducible  atomic.Uint64
	mismatchN     atomic.Uint64
	unsupported   atomic.Uint64
	unattested    atomic.Uint64
	buildsRun     atomic.Uint64
	buildErrors   atomic.Uint64
	asyncLaunched atomic.Uint64
	cacheHits     atomic.Uint64
}

// Limiter is an optional admission rate limiter for background rebuilds; a
// builder-heavy deployment can bound rebuild volume independently of request
// volume. Allow returns false to skip (defer) a rebuild.
type Limiter interface {
	Allow() bool
}

// RepoLocator resolves a source-repository URL to a local directory readable
// offline. It is satisfied structurally by reposcore.MirrorLocator (Task 63),
// so the wiring reuses the existing air-gap-aware mirror cache.
type RepoLocator interface {
	Locate(ctx context.Context, repoURL string) (dir string, resolved bool, online bool, err error)
}

// NewService validates the configuration and constructs the service. A nil
// Registry substitutes the built-in toolchain-gated stub builders.
func NewService(cfg Config) (*Service, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	reg := cfg.Registry
	if reg == nil {
		reg = BuiltinBuilders()
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	s := &Service{
		cfg:      cfg,
		registry: reg,
		locator:  cfg.Locator,
		limiter:  cfg.Limiter,
		onResult: cfg.OnResult,
		now:      now,
		logger:   logger,
		store:    newResultStore(cfg.CacheSize),
		recent:   newRecentRing(cfg.RecentSize),
		sem:      make(chan struct{}, cfg.MaxConcurrent),
		inflight: make(map[string]struct{}),
		byEco:    make(map[string]*VerdictCounts),
	}
	return s, nil
}

// Enabled reports whether the gate is active. Safe on a nil Service.
func (s *Service) Enabled() bool { return s != nil && s.cfg.Enabled }

// Mode returns the effective global mode (observe|enforce).
func (s *Service) Mode() Mode {
	if s == nil {
		return ModeObserve
	}
	return s.cfg.Mode
}

// Builders returns the ecosystems with a registered builder, for the admin
// surface.
func (s *Service) Builders() []string {
	if s == nil || s.registry == nil {
		return nil
	}
	return s.registry.Ecosystems()
}

// Verify runs the synchronous verification core: resolve a builder, locate the
// source, rebuild, and compare digests. It always returns a terminal Result
// (Done=true). It is the unit tested directly; the proxy gate calls Observe.
func (s *Service) Verify(ctx context.Context, req Request) Result {
	start := s.now()
	res := Result{
		Ecosystem:      strings.TrimSpace(req.Coordinate.Ecosystem),
		Coordinate:     req.Coordinate.String(),
		Name:           req.Coordinate.Name,
		Version:        req.Coordinate.Version,
		Tenant:         req.Tenant,
		CommitSHA:      req.Source.CommitSHA,
		RepositoryURL:  req.Source.RepositoryURL,
		Confidence:     req.Source.Confidence,
		UpstreamDigest: req.Coordinate.Digest,
		Done:           true,
	}
	finish := func(v Verdict, reason string) Result {
		res.Verdict = v
		res.Reason = reason
		res.Reproducible = v == VerdictReproducible
		res.Mismatch = v == VerdictMismatch
		res.duration = s.now().Sub(start)
		res.DurationMS = res.duration.Milliseconds()
		res.ComputedAt = s.now()
		s.record(res)
		return res
	}

	if strings.TrimSpace(req.Source.CommitSHA) == "" {
		return finish(VerdictUnattested, "no source-commit provenance association to rebuild from")
	}
	builder := s.registry.For(req.Coordinate.Ecosystem)
	if builder == nil {
		return finish(VerdictUnsupported, "no reproducible-build builder registered for ecosystem "+orNone(req.Coordinate.Ecosystem))
	}
	res.Builder = builder.Name()

	repoDir := strings.TrimSpace(req.Source.RepoDir)
	if repoDir == "" && s.locator != nil && strings.TrimSpace(req.Source.RepositoryURL) != "" {
		dir, resolved, online, err := s.locator.Locate(ctx, req.Source.RepositoryURL)
		res.Online = online
		switch {
		case err != nil:
			return finish(VerdictUnsupported, "source repository unavailable: "+err.Error())
		case !resolved:
			return finish(VerdictUnsupported, "source repository not available offline (air-gapped, not mirrored)")
		}
		repoDir = dir
	}

	out, err := builder.Build(ctx, BuildContext{
		Coordinate:     req.Coordinate,
		Source:         Source{CommitSHA: req.Source.CommitSHA, RepositoryURL: req.Source.RepositoryURL, Confidence: req.Source.Confidence, RepoDir: repoDir},
		RepoDir:        repoDir,
		UpstreamDigest: req.Coordinate.Digest,
		Upstream:       req.Upstream,
	})
	s.buildsRun.Add(1)
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return finish(VerdictUnsupported, "rebuild canceled/timed out: "+err.Error())
		case errors.Is(err, ErrToolchainUnavailable):
			return finish(VerdictUnsupported, "build toolchain unavailable: "+err.Error())
		case errors.Is(err, ErrUnsupported):
			return finish(VerdictUnsupported, err.Error())
		default:
			// Fail open: a builder error is not a mismatch verdict.
			s.buildErrors.Add(1)
			return finish(VerdictUnsupported, "rebuild error: "+err.Error())
		}
	}

	if strings.TrimSpace(out.Digest) == "" {
		return finish(VerdictUnsupported, "builder produced no rebuilt digest")
	}
	res.RebuiltDigest = out.Digest

	upstreamStr := req.Coordinate.Digest
	if strings.TrimSpace(out.UpstreamDigest) != "" {
		// The builder computed a normalized upstream digest for comparison.
		upstreamStr = out.UpstreamDigest
	}
	res.UpstreamDigest = upstreamStr

	up, okUp := parseDigest(upstreamStr)
	re, okRe := parseDigest(out.Digest)
	if !okUp || !okRe {
		return finish(VerdictUnsupported, "non-comparable digests (upstream or rebuilt digest unparsable)")
	}
	if up.Equal(re) {
		return finish(VerdictReproducible, "rebuilt artifact digest matches the upstream-served artifact ("+re.String()+")")
	}
	return finish(VerdictMismatch, fmt.Sprintf("rebuilt digest %s does not match upstream %s", re.Short(), up.Short()))
}

// Observe is the non-blocking entry point used by the proxy gate. It returns a
// cached terminal Result when one exists, computes the cheap terminal verdicts
// (unattested / unsupported) synchronously, and otherwise schedules a bounded
// background rebuild and returns a pending Result. Results are cached per
// (coordinate, digest). When Async is disabled it verifies synchronously.
func (s *Service) Observe(ctx context.Context, req Request) Result {
	if !s.Enabled() {
		return Result{Verdict: VerdictUnsupported, Reason: "subsystem disabled"}
	}
	key := req.cacheKey()
	if r, ok := s.store.get(key); ok {
		s.cacheHits.Add(1)
		return r
	}

	// Cheap terminal verdicts that require no build: resolve them synchronously and
	// cache so they are not recomputed.
	if strings.TrimSpace(req.Source.CommitSHA) == "" || s.registry.For(req.Coordinate.Ecosystem) == nil {
		r := s.Verify(ctx, req)
		s.store.put(key, r)
		if s.onResult != nil {
			s.onResult(r)
		}
		return r
	}

	if !s.cfg.Async {
		r := s.Verify(ctx, req)
		s.store.put(key, r)
		if s.onResult != nil {
			s.onResult(r)
		}
		return r
	}

	// Schedule a background rebuild (once per inflight key).
	if s.beginInflight(key) {
		s.asyncLaunched.Add(1)
		go s.runAsync(key, req)
	}
	return Result{
		Ecosystem:      strings.TrimSpace(req.Coordinate.Ecosystem),
		Coordinate:     req.Coordinate.String(),
		Name:           req.Coordinate.Name,
		Version:        req.Coordinate.Version,
		Tenant:         req.Tenant,
		CommitSHA:      req.Source.CommitSHA,
		RepositoryURL:  req.Source.RepositoryURL,
		UpstreamDigest: req.Coordinate.Digest,
		Pending:        true,
		Done:           false,
		Reason:         "reproducible-build verification scheduled",
	}
}

// runAsync performs a background rebuild under the concurrency cap and optional
// rate limiter, stores the result, and fires the completion hook. When no
// concurrency slot is free or the limiter denies, it leaves the result uncached
// so a later pull retries.
func (s *Service) runAsync(key string, req Request) {
	defer s.endInflight(key)
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		s.logger.Debug("rebuildverify: concurrency cap reached; deferring rebuild", "coordinate", req.Coordinate.String())
		return
	}
	if s.limiter != nil && !s.limiter.Allow() {
		s.logger.Debug("rebuildverify: rate limited; deferring rebuild", "coordinate", req.Coordinate.String())
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.BuildTimeout)
	defer cancel()
	r := s.Verify(ctx, req)
	s.store.put(key, r)
	if s.onResult != nil {
		s.onResult(r)
	}
}

func (s *Service) beginInflight(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.inflight[key]; ok {
		return false
	}
	s.inflight[key] = struct{}{}
	return true
}

func (s *Service) endInflight(key string) {
	s.mu.Lock()
	delete(s.inflight, key)
	s.mu.Unlock()
}

// Lookup returns a cached terminal Result for a coordinate/digest, if present.
func (s *Service) Lookup(req Request) (Result, bool) {
	if s == nil {
		return Result{}, false
	}
	return s.store.get(req.cacheKey())
}

// Decision is the enforce-mode gate outcome for a result.
type Decision struct {
	Block   bool
	Verdict Verdict
	Reason  string
}

// Gate maps a verification result to an enforce decision for a tenant. It blocks
// only a confirmed (Done) mismatch when the tenant's effective mode is enforce.
// Pending, reproducible, unsupported, and unattested results never block.
func (s *Service) Gate(res Result, tenant string) Decision {
	if s == nil || !res.Done {
		return Decision{}
	}
	if res.Verdict != VerdictMismatch {
		return Decision{Verdict: res.Verdict}
	}
	if !s.resolveMode(tenant).Enforces() {
		return Decision{Verdict: res.Verdict}
	}
	reason := res.Reason
	if reason == "" {
		reason = "reproducible-build mismatch: served artifact does not derive from the attested source commit"
	}
	return Decision{Block: true, Verdict: VerdictMismatch, Reason: reason}
}

// resolveMode returns the effective mode for a tenant, layering any per-tenant
// override over the global mode.
func (s *Service) resolveMode(tenant string) Mode {
	mode := s.cfg.Mode
	if tenant == "" {
		return mode
	}
	if ov, ok := s.cfg.Tenants[tenant]; ok && ov.Mode != "" {
		return ov.Mode
	}
	return mode
}

// record folds a terminal result into the counters, per-ecosystem tallies, and
// the recent ring.
func (s *Service) record(r Result) {
	s.verifications.Add(1)
	switch r.Verdict {
	case VerdictReproducible:
		s.reproducible.Add(1)
	case VerdictMismatch:
		s.mismatchN.Add(1)
	case VerdictUnsupported:
		s.unsupported.Add(1)
	case VerdictUnattested:
		s.unattested.Add(1)
	}
	eco := orNone(r.Ecosystem)
	s.mu.Lock()
	vc := s.byEco[eco]
	if vc == nil {
		vc = &VerdictCounts{}
		s.byEco[eco] = vc
	}
	vc.add(r.Verdict)
	s.mu.Unlock()
	s.recent.add(r)
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "unknown"
	}
	return s
}
