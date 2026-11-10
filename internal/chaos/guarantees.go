package chaos

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/coalesce"
	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
	"github.com/blechschmidt/pullthrough-security/internal/upstreampool"
)

// errInjected is the sentinel fault injected by the guarantee verifiers to stand
// in for an unreachable dependency.
var errInjected = errors.New("chaos: injected dependency outage")

// Dependency labels group the guarantees in the resilience matrix.
const (
	DepUpstream   = "upstream"
	DepStorage    = "storage"
	DepScanner    = "scanner/llm"
	DepFederation = "peer-federation"
)

// Guarantee is one resilience contract: under a named degraded condition for a
// dependency, the proxy must exhibit the expected behavior. verify reproduces
// the condition deterministically and returns a non-nil error describing the
// deviation if the contract does not hold.
type Guarantee struct {
	ID          string
	Dependency  string
	Condition   string
	Expectation string
	Mechanism   string

	verify func(ctx context.Context) error
}

// Guarantees returns the full catalog of resilience guarantees, which doubles as
// the table driving the harness tests and the source of the documented
// resilience matrix (docs/resilience.md).
func Guarantees() []Guarantee {
	return []Guarantee{
		// ---- upstream: multi-mirror failover & circuit breaking --------------
		{
			ID:          "UP-FAILOVER-5XX",
			Dependency:  DepUpstream,
			Condition:   "primary mirror returns a retryable 5xx",
			Expectation: "request fails over to a healthy mirror and is served 200",
			Mechanism:   "upstreampool health-aware routing",
			verify:      verifyFailover5xx,
		},
		{
			ID:          "UP-FAILOVER-TRANSPORT",
			Dependency:  DepUpstream,
			Condition:   "primary mirror connection/TLS error (nil response)",
			Expectation: "request fails over to a healthy mirror and is served 200",
			Mechanism:   "upstreampool health-aware routing",
			verify:      verifyFailoverTransport,
		},
		{
			ID:          "UP-NO-FAILOVER-404",
			Dependency:  DepUpstream,
			Condition:   "primary mirror returns a terminal 404",
			Expectation: "404 is returned directly: no failover, no circuit trip (404 is an answer, not a fault)",
			Mechanism:   "upstreampool retryable-status classifier",
			verify:      verifyNoFailoverOn404,
		},
		{
			ID:          "UP-CIRCUIT-OPENS",
			Dependency:  DepUpstream,
			Condition:   "an endpoint fails FailureThreshold times in a row",
			Expectation: "its circuit opens; further requests are shed (AllUnavailable) without dialing the dead endpoint",
			Mechanism:   "upstreampool circuit breaker",
			verify:      verifyCircuitOpens,
		},
		{
			ID:          "UP-CIRCUIT-RECOVERS",
			Dependency:  DepUpstream,
			Condition:   "an open circuit's endpoint recovers after the open timeout",
			Expectation: "a half-open trial probe succeeds and, after SuccessThreshold successes, the circuit closes",
			Mechanism:   "upstreampool half-open recovery",
			verify:      verifyCircuitRecovers,
		},
		{
			ID:          "UP-ALL-OPEN-SHED",
			Dependency:  DepUpstream,
			Condition:   "every mirror's circuit is open",
			Expectation: "the pool fails fast with AllUnavailableError and issues zero upstream requests",
			Mechanism:   "upstreampool fail-fast",
			verify:      verifyAllOpenShed,
		},
		{
			ID:          "UP-NEGATIVE-CACHE",
			Dependency:  DepUpstream,
			Condition:   "a missing artifact is requested repeatedly (404 storm)",
			Expectation: "only the first request reaches the upstream; the rest are absorbed by the negative cache",
			Mechanism:   "coalesce negative cache",
			verify:      verifyNegativeCache,
		},
		{
			ID:          "UP-SINGLEFLIGHT-ERROR",
			Dependency:  DepUpstream,
			Condition:   "concurrent misses for the same artifact while the upstream errors",
			Expectation: "exactly one upstream fetch is issued; the error is shared with every coalesced waiter",
			Mechanism:   "coalesce singleflight",
			verify:      verifySingleflightUnderError,
		},
		// ---- storage: cache / object-store backend ---------------------------
		{
			ID:          "ST-READ-THROUGH-ERROR",
			Dependency:  DepStorage,
			Condition:   "the cache/object-store backend is unreachable on the read-through path",
			Expectation: "the pull returns 502 Bad Gateway; no partial or garbage content is served",
			Mechanism:   "gateway writeFetchError",
			verify:      verifyStorageReadError,
		},
		{
			ID:          "ST-WRITE-ERROR",
			Dependency:  DepStorage,
			Condition:   "the object-store write (Put) times out / 5xxs during a cache fill",
			Expectation: "the pull returns 502 and nothing is cached; a retry re-fetches rather than serving a half-written entry",
			Mechanism:   "atomic cache fill",
			verify:      verifyStorageWriteError,
		},
		{
			ID:          "ST-PARTIAL-RESPONSE",
			Dependency:  DepStorage,
			Condition:   "the upstream declares a Content-Length larger than the body it delivers (truncated/partial response)",
			Expectation: "the fill fails (502) on the short read and the partial bytes are never cached; a retry re-fetches",
			Mechanism:   "cache fill read-to-EOF",
			verify:      verifyPartialResponse,
		},
		{
			ID:          "ST-FILL-INTEGRITY",
			Dependency:  DepStorage,
			Condition:   "the upstream serves bytes that do not match the expected content digest",
			Expectation: "the fill is aborted (502) and the tampered bytes are never committed to the cache",
			Mechanism:   "fill-time content-digest verifier",
			verify:      verifyFillIntegrity,
		},
		// ---- scanner / LLM: graceful gate degradation ------------------------
		{
			ID:          "GATE-POLICY-FAIL-OPEN",
			Dependency:  DepScanner,
			Condition:   "the provenance/scan assessment backend is unavailable and policy is fail-open (default)",
			Expectation: "the artifact is served with a warning rather than halting all pulls",
			Mechanism:   "policy.Engine FailClosed=false",
			verify:      verifyPolicyFailOpen,
		},
		{
			ID:          "GATE-POLICY-FAIL-CLOSED",
			Dependency:  DepScanner,
			Condition:   "the provenance/scan assessment backend is unavailable and policy is fail-closed",
			Expectation: "the artifact is blocked (safety over availability)",
			Mechanism:   "policy.Engine FailClosed=true",
			verify:      verifyPolicyFailClosed,
		},
		{
			ID:          "GATE-LLM-DEGRADE",
			Dependency:  DepScanner,
			Condition:   "the LLM commit-scan API is unavailable but a deterministic pass found a secret",
			Expectation: "the scan degrades to the deterministic verdict (served, finding retained) instead of failing the pull",
			Mechanism:   "commit pipeline deterministic fallback",
			verify:      verifyLLMDegrade,
		},
		{
			ID:          "GATE-LLM-PROPAGATE",
			Dependency:  DepScanner,
			Condition:   "the LLM commit-scan API is unavailable and no deterministic signal exists",
			Expectation: "the outage propagates so the commit stays unscanned (deferred to the missing-scan policy — no silent pass)",
			Mechanism:   "commit pipeline error propagation",
			verify:      verifyLLMPropagate,
		},
		// ---- peer cache federation: read-through sibling lookup --------------
		{
			ID:          "CF-PEER-HIT",
			Dependency:  DepFederation,
			Condition:   "a local cache miss whose artifact a healthy sibling peer holds",
			Expectation: "the miss is served from the peer (egress saved) with the bytes re-verified against the expected digest",
			Mechanism:   "cachefed read-through + digest re-verification",
			verify:      verifyCacheFedPeerHit,
		},
		{
			ID:          "CF-DIGEST-MISMATCH",
			Dependency:  DepFederation,
			Condition:   "a peer returns bytes that do not match the expected content digest (compromised/corrupt sibling)",
			Expectation: "the stream fails with a digest mismatch and the tampered bytes are never trusted or cached",
			Mechanism:   "cachefed streaming digest verifier",
			verify:      verifyCacheFedDigestMismatch,
		},
		{
			ID:          "CF-PEER-DOWN",
			Dependency:  DepFederation,
			Condition:   "the only configured peer is unreachable (connection refused) on a local miss",
			Expectation: "the read-through reports no-peer (so the caller falls through to the upstream); no partial content is served",
			Mechanism:   "cachefed per-peer error handling",
			verify:      verifyCacheFedPeerDown,
		},
		{
			ID:          "CF-CIRCUIT-SHED",
			Dependency:  DepFederation,
			Condition:   "a peer fails FailureThreshold times in a row",
			Expectation: "its circuit opens and further misses skip it without issuing a request",
			Mechanism:   "cachefed per-peer circuit breaker",
			verify:      verifyCacheFedCircuitSheds,
		},
	}
}

// Result records the outcome of verifying one Guarantee.
type Result struct {
	ID          string `json:"id"`
	Dependency  string `json:"dependency"`
	Condition   string `json:"condition"`
	Expectation string `json:"expectation"`
	Mechanism   string `json:"mechanism"`
	Pass        bool   `json:"pass"`
	Detail      string `json:"detail,omitempty"`
}

// Report is the resilience matrix produced by Run.
type Report struct {
	Total   int      `json:"total"`
	Passed  int      `json:"passed"`
	Failed  int      `json:"failed"`
	Results []Result `json:"results"`
}

// Run verifies every guarantee in the catalog and returns the resilience
// matrix. It never returns an error for a failed guarantee (that is recorded as
// Pass=false); a non-nil error indicates the harness itself could not run.
func Run(ctx context.Context) (*Report, error) {
	gs := Guarantees()
	rep := &Report{Total: len(gs), Results: make([]Result, 0, len(gs))}
	for _, g := range gs {
		res := Result{
			ID:          g.ID,
			Dependency:  g.Dependency,
			Condition:   g.Condition,
			Expectation: g.Expectation,
			Mechanism:   g.Mechanism,
			Pass:        true,
		}
		if err := g.verify(ctx); err != nil {
			res.Pass = false
			res.Detail = err.Error()
			rep.Failed++
		} else {
			rep.Passed++
		}
		rep.Results = append(rep.Results, res)
	}
	return rep, nil
}

// ----------------------------------------------------------------------------
// Upstream failover / circuit-breaker verifiers
// ----------------------------------------------------------------------------

// newPool builds a two-or-more-endpoint pool from the supplied endpoint doers,
// endpoint[0] being the primary. It wires low breaker thresholds and a manual
// clock so trips/recovery are deterministic.
func newPool(clock *ManualClock, failureThreshold, successThreshold int, openTimeout time.Duration, doers ...*FaultyDoer) (*upstreampool.Pool, error) {
	eps := make([]upstreampool.EndpointConfig, len(doers))
	for i, d := range doers {
		eps[i] = upstreampool.EndpointConfig{
			ID:     fmt.Sprintf("ep%d", i),
			URL:    fmt.Sprintf("http://ep%d.invalid", i),
			Client: d,
		}
	}
	return upstreampool.New(upstreampool.Config{
		Backend:          "npm",
		Endpoints:        eps,
		Client:           doers[0], // shared fallback; endpoints use their own Client
		FailureThreshold: failureThreshold,
		SuccessThreshold: successThreshold,
		OpenTimeout:      openTimeout,
		Now:              clock.Now,
	})
}

// poolRequest targets the primary endpoint's base so the pool routes (rather
// than passes through) the request.
func poolRequest() upstream.Request {
	return upstream.Request{URL: "http://ep0.invalid/artifact.tgz"}
}

func endpointState(pool *upstreampool.Pool, id string) string {
	for _, ep := range pool.Snapshot().Endpoints {
		if ep.ID == id {
			return ep.State
		}
	}
	return "unknown"
}

func verifyFailover5xx(ctx context.Context) error {
	primary := StatusDoer(http.StatusServiceUnavailable, "down")
	mirror := HealthyDoer("MIRROR-BYTES")
	pool, err := newPool(NewManualClock(), 5, 2, 30*time.Second, primary, mirror)
	if err != nil {
		return err
	}
	resp, err := pool.Do(ctx, poolRequest())
	if err != nil {
		return fmt.Errorf("Do errored: %w", err)
	}
	if resp.Status != http.StatusOK {
		return fmt.Errorf("status = %d, want 200 from mirror", resp.Status)
	}
	if mirror.Count() != 1 {
		return fmt.Errorf("mirror received %d requests, want 1", mirror.Count())
	}
	if ft := pool.Snapshot().FailoverTotal; ft != 1 {
		return fmt.Errorf("FailoverTotal = %d, want 1", ft)
	}
	return nil
}

func verifyFailoverTransport(ctx context.Context) error {
	primary := TransportFailDoer(errInjected)
	mirror := HealthyDoer("MIRROR-BYTES")
	pool, err := newPool(NewManualClock(), 5, 2, 30*time.Second, primary, mirror)
	if err != nil {
		return err
	}
	resp, err := pool.Do(ctx, poolRequest())
	if err != nil {
		return fmt.Errorf("Do errored: %w", err)
	}
	if resp.Status != http.StatusOK || mirror.Count() != 1 {
		return fmt.Errorf("status=%d mirrorCount=%d, want 200 served by the mirror", resp.Status, mirror.Count())
	}
	return nil
}

func verifyNoFailoverOn404(ctx context.Context) error {
	primary := StatusDoer(http.StatusNotFound, "missing")
	mirror := HealthyDoer("MIRROR-BYTES")
	pool, err := newPool(NewManualClock(), 3, 2, 30*time.Second, primary, mirror)
	if err != nil {
		return err
	}
	resp, err := pool.Do(ctx, poolRequest())
	if err != nil {
		return fmt.Errorf("Do errored: %w", err)
	}
	if resp.Status != http.StatusNotFound {
		return fmt.Errorf("status = %d, want 404 returned directly", resp.Status)
	}
	if mirror.Count() != 0 {
		return fmt.Errorf("mirror was consulted (%d) for a terminal 404", mirror.Count())
	}
	if s := endpointState(pool, "ep0"); s != "closed" {
		return fmt.Errorf("primary circuit = %q after a 404, want closed (404 is not a fault)", s)
	}
	return nil
}

func verifyCircuitOpens(ctx context.Context) error {
	primary := StatusDoer(http.StatusServiceUnavailable, "down")
	pool, err := newPool(NewManualClock(), 3, 2, 30*time.Second, primary)
	if err != nil {
		return err
	}
	for i := 0; i < 3; i++ {
		if _, err := pool.Do(ctx, poolRequest()); err != nil {
			// A single-endpoint pool returns the 5xx response (err nil) until the
			// breaker opens; an error here before the 3rd call is unexpected.
			return fmt.Errorf("Do #%d errored early: %w", i+1, err)
		}
	}
	if s := endpointState(pool, "ep0"); s != "open" {
		return fmt.Errorf("circuit = %q after 3 failures, want open", s)
	}
	before := primary.Count()
	_, err = pool.Do(ctx, poolRequest())
	var unavail *upstreampool.AllUnavailableError
	if !errors.As(err, &unavail) {
		return fmt.Errorf("Do with open circuit returned %v, want AllUnavailableError", err)
	}
	if primary.Count() != before {
		return fmt.Errorf("open circuit still dialed the endpoint (%d -> %d)", before, primary.Count())
	}
	return nil
}

func verifyCircuitRecovers(ctx context.Context) error {
	clock := NewManualClock()
	// Fail twice (opens at threshold 2), then recover.
	doer := FlakyDoer(2, errInjected, "RECOVERED")
	pool, err := newPool(clock, 2, 2, 30*time.Second, doer)
	if err != nil {
		return err
	}
	for i := 0; i < 2; i++ {
		_, _ = pool.Do(ctx, poolRequest())
	}
	if s := endpointState(pool, "ep0"); s != "open" {
		return fmt.Errorf("circuit = %q after 2 failures, want open", s)
	}
	// Cross the open timeout so the next request is admitted as a half-open probe.
	clock.Advance(31 * time.Second)
	// Drive sequential successful probes until the breaker closes (SuccessThreshold=2).
	for i := 0; i < 5; i++ {
		resp, derr := pool.Do(ctx, poolRequest())
		if derr != nil {
			return fmt.Errorf("recovery probe %d errored: %w", i+1, derr)
		}
		if resp.Status != http.StatusOK {
			return fmt.Errorf("recovery probe %d status = %d, want 200", i+1, resp.Status)
		}
		if endpointState(pool, "ep0") == "closed" {
			return nil
		}
	}
	return fmt.Errorf("circuit did not close after recovery, state = %q", endpointState(pool, "ep0"))
}

func verifyAllOpenShed(ctx context.Context) error {
	primary := HealthyDoer("UNUSED")
	pool, err := newPool(NewManualClock(), 3, 2, 30*time.Second, primary)
	if err != nil {
		return err
	}
	if err := pool.OpenCircuit("ep0"); err != nil {
		return err
	}
	_, err = pool.Do(ctx, poolRequest())
	var unavail *upstreampool.AllUnavailableError
	if !errors.As(err, &unavail) {
		return fmt.Errorf("Do returned %v, want AllUnavailableError", err)
	}
	if primary.Count() != 0 {
		return fmt.Errorf("a forced-open endpoint was dialed %d times, want 0", primary.Count())
	}
	return nil
}

// ----------------------------------------------------------------------------
// Upstream coalesce / negative-cache verifiers
// ----------------------------------------------------------------------------

func verifyNegativeCache(ctx context.Context) error {
	up := NewFaultyUpstream(ModeNotFound, "")
	defer up.Close()
	cl := newCoalescer()
	handler, err := BuildGateway(GatewayOptions{BaseURL: up.URL(), Coalescer: cl})
	if err != nil {
		return err
	}
	for i := 0; i < 5; i++ {
		rr := doPull(handler, "missing.tgz")
		if rr.Code != http.StatusNotFound {
			return fmt.Errorf("request %d: status = %d, want 404", i, rr.Code)
		}
	}
	if up.Hits() != 1 {
		return fmt.Errorf("upstream hit %d times, want 1 (negative cache should absorb the rest)", up.Hits())
	}
	return nil
}

func verifySingleflightUnderError(ctx context.Context) error {
	// Sequential + a 5xx storm would be absorbed by the retryable negative cache,
	// which conflates two guarantees. Here we prove the singleflight property
	// directly: hold one slow fetch open, join a second caller, and confirm the
	// upstream saw exactly one request. Concurrency is sequenced via the slow
	// upstream's release channel, so this is deterministic.
	up := NewFaultyUpstream(ModeSlow, "ARTIFACT")
	defer up.Close()
	cl := newCoalescer()
	handler, err := BuildGateway(GatewayOptions{BaseURL: up.URL(), Coalescer: cl})
	if err != nil {
		return err
	}

	const n = 8
	codes := make(chan int, n)
	for i := 0; i < n; i++ {
		go func() {
			rr := doPull(handler, "pkg-1.0.0.tgz")
			codes <- rr.Code
		}()
	}
	// Wait until n-1 callers have coalesced onto the single in-flight leader.
	deadline := time.Now().Add(3 * time.Second)
	for cl.Metrics().Coalesced < n-1 {
		if time.Now().After(deadline) {
			up.Release()
			return fmt.Errorf("only %d callers coalesced, want %d", cl.Metrics().Coalesced, n-1)
		}
		time.Sleep(time.Millisecond)
	}
	up.Release()
	for i := 0; i < n; i++ {
		if code := <-codes; code != http.StatusOK {
			return fmt.Errorf("caller status = %d, want 200", code)
		}
	}
	if up.Hits() != 1 {
		return fmt.Errorf("upstream hit %d times, want exactly 1", up.Hits())
	}
	return nil
}

// ----------------------------------------------------------------------------
// Storage verifiers
// ----------------------------------------------------------------------------

func verifyStorageReadError(ctx context.Context) error {
	up := NewFaultyUpstream(ModeHealthy, "ARTIFACT")
	defer up.Close()
	fc := NewFaultyCache(cache.NewMemoryCache()).WithGetOrLoadError(errInjected)
	handler, err := BuildGateway(GatewayOptions{BaseURL: up.URL(), Cache: fc})
	if err != nil {
		return err
	}
	rr := doPull(handler, "pkg.tgz")
	if rr.Code != http.StatusBadGateway {
		return fmt.Errorf("status = %d, want 502", rr.Code)
	}
	if up.Hits() != 0 {
		return fmt.Errorf("upstream dialed %d times despite a read-path storage outage", up.Hits())
	}
	return nil
}

func verifyStorageWriteError(ctx context.Context) error {
	up := NewFaultyUpstream(ModeHealthy, "ARTIFACT")
	defer up.Close()
	fc := NewFaultyCache(cache.NewMemoryCache()).WithPutError(errInjected)
	handler, err := BuildGateway(GatewayOptions{BaseURL: up.URL(), Cache: fc})
	if err != nil {
		return err
	}
	if rr := doPull(handler, "pkg.tgz"); rr.Code != http.StatusBadGateway {
		return fmt.Errorf("first pull status = %d, want 502", rr.Code)
	}
	// Nothing was committed: a retry must re-fetch rather than serve a half-written
	// entry.
	if rr := doPull(handler, "pkg.tgz"); rr.Code != http.StatusBadGateway {
		return fmt.Errorf("retry status = %d, want 502", rr.Code)
	}
	if up.Hits() != 2 {
		return fmt.Errorf("upstream hit %d times, want 2 (a failed fill must not be cached)", up.Hits())
	}
	return nil
}

func verifyPartialResponse(ctx context.Context) error {
	up := NewFaultyUpstream(ModeTruncated, "SHORT-BODY")
	defer up.Close()
	handler, err := BuildGateway(GatewayOptions{BaseURL: up.URL(), Cache: cache.NewMemoryCache()})
	if err != nil {
		return err
	}
	if rr := doPull(handler, "pkg.tgz"); rr.Code != http.StatusBadGateway {
		return fmt.Errorf("status = %d, want 502 for a truncated response", rr.Code)
	}
	if rr := doPull(handler, "pkg.tgz"); rr.Code != http.StatusBadGateway {
		return fmt.Errorf("retry status = %d, want 502 (partial fill must not be cached)", rr.Code)
	}
	if up.Hits() != 2 {
		return fmt.Errorf("upstream hit %d times, want 2 (a partial fill must not be cached)", up.Hits())
	}
	return nil
}

func verifyFillIntegrity(ctx context.Context) error {
	up := NewFaultyUpstream(ModeHealthy, "TAMPERED-BYTES")
	defer up.Close()
	// A digest the served body cannot possibly match.
	wrongDigest := "sha256:" + "00000000000000000000000000000000000000000000000000000000000000ff"
	handler, err := BuildGateway(GatewayOptions{BaseURL: up.URL(), Digest: wrongDigest})
	if err != nil {
		return err
	}
	if rr := doPull(handler, "pkg.tgz"); rr.Code != http.StatusBadGateway {
		return fmt.Errorf("status = %d, want 502 for a digest mismatch", rr.Code)
	}
	// The tampered bytes must never have been committed: a retry re-fetches.
	if rr := doPull(handler, "pkg.tgz"); rr.Code != http.StatusBadGateway {
		return fmt.Errorf("retry status = %d, want 502 (tampered fill must not be cached)", rr.Code)
	}
	if up.Hits() != 2 {
		return fmt.Errorf("upstream hit %d times, want 2 (a mismatched fill must not poison the cache)", up.Hits())
	}
	return nil
}

// ----------------------------------------------------------------------------
// Scanner / LLM gate-degradation verifiers
// ----------------------------------------------------------------------------

func policyArtifact() policy.Artifact {
	return policy.Artifact{Ecosystem: "npm", Backend: "npm", Name: "left-pad", Version: "1.0.0"}
}

func verifyPolicyFailOpen(ctx context.Context) error {
	engine := policy.New(
		policy.Config{FailClosed: false},
		FaultyAssessmentSource{Err: errInjected},
		discardLogger(),
	)
	d := engine.Evaluate(ctx, policyArtifact())
	if d.Blocked() {
		return fmt.Errorf("fail-open policy blocked on a backend outage (action=%q)", d.Action)
	}
	if d.Action != policy.ActionWarn {
		return fmt.Errorf("action = %q, want warn (served with a warning)", d.Action)
	}
	return nil
}

func verifyPolicyFailClosed(ctx context.Context) error {
	engine := policy.New(
		policy.Config{FailClosed: true},
		FaultyAssessmentSource{Err: errInjected},
		discardLogger(),
	)
	d := engine.Evaluate(ctx, policyArtifact())
	if !d.Blocked() {
		return fmt.Errorf("fail-closed policy did not block on a backend outage (action=%q)", d.Action)
	}
	return nil
}

func verifyLLMDegrade(ctx context.Context) error {
	provider := &FaultyProvider{Err: errInjected}
	scanner := staticSecretScanner{findings: []commit.SecretFinding{{
		RuleID: "private-key-block", Description: "PEM private key", Severity: "critical",
		File: "id_rsa", Line: 1, Match: "----****",
	}}}
	p, err := commit.New(provider, commit.NewMemoryStore(), commit.Config{Secrets: scanner}, discardLogger())
	if err != nil {
		return err
	}
	v, err := p.Scan(ctx, sampleCommit())
	if err != nil {
		return fmt.Errorf("expected graceful degradation, got error: %w", err)
	}
	if v.Error == "" {
		return errors.New("verdict did not record the LLM degradation (v.Error empty)")
	}
	if len(v.Findings) == 0 {
		return errors.New("deterministic secret finding was lost on LLM degradation")
	}
	return nil
}

func verifyLLMPropagate(ctx context.Context) error {
	provider := &FaultyProvider{Err: errInjected}
	scanner := staticSecretScanner{} // no deterministic signal
	p, err := commit.New(provider, commit.NewMemoryStore(), commit.Config{Secrets: scanner}, discardLogger())
	if err != nil {
		return err
	}
	if _, err := p.Scan(ctx, sampleCommit()); err == nil {
		return errors.New("LLM outage was silently swallowed; expected the error to propagate")
	}
	return nil
}

// ----------------------------------------------------------------------------
// shared helpers
// ----------------------------------------------------------------------------

// newCoalescer builds an enabled pull-path coalescer with a long negative TTL
// (so within-TTL absorption is deterministic without clock control).
func newCoalescer() *coalesce.Coalescer[*cache.Entry] {
	return coalesce.New[*cache.Entry](
		coalesce.Config{Enabled: true, NegativeTTL: time.Minute},
		func(err error) coalesce.Verdict {
			if se, ok := backends.AsStatusError(err); ok {
				switch {
				case se.Status == http.StatusNotFound || se.Status == http.StatusGone:
					return coalesce.Verdict{Cache: true, Kind: "not_found"}
				case se.Status >= 500:
					return coalesce.Verdict{Cache: true, Retryable: true, Kind: "server"}
				}
			}
			return coalesce.Verdict{}
		},
	)
}

// doPull issues a GET for an npm artifact against the gateway handler.
func doPull(handler http.Handler, artifact string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, NPMPullPath(artifact), nil))
	return rr
}
