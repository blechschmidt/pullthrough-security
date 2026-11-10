// Package cachefed implements cross-proxy peer cache federation (Task 143): a
// read-through sibling-lookup layer that lets a cluster of pull-through proxy
// instances satisfy a local cache miss from a sibling peer's cache before
// reaching out to the upstream registry, reducing egress and cache warming time.
//
// The design has two halves:
//
//   - A lightweight, authenticated peer protocol (protocol.go) that exposes
//     HEAD/GET by cache key over the proxy's existing content-addressable store.
//     A proxy answers a sibling only from its own already-gated, cacheable
//     entries — the local cache never holds an artifact that failed an admission
//     gate — so bytes exchanged between peers are, by construction, bytes that
//     already passed the serving proxy's gates.
//
//   - A read-through client (fetch.go) consulted on a local miss. It queries
//     healthy peers — selected and shed via a per-peer circuit breaker that
//     mirrors the Task 38 upstream health-aware routing state machine — with a
//     per-peer timeout and optional request hedging, and (critically) NEVER
//     trusts peer bytes blindly: the received stream is re-verified against the
//     expected content digest as it is read, so a tampered or corrupt peer can
//     never poison the local cache. The verified bytes are returned to the
//     gateway's normal cache-fill path, where they are additionally re-run
//     through every local admission gate exactly as an upstream fetch would be.
//
// Federation is strictly opt-in (cachefed.enabled) and composes with the
// emergency kill-switch: the gateway consults peers only after its lockdown
// freeze check, so a freeze serves already-cached artifacts without reaching any
// sibling. A nil *Federation, or one with no peers, is a valid no-op.
package cachefed

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

var (
	// ErrDisabled is returned by Fetch when federation is not enabled.
	ErrDisabled = errors.New("cachefed: federation disabled")
	// ErrNoPeer is returned by Fetch when no healthy peer could satisfy the miss
	// (either none are configured/healthy, or none held the key).
	ErrNoPeer = errors.New("cachefed: no peer could satisfy the request")
	// ErrNoDigest is returned by Fetch when RequireDigest is set and no expected
	// content digest is available to re-verify a peer response against.
	ErrNoDigest = errors.New("cachefed: no expected digest to verify a peer response")
	// ErrDigestMismatch is substituted for io.EOF when a peer's bytes fail
	// re-verification against the expected digest; it aborts the cache fill
	// before any tampered content is committed.
	ErrDigestMismatch = errors.New("cachefed: peer content digest mismatch")
)

// Peer is a sibling proxy this instance may consult on a local cache miss.
type Peer struct {
	// Name is a stable identifier for the peer, used in logs, metric labels, and
	// self-exclusion against the coordination NodeID. Defaults to the URL host.
	Name string
	// URL is the peer's base URL (scheme + host, no path), e.g.
	// "https://proxy-b.internal:8443".
	URL string
}

// Config configures a Federation. The zero value (Enabled false) is a no-op.
type Config struct {
	// Enabled turns the whole subsystem on. When false, New returns a no-op
	// Federation whose Fetch always returns ErrDisabled and whose Handler rejects
	// every request.
	Enabled bool
	// Serve controls whether this instance answers sibling HEAD/GET requests.
	// Independent of the read-through client: a node can consult peers without
	// serving them, or vice versa. Defaults to true when Enabled.
	Serve bool
	// Peers is the static roster of sibling proxies. A peer whose Name matches
	// SelfName (the coordination NodeID) is dropped so a node never federates to
	// itself.
	Peers []Peer
	// SelfName identifies this instance (typically the coordination NodeID). Used
	// only to self-exclude from the peer roster.
	SelfName string
	// AuthToken is the shared bearer token presented to — and required from —
	// peers. Resolved from a secretRef before New is called. When empty, serving
	// is disabled (there is nothing to authenticate against) and the client sends
	// no credential.
	AuthToken string
	// MaxPeerFanout caps how many peers a single miss may query concurrently.
	// Defaults to 2.
	MaxPeerFanout int
	// PeerTimeout bounds the time to receive response headers from one peer; it
	// does not bound the subsequent body stream (bounded by the caller's context).
	// Defaults to 3s.
	PeerTimeout time.Duration
	// HedgeDelay staggers the fan-out: the first peer is queried immediately and
	// each subsequent candidate is launched HedgeDelay after the previous, so a
	// slow peer does not hold up the request while a fast one could answer. Zero
	// launches all candidates at once (pure parallel fan-out).
	HedgeDelay time.Duration
	// RequireDigest refuses to consult peers unless an expected content digest is
	// known (either supplied by the caller or derivable from a content-addressed
	// cache key). It is the safe default: it guarantees every peer response can be
	// re-verified. Defaults to true.
	RequireDigest bool

	// Circuit-breaker tunables (mirror the upstream pool).
	FailureThreshold  int           // consecutive peer failures that trip the breaker (default 3)
	SuccessThreshold  int           // consecutive half-open successes that close it (default 2)
	OpenTimeout       time.Duration // how long a tripped peer is shed before a probe (default 30s)
	HalfOpenMaxProbes int           // trial probes admitted while half-open (default 1)
}

// peerState pairs a configured Peer with its live circuit breaker and parsed
// base URL.
type peerState struct {
	peer    Peer
	base    *url.URL
	breaker *breaker
}

// Doer is the minimal HTTP client surface the Federation needs. *http.Client
// satisfies it; tests inject a fake.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Federation is the read-through sibling-lookup layer. It is safe for concurrent
// use. A nil *Federation is a valid no-op (Enabled reports false).
type Federation struct {
	cfg     Config
	peers   []*peerState
	client  Doer
	metrics *Metrics
	logger  *slog.Logger
	now     func() time.Time
}

// Option customizes a Federation (used by tests to inject a clock or client).
type Option func(*Federation)

// WithClock overrides the Federation clock (and its breakers) for deterministic
// tests.
func WithClock(now func() time.Time) Option {
	return func(f *Federation) {
		if now != nil {
			f.now = now
		}
	}
}

// WithHTTPClient overrides the HTTP client used to reach peers.
func WithHTTPClient(c Doer) Option {
	return func(f *Federation) {
		if c != nil {
			f.client = c
		}
	}
}

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) Option {
	return func(f *Federation) {
		if l != nil {
			f.logger = l
		}
	}
}

// New constructs a Federation from cfg. It always returns a usable (non-nil)
// *Federation carrying a fresh Metrics so the metrics layer can bind
// unconditionally; when cfg.Enabled is false the result is an inert no-op. An
// error is returned only for a structurally invalid peer URL.
func New(cfg Config, metrics *Metrics, opts ...Option) (*Federation, error) {
	if metrics == nil {
		metrics = NewMetrics()
	}
	f := &Federation{
		cfg:     withDefaults(cfg),
		metrics: metrics,
		logger:  slog.Default(),
		now:     time.Now,
	}
	for _, o := range opts {
		o(f)
	}
	if f.client == nil {
		f.client = &http.Client{
			// No client-wide Timeout: per-peer header deadlines are enforced
			// explicitly in the read-through path so a large body stream is not
			// truncated by a short timeout.
			Transport: http.DefaultTransport,
		}
	}
	if !f.cfg.Enabled {
		return f, nil
	}

	params := breakerParams{
		failureThreshold:  f.cfg.FailureThreshold,
		successThreshold:  f.cfg.SuccessThreshold,
		openTimeout:       f.cfg.OpenTimeout,
		halfOpenMaxProbes: f.cfg.HalfOpenMaxProbes,
	}
	seen := make(map[string]bool)
	for _, p := range f.cfg.Peers {
		raw := strings.TrimSpace(p.URL)
		if raw == "" {
			return nil, fmt.Errorf("cachefed: peer %q has an empty URL", p.Name)
		}
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("cachefed: peer %q has an invalid URL %q: %w", p.Name, raw, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return nil, fmt.Errorf("cachefed: peer %q URL %q must be http or https", p.Name, raw)
		}
		if u.Host == "" {
			return nil, fmt.Errorf("cachefed: peer %q URL %q has no host", p.Name, raw)
		}
		name := strings.TrimSpace(p.Name)
		if name == "" {
			name = u.Host
		}
		// Self-exclusion: never federate to ourselves.
		if f.cfg.SelfName != "" && name == f.cfg.SelfName {
			continue
		}
		if seen[name] {
			return nil, fmt.Errorf("cachefed: duplicate peer name %q", name)
		}
		seen[name] = true
		f.peers = append(f.peers, &peerState{
			peer:    Peer{Name: name, URL: raw},
			base:    u,
			breaker: newBreaker(params, f.now),
		})
	}
	return f, nil
}

// withDefaults fills unset Config fields with their defaults.
func withDefaults(cfg Config) Config {
	if cfg.MaxPeerFanout <= 0 {
		cfg.MaxPeerFanout = 2
	}
	if cfg.PeerTimeout <= 0 {
		cfg.PeerTimeout = 3 * time.Second
	}
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = 3
	}
	if cfg.SuccessThreshold <= 0 {
		cfg.SuccessThreshold = 2
	}
	if cfg.OpenTimeout <= 0 {
		cfg.OpenTimeout = 30 * time.Second
	}
	if cfg.HalfOpenMaxProbes <= 0 {
		cfg.HalfOpenMaxProbes = 1
	}
	return cfg
}

// Enabled reports whether federation is active with at least the subsystem
// turned on. A nil Federation reports false.
func (f *Federation) Enabled() bool {
	return f != nil && f.cfg.Enabled
}

// servingEnabled reports whether this instance should answer sibling requests.
func (f *Federation) servingEnabled() bool {
	return f.Enabled() && f.cfg.Serve && f.cfg.AuthToken != ""
}

// PeerCount returns the number of configured (non-self) peers.
func (f *Federation) PeerCount() int {
	if f == nil {
		return 0
	}
	return len(f.peers)
}

// selectCandidates returns up to MaxPeerFanout peers currently eligible for a
// read-through attempt, cheaply pre-filtered by the circuit breaker. The
// authoritative (side-effecting) admission happens per-attempt via breaker.allow.
func (f *Federation) selectCandidates() []*peerState {
	out := make([]*peerState, 0, f.cfg.MaxPeerFanout)
	for _, p := range f.peers {
		if len(out) >= f.cfg.MaxPeerFanout {
			break
		}
		if p.breaker.peek() {
			out = append(out, p)
		}
	}
	return out
}

// PeerStatus is a point-in-time view of a federation peer for metrics and the
// admin API.
type PeerStatus struct {
	Name         string  `json:"name"`
	URL          string  `json:"url"`
	State        string  `json:"state"`
	TotalSuccess int64   `json:"totalSuccess"`
	TotalFailure int64   `json:"totalFailure"`
	LatencySum   float64 `json:"latencySum"`
	LatencyCount int64   `json:"latencyCount"`
	LastError    string  `json:"lastError,omitempty"`
}

// AvgLatencySeconds reports the mean peer round-trip latency, or 0 when no
// samples have been recorded.
func (s PeerStatus) AvgLatencySeconds() float64 {
	if s.LatencyCount == 0 {
		return 0
	}
	return s.LatencySum / float64(s.LatencyCount)
}

// PeerStatuses returns a stable, sorted snapshot of every peer's circuit state
// and cumulative counters. It performs no I/O.
func (f *Federation) PeerStatuses() []PeerStatus {
	if f == nil {
		return nil
	}
	out := make([]PeerStatus, 0, len(f.peers))
	for _, p := range f.peers {
		st, succ, fail, lcount, lsum, lerr := p.breaker.snapshot()
		out = append(out, PeerStatus{
			Name:         p.peer.Name,
			URL:          p.peer.URL,
			State:        st,
			TotalSuccess: succ,
			TotalFailure: fail,
			LatencySum:   lsum,
			LatencyCount: lcount,
			LastError:    lerr,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Metrics returns the subsystem's shared counter set (never nil).
func (f *Federation) Metrics() *Metrics {
	if f == nil {
		return nil
	}
	return f.metrics
}
