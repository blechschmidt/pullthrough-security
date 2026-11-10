// Package upstreampool provides health-aware, multi-mirror upstream routing for
// the proxy's HTTP-based backends (npm, pip, cargo, Go modules, NuGet,
// Docker/OCI). A Pool fronts an ordered list of equivalent mirror endpoints for
// one backend and transparently fails over from a flaky or unreachable mirror to
// the next healthy one, so a single bad upstream does not break pulls.
//
// Health is tracked two ways: passively, from the outcome of real proxied
// requests, and (optionally) actively, via a lightweight background probe. Each
// endpoint carries an independent circuit breaker (closed → open → half-open)
// that removes a failing mirror from rotation and automatically re-admits it
// once it recovers.
//
// A Pool is an upstream.Doer, so it drops in wherever a backend previously held
// a bare *upstream.Client (see internal/upstream). Backends remain oblivious to
// mirroring: they still resolve a single canonical UpstreamURL and the pool
// rewrites it onto whichever mirror serves the bytes. Because the proxy's
// content-addressable verification (digest checking in the cache and the Docker
// backend) runs on the bytes regardless of their origin, cache integrity holds
// identically across mirrors — a mirror serving different bytes for the same
// digest fails verification exactly as the primary would.
package upstreampool

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// Default circuit-breaker tunables, applied when a Config leaves them zero.
const (
	defaultFailureThreshold  = 5
	defaultSuccessThreshold  = 2
	defaultOpenTimeout       = 30 * time.Second
	defaultHalfOpenMaxProbes = 1
)

// EndpointConfig describes one mirror endpoint within a pool. The first endpoint
// in a Config is the primary (highest priority); the rest are mirrors consulted
// in order on failover.
type EndpointConfig struct {
	// ID is a stable identifier used in metrics labels and the admin API. When
	// empty it defaults to the endpoint's host.
	ID string
	// URL is the mirror's base URL (e.g. "https://registry.npmjs.org"). Required.
	URL string
	// Credentials, when non-zero, authenticate to this mirror specifically,
	// overriding the request's inherited credentials. Leave zero to use the
	// backend's configured upstream credentials (the common case where mirrors
	// share an account or are public).
	Credentials upstream.Credentials
	// Client, when non-nil, is a dedicated request executor for this endpoint
	// (e.g. a mirror behind a private CA with its own TLS policy). When nil the
	// pool's shared Client is used.
	Client upstream.Doer
}

// ProbeConfig configures optional active health probing. When enabled the pool
// periodically issues a lightweight request to each endpoint's Path so an
// endpoint's recovery (or failure) is detected without waiting for live traffic.
type ProbeConfig struct {
	Enabled  bool
	Interval time.Duration // between probe sweeps; default 15s
	Timeout  time.Duration // per-probe timeout; default 5s
	Path     string        // path appended to each endpoint base; default "/"
}

// Config configures a Pool.
type Config struct {
	// Backend is the backend/upstream name this pool serves (used as a metric
	// label and the notify event's Backend field). Required.
	Backend string
	// Ecosystem is the package ecosystem (npm, pip, docker, ...) for notify
	// events. Optional.
	Ecosystem string
	// Endpoints is the ordered mirror list; [0] is the primary. At least one is
	// required.
	Endpoints []EndpointConfig
	// Client is the shared request executor used for endpoints without their own
	// Client. Required.
	Client upstream.Doer

	// Circuit-breaker tunables (zero values fall back to the package defaults).
	FailureThreshold  int
	SuccessThreshold  int
	OpenTimeout       time.Duration
	HalfOpenMaxProbes int

	// Probe configures optional active health checking.
	Probe ProbeConfig

	// Retryable classifies an upstream HTTP status as a failover-worthy failure.
	// When nil, DefaultRetryable is used (5xx and 429). A status that is not
	// retryable (including 2xx/3xx and 4xx such as 404/401) counts as a healthy
	// response from the endpoint: the mirror answered, so the breaker does not
	// trip and the answer is returned to the caller.
	Retryable func(status int) bool

	// Notifier receives a circuit-open event each time an endpoint trips.
	// Optional.
	Notifier notify.Emitter
	// Logger is used for failover/trip logging. Optional.
	Logger *slog.Logger
	// Now overrides the clock, for tests. Optional.
	Now func() time.Time
}

// DefaultRetryable reports whether an upstream HTTP status should trigger
// failover to the next mirror: server errors (5xx) and rate-limiting (429).
func DefaultRetryable(status int) bool {
	return status >= 500 || status == 429
}

// Pool is a health-aware, ordered set of mirror endpoints for one backend. It
// implements upstream.Doer.
type Pool struct {
	backend   string
	ecosystem string
	endpoints []*endpoint
	client    upstream.Doer
	retryable func(int) bool
	notifier  notify.Emitter
	logger    *slog.Logger
	now       func() time.Time
	probe     ProbeConfig

	// aggregate, pool-level counters for metrics.
	mu            sync.Mutex
	failoverTotal int64

	proberOnce sync.Once
}

var _ upstream.Doer = (*Pool)(nil)

// New validates cfg and constructs a Pool.
func New(cfg Config) (*Pool, error) {
	if strings.TrimSpace(cfg.Backend) == "" {
		return nil, errors.New("upstreampool: backend name is required")
	}
	if cfg.Client == nil {
		return nil, fmt.Errorf("upstreampool %q: a shared client is required", cfg.Backend)
	}
	if len(cfg.Endpoints) == 0 {
		return nil, fmt.Errorf("upstreampool %q: at least one endpoint is required", cfg.Backend)
	}

	params := breakerParams{
		failureThreshold:  orInt(cfg.FailureThreshold, defaultFailureThreshold),
		successThreshold:  orInt(cfg.SuccessThreshold, defaultSuccessThreshold),
		openTimeout:       orDuration(cfg.OpenTimeout, defaultOpenTimeout),
		halfOpenMaxProbes: orInt(cfg.HalfOpenMaxProbes, defaultHalfOpenMaxProbes),
	}

	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	eps := make([]*endpoint, 0, len(cfg.Endpoints))
	seen := make(map[string]bool, len(cfg.Endpoints))
	for i, ec := range cfg.Endpoints {
		raw := strings.TrimSpace(ec.URL)
		if raw == "" {
			return nil, fmt.Errorf("upstreampool %q: endpoint %d has an empty URL", cfg.Backend, i)
		}
		u, err := url.Parse(strings.TrimRight(raw, "/"))
		if err != nil {
			return nil, fmt.Errorf("upstreampool %q: endpoint %q: invalid URL: %w", cfg.Backend, raw, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return nil, fmt.Errorf("upstreampool %q: endpoint %q: URL must be http(s), got %q", cfg.Backend, raw, u.Scheme)
		}
		id := strings.TrimSpace(ec.ID)
		if id == "" {
			id = u.Host
		}
		if seen[id] {
			return nil, fmt.Errorf("upstreampool %q: duplicate endpoint id %q", cfg.Backend, id)
		}
		seen[id] = true
		eps = append(eps, &endpoint{
			id:         id,
			base:       u,
			primary:    i == 0,
			creds:      ec.Credentials,
			hasCreds:   !ec.Credentials.IsZero(),
			client:     ec.Client,
			params:     params,
			state:      StateClosed,
			lastChange: now(),
		})
	}

	retryable := cfg.Retryable
	if retryable == nil {
		retryable = DefaultRetryable
	}

	return &Pool{
		backend:   cfg.Backend,
		ecosystem: cfg.Ecosystem,
		endpoints: eps,
		client:    cfg.Client,
		retryable: retryable,
		notifier:  cfg.Notifier,
		logger:    cfg.Logger,
		now:       now,
		probe:     cfg.Probe,
	}, nil
}

// Backend returns the pool's backend name.
func (p *Pool) Backend() string { return p.backend }

// Do implements upstream.Doer. It rewrites the request URL onto each healthy
// mirror in priority order, returning the first non-failover response (a 2xx, a
// 304, or any non-retryable status such as 404/401) and failing over past
// endpoints whose circuit is open or that return a retryable failure.
//
// Requests whose URL does not map onto any configured endpoint base (e.g. an
// ecosystem's separate artifact CDN reached via an absolute router, or a Docker
// token endpoint) are passed straight through to the shared client unchanged:
// they address a distinct host the pool has no mirror set for, and their bytes
// are digest-verified downstream regardless.
func (p *Pool) Do(ctx context.Context, r upstream.Request) (*upstream.Response, error) {
	rel, ok := p.relativize(r.URL)
	if !ok {
		return p.client.Do(ctx, r)
	}

	var (
		lastResp *upstream.Response
		lastErr  error
		attempts int
		skipped  int
	)
	for _, ep := range p.endpoints {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		allowed, isProbe := ep.acquire(p.now())
		if !allowed {
			skipped++
			continue
		}
		attempts++

		attempt := r
		attempt.URL = ep.urlFor(rel)
		if ep.hasCreds {
			attempt.Creds = ep.creds
		}

		start := p.now()
		resp, err := ep.executor(p.client).Do(ctx, attempt)
		latency := p.now().Sub(start).Seconds()

		success := classify(resp, err, p.retryable)
		opened := ep.release(p.now(), isProbe, success, latency, errString(err, resp))
		if opened {
			p.onCircuitOpen(ctx, ep)
		}

		if success {
			if !ep.primary {
				p.recordFailover()
				if p.logger != nil {
					p.logger.Warn("upstream failover served by mirror",
						"backend", p.backend, "mirror", ep.id, "url", ep.base.String())
				}
			}
			return resp, nil
		}

		// Retryable failure: discard this response and try the next mirror.
		if lastResp != nil {
			drainClose(lastResp.Body)
		}
		lastResp = resp
		lastErr = err
	}

	// Every eligible endpoint failed. Prefer returning the last HTTP response (a
	// 5xx) so the backend renders a faithful StatusError; otherwise the last
	// transport error; otherwise report that no endpoint was eligible.
	if lastResp != nil {
		return lastResp, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, &AllUnavailableError{Backend: p.backend, Endpoints: len(p.endpoints), Skipped: skipped}
}

// relativize strips the longest matching endpoint base prefix from an absolute
// request URL, returning the remainder (path + query, with a leading slash) that
// is recombined onto a chosen mirror. ok is false when the URL belongs to no
// configured endpoint, signalling a straight pass-through.
func (p *Pool) relativize(raw string) (rel string, ok bool) {
	best := -1
	bestLen := -1
	for i, ep := range p.endpoints {
		prefix := ep.base.String()
		if !strings.HasPrefix(raw, prefix) {
			continue
		}
		// Guard against a partial host match (e.g. base "https://a.com" matching
		// "https://a.com.evil/..."): the next char must be a path/query boundary.
		rest := raw[len(prefix):]
		if rest != "" && rest[0] != '/' && rest[0] != '?' {
			continue
		}
		if len(prefix) > bestLen {
			bestLen = len(prefix)
			best = i
		}
	}
	if best < 0 {
		return "", false
	}
	rest := raw[bestLen:]
	if rest == "" {
		rest = "/"
	}
	return rest, true
}

// onCircuitOpen logs the trip and emits a high-severity notification so an
// operator is alerted when a mirror is taken out of rotation.
func (p *Pool) onCircuitOpen(ctx context.Context, ep *endpoint) {
	if p.logger != nil {
		p.logger.Error("upstream circuit opened",
			"backend", p.backend, "mirror", ep.id, "url", ep.base.String())
	}
	if p.notifier == nil {
		return
	}
	snap := ep.snapshot()
	ev := notify.Event{
		Type:      notify.EventUpstreamCircuitOpen,
		Severity:  notify.SeverityHigh,
		Title:     fmt.Sprintf("Upstream mirror %q circuit opened", ep.id),
		Summary:   fmt.Sprintf("Mirror %s for backend %q failed health checks and was removed from rotation; traffic fails over to the remaining healthy mirrors.", ep.base.String(), p.backend),
		Ecosystem: p.ecosystem,
		Backend:   p.backend,
	}
	ev = ev.WithField("mirror", ep.id)
	ev = ev.WithField("url", ep.base.String())
	ev = ev.WithField("consecutive_failures", fmt.Sprintf("%d", snap.ConsecutiveFailures))
	if snap.LastError != "" {
		ev = ev.WithField("last_error", snap.LastError)
	}
	p.notifier.Emit(ctx, ev)
}

func (p *Pool) recordFailover() {
	p.mu.Lock()
	p.failoverTotal++
	p.mu.Unlock()
}

// classify decides whether an attempt counts as a healthy response (true) or a
// failover-worthy failure (false). Transport errors and retryable statuses are
// failures; everything else (including a normal 304 or 404) is a success.
func classify(resp *upstream.Response, err error, retryable func(int) bool) bool {
	if err != nil {
		return false
	}
	if resp == nil {
		return false
	}
	if resp.NotModified {
		return true
	}
	return !retryable(resp.Status)
}

// errString renders a compact, log-safe reason for a failed attempt.
func errString(err error, resp *upstream.Response) string {
	if err != nil {
		return err.Error()
	}
	if resp != nil {
		return fmt.Sprintf("upstream status %d", resp.Status)
	}
	return ""
}

// urlFor recombines the relative remainder onto this endpoint's base URL.
func (e *endpoint) urlFor(rel string) string {
	return e.base.String() + rel
}

// executor returns the endpoint's dedicated client, or the pool's shared one.
func (e *endpoint) executor(shared upstream.Doer) upstream.Doer {
	if e.client != nil {
		return e.client
	}
	return shared
}

func drainClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 4096))
	_ = body.Close()
}

func orInt(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func orDuration(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}

// AllUnavailableError reports that every endpoint in a pool was ineligible
// (circuit open or drained) so no request was attempted.
type AllUnavailableError struct {
	Backend   string
	Endpoints int
	Skipped   int
}

func (e *AllUnavailableError) Error() string {
	return fmt.Sprintf("upstreampool %q: all %d mirror endpoint(s) unavailable (circuit open or drained)", e.Backend, e.Endpoints)
}
