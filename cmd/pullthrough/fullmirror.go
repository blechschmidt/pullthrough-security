package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/coord"
	"github.com/blechschmidt/pullthrough-security/internal/egress"
	"github.com/blechschmidt/pullthrough-security/internal/fullmirror"
	"github.com/blechschmidt/pullthrough-security/internal/lockdown"
	"github.com/blechschmidt/pullthrough-security/internal/proxy"
	"github.com/blechschmidt/pullthrough-security/internal/ratelimit"
	"github.com/blechschmidt/pullthrough-security/internal/tlspin"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// fullMirrorUserAgent is the User-Agent of the full mirror's fetches through
// the gateway, as the download log shows them.
const fullMirrorUserAgent = "pullthrough-full-mirror"

// buildFullMirror builds the full-mirror engine (Task 189) for the upstreams
// that enable upstreams.<name>.fullMirror, or returns nil when none does. It
// reads no state and fetches nothing: wireFullMirror attaches it to the
// gateway and starts it.
func buildFullMirror(cfg *config.Config, egressGuard *egress.Guard, pinGuard *tlspin.Guard, connMetrics *upstream.ConnMetrics, auditLog *audit.Logger, logger *slog.Logger) (*fullmirror.Engine, error) {
	names := cfg.FullMirrorUpstreams()
	if len(names) == 0 {
		return nil, nil
	}
	// The adapters' own requests to the registries (feeds, version lists)
	// go out like the backends' do: through the egress guard, with each
	// upstream's TLS policy and pins.
	pool := newClientPool(cfg.Outbound, egressGuard, pinGuard, connMetrics)
	ua := cfg.Outbound.UserAgent
	if ua == "" {
		ua = upstream.DefaultUserAgent
	}
	var ups []fullmirror.Upstream
	for _, name := range names {
		up := cfg.Upstreams[name]
		fm := up.FullMirror
		include, err := fullmirror.CompilePatterns(fm.Include)
		if err != nil {
			return nil, fmt.Errorf("upstream %q: fullMirror.include: %w", name, err)
		}
		exclude, err := fullmirror.CompilePatterns(fm.Exclude)
		if err != nil {
			return nil, fmt.Errorf("upstream %q: fullMirror.exclude: %w", name, err)
		}
		latest, err := fullmirror.ParseVersionPolicy(fm.Versions, fm.Latest)
		if err != nil {
			return nil, fmt.Errorf("upstream %q: fullMirror.versions: %w", name, err)
		}
		window, err := fullmirror.ParseWindow(fm.OffPeak.Start, fm.OffPeak.End, fm.OffPeak.Timezone)
		if err != nil {
			return nil, fmt.Errorf("upstream %q: fullMirror.offPeak: %w", name, err)
		}
		client, err := pool.clientFor(up.TLS)
		if err != nil {
			return nil, fmt.Errorf("upstream %q: %w", name, err)
		}
		ups = append(ups, fullmirror.Upstream{
			Settings: fullmirror.Settings{
				Upstream: name, Type: up.Type, Include: include, Exclude: exclude, Latest: latest,
				MaxArtifactBytes: fm.MaxArtifactBytes, ByteBudget: fm.ByteBudget, Concurrency: fm.Concurrency,
				RequestsPerSecond: fm.RequestsPerSecond, PollInterval: fm.PollInterval, Window: window, DryRun: fm.DryRun,
			},
			URL: up.URL, Config: up.Settings, Options: fm.Feed, HTTP: client.HTTPClient(), UserAgent: ua,
			Authorize: upstreamAuthorizer(up.Credentials),
		})
	}
	opts := fullmirror.Options{
		Dir:       cfg.FullMirrorStateDir(),
		Upstreams: ups,
		Tenant:    cfg.FullMirror.Tenant,
		Logger:    logger.With("component", "fullmirror"),
	}
	if auditLog != nil {
		opts.Audit = auditLog
	}
	e, err := fullmirror.New(opts)
	if err != nil {
		return nil, err
	}
	logger.Info("full mirroring configured", "upstreams", names, "stateDir", opts.Dir, "tenant", opts.Tenant)
	return e, nil
}

// upstreamAuthorizer returns what adds an upstream's credentials to a feed
// adapter's request, as the backends add them to theirs: a token as a bearer
// token, else a user name and password as basic authentication, never over an
// Authorization header already set. It is nil when the upstream has none. The
// adapters call it only for requests to the upstream's own origin.
func upstreamAuthorizer(c config.Credentials) func(*http.Request) {
	if c.Token == "" && c.Username == "" && c.Password == "" {
		return nil
	}
	return func(r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			return
		}
		if c.Token != "" {
			r.Header.Set("Authorization", "Bearer "+c.Token)
			return
		}
		r.SetBasicAuth(c.Username, c.Password)
	}
}

// wireFullMirror attaches the engine to the gateway's gated serve pipeline,
// gates it on HA leadership and the emergency lockdown, has the proxy's rate
// limiter admit its fetches, and starts it.
func wireFullMirror(ctx context.Context, e *fullmirror.Engine, cfg *config.Config, gw *proxy.Gateway, guard *coord.Guard, lock *lockdown.Service, limiter *ratelimit.Limiter) {
	if e == nil {
		return
	}
	e.Attach(gatewayMirrorFetcher{gw: gw, tenant: cfg.FullMirror.Tenant, roles: cfg.FullMirror.Roles})
	e.SetLeaderGate(guard.IsLeader, guard.FencingToken)
	if lock != nil {
		e.SetKillSwitch(func() (bool, string) {
			st := lock.Status()
			return st.Active, string(st.Mode)
		})
	}
	if limiter != nil {
		e.SetLimiter(limiter)
	}
	e.Start(ctx)
}

// gatewayMirrorFetcher drives the full mirror's requests through the gateway
// as the system principal system:full-mirror of the configured tenant, with
// the configured roles: the same resolution, admission gates, digest checks
// and cache fill as a client pull, in the download log with via=system.
type gatewayMirrorFetcher struct {
	gw     *proxy.Gateway
	tenant string
	roles  []string
}

func (f gatewayMirrorFetcher) request(req fullmirror.FetchRequest) proxy.SystemFetchRequest {
	// NoReview: nobody asked for what the mirror fetches, so a refusal opens
	// no break-glass review (an existing grant still applies).
	return proxy.SystemFetchRequest{
		Backend: req.Upstream, Path: req.Path, Accept: req.Accept, MaxBytes: req.MaxBytes,
		Tenant: f.tenant, Subject: fullmirror.Subject, Roles: f.roles, UserAgent: fullMirrorUserAgent,
		NoReview: true,
	}
}

func (f gatewayMirrorFetcher) Lookup(ctx context.Context, req fullmirror.FetchRequest) (fullmirror.LookupResult, error) {
	res, err := f.gw.SystemLookup(ctx, f.request(req))
	return fullmirror.LookupResult{Cacheable: res.Cacheable, Cached: res.Cached, Size: res.Size}, err
}

func (f gatewayMirrorFetcher) Fetch(ctx context.Context, req fullmirror.FetchRequest, body io.Writer) (fullmirror.FetchResult, error) {
	res, err := f.gw.SystemFetch(ctx, f.request(req), body)
	return fullmirror.FetchResult{
		Status: res.Status, Cache: res.Cache, Admitted: res.Admitted, Size: res.Size,
		Gate: res.Gate, Code: res.Code, Reason: res.Reason, Action: res.Action, RetryAfter: res.RetryAfter,
	}, err
}
