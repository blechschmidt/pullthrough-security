package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/prewarm"
	"github.com/blechschmidt/pullthrough-security/internal/provgraph"
	"github.com/blechschmidt/pullthrough-security/internal/proxy"
)

// buildPrewarm constructs the predictive cache pre-warming subsystem (Task 134)
// from configuration. It returns (nil, nil) when disabled. The returned service
// has no fetcher yet (the fetcher owns the gateway, which is built later); the
// caller wires the fetcher, the HA leader gate, and the kill-switch, then starts
// it. When transitive-dependency pre-warming is requested it is backed by the
// provenance/dependency graph (provgraph); when that is disabled the transitive
// strategy is inert and only patch/minor-release forecasting runs.
func buildPrewarm(cfg *config.Config, provGraph *provgraph.Service, logger *slog.Logger) (*prewarm.Service, error) {
	pc := cfg.Prewarm
	if !pc.Enabled {
		logger.Info("predictive cache pre-warming disabled (set prewarm.enabled to forecast and pre-fetch likely pulls during off-peak windows)")
		return nil, nil
	}

	var depSource prewarm.DepSource
	if pc.TransitiveDeps {
		if provGraph != nil {
			depSource = provgraphDepSource{g: provGraph}
		} else {
			logger.Warn("prewarm.transitiveDeps is set but the provenance graph (provgraph) is disabled; " +
				"transitive-dependency pre-warming will be inactive — enable provgraph or unset prewarm.transitiveDeps")
		}
	}

	// Apply the configuration-intent defaults for the predictor knobs that
	// prewarm.New leaves to the heuristic predictor's own (looser) fallbacks.
	minPulls := pc.MinPulls
	if minPulls == 0 {
		minPulls = 3
	}
	recency := pc.RecencyWindow
	if recency == 0 {
		recency = 7 * 24 * time.Hour
	}
	patchLookahead := pc.PatchLookahead
	if patchLookahead == 0 {
		patchLookahead = 2
	}

	svc, err := prewarm.New(prewarm.Config{
		Enabled:         true,
		Interval:        pc.Interval,
		OffPeakStart:    pc.OffPeakStart,
		OffPeakEnd:      pc.OffPeakEnd,
		OffPeakTimezone: pc.OffPeakTimezone,
		MaxConcurrency:  pc.MaxConcurrency,
		MaxPerCycle:     pc.MaxPerCycle,
		RatePerMinute:   pc.RatePerMinute,
		MinPulls:        minPulls,
		RecencyWindow:   recency,
		PatchLookahead:  patchLookahead,
		PredictMinor:    pc.PredictMinor,
		TransitiveDeps:  pc.TransitiveDeps,
		HistorySize:     pc.HistorySize,
		HistoryPath:     pc.HistoryPath,
	}, prewarm.Deps{
		DepSource: depSource,
		Logger:    logger,
	})
	if err != nil {
		return nil, fmt.Errorf("prewarm: %w", err)
	}

	logger.Info("predictive cache pre-warming enabled",
		"interval", pc.Interval, "transitiveDeps", pc.TransitiveDeps && depSource != nil,
		"predictMinor", pc.PredictMinor, "historyPath", pc.HistoryPath != "")
	return svc, nil
}

// prewarmPullObserver adapts the predictive pre-warming service to the gateway's
// proxy.PullObserver tap, translating the proxy's pull event into the prewarm
// package's own type so neither package depends on the other.
type prewarmPullObserver struct{ svc *prewarm.Service }

func (o prewarmPullObserver) ObservePull(ev proxy.PullEvent) {
	o.svc.Observe(prewarm.PullEvent{
		Backend:   ev.Backend,
		Ecosystem: ev.Ecosystem,
		Name:      ev.Name,
		Version:   ev.Version,
		Path:      ev.Path,
		Tenant:    ev.Tenant,
		CacheHit:  ev.CacheHit,
		Size:      ev.Size,
		At:        ev.At,
	})
}

// newPrewarmPullObserver returns the gateway tap for svc, or nil when pre-warming
// is disabled (so the gateway collects no pull telemetry).
func newPrewarmPullObserver(svc *prewarm.Service) proxy.PullObserver {
	if svc == nil {
		return nil
	}
	return prewarmPullObserver{svc: svc}
}

// provgraphDepSource resolves a coordinate's direct dependencies from the
// provenance/dependency graph (Task 33) for transitive-dependency pre-warming.
type provgraphDepSource struct{ g *provgraph.Service }

func (d provgraphDepSource) Dependencies(_ context.Context, c prewarm.Coordinate) []prewarm.Coordinate {
	if d.g == nil {
		return nil
	}
	res, err := d.g.ForwardDependencies(c.Ecosystem, c.Name, c.Version)
	if err != nil {
		return nil
	}
	out := make([]prewarm.Coordinate, 0, len(res.Dependents))
	for _, dep := range res.Dependents {
		if dep.Name == "" {
			continue
		}
		out = append(out, prewarm.Coordinate{
			Ecosystem: dep.Ecosystem,
			Name:      dep.Name,
			Version:   dep.Version,
		})
	}
	return out
}

// gatewayPrewarmFetcher fetches and admission-gates a predicted target by driving
// a synthetic request through the gateway's pre-warm handler — the full gated
// pull pipeline minus client access-control and rate limiting. It reuses the
// exact cache-fill path a client pull takes, so the warmed artifact lands under
// the key a later client read will hit, and every admission gate (including the
// SSRF egress allowlist and the freeze lockdown) runs unchanged.
type gatewayPrewarmFetcher struct {
	handler http.Handler
	logger  *slog.Logger
}

// newGatewayPrewarmFetcher builds the fetcher over an already-constructed gateway.
func newGatewayPrewarmFetcher(gw *proxy.Gateway, logger *slog.Logger) *gatewayPrewarmFetcher {
	return &gatewayPrewarmFetcher{handler: gw.PrewarmHandler(), logger: logger}
}

// Fetch implements prewarm.Fetcher.
func (f *gatewayPrewarmFetcher) Fetch(ctx context.Context, t prewarm.Target) (prewarm.FetchResult, error) {
	if strings.TrimSpace(t.Path) == "" {
		return prewarm.FetchResult{Outcome: prewarm.OutcomeError}, fmt.Errorf("prewarm: empty target path")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.Path, nil)
	if err != nil {
		return prewarm.FetchResult{Outcome: prewarm.OutcomeError}, fmt.Errorf("prewarm: building request for %s: %w", t.Path, err)
	}
	// Pin the target tenant so that, under per-tenant cache namespacing, the warmed
	// cache key matches the one the originating tenant's later read will hit.
	if t.Tenant != "" {
		req = req.WithContext(auth.WithPrincipal(req.Context(),
			&auth.Principal{Subject: "prewarm", Team: t.Tenant, Method: "internal"}))
	}

	rec := &prewarmRecorder{}
	f.handler.ServeHTTP(rec, req)

	res := prewarm.FetchResult{Status: rec.statusOrOK(), Bytes: rec.bytes}
	switch rec.statusOrOK() {
	case http.StatusOK:
		// MISS means this request ran the upstream fetch (cache now warm); a HIT /
		// COALESCED-HIT means it was already present.
		if strings.EqualFold(rec.Header().Get("X-Cache"), "MISS") {
			res.Outcome = prewarm.OutcomeAdmitted
		} else {
			res.Outcome = prewarm.OutcomeAlreadyCached
		}
	case http.StatusNotModified:
		res.Outcome = prewarm.OutcomeAlreadyCached
	case http.StatusForbidden:
		// Every hard admission-gate block/quarantine writes 403; the artifact was
		// refused (and, when quarantined, evicted) and is never served.
		res.Outcome = prewarm.OutcomeGateBlocked
	default:
		// Upstream 404/410 for a predicted-but-nonexistent version, 5xx, etc.
		res.Outcome = prewarm.OutcomeError
	}
	return res, nil
}

// prewarmRecorder is a minimal http.ResponseWriter that captures the status and
// response headers of a synthetic pre-warm request while discarding the body —
// the artifact bytes have already been persisted into the cache by the pull
// pipeline, so the pre-warmer has no use for them.
type prewarmRecorder struct {
	header http.Header
	status int
	wrote  bool
	bytes  int64
}

func (r *prewarmRecorder) Header() http.Header {
	if r.header == nil {
		r.header = make(http.Header)
	}
	return r.header
}

func (r *prewarmRecorder) WriteHeader(code int) {
	if !r.wrote {
		r.status = code
		r.wrote = true
	}
}

func (r *prewarmRecorder) Write(b []byte) (int, error) {
	if !r.wrote {
		r.WriteHeader(http.StatusOK)
	}
	r.bytes += int64(len(b))
	return len(b), nil
}

// statusOrOK returns the recorded status, defaulting to 200 when the handler
// wrote a body without an explicit header (net/http semantics).
func (r *prewarmRecorder) statusOrOK() int {
	if r.status == 0 {
		return http.StatusOK
	}
	return r.status
}
