package upstreampool

import (
	"context"
	"net/http"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

const (
	defaultProbeInterval = 15 * time.Second
	defaultProbeTimeout  = 5 * time.Second
	defaultProbePath     = "/"
)

// StartProbing launches the optional active health prober if it is enabled in
// the pool's config. It is idempotent (only the first call starts the loop) and
// returns immediately; the loop runs until ctx is cancelled. Active probing
// complements passive health tracking: it drives an open endpoint's recovery
// (and detects a closed endpoint's failure) without waiting for live traffic.
func (p *Pool) StartProbing(ctx context.Context) {
	if !p.probe.Enabled {
		return
	}
	p.proberOnce.Do(func() {
		go p.probeLoop(ctx)
	})
}

func (p *Pool) probeLoop(ctx context.Context) {
	interval := orDuration(p.probe.Interval, defaultProbeInterval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.probeOnce(ctx)
		}
	}
}

// probeOnce issues one health probe to every endpoint that the breaker will
// currently admit. It reuses the same acquire/release machinery as live traffic
// so a probe success can recover a half-open breaker and a probe failure can
// trip a closed one — making the active probe a true health signal rather than a
// side channel.
func (p *Pool) probeOnce(ctx context.Context) {
	path := p.probe.Path
	if path == "" {
		path = defaultProbePath
	}
	timeout := orDuration(p.probe.Timeout, defaultProbeTimeout)

	for _, ep := range p.endpoints {
		allowed, isProbe := ep.acquire(p.now())
		if !allowed {
			continue
		}
		p.runProbe(ctx, ep, path, timeout, isProbe)
	}
}

func (p *Pool) runProbe(ctx context.Context, ep *endpoint, path string, timeout time.Duration, isProbe bool) {
	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req := upstream.Request{
		URL:    ep.base.String() + normalizeProbePath(path),
		Method: http.MethodGet,
	}
	if ep.hasCreds {
		req.Creds = ep.creds
	}

	start := p.now()
	resp, err := ep.executor(p.client).Do(pctx, req)
	latency := p.now().Sub(start).Seconds()

	success := classify(resp, err, p.retryable)
	if resp != nil {
		drainClose(resp.Body)
	}
	opened := ep.release(p.now(), isProbe, success, latency, errString(err, resp))
	if opened {
		p.onCircuitOpen(ctx, ep)
	}
}

func normalizeProbePath(path string) string {
	if path == "" {
		return "/"
	}
	if path[0] != '/' {
		return "/" + path
	}
	return path
}
