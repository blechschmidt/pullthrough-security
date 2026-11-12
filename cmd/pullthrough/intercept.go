package main

import (
	"fmt"
	"log/slog"
	"sort"

	"github.com/blechschmidt/pullthrough-security/internal/admin"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/intercept"
	"github.com/blechschmidt/pullthrough-security/internal/metrics"
	"github.com/blechschmidt/pullthrough-security/internal/proxy"
)

// buildInterceptor constructs the TLS-interception listeners (Tasks 100 and
// 172) — the forward proxy and the NAT listeners — from config, or returns nil
// when interception is disabled. It loads or generates the signing CA and
// builds the routing table (interceptRules).
//
// The caller hands the result to the gateway and the admin API as interfaces;
// interceptorDeps does so without turning a nil *intercept.Proxy into a non-nil
// interface value.
func buildInterceptor(cfg *config.Config, logger *slog.Logger, m *intercept.Metrics) (*intercept.Proxy, error) {
	ic := cfg.Server.Intercept
	if !ic.Enabled {
		return nil, nil
	}

	ca, err := intercept.LoadOrGenerateCA(intercept.CAOptions{
		CertFile:     ic.CACertFile,
		KeyFile:      ic.CAKeyFile,
		Generate:     ic.GenerateCA,
		Organization: ic.CAOrganization,
		CommonName:   ic.CACommonName,
		LeafTTL:      ic.LeafTTL,
		CacheSize:    ic.CertCacheSize,
	})
	if err != nil {
		return nil, fmt.Errorf("building intercept CA: %w", err)
	}

	router := intercept.NewRouter(interceptRules(cfg))
	if router.Len() == 0 {
		logger.Warn("tls-interception enabled but no upstream hosts to route; configure upstreams or server.intercept.hosts")
	}

	p, err := intercept.New(intercept.Options{
		ListenAddr:           ic.ListenAddr,
		NATListenAddr:        ic.NAT.HTTPSAddr,
		NATHTTPListenAddr:    ic.NAT.HTTPAddr,
		Router:               router,
		CA:                   ca,
		Logger:               logger,
		PassthroughUnmatched: ic.PassthroughUnmatched,
		AllowPlainHTTP:       ic.AllowPlainHTTP,
		ReadTimeout:          cfg.Server.ReadTimeout,
		WriteTimeout:         cfg.Server.WriteTimeout,
		Metrics:              m,
		FIPS:                 cfg.FIPS.Enabled,
	})
	if err != nil {
		return nil, fmt.Errorf("building intercept proxy: %w", err)
	}
	logger.Info("tls-interception configured",
		"forwardProxy", ic.ListenAddr,
		"natHttps", ic.NAT.HTTPSAddr,
		"natHttp", ic.NAT.HTTPAddr,
		"routes", router.Hosts(),
		"passthroughUnmatched", ic.PassthroughUnmatched,
		"caSubject", ca.Subject())
	return p, nil
}

// interceptRules builds the interception routing table: rule ("host" or
// "host/path") -> upstream name.
//
//   - Every enabled upstream's URL: its host and, when the URL has one, its
//     path — a client of an upstream configured as
//     https://repo1.maven.org/maven2 asks for /maven2/org/…, and the backend
//     expects /org/…;
//   - the hosts a stock client of the ecosystem uses for the same public
//     registry (intercept.ClientHosts);
//   - then the explicit server.intercept.hosts entries, which override.
//
// Upstreams are visited in name order, and the first to claim a rule keeps it,
// so the table is the same on every start.
func interceptRules(cfg *config.Config) map[string]string {
	names := make([]string, 0, len(cfg.Upstreams))
	for name := range cfg.Upstreams {
		names = append(names, name)
	}
	sort.Strings(names)

	rules := make(map[string]string)
	claim := func(rule, name string) {
		host, prefix, ok := intercept.ParseRule(rule)
		if !ok {
			return
		}
		key := host + prefix
		if _, taken := rules[key]; !taken {
			rules[key] = name
		}
	}
	for _, name := range names {
		up := cfg.Upstreams[name]
		if !up.IsEnabled() {
			continue
		}
		claim(intercept.RuleOf(up.URL), name)
	}
	// The client hosts come second: an upstream configured for one of them
	// explicitly keeps it.
	for _, name := range names {
		up := cfg.Upstreams[name]
		if !up.IsEnabled() {
			continue
		}
		for _, rule := range intercept.ClientHosts(up.Type, up.URL) {
			claim(rule, name)
		}
	}
	for rule, name := range cfg.Server.Intercept.Hosts {
		host, prefix, ok := intercept.ParseRule(rule)
		if !ok {
			continue
		}
		rules[host+prefix] = name
	}
	return rules
}

// interceptorDeps returns the interceptor as the gateway's and the admin API's
// dependency: true nils when interception is disabled, so their nil checks see
// the absent dependency.
func interceptorDeps(p *intercept.Proxy) (proxy.Interceptor, admin.InterceptInspector) {
	if p == nil {
		return nil, nil
	}
	return p, p
}

// bindInterceptMetrics surfaces what the interception listeners and the
// gateway's interception edge do (Task 172). It is a no-op when interception is
// disabled.
func bindInterceptMetrics(c *metrics.Collector, gw *proxy.Gateway, interceptor *intercept.Proxy, m *intercept.Metrics) {
	if c == nil || gw == nil || interceptor == nil || m == nil {
		return
	}
	perMode := func(pick func(intercept.MetricsSnapshot) map[intercept.Mode]uint64) func() []metrics.LabeledValue {
		return func() []metrics.LabeledValue {
			table := pick(m.Snapshot())
			out := make([]metrics.LabeledValue, 0, 2)
			for _, mode := range []intercept.Mode{intercept.ModeForward, intercept.ModeNAT} {
				out = append(out, metrics.LabeledValue{Labels: []string{string(mode)}, Value: float64(table[mode])})
			}
			return out
		}
	}
	c.BindCounterVec("pullthrough_intercept_connections_total",
		"Total client connections (and absolute-form requests) accepted by the interception listeners, by mode (intercept = forward proxy, nat).",
		[]string{"mode"}, perMode(func(s intercept.MetricsSnapshot) map[intercept.Mode]uint64 { return s.Connections }))
	c.BindCounterVec("pullthrough_intercept_tls_intercepted_total",
		"Total client TLS connections the proxy terminated with a minted certificate, by mode.",
		[]string{"mode"}, perMode(func(s intercept.MetricsSnapshot) map[intercept.Mode]uint64 { return s.Intercepted }))
	c.BindCounterVec("pullthrough_intercept_requests_total",
		"Total intercepted requests dispatched into the pipeline, by mode.",
		[]string{"mode"}, perMode(func(s intercept.MetricsSnapshot) map[intercept.Mode]uint64 { return s.Requests }))
	c.BindCounterVec("pullthrough_intercept_passthrough_total",
		"Total connections to unconfigured hosts passed on undecrypted (passthroughUnmatched), by mode.",
		[]string{"mode"}, perMode(func(s intercept.MetricsSnapshot) map[intercept.Mode]uint64 { return s.Passthrough }))
	c.BindCounterVec("pullthrough_intercept_unrouted_total",
		"Total requests to an intercepted host for a path no configured upstream serves (answered 404), by mode.",
		[]string{"mode"}, perMode(func(s intercept.MetricsSnapshot) map[intercept.Mode]uint64 { return s.Unrouted }))
	c.BindCounterVec("pullthrough_intercept_refused_total",
		"Total connections the interception listeners refused, by mode and reason (unmatched_host, no_server_name, not_tls, handshake, plain_http).",
		[]string{"mode", "reason"},
		func() []metrics.LabeledValue {
			var out []metrics.LabeledValue
			for _, r := range m.Snapshot().Refused {
				out = append(out, metrics.LabeledValue{Labels: []string{string(r.Mode), r.Reason}, Value: float64(r.Count)})
			}
			return out
		})
	c.BindCounter("pullthrough_intercept_rewritten_responses_total",
		"Total intercepted index documents whose links to a mount were moved onto the intercepted host.",
		func() float64 { return float64(gw.InterceptLinkMetrics().Rewritten) })
	c.BindCounter("pullthrough_intercept_rewritten_links_total",
		"Total links to a mount in intercepted responses that were moved onto the intercepted host.",
		func() float64 { return float64(gw.InterceptLinkMetrics().Links) })
}
