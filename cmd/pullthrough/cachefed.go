package main

import (
	"log/slog"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/cachefed"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/coord"
)

// buildCacheFed assembles the cross-proxy peer cache-federation layer (Task 143)
// from configuration. It always returns a usable (non-nil) *cachefed.Federation
// carrying a fresh Metrics so the metrics layer can bind unconditionally; the
// peer roster, auth, and read-through client are active only when
// cacheFed.enabled.
//
// The auth secret has already been resolved from its secretRef by
// config.ResolveRefs at startup, so cfg.CacheFed.Auth.SecretRef holds the
// cleartext shared token here. The coordination NodeID (Task 56) is used as this
// instance's identity so a peer entry pointing back at this node is self-excluded
// from the roster.
func buildCacheFed(cfg *config.Config, coordSvc *coord.Service, logger *slog.Logger) (*cachefed.Federation, error) {
	cf := cfg.CacheFed
	metrics := cachefed.NewMetrics()

	fedCfg := cachefed.Config{
		Enabled:           cf.Enabled,
		Serve:             cf.ServeOrDefault(),
		AuthToken:         strings.TrimSpace(cf.Auth.SecretRef),
		MaxPeerFanout:     cf.MaxPeerFanout,
		PeerTimeout:       cf.PeerTimeout,
		HedgeDelay:        cf.HedgeDelay,
		RequireDigest:     cf.RequireDigestOrDefault(),
		FailureThreshold:  cf.FailureThreshold,
		SuccessThreshold:  cf.SuccessThreshold,
		OpenTimeout:       cf.OpenTimeout,
		HalfOpenMaxProbes: cf.HalfOpenMaxProbes,
	}
	if coordSvc != nil {
		fedCfg.SelfName = coordSvc.NodeID()
	}
	for _, p := range cf.Peers {
		fedCfg.Peers = append(fedCfg.Peers, cachefed.Peer{Name: p.Name, URL: p.URL})
	}

	fed, err := cachefed.New(fedCfg, metrics, cachefed.WithLogger(logger))
	if err != nil {
		return nil, err
	}
	if cf.Enabled {
		logger.Info("cross-proxy cache federation enabled",
			"peers", fed.PeerCount(), "serve", fedCfg.Serve,
			"maxPeerFanout", fedCfg.MaxPeerFanout, "requireDigest", fedCfg.RequireDigest)
	}
	return fed, nil
}
