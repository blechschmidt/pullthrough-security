package main

import (
	"crypto"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/rekor"
	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
)

// rekorDeps bundles the transparency-log (Sigstore Rekor) wiring shared by the
// outbound attestation engine (submit path) and the inbound signature gate
// (inclusion-proof verify path): a single Metrics instance so pullthrough_rekor_*
// counts both, the trusted log verifier, and — when submission is enabled — the
// HTTP client. A nil/zero rekorDeps (transparency disabled) is harmless: submit
// is never wired and the gate performs no inclusion-proof check. (Task 142)
type rekorDeps struct {
	client                rekor.Client
	verifier              *rekor.Verifier
	metrics               *rekor.Metrics
	baseURL               string
	submit                bool
	requireInclusionProof bool
	logKeys               []crypto.PublicKey
}

// buildRekor assembles the transparency-log dependencies from configuration. It
// always returns a usable (non-nil) *rekorDeps carrying a fresh Metrics so the
// metrics layer can bind unconditionally; the submission client and verifier are
// populated only when transparency.rekor is enabled.
func buildRekor(cfg *config.Config, logger *slog.Logger) (*rekorDeps, error) {
	rc := cfg.Transparency.Rekor
	deps := &rekorDeps{metrics: rekor.NewMetrics()}
	if !rc.Enabled {
		return deps, nil
	}

	deps.submit = rc.Submit
	deps.requireInclusionProof = rc.RequireInclusionProof
	deps.baseURL = strings.TrimSpace(rc.URL)
	if deps.baseURL == "" {
		deps.baseURL = rekor.DefaultPublicURL
	}

	// Load the trusted Rekor log public keys: the dedicated transparency keys when
	// configured, otherwise the inbound sigverify gate's rekorKeyFiles so a single
	// set of log keys serves both paths.
	keyFiles := rc.PublicKeyFiles
	if len(keyFiles) == 0 {
		keyFiles = cfg.Sigverify.RekorKeyFiles
	}
	for _, f := range keyFiles {
		pemBytes, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("transparency.rekor: reading public key %q: %w", f, err)
		}
		pub, err := sigverify.ParsePublicKeyPEM(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("transparency.rekor: parsing public key %q: %w", f, err)
		}
		deps.logKeys = append(deps.logKeys, pub)
	}
	deps.verifier = rekor.NewVerifier(deps.logKeys)

	if rc.Submit {
		deps.client = rekor.NewHTTPClient(rekor.HTTPConfig{URL: deps.baseURL, Timeout: rc.Timeout})
	}

	logger.Info("transparency log (Sigstore Rekor) enabled",
		"url", deps.baseURL, "submit", deps.submit,
		"requireInclusionProof", deps.requireInclusionProof, "logKeys", len(deps.logKeys))
	return deps, nil
}
