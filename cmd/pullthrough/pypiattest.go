package main

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/pypiattest"
	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
)

// buildPyPIAttest constructs the inbound PyPI PEP 740 digital-attestation
// verification gate (Task 146) from configuration. It returns (nil, nil) when
// disabled. It reuses the signature gate's trust-material model (Fulcio roots +
// allowed Trusted-Publisher identities + Rekor keys, loadable from a portable
// offline trust bundle) since both verify Sigstore material.
func buildPyPIAttest(cfg *config.Config, logger *slog.Logger) (*pypiattest.Service, error) {
	pc := cfg.PyPIAttest
	if !pc.Enabled {
		logger.Info("inbound PyPI attestation verification disabled (set pypiAttestation.enabled to verify PyPI PEP 740 digital attestations)")
		return nil, nil
	}

	action := pypiattest.ActionAnnotate
	if a, ok := pypiattest.ParseAction(pc.Action); ok {
		action = a
	}

	roots, rekorKeys, keys, identities, err := buildPyPIAttestTrust(pc)
	if err != nil {
		return nil, err
	}

	timeout := pc.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	httpClient := &http.Client{Timeout: timeout}
	source := pypiattest.NewPyPISource(httpClient, pc.IndexURL, pc.IntegrityURL)

	tenants := make(map[string]pypiattest.TenantConfig)
	for t, tc := range pc.Tenants {
		if a, ok := pypiattest.ParseAction(tc.Action); ok && strings.TrimSpace(tc.Action) != "" {
			tenants[t] = pypiattest.TenantConfig{Action: a}
		}
	}

	svc, err := pypiattest.NewService(pypiattest.Config{
		Action:                  action,
		FailSeverity:            pypiattest.NormalizeSeverity(pc.FailSeverity),
		WarnSeverity:            pypiattest.NormalizeSeverity(pc.WarnSeverity),
		RequireAttestation:      pc.RequireAttestation,
		RequireTrustedPublisher: pc.RequireTrustedPublisher,
		RequireInclusionProof:   pc.RequireInclusionProof,
		FailOnError:             pc.FailOnError,
		Roots:                   roots,
		Identities:              identities,
		Keys:                    keys,
		RekorKeys:               rekorKeys,
		CacheTTL:                pc.CacheTTL,
		CacheMaxEntries:         pc.CacheSize,
		Offline:                 pc.Offline,
		Tenants:                 tenants,
	}, source, logger)
	if err != nil {
		return nil, fmt.Errorf("pypiattest: %w", err)
	}

	logger.Info("inbound PyPI attestation verification enabled",
		"action", action, "requireAttestation", pc.RequireAttestation,
		"requireTrustedPublisher", pc.RequireTrustedPublisher, "requireInclusionProof", pc.RequireInclusionProof,
		"trustRoots", roots != nil, "identities", len(identities), "rekorKeys", len(rekorKeys),
		"tenantOverrides", len(tenants), "offline", pc.Offline)
	return svc, nil
}

// buildPyPIAttestTrust assembles the gate's trust material from configuration:
// from a portable trust bundle when a path is configured (air-gapped), else from
// a PEM roots file + Rekor key files + the inline allowed-identity policy. It
// reuses the signature gate's trust-bundle format.
func buildPyPIAttestTrust(pc config.PyPIAttestConfig) (roots *x509.CertPool, rekorKeys []crypto.PublicKey, keys []sigverify.TrustedKey, identities []sigverify.Identity, err error) {
	if path := strings.TrimSpace(pc.TrustBundlePath); path != "" {
		f, oerr := os.Open(path)
		if oerr != nil {
			return nil, nil, nil, nil, fmt.Errorf("pypiattest: opening trust bundle %q: %w", path, oerr)
		}
		defer f.Close()
		bundle, lerr := sigverify.LoadTrustBundle(f, pc.TrustBundleDigest)
		if lerr != nil {
			return nil, nil, nil, nil, lerr
		}
		return bundle.Material()
	}

	if rootsFile := strings.TrimSpace(pc.TrustRootsFile); rootsFile != "" {
		pemBytes, rerr := os.ReadFile(rootsFile)
		if rerr != nil {
			return nil, nil, nil, nil, fmt.Errorf("pypiattest: reading trust roots %q: %w", rootsFile, rerr)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, nil, nil, nil, fmt.Errorf("pypiattest: no certificates found in trust roots %q", rootsFile)
		}
		roots = pool
	}

	for _, file := range pc.RekorKeyFiles {
		pemBytes, rerr := os.ReadFile(file)
		if rerr != nil {
			return nil, nil, nil, nil, fmt.Errorf("pypiattest: reading rekor key %q: %w", file, rerr)
		}
		pub, perr := sigverify.ParsePublicKeyPEM(pemBytes)
		if perr != nil {
			return nil, nil, nil, nil, fmt.Errorf("pypiattest: rekor key %q: %w", file, perr)
		}
		rekorKeys = append(rekorKeys, pub)
	}

	for _, id := range pc.Identities {
		identities = append(identities, sigverify.Identity{Issuer: id.Issuer, SubjectPattern: id.SubjectPattern})
	}
	return roots, rekorKeys, keys, identities, nil
}
