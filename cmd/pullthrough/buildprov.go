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

	"github.com/blechschmidt/pullthrough-security/internal/buildprov"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
)

// buildBuildProv constructs the inbound build-provenance verification gate (Task
// 72) from configuration. It returns (nil, nil) when disabled. It reuses the
// signature gate's trust material model (Fulcio roots + allowed identities,
// loadable from a portable offline trust bundle) since both verify Sigstore
// material; the npm provenance source is always wired and the GitHub
// artifact-attestation source is opt-in.
func buildBuildProv(cfg *config.Config, logger *slog.Logger) (*buildprov.Service, error) {
	bc := cfg.BuildProv
	if !bc.Enabled {
		logger.Info("inbound build-provenance verification disabled (set buildProv.enabled to verify npm/GitHub build provenance and cross-check the source commit)")
		return nil, nil
	}

	mode := buildprov.ModeObserve
	if m, ok := buildprov.ParseMode(bc.Mode); ok {
		mode = m
	}

	roots, rekorKeys, keys, identities, err := buildBuildProvTrust(bc)
	if err != nil {
		return nil, err
	}

	timeout := bc.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	httpClient := &http.Client{Timeout: timeout}

	npmBase := strings.TrimSpace(bc.NPMRegistryURL)
	if npmBase == "" {
		npmBase = "https://registry.npmjs.org"
	}
	sources := []buildprov.Source{buildprov.NewNPMSource(httpClient, npmBase)}
	if bc.EnableGitHubSource {
		sources = append(sources, buildprov.NewGitHubSource(httpClient, bc.GitHubAPIURL, bc.GitHubToken))
	}
	if bc.EnableGitLabSource {
		sources = append(sources, buildprov.NewGitLabSource(httpClient, bc.GitLabAPIURL, bc.GitLabHost, bc.GitLabToken))
	}
	if bc.EnableBitbucketSource {
		sources = append(sources, buildprov.NewBitbucketSource(httpClient, bc.BitbucketAPIURL, bc.BitbucketHost, bc.BitbucketToken))
	}

	forges, err := buildBuildProvForges(bc)
	if err != nil {
		return nil, err
	}

	tenants := make(map[string]buildprov.TenantConfig)
	for t, tc := range bc.Tenants {
		out := buildprov.TenantConfig{}
		if strings.TrimSpace(tc.Mode) != "" {
			if m, ok := buildprov.ParseMode(tc.Mode); ok {
				out.Mode = m
			}
		}
		if tc.RequireProvenance != nil {
			v := *tc.RequireProvenance
			out.RequireProvenance = &v
		}
		if out.Mode == "" && out.RequireProvenance == nil {
			continue
		}
		tenants[t] = out
	}

	action := policy.Action(strings.TrimSpace(bc.Action))
	if action == "" {
		action = policy.ActionQuarantine
	}

	svc, err := buildprov.NewService(buildprov.Config{
		Mode:                 mode,
		Action:               action,
		FailSeverity:         buildprov.NormalizeSeverity(bc.FailSeverity),
		WarnSeverity:         buildprov.NormalizeSeverity(bc.WarnSeverity),
		RequireProvenance:    bc.RequireProvenance,
		RequireTrustedSource: bc.RequireTrustedSource,
		FailOnError:          bc.FailOnError,
		Roots:                roots,
		Identities:           identities,
		Keys:                 keys,
		RekorKeys:            rekorKeys,
		Forges:               forges,
		CacheTTL:             bc.CacheTTL,
		CacheMaxEntries:      bc.CacheSize,
		Offline:              bc.Offline,
		Tenants:              tenants,
	}, buildprov.NewMultiSource(sources...), logger)
	if err != nil {
		return nil, fmt.Errorf("buildprov: %w", err)
	}

	logger.Info("inbound build-provenance verification enabled",
		"mode", mode, "githubSource", bc.EnableGitHubSource, "gitlabSource", bc.EnableGitLabSource,
		"bitbucketSource", bc.EnableBitbucketSource, "requireProvenance", bc.RequireProvenance,
		"trustRoots", roots != nil, "identities", len(identities), "forgeTrust", len(forges),
		"tenantOverrides", len(tenants), "offline", bc.Offline)
	return svc, nil
}

// buildBuildProvForges assembles per-forge trust material (Fulcio/CA roots +
// allowed OIDC-issuer identities, or a portable offline trust bundle) from
// configuration, so GitLab and Bitbucket provenance is verified under its own
// trust roots and issuers independently of the shared npm/GitHub material.
func buildBuildProvForges(bc config.BuildProvConfig) ([]buildprov.ForgeTrust, error) {
	if len(bc.Forges) == 0 {
		return nil, nil
	}
	out := make([]buildprov.ForgeTrust, 0, len(bc.Forges))
	for _, f := range bc.Forges {
		ft := buildprov.ForgeTrust{Name: f.Name}

		if path := strings.TrimSpace(f.TrustBundlePath); path != "" {
			file, err := os.Open(path)
			if err != nil {
				return nil, fmt.Errorf("buildprov: forge %q: opening trust bundle %q: %w", f.Name, path, err)
			}
			bundle, lerr := sigverify.LoadTrustBundle(file, f.TrustBundleDigest)
			_ = file.Close()
			if lerr != nil {
				return nil, fmt.Errorf("buildprov: forge %q: %w", f.Name, lerr)
			}
			roots, rekorKeys, keys, identities, merr := bundle.Material()
			if merr != nil {
				return nil, fmt.Errorf("buildprov: forge %q: %w", f.Name, merr)
			}
			ft.Roots, ft.RekorKeys, ft.Keys, ft.Identities = roots, rekorKeys, keys, identities
			out = append(out, ft)
			continue
		}

		if rootsFile := strings.TrimSpace(f.TrustRootsFile); rootsFile != "" {
			pemBytes, err := os.ReadFile(rootsFile)
			if err != nil {
				return nil, fmt.Errorf("buildprov: forge %q: reading trust roots %q: %w", f.Name, rootsFile, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pemBytes) {
				return nil, fmt.Errorf("buildprov: forge %q: no certificates found in trust roots %q", f.Name, rootsFile)
			}
			ft.Roots = pool
		} else if f.UseSystemTrustRoots {
			pool, err := x509.SystemCertPool()
			if err != nil {
				return nil, fmt.Errorf("buildprov: forge %q: loading system trust roots: %w", f.Name, err)
			}
			ft.Roots = pool
		}

		for _, file := range f.RekorKeyFiles {
			pemBytes, err := os.ReadFile(file)
			if err != nil {
				return nil, fmt.Errorf("buildprov: forge %q: reading rekor key %q: %w", f.Name, file, err)
			}
			pub, perr := sigverify.ParsePublicKeyPEM(pemBytes)
			if perr != nil {
				return nil, fmt.Errorf("buildprov: forge %q: rekor key %q: %w", f.Name, file, perr)
			}
			ft.RekorKeys = append(ft.RekorKeys, pub)
		}

		for _, id := range f.Identities {
			ft.Identities = append(ft.Identities, sigverify.Identity{Issuer: id.Issuer, SubjectPattern: id.SubjectPattern})
		}
		out = append(out, ft)
	}
	return out, nil
}

// buildBuildProvTrust assembles the gate's trust material from configuration:
// from a portable trust bundle when a path is configured (air-gapped), or from
// the inline allowed-identity policy otherwise. It reuses the signature gate's
// trust-bundle format.
func buildBuildProvTrust(bc config.BuildProvConfig) (roots *x509.CertPool, rekorKeys []crypto.PublicKey, keys []sigverify.TrustedKey, identities []sigverify.Identity, err error) {
	if path := strings.TrimSpace(bc.TrustBundlePath); path != "" {
		f, oerr := os.Open(path)
		if oerr != nil {
			return nil, nil, nil, nil, fmt.Errorf("buildprov: opening trust bundle %q: %w", path, oerr)
		}
		defer f.Close()
		bundle, lerr := sigverify.LoadTrustBundle(f, bc.TrustBundleDigest)
		if lerr != nil {
			return nil, nil, nil, nil, lerr
		}
		return bundle.Material()
	}
	for _, id := range bc.Identities {
		identities = append(identities, sigverify.Identity{Issuer: id.Issuer, SubjectPattern: id.SubjectPattern})
	}
	return nil, nil, nil, identities, nil
}
