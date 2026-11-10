package main

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/attestbundle"
	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/keyrotation"
)

// buildKeyRotation constructs the credential & signing-key rotation/expiry
// subsystem (Task 148) and registers a Source for each piece of long-lived trust
// material the deployment actually has: the audit HMAC/checkpoint keys, the cache
// key-encryption key (also registered as a safe in-place Rotator), the outbound
// attestation signing key, upstream credentials, and any monitored TLS
// certificates/CAs. It returns a non-nil service even when disabled so the
// metrics/admin layers can bind unconditionally; Start is a no-op when disabled.
func buildKeyRotation(
	cfg *config.Config,
	cacheImpl cache.Cache,
	auditLog *audit.Logger,
	attestor *attestbundle.Service,
	logger *slog.Logger,
) *keyrotation.Service {
	kc := cfg.KeyRotation
	svc := keyrotation.New(keyrotation.Config{
		Enabled:           kc.Enabled,
		ScanInterval:      kc.ScanInterval,
		WarnThreshold:     kc.WarnThreshold,
		CriticalThreshold: kc.CriticalThreshold,
		OverlapWindow:     kc.OverlapWindow,
	}, keyrotation.Deps{Logger: logger})

	if !kc.Enabled {
		logger.Info("key-rotation / expiry monitoring disabled (keyRotation.enabled=false)")
		return svc
	}

	policies := compileRotationPolicies(kc.Policies)

	registerCacheKEKMaterial(svc, cacheImpl, policies, logger)
	registerAuditKeyMaterial(svc, auditLog, policies)
	registerAttestKeyMaterial(svc, attestor, policies)
	registerUpstreamCredentialMaterial(svc, cfg, policies)
	registerCertificateMaterial(svc, kc.Certificates)

	logger.Info("key-rotation / expiry monitoring enabled",
		"scanInterval", kc.ScanInterval, "warn", kc.WarnThreshold,
		"critical", kc.CriticalThreshold, "monitoredCerts", len(kc.Certificates))
	return svc
}

// rotationPolicy is a compiled soft rotate-every policy, matchable by material id
// or kind.
type rotationPolicy map[string]config.KeyRotationPolicyConfig

func compileRotationPolicies(in []config.KeyRotationPolicyConfig) rotationPolicy {
	out := make(rotationPolicy, len(in))
	for _, p := range in {
		out[strings.TrimSpace(p.Material)] = p
	}
	return out
}

// apply attaches a soft rotation policy to a material (matched by id, then kind)
// so the scanner can warn when a key with no cryptographic expiry grows stale.
func (p rotationPolicy) apply(m *keyrotation.Material) {
	if pol, ok := p[m.ID]; ok {
		m.RotateEvery = pol.RotateEvery
		return
	}
	if pol, ok := p[string(m.Kind)]; ok {
		m.RotateEvery = pol.RotateEvery
	}
}

func registerCacheKEKMaterial(svc *keyrotation.Service, cacheImpl cache.Cache, policies rotationPolicy, logger *slog.Logger) {
	ec, ok := cacheImpl.(cache.EncryptionController)
	if !ok {
		return
	}
	if !ec.EncryptionStats().Enabled {
		return
	}
	svc.AddSource("cache-kek", keyrotation.SourceFunc(func(_ context.Context) ([]keyrotation.Material, error) {
		st := ec.EncryptionStats()
		m := keyrotation.Material{
			ID:          "cache.kek",
			Kind:        keyrotation.KindCacheKEK,
			KeyID:       st.PrimaryKeyID,
			Description: "at-rest cache key-encryption key",
			LastRotated: st.LastRotation,
		}
		// More than one known KEK means a prior key is still configured for unwrap:
		// a live dual-key overlap that must not be flagged as drift.
		if len(st.KnownKeyIDs) > 1 {
			m.Overlap = true
			m.PreviousKeyIDs = append([]string(nil), st.KnownKeyIDs[1:]...)
		}
		policies.apply(&m)
		return []keyrotation.Material{m}, nil
	}))
	svc.AddRotator("cache.kek", ec.EncryptionStats().PrimaryKeyID, keyrotation.RotatorFunc(func(ctx context.Context) (keyrotation.RotationOutcome, error) {
		rep, err := ec.RotateKEK(ctx)
		if err != nil {
			return keyrotation.RotationOutcome{}, err
		}
		detail := fmt.Sprintf("re-wrapped %d of %d object data keys to the active KEK", rep.Rewrapped, rep.Scanned)
		if rep.Unsupported {
			detail = "the active cache store cannot re-wrap in place (e.g. object storage); rotate by re-encrypting or draining the cache"
		}
		return keyrotation.RotationOutcome{
			NewPrimaryKeyID: rep.PrimaryKeyID,
			StartedAt:       rep.StartedAt,
			Duration:        rep.Duration,
			Scanned:         rep.Scanned,
			Rewrapped:       rep.Rewrapped,
			Detail:          detail,
		}, nil
	}))
}

func registerAuditKeyMaterial(svc *keyrotation.Service, auditLog *audit.Logger, policies rotationPolicy) {
	if auditLog == nil {
		return
	}
	svc.AddSource("audit", keyrotation.SourceFunc(func(_ context.Context) ([]keyrotation.Material, error) {
		st := auditLog.Stats()
		mats := []keyrotation.Material{{
			ID:          "audit.hmac",
			Kind:        keyrotation.KindAuditHMAC,
			Description: "audit log hash-chain HMAC key",
		}}
		if st.Signed {
			mats = append(mats, keyrotation.Material{
				ID:          "audit.checkpoint",
				Kind:        keyrotation.KindAuditCheckpoint,
				KeyID:       st.KeyID,
				Description: "audit Merkle checkpoint (STH) signing key",
			})
		}
		for i := range mats {
			policies.apply(&mats[i])
		}
		return mats, nil
	}))
}

func registerAttestKeyMaterial(svc *keyrotation.Service, attestor *attestbundle.Service, policies rotationPolicy) {
	if attestor == nil || attestor.KeyID() == "" {
		return
	}
	svc.AddSource("attest", keyrotation.SourceFunc(func(_ context.Context) ([]keyrotation.Material, error) {
		m := keyrotation.Material{
			ID:          "attest.signer",
			Kind:        keyrotation.KindAttestSigner,
			KeyID:       attestor.KeyID(),
			Description: "outbound attestation signing key",
		}
		policies.apply(&m)
		return []keyrotation.Material{m}, nil
	}))
}

func registerUpstreamCredentialMaterial(svc *keyrotation.Service, cfg *config.Config, policies rotationPolicy) {
	// Enumerate upstreams that carry a credential, by name only — never the secret
	// itself. A changing secretRef is deliberately invisible to config drift
	// (Task 85/133), so this lists what should be monitored and lets an operator
	// attach a soft rotation policy per upstream credential.
	names := make([]string, 0, len(cfg.Upstreams))
	for name, up := range cfg.Upstreams {
		if up.Credentials.Username == "" && up.Credentials.Password == "" && up.Credentials.Token == "" {
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return
	}
	sort.Strings(names)
	svc.AddSource("upstream-credentials", keyrotation.SourceFunc(func(_ context.Context) ([]keyrotation.Material, error) {
		mats := make([]keyrotation.Material, 0, len(names))
		for _, name := range names {
			m := keyrotation.Material{
				ID:          "upstream." + name + ".credential",
				Kind:        keyrotation.KindUpstreamCred,
				Description: "upstream credential for " + name,
			}
			policies.apply(&m)
			mats = append(mats, m)
		}
		return mats, nil
	}))
}

func registerCertificateMaterial(svc *keyrotation.Service, certs []config.MonitoredCertConfig) {
	if len(certs) == 0 {
		return
	}
	specs := make([]keyrotation.CertSpec, 0, len(certs))
	for _, mc := range certs {
		kind := keyrotation.KindTLSCert
		if mc.Kind == "ca-certificate" {
			kind = keyrotation.KindCA
		}
		specs = append(specs, keyrotation.CertSpec{
			ID:          mc.ID,
			Path:        mc.Path,
			Kind:        kind,
			Description: mc.Description,
		})
	}
	svc.AddSource("certificates", keyrotation.NewCertSource(specs, nil))
}
