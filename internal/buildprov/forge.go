package buildprov

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
)

// This file holds the forge provider abstraction. A "forge" is a source-control /
// CI provider that publishes build-provenance attestations — GitHub, GitLab,
// Bitbucket, or a self-hosted instance of any of them. Each forge keyless-signs
// its attestations with its OWN OIDC issuer, and may chain to its OWN Fulcio/CA
// trust root (notably a self-hosted GitLab running its own Sigstore deployment).
//
// The gate therefore verifies a discovered attestation against the trust material
// of the forge whose Source produced it, rather than one shared pool. This keeps
// the gate logic (service.go) forge-agnostic: adding a new forge means adding a
// Source (discovery) and a ForgeTrust (trust config); the verification,
// cross-check, findings, and admission logic are untouched.

// Well-known forge identifiers. A Source stamps the forge it discovered material
// from onto Material.Forge, and ForgeTrust.Name selects the matching trust
// material. The empty forge ("") denotes the shared/default trust material
// (used by the registry-level npm provenance source, whose signer is a GitHub
// Actions workflow).
const (
	// ForgeGitHub identifies GitHub (github.com and GitHub Enterprise).
	ForgeGitHub = "github"
	// ForgeGitLab identifies GitLab (gitlab.com and self-hosted GitLab).
	ForgeGitLab = "gitlab"
	// ForgeBitbucket identifies Bitbucket (bitbucket.org / Bitbucket Cloud).
	ForgeBitbucket = "bitbucket"
)

// NormalizeForge coerces a configured/observed forge id to its canonical lower
// form, mapping common aliases. An unrecognized non-empty value is returned
// lower-cased unchanged (operators may configure self-hosted forge ids).
func NormalizeForge(s string) string {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "", ForgeGitHub, ForgeGitLab, ForgeBitbucket:
		return v
	case "github.com", "gh":
		return ForgeGitHub
	case "gitlab.com", "gl":
		return ForgeGitLab
	case "bitbucket.org", "bb":
		return ForgeBitbucket
	default:
		return v
	}
}

// ForgeTrust declares the trust material for a single forge. When a forge is
// configured here, attestations discovered from that forge's Source are verified
// against this material (its own Fulcio/CA roots + allowed-identity policy);
// otherwise they fall back to the gate's default (Config.Roots / Config.Identities).
type ForgeTrust struct {
	// Name is the forge id this trust applies to (ForgeGitHub/GitLab/Bitbucket or a
	// self-hosted id). It must match the Material.Forge the forge's Source stamps.
	Name string
	// Roots is the forge's Fulcio/CA certificate pool. When nil the forge's
	// attestations cannot be chain-trusted (SourceVerified) even if the signature is
	// cryptographically valid.
	Roots *x509.CertPool
	// Identities is the forge's allowed keyless-signer policy (its OIDC issuer +
	// subject regex). An empty policy accepts any identity that chained to Roots.
	Identities []sigverify.Identity
	// Keys / RekorKeys are optional keyed-verification and Rekor material for the
	// forge (parallel to the default trust material).
	Keys      []sigverify.TrustedKey
	RekorKeys []crypto.PublicKey
}

// buildForgeVerifiers compiles a per-forge verifier map from the configured
// ForgeTrust entries. A malformed identity pattern is a configuration error.
func buildForgeVerifiers(forges []ForgeTrust) (map[string]*sigverify.Verifier, error) {
	if len(forges) == 0 {
		return nil, nil
	}
	out := make(map[string]*sigverify.Verifier, len(forges))
	for _, f := range forges {
		name := NormalizeForge(f.Name)
		if name == "" {
			return nil, fmt.Errorf("buildprov: forge trust entry has an empty name")
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("buildprov: duplicate forge trust entry %q", name)
		}
		v, err := sigverify.NewVerifier(f.Roots, f.Identities, f.Keys, f.RekorKeys)
		if err != nil {
			return nil, fmt.Errorf("buildprov: forge %q: %w", name, err)
		}
		out[name] = v
	}
	return out, nil
}
