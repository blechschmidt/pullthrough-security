package proxy

import (
	"context"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/terraform"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
)

// recordTerraformSignature surfaces the Terraform/OpenTofu backend's in-Fetch
// SHASUMS signature and SHA-256 verification status into the admission signal
// accumulator, so the policy-as-code and risk-scoring gates can reason about a
// provider's authenticity alongside the cosign/Sigstore signals other ecosystems
// produce. The verification itself (and its hard enforcement of digest mismatches
// and forged signatures) happens in the backend; this only reports the outcome.
//
// The status is read from the resolved metadata (populated on a cache miss) with
// a fallback to the persisted cache-entry metadata (populated on a cache hit), so
// the signal is recorded consistently regardless of cache outcome. A request that
// carries no Terraform verification metadata is left untouched.
func (g *Gateway) recordTerraformSignature(ctx context.Context, resolved *backends.Resolved, entry *cache.Entry) {
	sigStatus := terraformMeta(resolved, entry, terraform.MetaSignatureVerified)
	checksumStatus := terraformMeta(resolved, entry, terraform.MetaChecksumVerified)
	if sigStatus == "" && checksumStatus == "" {
		return
	}

	report := &sigverify.Report{Source: "terraform-shasums"}
	if sigStatus == "verified" {
		// The signing keys are asserted by the provider's registry, so a verified
		// signature is a registry-trusted identity. Mark the trust dimensions the
		// SignatureInput summarizer keys on.
		sr := sigverify.SignatureResult{
			Verified:        true,
			CryptoValid:     true,
			ChainTrusted:    true,
			IdentityTrusted: true,
			Identity:        terraformMeta(resolved, entry, terraform.MetaSigningKeyID),
		}
		report.Signatures = []sigverify.SignatureResult{sr}
		report.VerifiedSignature = true
	}
	recordSigverifySignal(ctx, report)
}

// terraformMeta reads a metadata key from the resolved metadata first (set on a
// cache miss) and falls back to the persisted cache-entry metadata (a cache hit).
func terraformMeta(resolved *backends.Resolved, entry *cache.Entry, key string) string {
	if resolved != nil && resolved.Metadata != nil {
		if v := resolved.Metadata[key]; v != "" {
			return v
		}
	}
	if entry != nil {
		if v := entry.Stat.Metadata[key]; v != "" {
			return v
		}
	}
	return ""
}
