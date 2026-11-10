package simreplay

import "github.com/blechschmidt/pullthrough-security/internal/policyengine"

// Redact returns a copy of in with sensitive leaf values stripped, suitable for
// persisting in a capture buffer that may be shipped off-box (to CI, a laptop,
// or an air-gapped reviewer).
//
// Redaction is deliberately fidelity-preserving: it only clears fields the
// admission engines do NOT key on — secret-finding file paths, signer identity
// and issuer strings, source-repository URLs and commit SHAs. The scalar
// signals the policy and risk engines actually evaluate (severities, counts,
// booleans, scores, license/nameguard outcomes) are retained verbatim, so a
// redacted record replays to the same verdict as the original. This guarantee is
// what lets a captured buffer be both shareable and a faithful replay corpus.
//
// Redact never mutates its argument; nested pointer sections are deep-copied
// before their sensitive fields are cleared.
func Redact(in policyengine.Input) policyengine.Input {
	out := in // shallow copy of value fields (Artifact, Tenant)

	if in.Vuln != nil {
		v := *in.Vuln
		// Vulnerability identifiers and severities are not sensitive and are central
		// to scoring, so the finding list is copied as-is.
		v.Findings = append([]policyengine.VulnFinding(nil), in.Vuln.Findings...)
		out.Vuln = &v
	}

	if in.License != nil {
		l := *in.License
		l.DeniedLicenses = append([]string(nil), in.License.DeniedLicenses...)
		l.Findings = append([]policyengine.LicenseFinding(nil), in.License.Findings...)
		out.License = &l
	}

	if in.Signature != nil {
		s := *in.Signature
		// Signer identity and issuer can carry PII (emails, SANs) and an internal OIDC
		// issuer URL; clear them. The trust booleans the engines key on are retained.
		s.Identity = redactedIfSet(s.Identity)
		s.Issuer = redactedIfSet(s.Issuer)
		out.Signature = &s
	}

	if in.Secret != nil {
		sec := *in.Secret
		sec.Findings = make([]policyengine.SecretFinding, len(in.Secret.Findings))
		for i, f := range in.Secret.Findings {
			// Keep the rule ID and severity (scoring inputs); drop the file path, which
			// can leak internal repository layout.
			sec.Findings[i] = policyengine.SecretFinding{
				RuleID:   f.RuleID,
				Severity: f.Severity,
				File:     redactedIfSet(f.File),
			}
		}
		out.Secret = &sec
	}

	if in.Nameguard != nil {
		ng := *in.Nameguard
		ng.Kinds = append([]string(nil), in.Nameguard.Kinds...)
		ng.Findings = append([]policyengine.NameguardFinding(nil), in.Nameguard.Findings...)
		out.Nameguard = &ng
	}

	if in.Provenance != nil {
		p := *in.Provenance
		// The source repo URL and commit SHA identify private infrastructure; clear
		// them. The provenance trust signals (found/confidence/verified/risk) remain.
		p.RepositoryURL = redactedIfSet(p.RepositoryURL)
		p.CommitSHA = redactedIfSet(p.CommitSHA)
		out.Provenance = &p
	}

	return out
}

// redactionPlaceholder is substituted for a non-empty sensitive value so a reader
// can tell a redacted-out value apart from a genuinely absent one.
const redactionPlaceholder = "[redacted]"

func redactedIfSet(v string) string {
	if v == "" {
		return ""
	}
	return redactionPlaceholder
}
