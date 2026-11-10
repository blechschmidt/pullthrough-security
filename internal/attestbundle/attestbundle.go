// Package attestbundle makes the proxy a supply-chain ATTESTER, not just a
// verifier. The inbound sigverify/provenance gates (Tasks 8/23) verify the
// attestations an artifact already carries; this package produces a NEW,
// proxy-signed attestation for every artifact the proxy serves, binding:
//
//   - the served artifact's content digest (the subject),
//   - its associated source repository and Git commit (from the provenance
//     association / provgraph),
//   - the admission verdicts it passed (vuln, license, signature, policy-engine,
//     risk-score, secret, nameguard) and its VEX status, and
//   - the identity of the proxy that vouched for it (the attester).
//
// The statement is an in-toto v1 Statement with a proxy-specific SLSA-style
// predicate, wrapped in a DSSE envelope and signed with the audit-log signing
// key (or a dedicated cosign key). Downstream CI can then *require the proxy's
// attestation* — "only deploy what our proxy admitted and signed" — turning the
// proxy's admission decision into a verifiable, transferable claim.
//
// SECURITY: an attestation only asserts what the proxy actually established at
// serve time. The subject digest is the digest of the bytes the proxy cached and
// served, so a downstream verifier that checks (a) the DSSE signature against the
// proxy's public key and (b) that one subject digest equals the artifact it is
// consuming gets a binding, non-repudiable claim. The predicate never overstates:
// a gate that did not run is omitted, not reported as passed.
package attestbundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

// In-toto / DSSE on-the-wire constants. The statement and envelope shapes match
// what cosign/Sigstore and `cosign download attestation` consume, so a downstream
// verifier can use off-the-shelf tooling against the proxy's public key.
const (
	// StatementType is the in-toto Statement v1 type URI.
	StatementType = "https://in-toto.io/Statement/v1"
	// PredicateType is the proxy's own predicate type. Versioned so the schema can
	// evolve without breaking downstream verifiers pinned to v1.
	PredicateType = "https://pullthrough.dev/attestations/served/v1"
	// DSSEPayloadType is the DSSE payloadType for an in-toto statement. It is bound
	// into the signature via PAE so it cannot be swapped.
	DSSEPayloadType = "application/vnd.in-toto+json"
	// ArtifactType is the OCI artifactType the referrers descriptor advertises for
	// the attestation manifest, mirroring the in-toto predicate type.
	ArtifactType = "application/vnd.in-toto+json; in-toto.io/predicate-type=" + PredicateType
)

// Statement is the in-toto v1 Statement: the signed claim binding subjects to a
// typed predicate. It is the DSSE payload.
type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
}

// Subject names a piece of content and its digest set. The proxy emits exactly
// one subject: the served artifact.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Predicate is the proxy's SLSA-style "served artifact" attestation predicate. It
// records who vouched for the artifact (the attester), what it is, where it came
// from (source commit), and the admission verdicts it passed.
type Predicate struct {
	// Attester identifies the proxy instance that produced and signed this claim.
	Attester Attester `json:"attester"`
	// Artifact restates the subject coordinates in a richer, queryable form than
	// the bare in-toto subject (ecosystem/backend/tenant), for downstream policy.
	Artifact Artifact `json:"artifact"`
	// Source is the associated source repository and Git commit, when the
	// provenance association resolved one. Omitted when no source was established.
	Source *Source `json:"source,omitempty"`
	// Admission is the set of gate verdicts the artifact passed at serve time.
	Admission Admission `json:"admission"`
	// ServedAt is when the proxy admitted and served the artifact (UTC).
	ServedAt time.Time `json:"servedAt"`
}

// Attester identifies the signing proxy. The KeyID lets a verifier select the
// correct public key without trial verification.
type Attester struct {
	// ID is the attester's logical identity, e.g. "pullthrough-proxy". It is the
	// SLSA builder.id analogue.
	ID string `json:"id"`
	// Name is a human-readable product name.
	Name string `json:"name,omitempty"`
	// Version is the proxy build version.
	Version string `json:"version,omitempty"`
	// Instance optionally identifies the specific deployment/host.
	Instance string `json:"instance,omitempty"`
	// KeyID is the short identifier of the signing key (see dsse.go keyID).
	KeyID string `json:"keyId,omitempty"`
}

// Artifact restates the admitted artifact's coordinates.
type Artifact struct {
	Ecosystem  string `json:"ecosystem,omitempty"`
	Backend    string `json:"backend,omitempty"`
	Name       string `json:"name,omitempty"`
	Version    string `json:"version,omitempty"`
	Coordinate string `json:"coordinate,omitempty"`
	Digest     string `json:"digest,omitempty"`
	Tenant     string `json:"tenant,omitempty"`
}

// Source is the associated source repository and commit.
type Source struct {
	RepositoryURL string `json:"repositoryUrl,omitempty"`
	CommitSHA     string `json:"commitSha,omitempty"`
	BuilderID     string `json:"builderId,omitempty"`
	// Confidence is the provenance association confidence (attested|claimed|
	// heuristic) carried through from the inbound provenance gate.
	Confidence string `json:"confidence,omitempty"`
	// SignatureVerified / ChainTrusted reflect whether the inbound attestation that
	// established this source was itself cryptographically verified and trusted.
	SignatureVerified bool `json:"signatureVerified,omitempty"`
	ChainTrusted      bool `json:"chainTrusted,omitempty"`
}

// Admission summarizes the verdicts each admission gate produced for the
// artifact. A gate that did not run is left nil/empty — never reported as passed.
type Admission struct {
	// Verdict is the overall serve-time decision. The proxy only attests artifacts
	// it admitted, so this is "admitted"; the field is explicit for downstream
	// rules and forward compatibility (e.g. "admitted-with-warnings").
	Verdict string `json:"verdict"`
	// Warned reports whether any gate warned (non-blocking) on the artifact.
	Warned bool `json:"warned,omitempty"`
	// Gates is a compact, ordered list of each gate's outcome, for a human-readable
	// audit trail alongside the structured sections below.
	Gates []GateOutcome `json:"gates,omitempty"`

	Vuln      *VulnVerdict      `json:"vuln,omitempty"`
	License   *LicenseVerdict   `json:"license,omitempty"`
	Signature *SignatureVerdict `json:"signature,omitempty"`
	Secret    *SecretVerdict    `json:"secret,omitempty"`
	Nameguard *NameguardVerdict `json:"nameguard,omitempty"`
	Risk      *RiskVerdict      `json:"risk,omitempty"`
	Policy    *PolicyVerdict    `json:"policy,omitempty"`
	VEX       *VEXSummary       `json:"vex,omitempty"`
}

// GateOutcome is a single gate's serve-time verdict.
type GateOutcome struct {
	Gate     string `json:"gate"`
	Decision string `json:"decision"` // pass|warn
	Summary  string `json:"summary,omitempty"`
}

// VulnVerdict summarizes the (post-VEX) vulnerability scan.
type VulnVerdict struct {
	Scanner       string `json:"scanner,omitempty"`
	MaxSeverity   string `json:"maxSeverity,omitempty"`
	Total         int    `json:"total"`
	CriticalCount int    `json:"criticalCount"`
	HighCount     int    `json:"highCount"`
	VEXSuppressed int    `json:"vexSuppressed,omitempty"`
}

// LicenseVerdict summarizes the license-compliance decision.
type LicenseVerdict struct {
	Action  string `json:"action,omitempty"`
	Code    string `json:"code,omitempty"`
	Allowed bool   `json:"allowed"`
}

// SignatureVerdict summarizes inbound signature/attestation verification.
type SignatureVerdict struct {
	Verified       bool   `json:"verified"`
	Attested       bool   `json:"attested"`
	Keyless        bool   `json:"keyless,omitempty"`
	ChainTrusted   bool   `json:"chainTrusted,omitempty"`
	SLSAProvenance bool   `json:"slsaProvenance,omitempty"`
	Identity       string `json:"identity,omitempty"`
	Issuer         string `json:"issuer,omitempty"`
}

// SecretVerdict summarizes deterministic secret-scan risk.
type SecretVerdict struct {
	FindingCount int    `json:"findingCount"`
	MaxSeverity  string `json:"maxSeverity,omitempty"`
}

// NameguardVerdict summarizes typosquat / dependency-confusion screening.
type NameguardVerdict struct {
	FindingCount        int    `json:"findingCount"`
	MaxSeverity         string `json:"maxSeverity,omitempty"`
	Typosquat           bool   `json:"typosquat,omitempty"`
	DependencyConfusion bool   `json:"dependencyConfusion,omitempty"`
}

// RiskVerdict carries the unified composite risk score and band.
type RiskVerdict struct {
	Score int    `json:"score"`
	Band  string `json:"band,omitempty"`
}

// PolicyVerdict carries the policy-as-code engine's effective action.
type PolicyVerdict struct {
	Action     string   `json:"action,omitempty"`
	MatchedIDs []string `json:"matchedRules,omitempty"`
}

// VEXSummary carries the VEX adjudication counts folded into the vuln verdict.
type VEXSummary struct {
	Suppressed int `json:"suppressed,omitempty"`
	Escalated  int `json:"escalated,omitempty"`
}

// Options carries the verdicts the policy and risk gates produce out-of-band from
// the aggregated admission document, mirroring findings.Options so the gateway
// can pass the identical accumulator state to both layers.
type Options struct {
	// Risk is the unified risk-score verdict, when the risk gate ran.
	Risk *findings.RiskSignal
	// Policy is the policy-as-code verdict, when the policy engine ran.
	Policy *findings.PolicySignal
	// ServedAt overrides the serve timestamp (tests). Zero uses the service clock.
	ServedAt time.Time
}

// BuildStatement projects an aggregated admission document into the in-toto
// statement the proxy will sign. It is pure and deterministic: identical inputs
// produce byte-identical statements (after canonical marshaling), which the
// golden tests rely on. attester identifies the signing proxy.
func BuildStatement(attester Attester, in policyengine.Input, opts Options) Statement {
	art := in.Artifact
	coord := art.Name
	if art.Version != "" {
		coord = art.Name + "@" + art.Version
	}

	subj := Subject{Name: coordOrName(coord, art.Name), Digest: digestSet(art.Digest)}

	pred := Predicate{
		Attester: attester,
		Artifact: Artifact{
			Ecosystem:  art.Ecosystem,
			Backend:    art.Backend,
			Name:       art.Name,
			Version:    art.Version,
			Coordinate: coord,
			Digest:     art.Digest,
			Tenant:     in.Tenant,
		},
		Admission: buildAdmission(in, opts),
		ServedAt:  opts.ServedAt.UTC(),
	}
	if src := buildSource(in.Provenance); src != nil {
		pred.Source = src
	}

	return Statement{
		Type:          StatementType,
		Subject:       []Subject{subj},
		PredicateType: PredicateType,
		Predicate:     pred,
	}
}

// coordOrName returns the coordinate when present, else the bare name, else a
// stable placeholder so the in-toto subject always has a non-empty name.
func coordOrName(coord, name string) string {
	if coord != "" {
		return coord
	}
	if name != "" {
		return name
	}
	return "unknown"
}

// digestSet splits a "<algo>:<hex>" digest into the in-toto digest map. An empty
// or malformed digest yields an empty map (a subject with no digest is still a
// valid, if unbindable, claim — the gateway only attests artifacts that have a
// resolved digest, so this is a defensive fallback).
func digestSet(digest string) map[string]string {
	algo, hexv, ok := splitDigest(digest)
	if !ok {
		return map[string]string{}
	}
	return map[string]string{algo: strings.ToLower(hexv)}
}

func splitDigest(d string) (algo, hexv string, ok bool) {
	i := strings.IndexByte(d, ':')
	if i <= 0 || i == len(d)-1 {
		return "", "", false
	}
	algo = strings.ToLower(strings.TrimSpace(d[:i]))
	hexv = strings.TrimSpace(d[i+1:])
	if algo == "" || hexv == "" {
		return "", "", false
	}
	if _, err := hex.DecodeString(hexv); err != nil {
		return "", "", false
	}
	return algo, hexv, true
}

// buildSource derives the Source section from the provenance signal. Returns nil
// when no source repository was established, so the predicate omits it rather than
// emitting an empty object.
func buildSource(p *policyengine.ProvenanceInput) *Source {
	if p == nil || (!p.Found && p.RepositoryURL == "" && p.CommitSHA == "") {
		return nil
	}
	if p.RepositoryURL == "" && p.CommitSHA == "" {
		return nil
	}
	return &Source{
		RepositoryURL:     p.RepositoryURL,
		CommitSHA:         p.CommitSHA,
		Confidence:        p.Confidence,
		SignatureVerified: p.SignatureVerified,
		ChainTrusted:      p.ChainTrusted,
	}
}

// buildAdmission projects the per-gate signals into the compact verdict sections.
func buildAdmission(in policyengine.Input, opts Options) Admission {
	a := Admission{Verdict: "admitted"}

	if v := in.Vuln; v != nil && v.Scanned {
		a.Vuln = &VulnVerdict{
			Scanner:       v.Scanner,
			MaxSeverity:   v.MaxSeverity,
			Total:         v.Total,
			CriticalCount: v.CriticalCount,
			HighCount:     v.HighCount,
			VEXSuppressed: v.VEXSuppressed,
		}
		a.Gates = append(a.Gates, GateOutcome{Gate: "vulnscan", Decision: "pass",
			Summary: vulnSummary(v)})
		if v.VEXSuppressed > 0 || v.VEXEscalated > 0 {
			a.VEX = &VEXSummary{Suppressed: v.VEXSuppressed, Escalated: v.VEXEscalated}
		}
	}
	if l := in.License; l != nil && l.Evaluated {
		a.License = &LicenseVerdict{Action: l.Action, Code: l.Code, Allowed: l.Allowed}
		decision := "pass"
		if l.Action == "warn" {
			decision = "warn"
			a.Warned = true
		}
		a.Gates = append(a.Gates, GateOutcome{Gate: "license", Decision: decision,
			Summary: firstNonEmpty(l.Code, l.Action)})
	}
	if s := in.Signature; s != nil && s.Checked {
		a.Signature = &SignatureVerdict{
			Verified:       s.Verified,
			Attested:       s.Attested,
			Keyless:        s.Keyless,
			ChainTrusted:   s.ChainTrusted,
			SLSAProvenance: s.SLSAProvenance,
			Identity:       s.Identity,
			Issuer:         s.Issuer,
		}
		a.Gates = append(a.Gates, GateOutcome{Gate: "sigverify", Decision: "pass",
			Summary: sigSummary(s)})
	}
	if sec := in.Secret; sec != nil && sec.Scanned {
		a.Secret = &SecretVerdict{FindingCount: sec.FindingCount, MaxSeverity: sec.MaxSeverity}
		a.Gates = append(a.Gates, GateOutcome{Gate: "secretscan", Decision: "pass"})
	}
	if n := in.Nameguard; n != nil && n.Scanned {
		a.Nameguard = &NameguardVerdict{
			FindingCount:        n.FindingCount,
			MaxSeverity:         n.MaxSeverity,
			Typosquat:           n.Typosquat,
			DependencyConfusion: n.DependencyConfusion,
		}
		decision := "pass"
		if n.FindingCount > 0 {
			decision = "warn"
			a.Warned = true
		}
		a.Gates = append(a.Gates, GateOutcome{Gate: "nameguard", Decision: decision})
	}
	if r := opts.Risk; r != nil {
		a.Risk = &RiskVerdict{Score: r.Score, Band: r.Band}
		decision := "pass"
		if strings.EqualFold(r.Action, "warn") {
			decision = "warn"
			a.Warned = true
		}
		a.Gates = append(a.Gates, GateOutcome{Gate: "riskscore", Decision: decision,
			Summary: r.Summary})
	}
	if p := opts.Policy; p != nil {
		pv := &PolicyVerdict{Action: p.Action}
		for _, m := range p.Matches {
			pv.MatchedIDs = append(pv.MatchedIDs, m.RuleID)
		}
		a.Policy = pv
		decision := "pass"
		if strings.EqualFold(p.Action, "warn") {
			decision = "warn"
			a.Warned = true
		}
		a.Gates = append(a.Gates, GateOutcome{Gate: "policyengine", Decision: decision,
			Summary: p.Reason})
	}
	return a
}

func vulnSummary(v *policyengine.VulnInput) string {
	if v.Total == 0 {
		return "no vulnerabilities"
	}
	return fmt.Sprintf("%d findings, max %s", v.Total, firstNonEmpty(v.MaxSeverity, "unknown"))
}

func sigSummary(s *policyengine.SignatureInput) string {
	switch {
	case s.Verified && s.Attested:
		return "signature and attestation verified"
	case s.Verified:
		return "signature verified"
	case s.Attested:
		return "attestation verified"
	default:
		return "not verified"
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// canonicalStatement marshals a statement to deterministic JSON: Go's
// encoding/json emits struct fields in declaration order and map keys sorted, so
// the output is stable for identical inputs. HTML escaping is disabled so URLs in
// the predicate type read cleanly.
func canonicalStatement(s Statement) ([]byte, error) {
	return canonicalJSON(s)
}

func canonicalJSON(v any) ([]byte, error) {
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// Encoder appends a trailing newline; trim it so the payload is exactly the
	// marshaled value (matters for a stable payload digest).
	out := strings.TrimRight(sb.String(), "\n")
	return []byte(out), nil
}

// digestBytes returns the lower-hex SHA-256 of b prefixed with "sha256:".
func digestBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
