package k8swebhook

import (
	"context"

	"github.com/blechschmidt/pullthrough-security/internal/dossier"
)

// Verdict is the normalized supply-chain verdict for one image, distilled from
// the proxy's per-coordinate dossier headline (Task 87).
type Verdict struct {
	// Decision is the dossier headline verdict: "block", "warn", "admit", or
	// "unknown" (no recorded signal for the coordinate).
	Decision string
	// RiskScore is the 0..100 composite risk score (0 when none recorded).
	RiskScore int
	// RiskBand is the risk band label (e.g. "high"), when scored.
	RiskBand string
	// Reasons are the top verdict drivers, worst-first.
	Reasons []string
	// Summary is the one-line human summary.
	Summary string
}

// hasSignal reports whether the dossier carried any supply-chain signal at all
// (as opposed to never having seen the coordinate).
func (v Verdict) hasSignal() bool {
	return v.Decision != "" && v.Decision != dossier.VerdictUnknown
}

// VerdictSource resolves the proxy's supply-chain verdict for an image
// coordinate. It is the narrow seam the decision engine depends on, satisfied
// in-process (BuilderSource, wrapping *dossier.Builder) or over HTTP (HTTPSource,
// calling the proxy admin API).
type VerdictSource interface {
	// Verdict returns the verdict for the image. tenant scopes the tenant-bearing
	// dossier sources (empty aggregates across tenants). An error means the
	// verdict could not be determined (the caller applies its failure policy).
	Verdict(ctx context.Context, tenant string, ref ImageRef, ecosystem string, stripRegistry bool) (Verdict, error)
}

// LockdownOracle is the narrow slice of the emergency-lockdown kill-switch (Task
// 74) the webhook consults. A *lockdown.Service satisfies it via LockdownAdapter.
// A nil oracle disables the kill-switch integration.
type LockdownOracle interface {
	// BlockedCoordinate reports whether a targeted block (ModeBlock) denies the
	// (ecosystem, name, version) coordinate everywhere.
	BlockedCoordinate(ecosystem, name, version string) (blocked bool, reason, incidentID string)
	// Active reports whether any lockdown posture (freeze/strict/block) is
	// engaged, with the active mode and incident identifier.
	Active() (active bool, mode, incidentID string)
}

// --- in-process dossier adapter ---------------------------------------------

// dossierBuilder is the subset of *dossier.Builder the source needs.
type dossierBuilder interface {
	Build(ctx context.Context, q dossier.Query) *dossier.Dossier
}

// BuilderSource resolves verdicts in-process from the shared dossier Builder —
// the default when the webhook runs inside the proxy binary. The dossier is a
// read-only projection over the verdicts already recorded by the pull path, so an
// image never pulled through the proxy resolves to "unknown".
type BuilderSource struct {
	builder dossierBuilder
}

// NewBuilderSource wraps a *dossier.Builder (or any compatible builder) as a
// VerdictSource.
func NewBuilderSource(b dossierBuilder) *BuilderSource { return &BuilderSource{builder: b} }

// Verdict implements VerdictSource against the in-process dossier Builder.
func (s *BuilderSource) Verdict(ctx context.Context, tenant string, ref ImageRef, ecosystem string, stripRegistry bool) (Verdict, error) {
	name, version := ref.Coordinate(stripRegistry)
	q := dossier.Query{
		Tenant:     tenant,
		Ecosystem:  ecosystem,
		Coordinate: name,
		Version:    version,
	}
	d := s.builder.Build(ctx, q)
	return verdictFromDossier(d), nil
}

// verdictFromDossier distills a dossier into the webhook's normalized Verdict.
func verdictFromDossier(d *dossier.Dossier) Verdict {
	if d == nil {
		return Verdict{Decision: dossier.VerdictUnknown}
	}
	return Verdict{
		Decision:  d.Headline.Verdict,
		RiskScore: d.Headline.RiskScore,
		RiskBand:  d.Headline.RiskBand,
		Reasons:   d.Headline.Reasons,
		Summary:   d.Headline.Summary,
	}
}
