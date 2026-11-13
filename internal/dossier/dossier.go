// Package dossier assembles a single read-only "360 view" of the complete
// security story for one artifact coordinate. Given a (tenant, ecosystem,
// coordinate[, version]) it fans out across the subsystems that already own the
// individual facts — provenance/source-commit (provgraph + buildprov), the
// unified admission findings (findings), the explainable risk score (riskscore),
// vulnerabilities and VEX state (vulnscan), license disposition (derived from
// findings), signature/attestation status (sigverify + attestbundle),
// approval/break-glass history (approvals), the reproducible-build verdict
// (rebuildverify), SBOM drift (sbomdiff), the LLM package-content scan verdict
// (llmpkgscan), and the correlated forensic event timeline (timeline) — and
// folds them into one opinionated, human-first card optimized for incident
// triage.
//
// Unlike the generic federated query DSL (internal/queryapi), this is a fixed
// projection: the caller does not choose fields, it gets the whole story. The
// package owns no source of truth; every fact is read live through a narrow
// provider interface, and a nil provider (its subsystem disabled or unwired)
// simply contributes an absent section. The fan-out is bounded by a per-source
// timeout so one slow or wedged subsystem degrades to a partial result rather
// than hanging the whole dossier.
package dossier

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/approvals"
	"github.com/blechschmidt/pullthrough-security/internal/attestbundle"
	"github.com/blechschmidt/pullthrough-security/internal/buildprov"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/provgraph"
	"github.com/blechschmidt/pullthrough-security/internal/pypiattest"
	"github.com/blechschmidt/pullthrough-security/internal/rebuildverify"
	"github.com/blechschmidt/pullthrough-security/internal/remediation"
	"github.com/blechschmidt/pullthrough-security/internal/riskscore"
	"github.com/blechschmidt/pullthrough-security/internal/sbomdiff"
	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
	"github.com/blechschmidt/pullthrough-security/internal/timeline"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// defaultSourceTimeout bounds each subsystem fan-out leg. The sources are almost
// all in-memory reads, so this is generous; it exists to keep one wedged
// subsystem (a blocking provgraph traversal, a slow timeline reconstruction)
// from stalling the whole dossier. A per-source overrun is reported as a timeout
// status and the section is left absent — the rest of the dossier still renders.
const defaultSourceTimeout = 3 * time.Second

// defaultTimelineLimit bounds the correlated event chain embedded in a dossier.
const defaultTimelineLimit = 100

// Source status values reported per fan-out leg.
const (
	StatusOK       = "ok"       // the source contributed data
	StatusEmpty    = "empty"    // the source is wired but had nothing for this coordinate
	StatusDisabled = "disabled" // the source is not wired/enabled
	StatusTimeout  = "timeout"  // the source exceeded its per-source budget
	StatusError    = "error"    // the source returned an error
)

// Query identifies the artifact whose dossier to assemble. Coordinate may be a
// bare package name or a "name@version" string; an explicit Version, when set,
// takes precedence. Tenant scopes the tenant-bearing sources (findings, risk,
// approvals, attestations); an empty tenant aggregates across tenants.
type Query struct {
	Tenant     string
	Ecosystem  string
	Coordinate string
	Version    string
}

// --- provider seams ---------------------------------------------------------
//
// Each provider is the narrow read-only interface onto one subsystem's existing
// read-model. Every concrete service already satisfies its provider, so wiring
// is a direct assignment. A nil provider contributes an absent section.

// FindingsProvider exposes the unified admission-findings store (Task 42). It is
// the spine: its documents carry the fullest artifact identity and the
// normalized cross-gate findings (vuln, license, signature, ...).
type FindingsProvider interface {
	Documents(tenant, q string) []findings.Document
}

// RiskProvider exposes the unified explainable risk score (Task 37).
type RiskProvider interface {
	Enabled() bool
	Recent(limit int) []riskscore.Assessment
}

// VulnProvider exposes cached vulnerability reports and quarantine state (Task 15/27).
type VulnProvider interface {
	Reports() []*vulnscan.Report
	IsQuarantined(digest string) bool
}

// SigverifyProvider exposes cached signature/attestation verification reports (Task 23).
type SigverifyProvider interface {
	Reports() []*sigverify.Report
}

// BuildProvProvider exposes inbound build-provenance verification reports (Task 72).
type BuildProvProvider interface {
	Enabled() bool
	Reports() []*buildprov.Report
}

// PyPIAttestProvider exposes inbound PyPI PEP 740 attestation verification reports
// (Task 146).
type PyPIAttestProvider interface {
	Enabled() bool
	Reports() []*pypiattest.Report
}

// ProvgraphProvider exposes the supply-chain graph's source-commit and
// blast-radius queries (Task 33).
type ProvgraphProvider interface {
	PathToCommit(ecosystem, name, version string) (provgraph.PathResult, error)
	ReverseDependencies(ecosystem, name, version string) (provgraph.DepResult, error)
}

// RebuildProvider exposes the reproducible-build verification results (Task 68).
type RebuildProvider interface {
	Enabled() bool
	Recent(limit int) []rebuildverify.Result
}

// SbomDriftProvider exposes the latest SBOM dependency-drift diff (Task 64).
type SbomDriftProvider interface {
	Enabled() bool
	DiffLatest(tenant, ecosystem, coordinate string) (*sbomdiff.Diff, bool)
}

// ApprovalsProvider exposes the quarantine-review / break-glass workflow (Task 50).
type ApprovalsProvider interface {
	Enabled() bool
	List(status string, limit int) []approvals.Request
}

// AttestProvider exposes the proxy's outbound attestation bundles (Task 46).
type AttestProvider interface {
	Get(tenant, pkg string) (*attestbundle.Bundle, bool)
}

// TimelineProvider exposes the forensic incident-timeline correlation (Task 77).
type TimelineProvider interface {
	Query(ctx context.Context, q timeline.Query) (timeline.Result, error)
}

// RemediationProvider exposes the automated dependency-remediation advisor (Task
// 121): for a flagged coordinate it computes the nearest safe upgrade. The
// remediation.Service satisfies it.
type RemediationProvider interface {
	Enabled() bool
	Advise(ctx context.Context, req remediation.Request) (*remediation.Advice, error)
}

// SuppressionProvider exposes the immutable suppression audit trail (Task 165):
// for a coordinate it returns every recorded suppression (VEX, reachability,
// policy, break-glass) newest-first. The *findings.SuppressionLedger satisfies it.
type SuppressionProvider interface {
	ByCoordinate(tenant, coordinate string) []findings.SuppressionRecord
}

// LLMPackageScanProvider exposes the sandboxed LLM package-content scan's stored
// verdicts (Task 173). ForCoordinate is tenant-scoped by the provider: a verdict
// quotes the package it describes, so a tenant-bound reader is given only
// verdicts on bytes its own tenant has pulled. Standing applies the gate's
// current thresholds and action to a stored verdict. The *llmpkgscan.Service
// satisfies it.
type LLMPackageScanProvider interface {
	Enabled() bool
	ForCoordinate(tenant, ecosystem, name, version string) []*llmpkgscan.Verdict
	Standing(v *llmpkgscan.Verdict) llmpkgscan.Standing
}

// ReleasesProvider lists the releases that ship a coordinate (Task 180),
// tenant-scoped: a tenant-bound reader sees its own tenant's releases only.
// version may be empty (every version of the package).
type ReleasesProvider interface {
	ReleasesShipping(ctx context.Context, tenant, ecosystem, name, version string) ([]ReleaseRef, error)
}

// RepositoryScansProvider lists the dependency scans of tracked repositories
// that read a coordinate (Task 181), tenant-scoped like the releases.
type RepositoryScansProvider interface {
	RepositoryScansOf(ctx context.Context, tenant, ecosystem, name, version string) ([]RepoScanRef, error)
}

// Providers bundles the optional subsystem read-models the dossier folds
// together. Any nil field yields an absent section reported as "disabled".
type Providers struct {
	Findings     FindingsProvider
	Risk         RiskProvider
	Vuln         VulnProvider
	Sigverify    SigverifyProvider
	BuildProv    BuildProvProvider
	PyPIAttest   PyPIAttestProvider
	Provgraph    ProvgraphProvider
	Rebuild      RebuildProvider
	SbomDrift    SbomDriftProvider
	Approvals    ApprovalsProvider
	Attest       AttestProvider
	Timeline     TimelineProvider
	Remediation  RemediationProvider
	Suppressions SuppressionProvider
	// LLMPackageScan is the LLM package-content scan gate (Task 173).
	LLMPackageScan LLMPackageScanProvider
	// Releases is the repository registry (Task 180).
	Releases ReleasesProvider
	// RepositoryScans is the registry's dependency scans (Task 181).
	RepositoryScans RepositoryScansProvider
}

// Config tunes the builder. The zero value is usable: it falls back to the
// package defaults and a real clock.
type Config struct {
	// SourceTimeout bounds each fan-out leg. Defaults to defaultSourceTimeout.
	SourceTimeout time.Duration
	// TimelineLimit bounds the embedded event chain. Defaults to defaultTimelineLimit.
	TimelineLimit int
	// Now supplies the clock (for deterministic tests). Defaults to time.Now.
	Now func() time.Time
}

// Builder assembles dossiers from the wired providers.
type Builder struct {
	providers Providers
	timeout   time.Duration
	tlLimit   int
	now       func() time.Time
}

// New constructs a Builder over the given providers.
func New(cfg Config, providers Providers) *Builder {
	b := &Builder{
		providers: providers,
		timeout:   cfg.SourceTimeout,
		tlLimit:   cfg.TimelineLimit,
		now:       cfg.Now,
	}
	if b.timeout <= 0 {
		b.timeout = defaultSourceTimeout
	}
	if b.tlLimit <= 0 {
		b.tlLimit = defaultTimelineLimit
	}
	if b.now == nil {
		b.now = time.Now
	}
	return b
}

// Sources reports which providers are wired and enabled, for the schema/health
// surface and so a caller can tell "absent" from "disabled".
func (b *Builder) Sources() map[string]bool {
	p := b.providers
	return map[string]bool{
		"findings":     p.Findings != nil,
		"riskscore":    p.Risk != nil && p.Risk.Enabled(),
		"vulnscan":     p.Vuln != nil,
		"sigverify":    p.Sigverify != nil,
		"buildprov":    p.BuildProv != nil && p.BuildProv.Enabled(),
		"pypiattest":   p.PyPIAttest != nil && p.PyPIAttest.Enabled(),
		"provgraph":    p.Provgraph != nil,
		"rebuild":      p.Rebuild != nil && p.Rebuild.Enabled(),
		"sbomdrift":    p.SbomDrift != nil && p.SbomDrift.Enabled(),
		"approvals":    p.Approvals != nil && p.Approvals.Enabled(),
		"attest":       p.Attest != nil,
		"timeline":     p.Timeline != nil,
		"suggestedfix": p.Remediation != nil && p.Remediation.Enabled(),
		"suppression":  p.Suppressions != nil,
		"llmpkgscan":   p.LLMPackageScan != nil && p.LLMPackageScan.Enabled(),
		"releases":     p.Releases != nil,
		"reposcans":    p.RepositoryScans != nil,
	}
}

// Build assembles the dossier for q. It never returns an error: a malformed or
// empty coordinate yields an empty-but-valid dossier, and any per-source failure
// is captured as a SourceStatus rather than aborting the whole projection.
func (b *Builder) Build(ctx context.Context, q Query) *Dossier {
	now := b.now().UTC()
	id := parseIdent(q)

	d := &Dossier{
		Tenant:      strings.TrimSpace(q.Tenant),
		Ecosystem:   id.eco,
		Name:        id.name,
		Version:     id.version,
		Coordinate:  id.coord,
		GeneratedAt: now,
	}

	// A coordinate is mandatory: without one there is nothing to pivot on.
	if id.name == "" && id.coord == "" {
		d.Headline = Headline{Verdict: VerdictUnknown, Summary: "no coordinate supplied"}
		return d
	}

	jobs := b.jobs(id, q.Tenant, now)

	var mu sync.Mutex
	results := make([]SourceStatus, len(jobs))
	var wg sync.WaitGroup
	for i := range jobs {
		j := jobs[i]
		st := SourceStatus{Source: j.name}
		if !j.enabled {
			st.Status = StatusDisabled
			results[i] = st
			continue
		}
		wg.Add(1)
		go func(idx int, j sourceJob, st SourceStatus) {
			defer wg.Done()
			sctx, cancel := context.WithTimeout(ctx, b.timeout)
			defer cancel()
			start := b.now()
			done := make(chan struct{})
			var status, detail string
			go func() {
				defer close(done)
				defer func() {
					// A panicking provider must not take down the dossier; treat
					// it as a source error.
					if rec := recover(); rec != nil {
						status, detail = StatusError, "panic in source"
					}
				}()
				status, detail = j.fn(sctx, &mu, d)
			}()
			select {
			case <-done:
				st.Status, st.Detail = status, detail
			case <-sctx.Done():
				st.Status = StatusTimeout
				st.Detail = sctx.Err().Error()
			}
			st.TookMS = b.now().Sub(start).Milliseconds()
			results[idx] = st
		}(i, j, st)
	}
	wg.Wait()

	d.Sources = results
	for _, s := range results {
		if s.Status == StatusTimeout || s.Status == StatusError {
			d.Partial = true
		}
	}

	d.Headline = synthesizeHeadline(d)
	return d
}

// sourceJob is one fan-out leg. fn does the source's work under the supplied
// mutex (it locks only while mutating the shared dossier) and returns the leg's
// terminal status and an optional human detail.
type sourceJob struct {
	name    string
	enabled bool
	fn      func(ctx context.Context, mu *sync.Mutex, d *Dossier) (status, detail string)
}

// jobs builds the ordered fan-out plan for the given identity and tenant. The
// order is the canonical display order; concurrency does not depend on it.
func (b *Builder) jobs(id ident, tenant string, now time.Time) []sourceJob {
	p := b.providers
	return []sourceJob{
		{name: "findings", enabled: p.Findings != nil, fn: func(ctx context.Context, mu *sync.Mutex, d *Dossier) (string, string) {
			return b.fillFindings(id, tenant, mu, d)
		}},
		{name: "riskscore", enabled: p.Risk != nil && p.Risk.Enabled(), fn: func(ctx context.Context, mu *sync.Mutex, d *Dossier) (string, string) {
			return b.fillRisk(id, tenant, mu, d)
		}},
		{name: "vulnscan", enabled: p.Vuln != nil, fn: func(ctx context.Context, mu *sync.Mutex, d *Dossier) (string, string) {
			return b.fillVuln(id, mu, d)
		}},
		{name: "sigverify", enabled: p.Sigverify != nil, fn: func(ctx context.Context, mu *sync.Mutex, d *Dossier) (string, string) {
			return b.fillSigverify(id, mu, d)
		}},
		{name: "provenance", enabled: p.BuildProv != nil || p.PyPIAttest != nil || p.Provgraph != nil, fn: func(ctx context.Context, mu *sync.Mutex, d *Dossier) (string, string) {
			return b.fillProvenance(id, mu, d)
		}},
		{name: "rebuild", enabled: p.Rebuild != nil && p.Rebuild.Enabled(), fn: func(ctx context.Context, mu *sync.Mutex, d *Dossier) (string, string) {
			return b.fillRebuild(id, mu, d)
		}},
		{name: "sbomdrift", enabled: p.SbomDrift != nil && p.SbomDrift.Enabled(), fn: func(ctx context.Context, mu *sync.Mutex, d *Dossier) (string, string) {
			return b.fillSbomDrift(id, tenant, mu, d)
		}},
		{name: "approvals", enabled: p.Approvals != nil && p.Approvals.Enabled(), fn: func(ctx context.Context, mu *sync.Mutex, d *Dossier) (string, string) {
			return b.fillApprovals(id, tenant, now, mu, d)
		}},
		{name: "attest", enabled: p.Attest != nil, fn: func(ctx context.Context, mu *sync.Mutex, d *Dossier) (string, string) {
			return b.fillAttest(id, tenant, mu, d)
		}},
		{name: "timeline", enabled: p.Timeline != nil, fn: func(ctx context.Context, mu *sync.Mutex, d *Dossier) (string, string) {
			return b.fillTimeline(ctx, id, tenant, mu, d)
		}},
		{name: "suggestedfix", enabled: p.Remediation != nil && p.Remediation.Enabled(), fn: func(ctx context.Context, mu *sync.Mutex, d *Dossier) (string, string) {
			return b.fillSuggestedFix(ctx, id, tenant, mu, d)
		}},
		{name: "suppression", enabled: p.Suppressions != nil, fn: func(ctx context.Context, mu *sync.Mutex, d *Dossier) (string, string) {
			return b.fillSuppression(id, tenant, mu, d)
		}},
		{name: "llmpkgscan", enabled: p.LLMPackageScan != nil && p.LLMPackageScan.Enabled(), fn: func(ctx context.Context, mu *sync.Mutex, d *Dossier) (string, string) {
			return b.fillLLMPackageScan(id, tenant, mu, d)
		}},
		{name: "releases", enabled: p.Releases != nil, fn: func(ctx context.Context, mu *sync.Mutex, d *Dossier) (string, string) {
			return b.fillReleases(ctx, id, tenant, mu, d)
		}},
		{name: "reposcans", enabled: p.RepositoryScans != nil, fn: func(ctx context.Context, mu *sync.Mutex, d *Dossier) (string, string) {
			return b.fillRepositoryScans(ctx, id, tenant, mu, d)
		}},
	}
}
