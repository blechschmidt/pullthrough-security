// Package queryapi implements a read-only, dependency-free federated query
// layer over the proxy's security data model. It joins the per-coordinate facts
// that today live in separate subsystems — the provenance/dependency graph
// (provgraph), normalized admission findings (findings), the unified risk score
// (riskscore), vulnerability/VEX state (vulnscan), outstanding break-glass
// exceptions (approvals), and recent SOC verdicts (secops) — into a single
// denormalized row per (tenant, ecosystem, coordinate). A small JSON
// query/projection DSL (see dsl.go and schema.go) then filters, orders,
// projects, and paginates those rows so operators and CI can ask cross-cutting
// questions that previously required hitting many admin endpoints and joining
// the results by hand.
//
// The package owns no source of truth: every fact is read live, through narrow
// provider interfaces, from the subsystem that owns it. A nil provider (its
// subsystem disabled or unwired) simply contributes nothing, so the layer
// degrades gracefully.
package queryapi

import (
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/approvals"
	"github.com/blechschmidt/pullthrough-security/internal/buildprov"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/metering"
	"github.com/blechschmidt/pullthrough-security/internal/provgraph"
	"github.com/blechschmidt/pullthrough-security/internal/rebuildverify"
	"github.com/blechschmidt/pullthrough-security/internal/riskscore"
	"github.com/blechschmidt/pullthrough-security/internal/sbomdiff"
	"github.com/blechschmidt/pullthrough-security/internal/secops"
	"github.com/blechschmidt/pullthrough-security/internal/snapshot"
	"github.com/blechschmidt/pullthrough-security/internal/timeline"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// neverServed is the sentinel age (in seconds) for a coordinate that has no
// recorded serve/verdict event. Treating "never served" as infinitely old means
// a recency filter such as `servedAgeSec lt 86400` naturally excludes it.
const neverServed = int64(1) << 62

// The provider interfaces are the narrow read-only seams the model is built
// through. Each concrete subsystem type satisfies its provider directly; any
// provider left nil is skipped.

// FindingsProvider exposes the aggregated admission-findings store (Task 42).
// It is the spine of the join: its documents are tenant-scoped and carry the
// fullest artifact identity (ecosystem, name, version, digest, coordinate).
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

// ApprovalsProvider exposes outstanding break-glass exceptions (Task 50).
type ApprovalsProvider interface {
	Enabled() bool
	List(status string, limit int) []approvals.Request
}

// ProvgraphProvider exposes blast-radius / reverse-dependency queries (Task 33),
// used to count how many downstream dependency paths reach a coordinate.
type ProvgraphProvider interface {
	ReverseDependencies(ecosystem, name, version string) (provgraph.DepResult, error)
}

// SecOpsProvider exposes the recent notable-verdict feed (Task 60), used to
// stamp each coordinate with its most recent serve decision and time.
type SecOpsProvider interface {
	Summary() secops.Summary
}

// SnapshotProvider exposes the organization snapshot live state and active freeze
// (Task 70), used to mark each coordinate with whether it was captured in the
// served-state snapshot and whether it is part of the currently-frozen set.
type SnapshotProvider interface {
	Enabled() bool
	QueryFacts() []snapshot.QueryFact
}

// TimelineProvider exposes the forensic incident-timeline correlation layer
// (Task 77): a per-coordinate roll-up of the unified, deduplicated event history
// (pulls, verdicts, overrides, anomalies, lockdown actions) reconstructed across
// subsystems, used to stamp each coordinate with how much forensic activity it
// has and whether any of it is Merkle-provable.
type TimelineProvider interface {
	CoordinateIndex() map[string]timeline.CoordinateStat
}

// BuildProvProvider exposes inbound build-provenance verification reports (Task
// 72), used to stamp each coordinate with its proven source commit/repository
// and the headline provenance-verification signals.
type BuildProvProvider interface {
	Enabled() bool
	Reports() []*buildprov.Report
}

// RebuildProvider exposes reproducible-build verification results (Task 68),
// used to stamp each coordinate with its rebuild verdict.
type RebuildProvider interface {
	Enabled() bool
	Recent(limit int) []rebuildverify.Result
}

// SbomDriftProvider exposes the latest SBOM dependency-drift diff (Task 64),
// used to stamp each coordinate with its drift score.
type SbomDriftProvider interface {
	Enabled() bool
	DiffLatest(tenant, ecosystem, coordinate string) (*sbomdiff.Diff, bool)
}

// MeteringProvider exposes per-tenant cumulative usage totals (Task 84), used to
// stamp each coordinate row with the consuming tenant's accumulated usage so
// queries can join supply-chain facts against consumption/chargeback.
type MeteringProvider interface {
	Enabled() bool
	TenantUsage(tenant string) (metering.TenantTotals, bool)
}

// Providers bundles the optional subsystem read-models the query layer joins.
// A nil field means the subsystem is disabled or unwired and contributes nothing.
type Providers struct {
	Findings  FindingsProvider
	Risk      RiskProvider
	Vuln      VulnProvider
	Approvals ApprovalsProvider
	Provgraph ProvgraphProvider
	SecOps    SecOpsProvider
	Snapshot  SnapshotProvider
	Timeline  TimelineProvider
	Metering  MeteringProvider
	BuildProv BuildProvProvider
	Rebuild   RebuildProvider
	SbomDrift SbomDriftProvider
}

// enabled reports which subsystems are contributing to the model, so the schema
// endpoint can advertise what is and is not wired.
func (p Providers) enabled() map[string]bool {
	return map[string]bool{
		"findings":  p.Findings != nil,
		"riskscore": p.Risk != nil && p.Risk.Enabled(),
		"vulnscan":  p.Vuln != nil,
		"approvals": p.Approvals != nil && p.Approvals.Enabled(),
		"provgraph": p.Provgraph != nil,
		"secops":    p.SecOps != nil,
		"snapshot":  p.Snapshot != nil && p.Snapshot.Enabled(),
		"timeline":  p.Timeline != nil,
		"metering":  p.Metering != nil && p.Metering.Enabled(),
		"buildprov": p.BuildProv != nil && p.BuildProv.Enabled(),
		"rebuild":   p.Rebuild != nil && p.Rebuild.Enabled(),
		"sbomdrift": p.SbomDrift != nil && p.SbomDrift.Enabled(),
	}
}

// Record is the denormalized, queryable join of every subsystem fact about a
// single (tenant, ecosystem, coordinate). The field registry in schema.go maps
// stable query field names onto these struct fields; the DSL never touches the
// struct directly.
type Record struct {
	// Identity.
	Tenant     string `json:"tenant,omitempty"`
	Ecosystem  string `json:"ecosystem,omitempty"`
	Name       string `json:"name,omitempty"`
	Version    string `json:"version,omitempty"`
	Coordinate string `json:"coordinate,omitempty"` // normalized name@version
	Digest     string `json:"digest,omitempty"`
	Backend    string `json:"backend,omitempty"`

	// Risk (riskscore).
	HasRisk     bool   `json:"hasRisk"`
	RiskScore   int    `json:"riskScore"`
	RiskBand    string `json:"riskBand,omitempty"`
	RiskBlock   bool   `json:"riskBlock"`
	RiskWarn    bool   `json:"riskWarn"`
	RiskExceeds bool   `json:"riskExceeds"`
	// BlockAdjacent is a convenience derivation: the risk band is high or
	// critical (i.e. at or one step below an outright block under a typical
	// block-above-high threshold).
	BlockAdjacent bool `json:"blockAdjacent"`

	// Signatures (derived from the sigverify findings gate). SignatureVerified is
	// true unless a non-suppressed unverified-signature finding is present.
	SignatureVerified bool   `json:"signatureVerified"`
	SignatureStatus   string `json:"signatureStatus,omitempty"` // verified|unverified

	// Findings (admission gates).
	Findings         int      `json:"findings"`
	BlockingFindings int      `json:"blockingFindings"`
	FindingGates     []string `json:"findingGates,omitempty"`
	FindingRules     []string `json:"findingRules,omitempty"`
	WorstSeverity    string   `json:"worstSeverity,omitempty"`

	// Vulnerabilities (vulnscan / VEX).
	HasVuln       bool     `json:"hasVuln"`
	VulnCritical  int      `json:"vulnCritical"`
	VulnHigh      int      `json:"vulnHigh"`
	VulnMedium    int      `json:"vulnMedium"`
	VulnLow       int      `json:"vulnLow"`
	VulnTotal     int      `json:"vulnTotal"`
	MaxCVSS       float64  `json:"maxCvss"`
	MaxSeverity   string   `json:"maxSeverity,omitempty"`
	CVEs          []string `json:"cves,omitempty"`
	Quarantined   bool     `json:"quarantined"`
	VEXSuppressed int      `json:"vexSuppressed"`

	// Provenance graph (downstream blast radius).
	DownstreamPaths  int `json:"downstreamPaths"`
	DirectDependents int `json:"directDependents"`

	// Source identity & inbound build provenance (findings spine + buildprov,
	// Task 72). These are the dossier (Task 87) field set surfaced for querying.
	SourceCommit       string `json:"sourceCommit,omitempty"`
	SourceRepo         string `json:"sourceRepo,omitempty"`
	HasProvenance      bool   `json:"hasProvenance"`
	ProvenanceVerified bool   `json:"provenanceVerified"`
	SourceVerified     bool   `json:"sourceVerified"`
	ProvenanceMismatch bool   `json:"provenanceMismatch"`

	// Reproducible-build verification (rebuildverify, Task 68).
	RebuildVerdict string `json:"rebuildVerdict,omitempty"`
	Reproducible   bool   `json:"reproducible"`

	// SBOM dependency drift (sbomdiff, Task 64).
	SbomDriftScore       float64 `json:"sbomDriftScore"`
	SbomDriftSignificant bool    `json:"sbomDriftSignificant"`

	// Approvals (outstanding break-glass exceptions).
	OutstandingApprovals int      `json:"outstandingApprovals"`
	ApprovalGates        []string `json:"approvalGates,omitempty"`

	// Recent serve decision (secops).
	LastVerdict     string    `json:"lastVerdict,omitempty"` // block|warn|admit
	LastVerdictGate string    `json:"lastVerdictGate,omitempty"`
	Served          bool      `json:"served"`
	ServedAt        time.Time `json:"servedAt,omitempty"`
	ServedAgeSec    int64     `json:"servedAgeSec"`

	// Snapshot / freeze (Task 70).
	Snapshotted     bool   `json:"snapshotted"`
	Frozen          bool   `json:"frozen"`
	SnapshotVerdict string `json:"snapshotVerdict,omitempty"`
	SnapshotBand    string `json:"snapshotBand,omitempty"`

	// Forensic timeline activity (Task 77).
	TimelineEvents     int       `json:"timelineEvents"`
	TimelineLastSource string    `json:"timelineLastSource,omitempty"`
	TimelineLastAt     time.Time `json:"timelineLastAt,omitempty"`
	TimelineProvable   bool      `json:"timelineProvable"`

	// Consuming-tenant usage totals (metering, Task 84). These are tenant-grain
	// cumulative values stamped onto every coordinate row for the tenant, so a
	// query can join supply-chain facts against consumption/chargeback.
	TenantRequests        int64 `json:"tenantRequests,omitempty"`
	TenantBytesServed     int64 `json:"tenantBytesServed,omitempty"`
	TenantStorageBytes    int64 `json:"tenantStorageBytes,omitempty"`
	TenantScanInvocations int64 `json:"tenantScanInvocations,omitempty"`
	TenantScanCostMicros  int64 `json:"tenantScanCostMicros,omitempty"`
	TenantBlocked         int64 `json:"tenantBlocked,omitempty"`
	TenantQuarantined     int64 `json:"tenantQuarantined,omitempty"`

	FirstSeen time.Time `json:"firstSeen,omitempty"`
	LastSeen  time.Time `json:"lastSeen,omitempty"`
}

// modelIndex accumulates records during a build, keyed by the canonical
// (tenant, ecosystem, coordinate) identity, with secondary indexes for the
// tenant-less sources (vulnscan, secops) that join by digest or coordinate.
type modelIndex struct {
	byKey    map[string]*Record
	byDigest map[string][]*Record
	byCoord  map[string][]*Record // key: ecosystem|coordinate
	order    []*Record            // insertion order, for deterministic output
}

func newModelIndex() *modelIndex {
	return &modelIndex{
		byKey:    make(map[string]*Record),
		byDigest: make(map[string][]*Record),
		byCoord:  make(map[string][]*Record),
	}
}

// ensure returns the record for the given identity, creating it if absent and
// registering it in the secondary indexes.
func (mi *modelIndex) ensure(tenant, ecosystem, name, version, coordinate, digest, backend string) *Record {
	coord := normalizeCoordinate(ecosystem, name, version, coordinate)
	key := recordKey(tenant, ecosystem, coord)
	r := mi.byKey[key]
	if r == nil {
		r = &Record{
			Tenant:            strings.TrimSpace(tenant),
			Ecosystem:         strings.TrimSpace(ecosystem),
			Name:              strings.TrimSpace(name),
			Version:           strings.TrimSpace(version),
			Coordinate:        coord,
			Backend:           strings.TrimSpace(backend),
			SignatureVerified: true, // assume verified until a finding says otherwise
			ServedAgeSec:      neverServed,
		}
		mi.byKey[key] = r
		mi.order = append(mi.order, r)
		mi.indexCoord(r)
	}
	// Backfill identity fields that a later, richer source may supply.
	if r.Name == "" && name != "" {
		r.Name = strings.TrimSpace(name)
	}
	if r.Version == "" && version != "" {
		r.Version = strings.TrimSpace(version)
	}
	if r.Backend == "" && backend != "" {
		r.Backend = strings.TrimSpace(backend)
	}
	if digest != "" {
		mi.setDigest(r, digest)
	}
	return r
}

func (mi *modelIndex) indexCoord(r *Record) {
	ck := coordIndexKey(r.Ecosystem, r.Coordinate)
	if ck != "" {
		mi.byCoord[ck] = append(mi.byCoord[ck], r)
	}
}

func (mi *modelIndex) setDigest(r *Record, digest string) {
	if r.Digest == digest {
		return
	}
	if r.Digest == "" {
		r.Digest = digest
		mi.byDigest[digest] = append(mi.byDigest[digest], r)
	}
}

// matchVuln returns the records a tenant-less vulnerability report should
// enrich: first by digest, then falling back to ecosystem+coordinate.
func (mi *modelIndex) matchVuln(art vulnscan.Artifact) []*Record {
	if art.Digest != "" {
		if rs := mi.byDigest[art.Digest]; len(rs) > 0 {
			return rs
		}
	}
	coord := normalizeCoordinate(art.Ecosystem, art.Name, art.Version, "")
	return mi.byCoord[coordIndexKey(art.Ecosystem, coord)]
}

// matchEvent returns the records a tenant-less secops verdict should stamp,
// matched by ecosystem+coordinate.
func (mi *modelIndex) matchEvent(ecosystem, artifact string) []*Record {
	coord := normalizeCoordinate(ecosystem, "", "", artifact)
	return mi.byCoord[coordIndexKey(ecosystem, coord)]
}

// build assembles the full denormalized model from every wired provider and
// finalizes the derived fields relative to now.
func (p Providers) build(now time.Time) []*Record {
	mi := newModelIndex()

	// 1. Findings — the tenant-bearing spine.
	if p.Findings != nil {
		docs := p.Findings.Documents("", "")
		for i := range docs {
			d := &docs[i]
			r := mi.ensure(d.Tenant, d.Artifact.Ecosystem, d.Artifact.Name, d.Artifact.Version, d.Artifact.Coordinate, d.Artifact.Digest, d.Artifact.Backend)
			mergeFindings(r, d)
			if r.SourceCommit == "" && d.Artifact.CommitSHA != "" {
				r.SourceCommit = d.Artifact.CommitSHA
			}
			if r.SourceRepo == "" && d.Artifact.RepositoryURL != "" {
				r.SourceRepo = d.Artifact.RepositoryURL
			}
			touch(r, d.GeneratedAt)
		}
	}

	// 2. Risk — tenant-bearing.
	if p.Risk != nil && p.Risk.Enabled() {
		for _, a := range p.Risk.Recent(0) {
			r := mi.ensure(a.Tenant, a.Artifact.Ecosystem, a.Artifact.Name, a.Artifact.Version, a.Artifact.Coordinate, a.Artifact.Digest, a.Artifact.Backend)
			mergeRisk(r, a)
			touch(r, a.ScoredAt)
		}
	}

	// 3. Approvals — outstanding (currently-active) break-glass grants only.
	if p.Approvals != nil && p.Approvals.Enabled() {
		for _, req := range p.Approvals.List(string(approvals.StatusApproved), 0) {
			if req.Status != approvals.StatusApproved || !req.ExpiresAt.After(now) {
				continue
			}
			r := mi.ensure(req.Tenant, req.Ecosystem, "", "", req.Coordinate, "", req.Backend)
			r.OutstandingApprovals++
			addUnique(&r.ApprovalGates, req.Gate)
			touch(r, req.GrantedAt)
		}
	}

	// 4. Vulnerabilities — tenant-less; enrich matching records (by digest, then
	//    coordinate), creating a tenant-less record only when nothing matches.
	if p.Vuln != nil {
		for _, rep := range p.Vuln.Reports() {
			if rep == nil {
				continue
			}
			targets := mi.matchVuln(rep.Artifact)
			if len(targets) == 0 {
				targets = []*Record{mi.ensure("", rep.Artifact.Ecosystem, rep.Artifact.Name, rep.Artifact.Version, "", rep.Artifact.Digest, "")}
			}
			for _, r := range targets {
				mergeVuln(r, rep, p.Vuln)
				touch(r, rep.ScannedAt)
			}
		}
	}

	// 5. Recent SOC verdicts — tenant-less stamp of the most recent serve decision.
	if p.SecOps != nil {
		recent := p.SecOps.Summary().Recent
		// Oldest-first so the newest verdict wins the per-record stamp.
		for i := len(recent) - 1; i >= 0; i-- {
			ev := recent[i]
			if ev.Artifact == "" {
				continue
			}
			for _, r := range mi.matchEvent(ev.Ecosystem, ev.Artifact) {
				mergeEvent(r, ev)
				touch(r, ev.Time)
			}
		}
	}

	// 6. Downstream blast radius — count reverse-dependency paths per coordinate.
	if p.Provgraph != nil {
		for _, r := range mi.order {
			if r.Name == "" {
				continue
			}
			if dep, err := p.Provgraph.ReverseDependencies(r.Ecosystem, r.Name, r.Version); err == nil && dep.Found {
				r.DownstreamPaths = dep.Total
				r.DirectDependents = dep.Direct
			}
		}
	}

	// 7. Snapshot live state / freeze — tenant-bearing; mark each served
	//    coordinate as captured, and whether it is in the active frozen set.
	if p.Snapshot != nil && p.Snapshot.Enabled() {
		for _, f := range p.Snapshot.QueryFacts() {
			r := mi.ensure(f.Tenant, f.Ecosystem, f.Name, f.Version, f.Coordinate, f.Digest, "")
			r.Snapshotted = true
			r.Frozen = f.Frozen
			r.SnapshotVerdict = f.Verdict
			r.SnapshotBand = f.RiskBand
			touch(r, f.ServedAt)
		}
	}

	// 8. Forensic timeline activity — stamp each coordinate with its correlated
	//    event count, latest source, and whether any of it is Merkle-provable. The
	//    index is built once and looked up per record, so the join stays O(records).
	if p.Timeline != nil {
		idx := p.Timeline.CoordinateIndex()
		for _, r := range mi.order {
			if st, ok := idx[coordIndexKey(r.Ecosystem, r.Coordinate)]; ok {
				r.TimelineEvents = st.Events
				r.TimelineLastSource = st.LastSource
				r.TimelineLastAt = st.LastAt
				r.TimelineProvable = st.HasProof
				touch(r, st.LastAt)
			}
		}
	}

	// 9. Consuming-tenant usage totals — stamp each coordinate with its tenant's
	//    cumulative usage. Looked up once per distinct tenant and reused.
	if p.Metering != nil && p.Metering.Enabled() {
		cache := map[string]metering.TenantTotals{}
		seen := map[string]bool{}
		for _, r := range mi.order {
			if r.Tenant == "" {
				continue
			}
			tt, ok := cache[r.Tenant]
			if !ok && !seen[r.Tenant] {
				tt, ok = p.Metering.TenantUsage(r.Tenant)
				seen[r.Tenant] = true
				if ok {
					cache[r.Tenant] = tt
				}
			}
			if ok {
				r.TenantRequests = tt.Requests
				r.TenantBytesServed = tt.BytesServed
				r.TenantStorageBytes = tt.StorageBytes
				r.TenantScanInvocations = tt.ScanInvocations
				r.TenantScanCostMicros = tt.ScanCostMicros
				r.TenantBlocked = tt.Blocked
				r.TenantQuarantined = tt.Quarantined
			}
		}
	}

	// 10. Inbound build provenance — tenant-less; enrich matching records by
	//     digest then coordinate with the proven source and verification signals.
	if p.BuildProv != nil && p.BuildProv.Enabled() {
		for _, rep := range p.BuildProv.Reports() {
			if rep == nil {
				continue
			}
			art := vulnscan.Artifact{Ecosystem: rep.Artifact.Ecosystem, Name: rep.Artifact.Name, Version: rep.Artifact.Version, Digest: rep.Artifact.Digest}
			targets := mi.matchVuln(art)
			for _, r := range targets {
				mergeBuildProv(r, rep)
				touch(r, rep.VerifiedAt)
			}
		}
	}

	// 11. Reproducible-build verdicts — tenant-bearing; match by coordinate.
	if p.Rebuild != nil && p.Rebuild.Enabled() {
		for _, res := range p.Rebuild.Recent(0) {
			coord := normalizeCoordinate(res.Ecosystem, res.Name, res.Version, res.Coordinate)
			for _, r := range mi.byCoord[coordIndexKey(res.Ecosystem, coord)] {
				if r.RebuildVerdict == "" || res.ComputedAt.After(r.LastSeen) {
					r.RebuildVerdict = string(res.Verdict)
					r.Reproducible = res.Reproducible
				}
				touch(r, res.ComputedAt)
			}
		}
	}

	// 12. SBOM drift — tenant-bearing; one latest-diff lookup per record.
	if p.SbomDrift != nil && p.SbomDrift.Enabled() {
		for _, r := range mi.order {
			if r.Name == "" {
				continue
			}
			if diff, ok := p.SbomDrift.DiffLatest(r.Tenant, r.Ecosystem, r.Name); ok && diff != nil {
				r.SbomDriftScore = diff.DriftScore
				r.SbomDriftSignificant = diff.Significant
			}
		}
	}

	for _, r := range mi.order {
		finalize(r, now)
	}
	return mi.order
}

// mergeBuildProv folds an inbound build-provenance report into a record.
func mergeBuildProv(r *Record, rep *buildprov.Report) {
	r.HasProvenance = r.HasProvenance || rep.Present
	r.ProvenanceVerified = r.ProvenanceVerified || rep.Verified
	r.SourceVerified = r.SourceVerified || rep.SourceVerified
	r.ProvenanceMismatch = r.ProvenanceMismatch || rep.Mismatch
	if rep.CommitSHA != "" {
		r.SourceCommit = rep.CommitSHA
	}
	if rep.RepositoryURL != "" && r.SourceRepo == "" {
		r.SourceRepo = rep.RepositoryURL
	}
}

func mergeFindings(r *Record, d *findings.Document) {
	for i := range d.Findings {
		f := &d.Findings[i]
		// The sigverify gate is authoritative for signature state even when the
		// finding is VEX-suppressed: a suppressed unverified-signature finding
		// still means the signature was not verified.
		if f.Gate == findings.GateSigverify {
			r.SignatureVerified = false
			r.SignatureStatus = "unverified"
		}
		if f.Suppressed {
			continue
		}
		r.Findings++
		if f.Level == findings.LevelError {
			r.BlockingFindings++
		}
		addUnique(&r.FindingGates, string(f.Gate))
		if f.RuleID != "" {
			addUnique(&r.FindingRules, f.RuleID)
		}
		r.WorstSeverity = worseFindingSeverity(r.WorstSeverity, string(f.Severity))
	}
	if r.SignatureStatus == "" {
		r.SignatureStatus = "verified"
	}
}

func mergeRisk(r *Record, a riskscore.Assessment) {
	// Keep the highest-scoring assessment when a coordinate has several.
	if r.HasRisk && a.Score <= r.RiskScore {
		return
	}
	r.HasRisk = true
	r.RiskScore = a.Score
	r.RiskBand = string(a.Band)
	r.RiskBlock = a.Block
	r.RiskWarn = a.Warn
	r.RiskExceeds = a.Exceeds
}

func mergeVuln(r *Record, rep *vulnscan.Report, vp VulnProvider) {
	r.HasVuln = true
	r.VulnCritical += rep.Counts.Critical
	r.VulnHigh += rep.Counts.High
	r.VulnMedium += rep.Counts.Medium
	r.VulnLow += rep.Counts.Low
	r.VulnTotal += rep.Counts.Total()
	r.VEXSuppressed += rep.VEXSuppressed
	if rep.MaxCVSS > r.MaxCVSS {
		r.MaxCVSS = rep.MaxCVSS
	}
	r.MaxSeverity = worseFindingSeverity(r.MaxSeverity, string(rep.MaxSeverity))
	for i := range rep.Vulnerabilities {
		v := &rep.Vulnerabilities[i]
		if v.Withdrawn || v.Suppressed || v.ID == "" {
			continue
		}
		addUnique(&r.CVEs, v.ID)
	}
	if rep.Digest != "" && vp.IsQuarantined(rep.Digest) {
		r.Quarantined = true
	}
}

func mergeEvent(r *Record, ev secops.NotableEvent) {
	// The model walks oldest-first, so the last write wins (the newest verdict).
	r.Served = true
	r.LastVerdict = strings.ToLower(string(ev.Outcome))
	r.LastVerdictGate = ev.Gate
	if ev.Backend != "" && r.Backend == "" {
		r.Backend = ev.Backend
	}
	if !ev.Time.IsZero() {
		if r.ServedAt.IsZero() || ev.Time.After(r.ServedAt) {
			r.ServedAt = ev.Time
		}
	}
}

// finalize computes the derived fields that depend on the build clock and sorts
// the multi-valued fields so output is deterministic.
func finalize(r *Record, now time.Time) {
	r.BlockAdjacent = r.RiskBand == string(riskscore.BandHigh) || r.RiskBand == string(riskscore.BandCritical)
	if r.Served && !r.ServedAt.IsZero() {
		age := int64(now.Sub(r.ServedAt).Seconds())
		if age < 0 {
			age = 0
		}
		r.ServedAgeSec = age
	} else {
		r.ServedAgeSec = neverServed
	}
	sort.Strings(r.CVEs)
	sort.Strings(r.FindingGates)
	sort.Strings(r.FindingRules)
	sort.Strings(r.ApprovalGates)
}

func touch(r *Record, t time.Time) {
	if t.IsZero() {
		return
	}
	if r.FirstSeen.IsZero() || t.Before(r.FirstSeen) {
		r.FirstSeen = t
	}
	if t.After(r.LastSeen) {
		r.LastSeen = t
	}
}

// --- identity normalization -------------------------------------------------

// normalizeCoordinate produces a stable join coordinate. When name (and
// optionally version) are known it prefers name@version, which is consistent
// across the findings/risk/vuln sources. Otherwise it falls back to the supplied
// coordinate string, stripping any leading "ecosystem/" qualifier so that
// "npm/lodash@4.17.21" and "lodash@4.17.21" join.
func normalizeCoordinate(ecosystem, name, version, coordinate string) string {
	name = strings.TrimSpace(name)
	if name != "" {
		if v := strings.TrimSpace(version); v != "" {
			return name + "@" + v
		}
		return name
	}
	c := strings.TrimSpace(coordinate)
	if c == "" {
		return ""
	}
	if eco := strings.TrimSpace(ecosystem); eco != "" {
		c = strings.TrimPrefix(c, eco+"/")
	}
	// Strip a generic leading "<something>/" ecosystem qualifier if present.
	if i := strings.IndexByte(c, '/'); i >= 0 && !strings.ContainsAny(c[:i], "@") {
		c = c[i+1:]
	}
	return c
}

func recordKey(tenant, ecosystem, coord string) string {
	return strings.ToLower(strings.TrimSpace(tenant)) + "\x00" +
		strings.ToLower(strings.TrimSpace(ecosystem)) + "\x00" +
		strings.ToLower(coord)
}

func coordIndexKey(ecosystem, coord string) string {
	if coord == "" {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(ecosystem)) + "\x00" + strings.ToLower(coord)
}

func addUnique(dst *[]string, v string) {
	v = strings.TrimSpace(v)
	if v == "" {
		return
	}
	for _, e := range *dst {
		if e == v {
			return
		}
	}
	*dst = append(*dst, v)
}

// severityRank orders canonical severities for "worst-of" reduction.
var severityRank = map[string]int{
	"none": 0, "": 0, "unknown": 1, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5,
}

func worseFindingSeverity(cur, next string) string {
	cur = strings.ToLower(cur)
	next = strings.ToLower(next)
	if severityRank[next] > severityRank[cur] {
		return next
	}
	if cur == "" {
		return next
	}
	return cur
}
