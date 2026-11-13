package queryapi

import "sort"

// FieldKind classifies a queryable field's value type, which determines the set
// of operators it accepts and how values coerce and compare.
type FieldKind string

const (
	KindString FieldKind = "string" // case-insensitive string
	KindNumber FieldKind = "number" // integer or float
	KindBool   FieldKind = "bool"
	KindList   FieldKind = "list" // []string (set membership)
	KindTime   FieldKind = "time" // RFC3339 in output; not filterable
)

// Field is one column in the stable query schema: a name, its value kind, a
// human description, whether predicates may reference it, and the accessor that
// projects it out of a Record.
type Field struct {
	Name       string    `json:"name"`
	Kind       FieldKind `json:"kind"`
	Desc       string    `json:"description"`
	Filterable bool      `json:"filterable"`
	get        func(*Record) any
}

// iv/fv/iv64 box numeric accessor results so the field literals stay terse.
func iv(n int) any     { return n }
func fv(f float64) any { return f }

// fieldList is the canonical, stable field registry. Adding a field here is the
// only change needed to expose a new queryable/projectable column; the DSL,
// schema doc, UI console, and ptctl all read from it. Order is the documentation
// order.
var fieldList = []Field{
	// Identity.
	{Name: "tenant", Kind: KindString, Filterable: true, Desc: "Tenant/team scope the coordinate was served to.", get: func(r *Record) any { return r.Tenant }},
	{Name: "ecosystem", Kind: KindString, Filterable: true, Desc: "Package ecosystem (npm, pypi, go, maven, docker, ...).", get: func(r *Record) any { return r.Ecosystem }},
	{Name: "name", Kind: KindString, Filterable: true, Desc: "Package name.", get: func(r *Record) any { return r.Name }},
	{Name: "version", Kind: KindString, Filterable: true, Desc: "Package version.", get: func(r *Record) any { return r.Version }},
	{Name: "coordinate", Kind: KindString, Filterable: true, Desc: "Normalized name@version coordinate.", get: func(r *Record) any { return r.Coordinate }},
	{Name: "digest", Kind: KindString, Filterable: true, Desc: "Content digest, when known.", get: func(r *Record) any { return r.Digest }},
	{Name: "backend", Kind: KindString, Filterable: true, Desc: "Serving backend name.", get: func(r *Record) any { return r.Backend }},

	// Risk.
	{Name: "hasRisk", Kind: KindBool, Filterable: true, Desc: "A risk assessment exists for the coordinate.", get: func(r *Record) any { return r.HasRisk }},
	{Name: "riskScore", Kind: KindNumber, Filterable: true, Desc: "Unified risk score, 0-100.", get: func(r *Record) any { return iv(r.RiskScore) }},
	{Name: "riskBand", Kind: KindString, Filterable: true, Desc: "Risk band: low|medium|high|critical.", get: func(r *Record) any { return r.RiskBand }},
	{Name: "riskBlock", Kind: KindBool, Filterable: true, Desc: "Risk threshold marks the coordinate for block.", get: func(r *Record) any { return r.RiskBlock }},
	{Name: "riskWarn", Kind: KindBool, Filterable: true, Desc: "Risk threshold marks the coordinate for warn.", get: func(r *Record) any { return r.RiskWarn }},
	{Name: "blockAdjacent", Kind: KindBool, Filterable: true, Desc: "Risk band is high or critical (block-adjacent).", get: func(r *Record) any { return r.BlockAdjacent }},

	// Signature.
	{Name: "signatureVerified", Kind: KindBool, Filterable: true, Desc: "No unverified-signature finding is present (assumed true absent a sigverify finding).", get: func(r *Record) any { return r.SignatureVerified }},
	{Name: "signatureStatus", Kind: KindString, Filterable: true, Desc: "verified|unverified.", get: func(r *Record) any { return r.SignatureStatus }},

	// Findings.
	{Name: "findings", Kind: KindNumber, Filterable: true, Desc: "Count of non-suppressed admission findings.", get: func(r *Record) any { return iv(r.Findings) }},
	{Name: "blockingFindings", Kind: KindNumber, Filterable: true, Desc: "Count of error-level (build-failing) findings.", get: func(r *Record) any { return iv(r.BlockingFindings) }},
	{Name: "findingGates", Kind: KindList, Filterable: true, Desc: "Gates that produced findings (vulnscan, license, sigverify, ...).", get: func(r *Record) any { return r.FindingGates }},
	{Name: "findingRules", Kind: KindList, Filterable: true, Desc: "Catalog rule IDs of the findings.", get: func(r *Record) any { return r.FindingRules }},
	{Name: "worstSeverity", Kind: KindString, Filterable: true, Desc: "Worst finding severity.", get: func(r *Record) any { return r.WorstSeverity }},

	// Vulnerabilities.
	{Name: "hasVuln", Kind: KindBool, Filterable: true, Desc: "A vulnerability report exists for the coordinate.", get: func(r *Record) any { return r.HasVuln }},
	{Name: "vulnCritical", Kind: KindNumber, Filterable: true, Desc: "Critical-severity vulnerability count.", get: func(r *Record) any { return iv(r.VulnCritical) }},
	{Name: "vulnHigh", Kind: KindNumber, Filterable: true, Desc: "High-severity vulnerability count.", get: func(r *Record) any { return iv(r.VulnHigh) }},
	{Name: "vulnMedium", Kind: KindNumber, Filterable: true, Desc: "Medium-severity vulnerability count.", get: func(r *Record) any { return iv(r.VulnMedium) }},
	{Name: "vulnLow", Kind: KindNumber, Filterable: true, Desc: "Low-severity vulnerability count.", get: func(r *Record) any { return iv(r.VulnLow) }},
	{Name: "vulnTotal", Kind: KindNumber, Filterable: true, Desc: "Total vulnerability count.", get: func(r *Record) any { return iv(r.VulnTotal) }},
	{Name: "maxCvss", Kind: KindNumber, Filterable: true, Desc: "Highest CVSS score across the coordinate's vulnerabilities.", get: func(r *Record) any { return fv(r.MaxCVSS) }},
	{Name: "maxSeverity", Kind: KindString, Filterable: true, Desc: "Highest vulnerability severity.", get: func(r *Record) any { return r.MaxSeverity }},
	{Name: "cves", Kind: KindList, Filterable: true, Desc: "Vulnerability identifiers (CVE/GHSA/OSV).", get: func(r *Record) any { return r.CVEs }},
	{Name: "quarantined", Kind: KindBool, Filterable: true, Desc: "The artifact is currently quarantined by the vuln gate.", get: func(r *Record) any { return r.Quarantined }},
	{Name: "vexSuppressed", Kind: KindNumber, Filterable: true, Desc: "Count of VEX-suppressed vulnerabilities.", get: func(r *Record) any { return iv(r.VEXSuppressed) }},

	// Provenance graph.
	{Name: "downstreamPaths", Kind: KindNumber, Filterable: true, Desc: "Number of downstream dependency paths (reverse-dependency blast radius).", get: func(r *Record) any { return iv(r.DownstreamPaths) }},
	{Name: "directDependents", Kind: KindNumber, Filterable: true, Desc: "Number of direct downstream dependents.", get: func(r *Record) any { return iv(r.DirectDependents) }},

	// Source identity & inbound build provenance (dossier field set, Task 87).
	{Name: "sourceCommit", Kind: KindString, Filterable: true, Desc: "Proven or claimed source commit SHA bound to the artifact.", get: func(r *Record) any { return r.SourceCommit }},
	{Name: "sourceRepo", Kind: KindString, Filterable: true, Desc: "Source repository URL bound to the artifact.", get: func(r *Record) any { return r.SourceRepo }},
	{Name: "hasProvenance", Kind: KindBool, Filterable: true, Desc: "An inbound build-provenance attestation was discovered.", get: func(r *Record) any { return r.HasProvenance }},
	{Name: "provenanceVerified", Kind: KindBool, Filterable: true, Desc: "An inbound provenance attestation cryptographically verified and bound the digest.", get: func(r *Record) any { return r.ProvenanceVerified }},
	{Name: "sourceVerified", Kind: KindBool, Filterable: true, Desc: "A verified attestation chained to a trusted root with an allowed identity.", get: func(r *Record) any { return r.SourceVerified }},
	{Name: "provenanceMismatch", Kind: KindBool, Filterable: true, Desc: "The proven source disagrees with the claimed one.", get: func(r *Record) any { return r.ProvenanceMismatch }},

	// Reproducible build (Task 68).
	{Name: "rebuildVerdict", Kind: KindString, Filterable: true, Desc: "Reproducible-build verdict: reproducible|mismatch|unsupported|unattested.", get: func(r *Record) any { return r.RebuildVerdict }},
	{Name: "reproducible", Kind: KindBool, Filterable: true, Desc: "The artifact rebuilt bit-for-bit from its source commit.", get: func(r *Record) any { return r.Reproducible }},

	// SBOM drift (Task 64).
	{Name: "sbomDriftScore", Kind: KindNumber, Filterable: true, Desc: "Composite 0-100 SBOM dependency-drift score for the latest version transition.", get: func(r *Record) any { return fv(r.SbomDriftScore) }},
	{Name: "sbomDriftSignificant", Kind: KindBool, Filterable: true, Desc: "The latest SBOM drift met the significance threshold.", get: func(r *Record) any { return r.SbomDriftSignificant }},

	// Approvals.
	{Name: "outstandingApprovals", Kind: KindNumber, Filterable: true, Desc: "Count of active break-glass exceptions.", get: func(r *Record) any { return iv(r.OutstandingApprovals) }},
	{Name: "approvalGates", Kind: KindList, Filterable: true, Desc: "Gates with active break-glass exceptions.", get: func(r *Record) any { return r.ApprovalGates }},

	// Recent serve decision.
	{Name: "served", Kind: KindBool, Filterable: true, Desc: "A serve/verdict event was recorded for the coordinate.", get: func(r *Record) any { return r.Served }},
	{Name: "lastVerdict", Kind: KindString, Filterable: true, Desc: "Most recent serve decision: block|warn|admit.", get: func(r *Record) any { return r.LastVerdict }},
	{Name: "lastVerdictGate", Kind: KindString, Filterable: true, Desc: "Gate that produced the most recent verdict.", get: func(r *Record) any { return r.LastVerdictGate }},
	{Name: "servedAgeSec", Kind: KindNumber, Filterable: true, Desc: "Seconds since the most recent serve/verdict (very large if never served).", get: func(r *Record) any { return iv64(r.ServedAgeSec) }},
	{Name: "servedAt", Kind: KindTime, Filterable: false, Desc: "Timestamp of the most recent serve/verdict.", get: func(r *Record) any { return r.ServedAt }},
	// Snapshot / freeze (Task 70).
	{Name: "snapshotted", Kind: KindBool, Filterable: true, Desc: "The coordinate is present in the served-state snapshot live set.", get: func(r *Record) any { return r.Snapshotted }},
	{Name: "frozen", Kind: KindBool, Filterable: true, Desc: "The coordinate is part of the currently-active frozen snapshot set.", get: func(r *Record) any { return r.Frozen }},
	{Name: "snapshotVerdict", Kind: KindString, Filterable: true, Desc: "Admission verdict recorded for the coordinate at snapshot time: admit|warn.", get: func(r *Record) any { return r.SnapshotVerdict }},
	{Name: "snapshotBand", Kind: KindString, Filterable: true, Desc: "Risk band recorded for the coordinate at snapshot time.", get: func(r *Record) any { return r.SnapshotBand }},

	// Forensic timeline (Task 77).
	{Name: "timelineEvents", Kind: KindNumber, Filterable: true, Desc: "Count of correlated forensic-timeline events (pulls, verdicts, overrides, anomalies) for the coordinate.", get: func(r *Record) any { return iv(r.TimelineEvents) }},
	{Name: "timelineLastSource", Kind: KindString, Filterable: true, Desc: "Subsystem that produced the coordinate's most recent timeline event.", get: func(r *Record) any { return r.TimelineLastSource }},
	{Name: "timelineLastAt", Kind: KindTime, Filterable: false, Desc: "Timestamp of the coordinate's most recent timeline event.", get: func(r *Record) any { return r.TimelineLastAt }},
	{Name: "timelineProvable", Kind: KindBool, Filterable: true, Desc: "At least one timeline event for the coordinate carries a Merkle inclusion proof.", get: func(r *Record) any { return r.TimelineProvable }},

	// Repository dependency scans (Task 181).
	{Name: "repoScanVerdict", Kind: KindString, Filterable: true, Desc: "Worst verdict the current dependency scans of tracked repositories (default-branch heads, releases) read in the coordinate: malicious|suspicious|unscanned (empty when they judge it benign, or no scanned lock file pins it).", get: func(r *Record) any { return r.RepoScanVerdict }},
	{Name: "repoScanRepos", Kind: KindList, Filterable: true, Desc: "Tracked repositories whose current scans flag the coordinate or could not examine it.", get: func(r *Record) any { return r.RepoScanRepos }},
	{Name: "repoScanFlagged", Kind: KindBool, Filterable: true, Desc: "A repository dependency scan judged the coordinate malicious or suspicious.", get: func(r *Record) any { return r.RepoScanFlagged }},
	{Name: "repoScanUnscanned", Kind: KindBool, Filterable: true, Desc: "A repository dependency scan could not examine the coordinate (unscanned is never benign).", get: func(r *Record) any { return r.RepoScanUnscanned }},
	{Name: "repoScanModel", Kind: KindString, Filterable: true, Desc: "Model behind the worst repository-scan verdict.", get: func(r *Record) any { return r.RepoScanModel }},
	{Name: "repoScanAt", Kind: KindTime, Filterable: false, Desc: "When a repository dependency scan last read the coordinate.", get: func(r *Record) any { return r.RepoScanAt }},

	// Consuming-tenant usage totals (metering, Task 84).
	{Name: "tenantRequests", Kind: KindNumber, Filterable: true, Desc: "Cumulative metered requests for the coordinate's consuming tenant.", get: func(r *Record) any { return r.TenantRequests }},
	{Name: "tenantBytesServed", Kind: KindNumber, Filterable: true, Desc: "Cumulative bytes served to the coordinate's consuming tenant (cache hit + upstream).", get: func(r *Record) any { return r.TenantBytesServed }},
	{Name: "tenantStorageBytes", Kind: KindNumber, Filterable: true, Desc: "Cumulative cache-fill storage footprint attributed to the consuming tenant.", get: func(r *Record) any { return r.TenantStorageBytes }},
	{Name: "tenantScanInvocations", Kind: KindNumber, Filterable: true, Desc: "Cumulative admission-scan invocations attributed to the consuming tenant.", get: func(r *Record) any { return r.TenantScanInvocations }},
	{Name: "tenantScanCostMicros", Kind: KindNumber, Filterable: true, Desc: "Estimated cumulative scan/LLM cost (micro-units) for the consuming tenant.", get: func(r *Record) any { return r.TenantScanCostMicros }},
	{Name: "tenantBlocked", Kind: KindNumber, Filterable: true, Desc: "Cumulative admission-gate refusals attributed to the consuming tenant.", get: func(r *Record) any { return r.TenantBlocked }},
	{Name: "tenantQuarantined", Kind: KindNumber, Filterable: true, Desc: "Cumulative quarantine events attributed to the consuming tenant.", get: func(r *Record) any { return r.TenantQuarantined }},

	{Name: "firstSeen", Kind: KindTime, Filterable: false, Desc: "Earliest timestamp across all sources.", get: func(r *Record) any { return r.FirstSeen }},
	{Name: "lastSeen", Kind: KindTime, Filterable: false, Desc: "Latest timestamp across all sources.", get: func(r *Record) any { return r.LastSeen }},
}

func iv64(n int64) any { return n }

// fieldIndex maps a field name to its definition for O(1) validation/lookup.
var fieldIndex = func() map[string]Field {
	m := make(map[string]Field, len(fieldList))
	for _, f := range fieldList {
		m[f.Name] = f
	}
	return m
}()

// defaultSelect is the projection used when a query omits "select".
var defaultSelect = []string{
	"tenant", "ecosystem", "coordinate", "riskScore", "riskBand",
	"signatureVerified", "downstreamPaths", "vulnTotal", "blockingFindings",
	"outstandingApprovals", "lastVerdict", "servedAgeSec",
}

// operatorsFor returns the operators valid for a field kind, in a stable order.
func operatorsFor(k FieldKind) []string {
	switch k {
	case KindString:
		return []string{"eq", "ne", "in", "nin", "contains", "prefix", "exists"}
	case KindNumber:
		return []string{"eq", "ne", "gt", "gte", "lt", "lte", "in", "nin", "exists"}
	case KindBool:
		return []string{"eq", "ne", "exists"}
	case KindList:
		return []string{"contains", "in", "nin", "exists"}
	default:
		return nil
	}
}

// Schema is the stable, self-describing contract returned by the schema
// endpoint: every queryable field, the operators each accepts, the wired
// subsystems, and the engine's result bounds.
type Schema struct {
	Fields       []SchemaField    `json:"fields"`
	Operators    map[string]OpDoc `json:"operators"`
	Default      []string         `json:"defaultSelect"`
	MaxLimit     int              `json:"maxLimit"`
	DefaultLimit int              `json:"defaultLimit"`
	MaxScan      int              `json:"maxScan"`
	Sources      map[string]bool  `json:"sources"`
}

// SchemaField is one field in the published schema.
type SchemaField struct {
	Name       string    `json:"name"`
	Kind       FieldKind `json:"kind"`
	Desc       string    `json:"description"`
	Filterable bool      `json:"filterable"`
	Operators  []string  `json:"operators,omitempty"`
}

// OpDoc documents one operator.
type OpDoc struct {
	Summary string `json:"summary"`
}

// operatorDocs is the canonical operator catalog.
var operatorDocs = map[string]OpDoc{
	"eq":       {Summary: "Equal (case-insensitive for strings)."},
	"ne":       {Summary: "Not equal."},
	"gt":       {Summary: "Greater than (numbers)."},
	"gte":      {Summary: "Greater than or equal (numbers)."},
	"lt":       {Summary: "Less than (numbers)."},
	"lte":      {Summary: "Less than or equal (numbers)."},
	"in":       {Summary: "Value is one of the provided list (set membership / list intersection)."},
	"nin":      {Summary: "Value is none of the provided list."},
	"contains": {Summary: "Substring (strings) or element membership (lists)."},
	"prefix":   {Summary: "String has the given prefix."},
	"exists":   {Summary: "Field is present/non-empty (value true) or absent/empty (value false)."},
}

// schema builds the published Schema for the given engine bounds and wired
// providers.
func (e *Engine) schema() Schema {
	out := Schema{
		Operators:    operatorDocs,
		Default:      append([]string(nil), defaultSelect...),
		MaxLimit:     e.maxLimit,
		DefaultLimit: e.defaultLimit,
		MaxScan:      e.maxScan,
		Sources:      e.providers.enabled(),
	}
	for _, f := range fieldList {
		sf := SchemaField{Name: f.Name, Kind: f.Kind, Desc: f.Desc, Filterable: f.Filterable}
		if f.Filterable {
			sf.Operators = operatorsFor(f.Kind)
		}
		out.Fields = append(out.Fields, sf)
	}
	return out
}

// FieldNames returns the registered field names in a stable, sorted order (used
// by clients that want to validate a projection locally).
func FieldNames() []string {
	names := make([]string, 0, len(fieldList))
	for _, f := range fieldList {
		names = append(names, f.Name)
	}
	sort.Strings(names)
	return names
}
