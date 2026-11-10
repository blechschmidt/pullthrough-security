package queryapi

import (
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/approvals"
	"github.com/blechschmidt/pullthrough-security/internal/buildprov"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/provgraph"
	"github.com/blechschmidt/pullthrough-security/internal/rebuildverify"
	"github.com/blechschmidt/pullthrough-security/internal/riskscore"
	"github.com/blechschmidt/pullthrough-security/internal/sbomdiff"
	"github.com/blechschmidt/pullthrough-security/internal/secops"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// --- dossier field set providers (Task 87) ----------------------------------

type fakeBuildProv struct{ reports []*buildprov.Report }

func (f *fakeBuildProv) Enabled() bool                { return true }
func (f *fakeBuildProv) Reports() []*buildprov.Report { return f.reports }

type fakeRebuild struct{ recent []rebuildverify.Result }

func (f *fakeRebuild) Enabled() bool                           { return true }
func (f *fakeRebuild) Recent(limit int) []rebuildverify.Result { return f.recent }

type fakeSbomDrift struct{ byCoord map[string]*sbomdiff.Diff }

func (f *fakeSbomDrift) Enabled() bool { return true }
func (f *fakeSbomDrift) DiffLatest(tenant, eco, coord string) (*sbomdiff.Diff, bool) {
	d, ok := f.byCoord[coord]
	return d, ok
}

func TestDossierFieldSet(t *testing.T) {
	fp := &fakeFindings{docs: []findings.Document{{
		Tenant: "acme",
		Artifact: findings.Artifact{
			Ecosystem: "npm", Name: "evil", Version: "1.0.0", Digest: "sha256:evil",
			Coordinate: "npm/evil@1.0.0",
		},
		GeneratedAt: fixedNow.Add(-time.Hour),
	}}}
	providers := Providers{
		Findings: fp,
		BuildProv: &fakeBuildProv{reports: []*buildprov.Report{{
			Artifact: buildprov.Artifact{Ecosystem: "npm", Name: "evil", Version: "1.0.0", Digest: "sha256:evil"},
			Present:  true, Verified: true, SourceVerified: false, Mismatch: true,
			CommitSHA: "cafebabe", RepositoryURL: "https://github.com/evil/evil", VerifiedAt: fixedNow,
		}}},
		Rebuild: &fakeRebuild{recent: []rebuildverify.Result{{
			Ecosystem: "npm", Name: "evil", Version: "1.0.0", Coordinate: "evil@1.0.0",
			Verdict: rebuildverify.VerdictMismatch, Mismatch: true, ComputedAt: fixedNow,
		}}},
		SbomDrift: &fakeSbomDrift{byCoord: map[string]*sbomdiff.Diff{
			"evil": {DriftScore: 63.5, Significant: true},
		}},
	}
	e := New(Config{Now: func() time.Time { return fixedNow }}, providers)

	res, err := e.Query(Query{
		Tenant: "acme",
		Select: []string{"coordinate", "sourceCommit", "provenanceMismatch", "rebuildVerdict", "sbomDriftScore", "sbomDriftSignificant"},
		Where:  &Filter{Field: "provenanceMismatch", Op: "eq", Value: true},
	})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if res.Total != 1 {
		t.Fatalf("expected 1 row, got %d", res.Total)
	}
	row := res.Rows[0]
	if row["sourceCommit"] != "cafebabe" {
		t.Errorf("sourceCommit = %v", row["sourceCommit"])
	}
	if row["rebuildVerdict"] != "mismatch" {
		t.Errorf("rebuildVerdict = %v", row["rebuildVerdict"])
	}
	if row["sbomDriftSignificant"] != true {
		t.Errorf("sbomDriftSignificant = %v", row["sbomDriftSignificant"])
	}
	// The new fields must be advertised in the schema and report wired sources.
	sch := e.Schema()
	if !sch.Sources["buildprov"] || !sch.Sources["rebuild"] || !sch.Sources["sbomdrift"] {
		t.Errorf("schema sources missing dossier providers: %+v", sch.Sources)
	}
}

// --- seeded in-memory providers ---------------------------------------------

type fakeFindings struct{ docs []findings.Document }

func (f *fakeFindings) Documents(tenant, q string) []findings.Document {
	return append([]findings.Document(nil), f.docs...)
}

type fakeRisk struct {
	enabled bool
	recent  []riskscore.Assessment
}

func (f *fakeRisk) Enabled() bool { return f.enabled }
func (f *fakeRisk) Recent(limit int) []riskscore.Assessment {
	return append([]riskscore.Assessment(nil), f.recent...)
}

type fakeVuln struct {
	reports     []*vulnscan.Report
	quarantined map[string]bool
}

func (f *fakeVuln) Reports() []*vulnscan.Report { return f.reports }
func (f *fakeVuln) IsQuarantined(d string) bool { return f.quarantined[d] }

type fakeApprovals struct {
	enabled  bool
	requests []approvals.Request
}

func (f *fakeApprovals) Enabled() bool { return f.enabled }
func (f *fakeApprovals) List(status string, limit int) []approvals.Request {
	var out []approvals.Request
	for _, r := range f.requests {
		if status == "" || string(r.Status) == status {
			out = append(out, r)
		}
	}
	return out
}

type fakeProvgraph struct {
	deps map[string]provgraph.DepResult
}

func (f *fakeProvgraph) ReverseDependencies(eco, name, version string) (provgraph.DepResult, error) {
	if d, ok := f.deps[name+"@"+version]; ok {
		return d, nil
	}
	return provgraph.DepResult{Found: false}, nil
}

type fakeSecOps struct{ recent []secops.NotableEvent }

func (f *fakeSecOps) Summary() secops.Summary { return secops.Summary{Recent: f.recent} }

// fixedNow is the deterministic clock anchor for the tests.
var fixedNow = time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)

// seededProviders builds a small, deterministic federated model with a handful
// of coordinates exercising every subsystem and every interesting combination
// the example queries care about.
func seededProviders() Providers {
	// evil@1.0.0 for tenant "acme": block-adjacent (critical), unverified
	// signature, served 1h ago, 12 downstream paths, quarantined with a CVE.
	// safe@2.0.0 for tenant "acme": low risk, verified signature, few deps.
	// stale@0.1.0 for tenant "beta": high risk but served 3 days ago.
	doc := func(tenant, eco, name, ver, digest string, gen time.Time, fs ...findings.Finding) findings.Document {
		return findings.Document{
			Tenant: tenant,
			Artifact: findings.Artifact{
				Ecosystem: eco, Name: name, Version: ver, Digest: digest,
				Coordinate: eco + "/" + name + "@" + ver,
			},
			Findings:    fs,
			GeneratedAt: gen,
		}
	}
	sig := findings.Finding{RuleID: "PT-SIGVERIFY-UNVERIFIED", Gate: findings.GateSigverify, Severity: findings.SeverityHigh, Level: findings.LevelError, Title: "unverified"}
	vulnF := findings.Finding{RuleID: "PT-VULN", Gate: findings.GateVulnscan, Severity: findings.SeverityCritical, Level: findings.LevelError, Title: "vuln"}

	fp := &fakeFindings{docs: []findings.Document{
		doc("acme", "npm", "evil", "1.0.0", "sha256:evil", fixedNow.Add(-time.Hour), sig, vulnF),
		doc("acme", "npm", "safe", "2.0.0", "sha256:safe", fixedNow.Add(-2*time.Hour)),
		doc("beta", "pypi", "stale", "0.1.0", "sha256:stale", fixedNow.Add(-72*time.Hour), sig),
	}}

	rp := &fakeRisk{enabled: true, recent: []riskscore.Assessment{
		{Tenant: "acme", Artifact: riskscore.Artifact{Ecosystem: "npm", Name: "evil", Version: "1.0.0"}, Score: 95, Band: riskscore.BandCritical, Block: true, Exceeds: true, ScoredAt: fixedNow.Add(-time.Hour)},
		{Tenant: "acme", Artifact: riskscore.Artifact{Ecosystem: "npm", Name: "safe", Version: "2.0.0"}, Score: 10, Band: riskscore.BandLow, ScoredAt: fixedNow.Add(-2 * time.Hour)},
		{Tenant: "beta", Artifact: riskscore.Artifact{Ecosystem: "pypi", Name: "stale", Version: "0.1.0"}, Score: 70, Band: riskscore.BandHigh, Warn: true, ScoredAt: fixedNow.Add(-72 * time.Hour)},
	}}

	vp := &fakeVuln{
		quarantined: map[string]bool{"sha256:evil": true},
		reports: []*vulnscan.Report{
			{
				Digest:      "sha256:evil",
				Artifact:    vulnscan.Artifact{Ecosystem: "npm", Name: "evil", Version: "1.0.0", Digest: "sha256:evil"},
				Counts:      vulnscan.SeverityCounts{Critical: 1},
				MaxSeverity: vulnscan.SeverityCritical, MaxCVSS: 9.8,
				ScannedAt:       fixedNow.Add(-time.Hour),
				Vulnerabilities: []vulnscan.Vulnerability{{ID: "CVE-2026-0001", Severity: vulnscan.SeverityCritical}},
			},
		},
	}

	ap := &fakeApprovals{enabled: true, requests: []approvals.Request{
		{ID: "r1", Tenant: "acme", Ecosystem: "npm", Coordinate: "evil@1.0.0", Gate: "vulnscan", Reason: "vuln", Status: approvals.StatusApproved, GrantedAt: fixedNow.Add(-30 * time.Minute), ExpiresAt: fixedNow.Add(time.Hour)},
		// An expired grant must NOT count as outstanding.
		{ID: "r2", Tenant: "acme", Ecosystem: "npm", Coordinate: "safe@2.0.0", Gate: "license", Status: approvals.StatusApproved, GrantedAt: fixedNow.Add(-3 * time.Hour), ExpiresAt: fixedNow.Add(-time.Hour)},
	}}

	gp := &fakeProvgraph{deps: map[string]provgraph.DepResult{
		"evil@1.0.0": {Found: true, Total: 12, Direct: 3},
		"safe@2.0.0": {Found: true, Total: 1, Direct: 1},
	}}

	sp := &fakeSecOps{recent: []secops.NotableEvent{
		{Seq: 3, Time: fixedNow.Add(-time.Hour), Gate: "riskscore", Outcome: secops.Outcome("block"), Ecosystem: "npm", Artifact: "evil@1.0.0"},
		{Seq: 2, Time: fixedNow.Add(-2 * time.Hour), Gate: "none", Outcome: secops.Outcome("admit"), Ecosystem: "npm", Artifact: "safe@2.0.0"},
		{Seq: 1, Time: fixedNow.Add(-72 * time.Hour), Gate: "riskscore", Outcome: secops.Outcome("warn"), Ecosystem: "pypi", Artifact: "stale@0.1.0"},
	}}

	return Providers{Findings: fp, Risk: rp, Vuln: vp, Approvals: ap, Provgraph: gp, SecOps: sp}
}

func newTestEngine() *Engine {
	return New(Config{Now: func() time.Time { return fixedNow }}, seededProviders())
}

// --- tests ------------------------------------------------------------------

func TestModelJoin(t *testing.T) {
	e := newTestEngine()
	model := e.providers.build(fixedNow)
	if len(model) != 3 {
		t.Fatalf("expected 3 joined coordinates, got %d", len(model))
	}
	var evil *Record
	for _, r := range model {
		if r.Coordinate == "evil@1.0.0" {
			evil = r
		}
	}
	if evil == nil {
		t.Fatal("evil@1.0.0 not found in model")
	}
	if evil.RiskBand != "critical" || !evil.BlockAdjacent {
		t.Errorf("risk join wrong: band=%q blockAdjacent=%v", evil.RiskBand, evil.BlockAdjacent)
	}
	if evil.SignatureVerified {
		t.Error("evil should have an unverified signature")
	}
	if evil.DownstreamPaths != 12 || evil.DirectDependents != 3 {
		t.Errorf("provgraph join wrong: paths=%d direct=%d", evil.DownstreamPaths, evil.DirectDependents)
	}
	if !evil.Quarantined || evil.VulnCritical != 1 {
		t.Errorf("vuln join wrong: quarantined=%v crit=%d", evil.Quarantined, evil.VulnCritical)
	}
	if len(evil.CVEs) != 1 || evil.CVEs[0] != "CVE-2026-0001" {
		t.Errorf("cve join wrong: %v", evil.CVEs)
	}
	if evil.OutstandingApprovals != 1 {
		t.Errorf("approvals join wrong: %d", evil.OutstandingApprovals)
	}
	if evil.LastVerdict != "block" {
		t.Errorf("secops join wrong: %q", evil.LastVerdict)
	}
	if evil.ServedAgeSec != 3600 {
		t.Errorf("served age wrong: %d", evil.ServedAgeSec)
	}
}

func TestExpiredApprovalNotOutstanding(t *testing.T) {
	e := newTestEngine()
	model := e.providers.build(fixedNow)
	for _, r := range model {
		if r.Coordinate == "safe@2.0.0" && r.OutstandingApprovals != 0 {
			t.Errorf("expired grant counted as outstanding for safe@2.0.0: %d", r.OutstandingApprovals)
		}
	}
}

// TestFlagshipQuery is the motivating cross-cutting question: every coordinate
// served to tenant "acme" in the last 24h whose risk band is block-adjacent AND
// has an unverified signature AND appears in >5 downstream dependency paths.
func TestFlagshipQuery(t *testing.T) {
	e := newTestEngine()
	res, err := e.Query(Query{
		Tenant: "acme",
		Select: []string{"coordinate", "riskBand", "downstreamPaths", "signatureVerified"},
		Where: &Filter{And: []Filter{
			{Field: "servedAgeSec", Op: "lt", Value: float64(86400)},
			{Field: "blockAdjacent", Op: "eq", Value: true},
			{Field: "signatureVerified", Op: "eq", Value: false},
			{Field: "downstreamPaths", Op: "gt", Value: float64(5)},
		}},
	})
	if err != nil {
		t.Fatalf("query error: %v", err)
	}
	if res.Total != 1 || res.Returned != 1 {
		t.Fatalf("expected exactly 1 match, got total=%d returned=%d", res.Total, res.Returned)
	}
	row := res.Rows[0]
	if row["coordinate"] != "evil@1.0.0" {
		t.Errorf("unexpected match: %v", row)
	}
	if row["downstreamPaths"] != 12 {
		t.Errorf("downstreamPaths projection wrong: %v", row["downstreamPaths"])
	}
	if res.Cost <= 0 {
		t.Error("expected a positive query cost")
	}
}

func TestTenantScoping(t *testing.T) {
	e := newTestEngine()
	res, err := e.Query(Query{Tenant: "beta", Select: []string{"coordinate"}})
	if err != nil {
		t.Fatalf("query error: %v", err)
	}
	if res.Total != 1 || res.Rows[0]["coordinate"] != "stale@0.1.0" {
		t.Fatalf("tenant scoping failed: %+v", res.Rows)
	}
}

func TestOrderingAndPagination(t *testing.T) {
	e := newTestEngine()
	res, err := e.Query(Query{
		Select:  []string{"coordinate", "riskScore"},
		OrderBy: []Order{{Field: "riskScore", Desc: true}},
		Limit:   2,
	})
	if err != nil {
		t.Fatalf("query error: %v", err)
	}
	if res.Total != 3 || res.Returned != 2 || !res.Truncated {
		t.Fatalf("pagination wrong: total=%d returned=%d truncated=%v", res.Total, res.Returned, res.Truncated)
	}
	if res.Rows[0]["coordinate"] != "evil@1.0.0" || res.Rows[1]["coordinate"] != "stale@0.1.0" {
		t.Errorf("ordering wrong: %v, %v", res.Rows[0]["coordinate"], res.Rows[1]["coordinate"])
	}
	// Second page.
	res2, err := e.Query(Query{
		Select:  []string{"coordinate"},
		OrderBy: []Order{{Field: "riskScore", Desc: true}},
		Limit:   2, Offset: 2,
	})
	if err != nil {
		t.Fatalf("query error: %v", err)
	}
	if res2.Returned != 1 || res2.Rows[0]["coordinate"] != "safe@2.0.0" {
		t.Fatalf("second page wrong: %+v", res2.Rows)
	}
	if res2.Truncated {
		t.Error("last page should not be truncated")
	}
}

func TestListOperators(t *testing.T) {
	e := newTestEngine()
	res, err := e.Query(Query{
		Select: []string{"coordinate"},
		Where:  &Filter{Field: "findingGates", Op: "contains", Value: "sigverify"},
	})
	if err != nil {
		t.Fatalf("query error: %v", err)
	}
	if res.Total != 2 {
		t.Fatalf("expected 2 coordinates with a sigverify gate, got %d", res.Total)
	}
}

func TestInOperator(t *testing.T) {
	e := newTestEngine()
	res, err := e.Query(Query{
		Select: []string{"coordinate", "riskBand"},
		Where:  &Filter{Field: "riskBand", Op: "in", Value: []any{"high", "critical"}},
	})
	if err != nil {
		t.Fatalf("query error: %v", err)
	}
	if res.Total != 2 {
		t.Fatalf("expected 2 block-adjacent coordinates, got %d", res.Total)
	}
}

func TestNotAndOr(t *testing.T) {
	e := newTestEngine()
	res, err := e.Query(Query{
		Select: []string{"coordinate"},
		Where: &Filter{Or: []Filter{
			{Field: "quarantined", Op: "eq", Value: true},
			{Not: &Filter{Field: "signatureVerified", Op: "eq", Value: true}},
		}},
	})
	if err != nil {
		t.Fatalf("query error: %v", err)
	}
	// evil (quarantined + unverified) and stale (unverified) => 2.
	if res.Total != 2 {
		t.Fatalf("expected 2, got %d (%+v)", res.Total, res.Rows)
	}
}

func TestWildcardSelect(t *testing.T) {
	e := newTestEngine()
	res, err := e.Query(Query{Select: []string{"*"}, Tenant: "acme", Limit: 1})
	if err != nil {
		t.Fatalf("query error: %v", err)
	}
	if len(res.Fields) != len(fieldList) {
		t.Fatalf("wildcard select should expand to all %d fields, got %d", len(fieldList), len(res.Fields))
	}
	if len(res.Rows) != 1 {
		t.Fatalf("expected 1 row")
	}
	if _, ok := res.Rows[0]["servedAt"]; !ok {
		t.Error("wildcard row should include time field servedAt")
	}
}

func TestValidationErrors(t *testing.T) {
	e := newTestEngine()
	cases := []struct {
		name string
		q    Query
		code string
	}{
		{"unknown select", Query{Select: []string{"nope"}}, "invalid_field"},
		{"unknown filter field", Query{Where: &Filter{Field: "nope", Op: "eq", Value: 1}}, "invalid_field"},
		{"bad operator", Query{Where: &Filter{Field: "riskScore", Op: "contains", Value: 1}}, "invalid_operator"},
		{"non-filterable", Query{Where: &Filter{Field: "servedAt", Op: "eq", Value: "x"}}, "not_filterable"},
		{"negative limit", Query{Limit: -1}, "invalid_limit"},
		{"negative offset", Query{Offset: -1}, "invalid_offset"},
		{"in without list", Query{Where: &Filter{Field: "riskBand", Op: "in", Value: "high"}}, "invalid_value"},
		{"ambiguous node", Query{Where: &Filter{Field: "tenant", Op: "eq", Value: "a", And: []Filter{{Field: "tenant", Op: "eq", Value: "b"}}}}, "ambiguous_filter"},
		{"empty node", Query{Where: &Filter{}}, "empty_filter"},
		{"bad orderby", Query{OrderBy: []Order{{Field: "nope"}}}, "invalid_field"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.Query(tc.q)
			if err == nil {
				t.Fatalf("expected error")
			}
			qe, ok := err.(*QueryError)
			if !ok {
				t.Fatalf("expected *QueryError, got %T", err)
			}
			if qe.Code != tc.code {
				t.Errorf("expected code %q, got %q (%s)", tc.code, qe.Code, qe.Msg)
			}
		})
	}
	// Rejections are counted.
	if got := e.Snapshot().RejectedTotal; got != int64(len(cases)) {
		t.Errorf("expected %d rejected, got %d", len(cases), got)
	}
}

func TestLimitClamp(t *testing.T) {
	e := New(Config{MaxLimit: 2, Now: func() time.Time { return fixedNow }}, seededProviders())
	res, err := e.Query(Query{Limit: 1000})
	if err != nil {
		t.Fatalf("query error: %v", err)
	}
	if res.Limit != 2 {
		t.Errorf("limit should clamp to maxLimit 2, got %d", res.Limit)
	}
}

func TestMetricsAccounting(t *testing.T) {
	e := newTestEngine()
	for i := 0; i < 3; i++ {
		if _, err := e.Query(Query{Select: []string{"coordinate"}}); err != nil {
			t.Fatalf("query error: %v", err)
		}
	}
	m := e.Snapshot()
	if m.QueriesTotal != 3 {
		t.Errorf("expected 3 queries, got %d", m.QueriesTotal)
	}
	if m.CostUnitsTotal <= 0 || m.MaxCost <= 0 || m.LastCost <= 0 {
		t.Errorf("expected positive cost accounting, got %+v", m)
	}
	if m.RowsReturnedTotal != 9 { // 3 rows x 3 queries
		t.Errorf("expected 9 returned rows total, got %d", m.RowsReturnedTotal)
	}
}

func TestSchemaStable(t *testing.T) {
	e := newTestEngine()
	s := e.Schema()
	if len(s.Fields) != len(fieldList) {
		t.Fatalf("schema field count mismatch")
	}
	if !s.Sources["provgraph"] || !s.Sources["riskscore"] {
		t.Errorf("schema should advertise wired sources: %+v", s.Sources)
	}
	if s.MaxLimit != DefaultMaxLimit || s.DefaultLimit != DefaultLimit {
		t.Errorf("schema bounds wrong: %+v", s)
	}
	// Every filterable field must publish a non-empty operator set.
	for _, f := range s.Fields {
		if f.Filterable && len(f.Operators) == 0 {
			t.Errorf("filterable field %q has no operators", f.Name)
		}
	}
}

func TestEmptyModelDegrades(t *testing.T) {
	e := New(Config{Now: func() time.Time { return fixedNow }}, Providers{})
	res, err := e.Query(Query{Select: []string{"coordinate"}})
	if err != nil {
		t.Fatalf("query error: %v", err)
	}
	if res.Total != 0 || res.Returned != 0 {
		t.Errorf("empty model should yield no rows, got %+v", res)
	}
}
