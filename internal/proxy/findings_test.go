package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/riskscore"
)

func newFindingsGateway(t *testing.T, store *findings.Store, engine *riskscore.Engine) *Gateway {
	t.Helper()
	g, err := New(Dependencies{
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:     cache.NewMemoryCache(),
		Backends:  backends.NewRegistry(),
		Findings:  store,
		RiskScore: engine,
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

func TestRecordFindingsStoresNormalizedDocument(t *testing.T) {
	store := findings.NewStore(findings.StoreOptions{})
	g := newFindingsGateway(t, store, nil)

	in := policyengine.Input{
		Tenant:   "acme",
		Artifact: policyengine.ArtifactInput{Ecosystem: "npm", Backend: "npm", Name: "evil", Version: "1.0.0"},
		Vuln: &policyengine.VulnInput{
			Scanned: true, Scanner: "osv", Total: 1, CriticalCount: 1, MaxSeverity: "critical",
			Findings: []policyengine.VulnFinding{{ID: "CVE-1", Severity: "critical", Package: "evil", Version: "1.0.0"}},
		},
	}
	r := reqWithSignals(in)

	g.recordFindings(r)

	doc, ok := store.Get("acme", "evil@1.0.0")
	if !ok {
		t.Fatal("expected the findings document to be recorded")
	}
	if len(doc.Findings) != 1 || doc.Findings[0].Identifier != "CVE-1" {
		t.Fatalf("unexpected findings: %+v", doc.Findings)
	}
	if !doc.HasBlocking() {
		t.Error("critical CVE should produce a blocking (error-level) finding")
	}
}

func TestRecordFindingsIncludesRiskAndPolicySignals(t *testing.T) {
	store := findings.NewStore(findings.StoreOptions{})
	engine, err := riskscore.New(riskscore.Config{
		Enabled:   true,
		Threshold: riskscore.Threshold{Band: riskscore.BandHigh, Action: riskscore.ThresholdWarn},
	})
	if err != nil {
		t.Fatal(err)
	}
	g := newFindingsGateway(t, store, engine)

	in := criticalInput()
	in.Tenant = "acme"
	r := reqWithSignals(in)

	// The risk gate runs first, stashing its verdict onto the accumulator.
	if ok := g.gateRiskScore(httptest.NewRecorder(), r, "npm", "npm"); !ok {
		t.Fatal("warn mode must admit")
	}
	g.recordFindings(r)

	doc, ok := store.Get("acme", in.Artifact.Name+"@"+in.Artifact.Version)
	if !ok {
		t.Fatal("expected a recorded document")
	}
	var sawRisk bool
	for _, f := range doc.Findings {
		if f.RuleID == findings.RuleRiskThreshold {
			sawRisk = true
		}
	}
	if !sawRisk {
		t.Errorf("expected a risk-threshold finding to be folded in; got %+v", doc.Findings)
	}
}

func TestRecordFindingsNoStoreIsNoop(t *testing.T) {
	g := newFindingsGateway(t, nil, nil)
	// Must not panic with a nil store.
	g.recordFindings(reqWithSignals(criticalInput()))
}

func TestRecordFindingsSkipsUnaddressable(t *testing.T) {
	store := findings.NewStore(findings.StoreOptions{})
	g := newFindingsGateway(t, store, nil)
	// No accumulator on the context at all.
	r := httptest.NewRequest(http.MethodGet, "/v1/npm/x", nil)
	r = r.WithContext(context.Background())
	g.recordFindings(r)
	if store.Len() != 0 {
		t.Error("recording without an accumulator should store nothing")
	}
}

// A backend that names no package coordinate — a file of a generic upstream —
// still has a refusal explained: what the gates found is kept under the file
// name the gates and the break-glass review know the artifact by. An unnamed
// artifact nothing was found in leaves no document.
func TestRecordFindingsKeepsAnUnnamedArtifactsFindingsUnderItsFileName(t *testing.T) {
	store := findings.NewStore(findings.StoreOptions{})
	g := newFindingsGateway(t, store, nil)
	resolved := &backends.Resolved{UpstreamURL: "https://downloads.example/releases/1.4.2/tool-1.4.2.tar.gz?sig=x"}
	pull := func(l *policyengine.LLMPackageInput) {
		r := g.withAdmissionSignals(httptest.NewRequest(http.MethodGet, "/v1/tools/releases/1.4.2/tool-1.4.2.tar.gz", nil), "tools", "generic", resolved)
		s := signalsFrom(r.Context())
		if s == nil {
			t.Fatal("no signal accumulator was attached")
		}
		s.input.LLMPackage = l
		g.recordFindings(r)
	}

	pull(&policyengine.LLMPackageInput{Scanned: true, Verdict: "benign", Disposition: "benign"})
	if n := store.Len(); n != 0 {
		t.Fatalf("a clean unnamed artifact left %d findings document(s)", n)
	}

	pull(&policyengine.LLMPackageInput{
		Scanned: true, Verdict: "malicious", Disposition: "malicious", Confidence: 0.97,
		Findings: []policyengine.LLMPackageFinding{{
			RuleID: findings.RuleLLMMaliciousPackage, Category: "malicious-package", Severity: "critical",
			Title: "the package downloads and runs a remote script", File: "tool-1.4.2/install.sh", Line: 3,
		}},
	})
	doc, ok := store.Get("", "tool-1.4.2.tar.gz")
	if !ok {
		t.Fatalf("the refusal of an unnamed artifact left no findings document (%d documents)", store.Len())
	}
	if doc.Artifact.Name != "tool-1.4.2.tar.gz" || doc.Artifact.Ecosystem != "generic" || doc.Artifact.Backend != "tools" {
		t.Errorf("document artifact = %+v, want the file name under the generic upstream", doc.Artifact)
	}
	if len(doc.Findings) != 1 || doc.Findings[0].RuleID != findings.RuleLLMMaliciousPackage || doc.Findings[0].Location.File != "tool-1.4.2/install.sh" {
		t.Errorf("findings = %+v, want the malicious-package finding at tool-1.4.2/install.sh", doc.Findings)
	}
}
