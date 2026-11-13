package main

import (
	"context"
	"sync"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/repos"
)

// fakeSIEM keeps the documents forwarded.
type fakeSIEM struct {
	mu   sync.Mutex
	docs []findings.Document
}

func (f *fakeSIEM) ForwardFindings(_ context.Context, doc findings.Document) {
	f.mu.Lock()
	f.docs = append(f.docs, doc)
	f.mu.Unlock()
}

// A scan's findings document goes through the findings layer as a pull's does
// (Task 181): de-duplicated, its break-glass suppressions in the trail, kept in
// the store, forwarded to the SIEM.
func TestScanFindingsSink(t *testing.T) {
	store := findings.NewStore(findings.StoreOptions{})
	ledger := findings.NewSuppressionLedger(findings.SuppressionLedgerOptions{})
	m := findings.NewMetrics()
	siem := &fakeSIEM{}
	sink := newScanFindingsSink(store, m, ledger, siem)

	rep := repos.ScanReport{
		Repo: "widgets", Tenant: "team-a", Commit: "abcdefabcdefabcdefabcdefabcdefabcdefabcd", Kind: repos.ScanRelease,
		Dependencies: []repos.DependencyScan{
			// The same lock-file line twice: one finding after de-duplication.
			{Type: "npm", Name: "evil-pad", Version: "1.0.0", Files: []string{"package-lock.json:21", "package-lock.json:21"}, Verdict: repos.VerdictMalicious,
				Detail: &repos.VerdictDetail{Digest: "sha256:evil", Model: "model-1"}},
			{Type: "npm", Name: "odd-pad", Version: "1.0.0", Files: []string{"package-lock.json:30"}, Verdict: repos.VerdictMalicious, Released: "apr-1",
				Detail: &repos.VerdictDetail{Digest: "sha256:odd", Model: "model-1"}},
			{Type: "npm", Name: "left-pad", Version: "1.0.0", Files: []string{"package-lock.json:9"}, Verdict: repos.VerdictBenign},
		},
	}
	doc := rep.FindingsDocument()
	doc.Findings = append(doc.Findings, doc.Findings[0]) // a duplicate the layer must fold
	sink.RecordScanFindings(context.Background(), doc)

	got, ok := store.Get("team-a", repos.RepoScanName("widgets")+"@"+rep.Commit)
	if !ok || len(got.Findings) != 2 {
		t.Fatalf("store: %v %d findings", ok, len(got.Findings))
	}
	if len(siem.docs) != 1 || len(siem.docs[0].Findings) != 2 {
		t.Fatalf("SIEM: %+v", siem.docs)
	}
	recs := ledger.Recent(10)
	if len(recs) != 1 || recs[0].Mechanism != findings.MechanismBreakGlass || recs[0].Coordinate != "npm/odd-pad@1.0.0" {
		t.Fatalf("suppression trail: %+v", recs)
	}
	if snap := m.Snapshot(); snap.Collapsed == 0 {
		t.Fatalf("dedup metrics: %+v", snap)
	}
	if newScanFindingsSink(nil, nil, nil, nil) != nil {
		t.Fatal("a sink with nowhere to send findings")
	}
}
