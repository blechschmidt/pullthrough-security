package main

import (
	"context"

	"github.com/blechschmidt/pullthrough-security/internal/dossier"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/proxy"
	"github.com/blechschmidt/pullthrough-security/internal/queryapi"
	"github.com/blechschmidt/pullthrough-security/internal/repos"
)

// The repository registry's dependency scans (Task 181): adapters between the
// registry, the gateway's LLM package-content scan gate and the findings layer.

// gatewayObjectScanner puts the registry's dependencies before the LLM
// package-content scan gate through the gateway: the verdict cache, the cost
// budget, the concurrency limits and the per-tenant share are the gate's own.
type gatewayObjectScanner struct {
	gw     *proxy.Gateway
	svc    *llmpkgscan.Service
	eco    map[string]string // upstream name -> its type, as the gateway sees it
	static repos.ScannerStatus
}

// newObjectScanner returns the scanner, or nil when the gate is off (an untyped
// nil, so "no scanner" is not a non-nil interface holding nil).
func newObjectScanner(gw *proxy.Gateway, svc *llmpkgscan.Service, eco map[string]string) repos.ObjectScanner {
	if gw == nil || !svc.Enabled() {
		return nil
	}
	st := svc.Status()
	return gatewayObjectScanner{gw: gw, svc: svc, eco: eco, static: repos.ScannerStatus{
		Enabled: true, Provider: st.Provider, Model: st.Model, PromptVersion: st.PromptVersion,
		Action: string(st.Action), FailMode: string(st.FailMode),
	}}
}

func (s gatewayObjectScanner) Status() repos.ScannerStatus {
	st := s.static
	st.Enabled = s.svc.Enabled()
	return st
}

func (s gatewayObjectScanner) Scope(ecosystem, upstream string) (bool, string) {
	if t := s.eco[upstream]; t != "" {
		ecosystem = t
	}
	if s.svc.AppliesTo(ecosystem, upstream) {
		return true, ""
	}
	if s.svc.Applies(ecosystem) {
		return false, "the upstream " + upstream + " is excluded from the LLM package scan (llmPackageScan.excludeUpstreams)"
	}
	return false, "the LLM package scan does not cover " + ecosystem + " artifacts (llmPackageScan.include / exclude)"
}

func (s gatewayObjectScanner) ScanObject(ctx context.Context, req repos.ObjectScanRequest) (repos.ObjectScan, error) {
	sl, err := s.gw.SystemScan(ctx, proxy.SystemScanRequest{
		Backend: req.Upstream, Path: req.Path, Accept: req.Accept,
		Tenant: req.Tenant, Subject: req.Subject, Roles: req.Roles,
		CacheKey: req.CacheKey, Digest: req.Digest,
	})
	if err != nil {
		return repos.ObjectScan{}, err
	}
	return objectScanFrom(sl), nil
}

// objectScanFrom translates the gateway's reading of an object.
func objectScanFrom(sl *proxy.SystemLLMScan) repos.ObjectScan {
	if sl == nil {
		return repos.ObjectScan{}
	}
	out := repos.ObjectScan{
		Applicable: sl.Applicable, NotApplicable: sl.NotApplicable, NotApplicableReason: sl.NotApplicableReason,
		BreakGlass: sl.BreakGlass, ReviewCoordinate: sl.ReviewCoordinate,
	}
	rep := sl.Report
	if !sl.Applicable || rep == nil {
		return out
	}
	out.Verdict, out.Reason, out.Cached = string(rep.Disposition), rep.Reason, rep.Cached
	out.Refused, out.Action = !sl.Decision.Served(), sl.Decision.Action
	if u := rep.Unscanned; u != nil {
		out.Unscanned = &repos.UnscannedInfo{
			Code: u.Code, Reason: u.Reason, Detail: u.Detail, Content: u.Content,
			// A spent budget and an open breaker are not transient for a pull
			// (they last), but a later attempt of a scan is worth making.
			Retryable: u.Transient || u.Code == llmpkgscan.CodeBudgetExhausted || u.Code == llmpkgscan.CodeProviderUnavailable,
		}
	}
	if v := rep.Verdict; v != nil {
		d := &repos.VerdictDetail{
			Digest: v.Digest, ModelVerdict: v.Verdict, Confidence: v.Confidence, Provider: v.Provider,
			Model: v.Model, PromptVersion: v.PromptVersion, Mode: v.Mode, ScannedAt: v.ScannedAt,
			Scope: v.Scope, ReadAs: llmpkgscan.DescribeVariant(v), Format: v.Format, Truncated: v.Truncated,
			Files: v.Files, StructuralRisk: v.StructuralRisk, Reasons: append([]string(nil), v.Reasons...),
		}
		for _, hit := range v.Injection {
			if hit.Strong {
				d.PromptInjection = true
			}
		}
		for _, ev := range v.Evidence {
			d.Evidence = append(d.Evidence, repos.ScanEvidence{Path: ev.Path, Line: ev.Line, Excerpt: ev.Excerpt, Verified: ev.Verified})
		}
		out.Detail = d
	}
	return out
}

// objectScanPtr is objectScanFrom for an optional reading.
func objectScanPtr(sl *proxy.SystemLLMScan) *repos.ObjectScan {
	if sl == nil {
		return nil
	}
	o := objectScanFrom(sl)
	return &o
}

// scanFindingsSink takes a scan's findings document through the findings
// layer as the gateway takes a pull's: de-duplication, the suppression trail,
// the findings store (SARIF, dossier, query and MCP APIs) and the SIEM.
type scanFindingsSink struct {
	store   *findings.Store
	metrics *findings.Metrics
	ledger  *findings.SuppressionLedger
	siem    proxy.SIEMForwarder
}

// newScanFindingsSink returns the sink, or nil when there is nowhere to send
// findings.
func newScanFindingsSink(store *findings.Store, m *findings.Metrics, ledger *findings.SuppressionLedger, siem proxy.SIEMForwarder) repos.FindingsSink {
	if store == nil && siem == nil {
		return nil
	}
	return scanFindingsSink{store: store, metrics: m, ledger: ledger, siem: siem}
}

func (f scanFindingsSink) RecordScanFindings(ctx context.Context, doc findings.Document) {
	f.metrics.RecordDedup(doc.Deduplicate())
	f.ledger.RecordFromDocument(ctx, &doc)
	f.store.Record(doc)
	if f.siem != nil {
		f.siem.ForwardFindings(ctx, doc)
	}
}

// dossierRepoScans answers the dossier's "dependency scans in repositories".
type dossierRepoScans struct{ svc *repos.Service }

func (d dossierRepoScans) RepositoryScansOf(ctx context.Context, tenant, ecosystem, name, version string) ([]dossier.RepoScanRef, error) {
	refs, err := d.svc.ScansOf(ctx, tenant, ecosystem, name, version)
	if err != nil {
		return nil, err
	}
	out := make([]dossier.RepoScanRef, 0, len(refs))
	for _, r := range refs {
		ref := dossier.RepoScanRef{
			Repo: r.Repo, Commit: r.Commit, Kind: r.Kind, Ref: r.Ref, Tags: r.Tags, Current: r.Current,
			Version: r.Version, Verdict: r.Verdict, Reason: r.Reason, Files: r.Files, Pinned: r.Pinned,
			Released: r.Released, ScannedAt: r.ScanAt,
		}
		if r.Unscanned != nil {
			ref.UnscannedCode = r.Unscanned.Code
		}
		if v := r.Detail; v != nil {
			ref.Model, ref.Confidence, ref.Digest = v.Model, v.Confidence, v.Digest
			if !v.ScannedAt.IsZero() {
				ref.ScannedAt = v.ScannedAt
			}
		}
		out = append(out, ref)
	}
	return out, nil
}

// queryRepoScans feeds the query API (and through it the MCP server) the
// dependencies of every repository's current scans.
type queryRepoScans struct{ svc *repos.Service }

func (q queryRepoScans) RepoScanFacts() []queryapi.RepoScanFact {
	facts := q.svc.ScanFacts(context.Background(), "")
	out := make([]queryapi.RepoScanFact, 0, len(facts))
	for _, f := range facts {
		out = append(out, queryapi.RepoScanFact{
			Tenant: f.Tenant, Ecosystem: f.Ecosystem, Name: f.Name, Version: f.Version, Digest: f.Digest,
			Repo: f.Repo, Verdict: f.Verdict, Model: f.Model, ScannedAt: f.ScannedAt,
		})
	}
	return out
}
