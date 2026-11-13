package mcpserver

import (
	"context"

	"github.com/blechschmidt/pullthrough-security/internal/attestbundle"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/provgraph"
	"github.com/blechschmidt/pullthrough-security/internal/queryapi"
	"github.com/blechschmidt/pullthrough-security/internal/repos"
	"github.com/blechschmidt/pullthrough-security/internal/riskscore"
	"github.com/blechschmidt/pullthrough-security/internal/timeline"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// Backend is the primary read-model the MCP server projects over: the federated
// query engine (Task 67). Reusing it means every tool answers from the same
// stable field registry and inherits the engine's deterministic cost bounds,
// rather than reinventing per-tool projections. *queryapi.Engine satisfies it.
type Backend interface {
	// Query validates, executes, and paginates a federated query. A validation
	// failure returns a *queryapi.QueryError.
	Query(q queryapi.Query) (queryapi.Result, error)
	// Schema returns the stable, self-describing field registry and bounds.
	Schema() queryapi.Schema
}

// FindingsProvider supplies the full aggregated findings document for a
// coordinate so get_findings can return SARIF and per-finding detail rather than
// only the query summary. *findings.Store satisfies it.
type FindingsProvider interface {
	Get(tenant, pkg string) (findings.Document, bool)
}

// TimelineProvider supplies the reconstructed forensic timeline for a scope so
// get_timeline can return the correlated event chain. *timeline.Engine
// satisfies it.
type TimelineProvider interface {
	Query(ctx context.Context, q timeline.Query) (timeline.Result, error)
}

// ProvenanceProvider supplies dependency-graph provenance queries so
// get_provenance can return a path-to-commit and reverse-dependency blast
// radius. *provgraph.Service satisfies it.
type ProvenanceProvider interface {
	PathToCommit(ecosystem, name, version string) (provgraph.PathResult, error)
	ReverseDependencies(ecosystem, name, version string) (provgraph.DepResult, error)
}

// AttestProvider supplies the proxy's outbound attestation bundle for a
// coordinate so get_provenance can report whether the served artifact is signed.
// *attestbundle.Service satisfies it.
type AttestProvider interface {
	Get(tenant, pkg string) (*attestbundle.Bundle, bool)
}

// VulnProvider supplies the full VEX-applied vulnerability report for an
// artifact digest so get_vulnerabilities can return per-CVE detail. *vulnscan.Service
// satisfies it.
type VulnProvider interface {
	Report(digest string) (*vulnscan.Report, bool)
}

// RiskProvider supplies recent risk assessments so get_risk_verdict can enrich
// the summary with the explainable contribution breakdown. *riskscore.Engine
// satisfies it.
type RiskProvider interface {
	Recent(limit int) []riskscore.Assessment
}

// RepoScanProvider supplies the dependency scans of tracked repositories (Task
// 181) so get_repository_scan can return a revision's per-dependency verdicts.
// *repos.Service satisfies it.
type RepoScanProvider interface {
	ScanReport(ctx context.Context, tenant, name, rev string) (*repos.ScanReportView, error)
}
