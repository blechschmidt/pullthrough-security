package grpcapi

import (
	"context"

	"github.com/blechschmidt/pullthrough-security/internal/attestbundle"
	"github.com/blechschmidt/pullthrough-security/internal/compliance"
	"github.com/blechschmidt/pullthrough-security/internal/dossier"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/provgraph"
	"github.com/blechschmidt/pullthrough-security/internal/queryapi"
	"github.com/blechschmidt/pullthrough-security/internal/riskscore"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// Backend is the primary read-model the gRPC/Connect service projects over: the
// federated query engine (Task 67). Reusing it means every RPC answers from the
// same stable field registry as the GraphQL and MCP surfaces and inherits the
// engine's deterministic cost bounds, rather than reinventing per-RPC
// projections. *queryapi.Engine satisfies it.
type Backend interface {
	// Query validates, executes, and paginates a federated query. A validation
	// failure returns a *queryapi.QueryError.
	Query(q queryapi.Query) (queryapi.Result, error)
}

// DossierProvider assembles the unified per-coordinate "360 view" (Task 87) by
// folding every wired subsystem's view of a coordinate into one card.
// *dossier.Builder satisfies it.
type DossierProvider interface {
	Build(ctx context.Context, q dossier.Query) *dossier.Dossier
}

// FindingsProvider supplies the full aggregated findings document for a
// coordinate so GetFindings can return per-finding detail rather than only the
// query summary. *findings.Store satisfies it.
type FindingsProvider interface {
	Get(tenant, pkg string) (findings.Document, bool)
}

// ProvenanceProvider supplies dependency-graph provenance queries so
// GetProvenance can return a path-to-commit and reverse-dependency blast radius.
// *provgraph.Service satisfies it.
type ProvenanceProvider interface {
	PathToCommit(ecosystem, name, version string) (provgraph.PathResult, error)
	ReverseDependencies(ecosystem, name, version string) (provgraph.DepResult, error)
}

// AttestProvider supplies the proxy's outbound attestation bundle for a
// coordinate so GetProvenance can report whether the served artifact is signed.
// *attestbundle.Service satisfies it.
type AttestProvider interface {
	Get(tenant, pkg string) (*attestbundle.Bundle, bool)
}

// VulnProvider supplies the full VEX-applied vulnerability report for an
// artifact digest. *vulnscan.Service satisfies it.
type VulnProvider interface {
	Report(digest string) (*vulnscan.Report, bool)
}

// RiskProvider supplies recent risk assessments so GetRiskVerdict can enrich the
// summary with the explainable contribution breakdown. *riskscore.Engine
// satisfies it.
type RiskProvider interface {
	Recent(limit int) []riskscore.Assessment
}

// ComplianceProvider supplies the continuous-compliance scorecard (Task 35).
// *compliance.Service satisfies it.
type ComplianceProvider interface {
	Latest() compliance.Scorecard
	Recompute() compliance.Scorecard
}
