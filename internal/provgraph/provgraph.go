// Package provgraph turns the proxy's package-to-commit provenance data (Task 8)
// together with cache/scan metadata (SBOM components, CVE findings, signature
// status) into a queryable supply-chain graph (Task 33).
//
// Every artifact the proxy pulls, and what was learned about it during
// admission, is ingested as an Event into an in-memory, thread-safe graph of
// typed nodes (packages, versions, commits, CVEs, signers) and typed edges
// (has-version, depends-on, built-from-commit, affected-by-CVE, signed-by). On
// top of that graph the package exposes a read API:
//
//   - BlastRadius: which cached artifacts are affected by a given CVE or commit,
//     following reverse dependency edges so transitive consumers are included;
//   - ReverseDependencies: which artifacts depend on a given artifact;
//   - PathToCommit: a path from an artifact to the source commit it was built
//     from (directly, or through its dependencies).
//
// The graph is also exported as a self-contained JSON document (for offline
// analysis and the admin force-directed visualization) and exposes size metrics.
//
// The package is deliberately self-contained: it depends only on the standard
// library so it can be embedded anywhere and unit-tested in isolation. Callers
// translate their own domain types (provenance.Link, vulnscan.Report,
// sigverify.Report) into the Event/ref types defined here.
package provgraph

import "time"

// NodeKind enumerates the kinds of entity a node represents.
type NodeKind string

const (
	// NodePackage is a package coordinate without a version (ecosystem + name).
	// It groups all observed versions of a package.
	NodePackage NodeKind = "package"
	// NodeVersion is a concrete package@version — a cached artifact. This is the
	// unit blast-radius and reverse-dependency queries operate over.
	NodeVersion NodeKind = "version"
	// NodeCommit is a source-control commit a version was built from.
	NodeCommit NodeKind = "commit"
	// NodeCVE is a vulnerability advisory (CVE/GHSA/OSV id).
	NodeCVE NodeKind = "cve"
	// NodeSigner is a signing identity that signed an artifact.
	NodeSigner NodeKind = "signer"
)

// EdgeKind enumerates the typed relationships between nodes.
type EdgeKind string

const (
	// EdgeHasVersion connects a package node to one of its version nodes.
	EdgeHasVersion EdgeKind = "has-version"
	// EdgeDependsOn connects a version to a version it depends on (SBOM edge).
	EdgeDependsOn EdgeKind = "depends-on"
	// EdgeBuiltFromCommit connects a version to the commit it was built from.
	EdgeBuiltFromCommit EdgeKind = "built-from-commit"
	// EdgeAffectedByCVE connects a version to a CVE that affects it.
	EdgeAffectedByCVE EdgeKind = "affected-by-cve"
	// EdgeSignedBy connects a version to the identity that signed it.
	EdgeSignedBy EdgeKind = "signed-by"
)

// ArtifactRef identifies a package artifact being ingested.
type ArtifactRef struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Digest    string `json:"digest,omitempty"`
}

// CommitRef is the source revision an artifact was built from, joined with the
// scan verdict for that commit when one is known.
type CommitRef struct {
	SHA             string `json:"sha"`
	RepositoryURL   string `json:"repositoryUrl,omitempty"`
	BuilderID       string `json:"builderId,omitempty"`
	Confidence      string `json:"confidence,omitempty"`
	RiskScore       int    `json:"riskScore,omitempty"`
	Malicious       bool   `json:"malicious,omitempty"`
	HighestSeverity string `json:"highestSeverity,omitempty"`
	// RepoHealth and RepoHealthGrade carry the source-repository health score
	// (Task 63) when it was derived for this commit's repository (0 / "" when the
	// repository was not resolved or the provider is disabled).
	RepoHealth      int    `json:"repoHealth,omitempty"`
	RepoHealthGrade string `json:"repoHealthGrade,omitempty"`
}

// CVERef is a vulnerability finding affecting an artifact.
type CVERef struct {
	ID         string  `json:"id"`
	Severity   string  `json:"severity,omitempty"`
	CVSS       float64 `json:"cvss,omitempty"`
	Package    string  `json:"package,omitempty"`
	Version    string  `json:"version,omitempty"`
	Suppressed bool    `json:"suppressed,omitempty"`
}

// SignerRef is a signing identity that signed an artifact.
type SignerRef struct {
	Identity string `json:"identity"`
	Issuer   string `json:"issuer,omitempty"`
	Verified bool   `json:"verified,omitempty"`
	Keyless  bool   `json:"keyless,omitempty"`
}

// Event is a single ingestion record describing a pulled artifact and what was
// learned about it during admission. Only Artifact (with at least an ecosystem
// and name) is required; the rest are optional and additive — repeated ingests
// of the same artifact upsert nodes and edges idempotently.
type Event struct {
	// Artifact is the pulled artifact the event is about.
	Artifact ArtifactRef
	// Commit is the source revision the artifact was built from, when known.
	Commit *CommitRef
	// Dependencies are the artifact's SBOM components (depends-on edges).
	Dependencies []ArtifactRef
	// CVEs are the vulnerability findings affecting the artifact.
	CVEs []CVERef
	// Signers are the identities that signed the artifact.
	Signers []SignerRef
	// Time is when the event was observed. Zero means "now".
	Time time.Time
}

// Ingestor is the narrow ingestion surface other subsystems depend on, so the
// proxy can feed events without importing the concrete Service. The Service
// satisfies it.
type Ingestor interface {
	Ingest(ev Event)
}
