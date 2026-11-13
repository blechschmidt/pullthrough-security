// Package mcpserver implements a read-only Model Context Protocol (MCP) server
// that exposes the proxy's supply-chain security knowledge to AI assistants
// (Claude, Codex, IDE agents). It turns the proxy into a first-class context
// source for agentic developer workflows: an agent can ask "is this package safe
// to add?" and get the proxy's authoritative verdict, findings, provenance,
// timeline, and known vulnerabilities for a coordinate.
//
// The server speaks MCP (JSON-RPC 2.0) over two transports:
//
//   - HTTP, mounted under the admin API at POST /api/mcp. It reuses the admin
//     RBAC layer: the endpoint requires the read capability (CapRead) and is
//     hard-scoped to the caller's tenant taken from the authenticated
//     adminauth.Identity. See internal/admin/mcp.go.
//   - stdio (newline-delimited JSON-RPC), via ServeStdio, so the package can be
//     embedded as a local stdio MCP server. ptctl provides a thin stdio↔HTTP
//     bridge for IDE agents (see `ptctl mcp --stdio`).
//
// Every tool projects over the existing federated query engine (Task 67),
// reusing its stable field registry rather than reinventing per-tool
// projections, and therefore inherits the engine's deterministic cost bounds.
// Tools optionally enrich the summary with detail from the backing subsystems
// (findings/SARIF, provgraph + attestbundle, timeline, vulnscan/VEX) when those
// providers are wired; with nothing wired they degrade to the query summary.
package mcpserver

import (
	"strings"
)

// DefaultMaxDetailItems bounds the number of detail records (findings,
// vulnerabilities, timeline events, dependents) any single tool returns, so a
// hostile or careless call cannot make the proxy marshal an unbounded payload.
const DefaultMaxDetailItems = 100

// serverName is the MCP server identity reported in the initialize handshake.
const serverName = "pullthrough-security"

// supportedProtocolVersion is the MCP protocol revision this server implements.
// The initialize handler echoes a client's requested version when present so a
// newer client negotiates down gracefully, otherwise it advertises this.
const supportedProtocolVersion = "2025-06-18"

// Config constructs a Server. Backend is required (it powers run_query and every
// tool's base projection); the detail providers and bounds are optional.
type Config struct {
	// Backend is the federated query engine the server projects over. Required.
	Backend Backend
	// Version is the proxy build version, reported in the MCP serverInfo and used
	// as the SARIF tool version. Defaults to "dev".
	Version string
	// MaxDetailItems bounds per-tool detail payloads. Defaults to
	// DefaultMaxDetailItems when <= 0.
	MaxDetailItems int

	// Optional detail providers. Each is consulted only when non-nil; a tool
	// degrades to the query summary when its provider is absent.
	Findings  FindingsProvider
	Timeline  TimelineProvider
	Provgraph ProvenanceProvider
	Attest    AttestProvider
	Vuln      VulnProvider
	Risk      RiskProvider
	// RepoScans is the repository registry's dependency scans (Task 181).
	RepoScans RepoScanProvider
}

// Server is a read-only MCP server. It is safe for concurrent use: it holds no
// mutable per-request state beyond the metrics counters, which are synchronized.
type Server struct {
	backend   Backend
	version   string
	maxDetail int

	findings  FindingsProvider
	timeline  TimelineProvider
	provgraph ProvenanceProvider
	attest    AttestProvider
	vuln      VulnProvider
	risk      RiskProvider
	repoScans RepoScanProvider

	tools  []tool
	byName map[string]tool

	metrics metrics
}

// New constructs a Server from cfg. It returns nil when no backend is supplied,
// so callers can treat a disabled/unwired MCP surface uniformly via Enabled.
func New(cfg Config) *Server {
	if cfg.Backend == nil {
		return nil
	}
	s := &Server{
		backend:   cfg.Backend,
		version:   strings.TrimSpace(cfg.Version),
		maxDetail: cfg.MaxDetailItems,
		findings:  cfg.Findings,
		timeline:  cfg.Timeline,
		provgraph: cfg.Provgraph,
		attest:    cfg.Attest,
		vuln:      cfg.Vuln,
		risk:      cfg.Risk,
		repoScans: cfg.RepoScans,
	}
	if s.version == "" {
		s.version = "dev"
	}
	if s.maxDetail <= 0 {
		s.maxDetail = DefaultMaxDetailItems
	}
	s.tools = s.buildTools()
	s.byName = make(map[string]tool, len(s.tools))
	for _, t := range s.tools {
		s.byName[t.Name] = t
	}
	return s
}

// Enabled reports whether the server is usable.
func (s *Server) Enabled() bool { return s != nil && s.backend != nil }

// Snapshot returns the server's cumulative per-tool telemetry.
func (s *Server) Snapshot() Snapshot {
	if s == nil {
		return Snapshot{ToolCalls: map[string]int64{}, ToolErrors: map[string]int64{}}
	}
	return s.metrics.snapshot()
}
