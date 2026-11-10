package vexexport

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/approvals"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/snapshot"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

const (
	defaultAuthor      = "pullthrough-security"
	defaultIDNamespace = "https://pullthrough.security/vex"
)

// Config configures the VEX export service.
type Config struct {
	// Enabled turns outbound VEX authoring on. When false the admin endpoint and
	// ptctl subcommand report the surface absent.
	Enabled bool
	// Author is the OpenVEX "author" / CycloneDX metadata author stamped into
	// every exported document. Defaults to "pullthrough-security".
	Author string
	// IDNamespace is the base URI exported OpenVEX document @id values are minted
	// under. Defaults to "https://pullthrough.security/vex".
	IDNamespace string
}

// CorpusSource exposes the loaded VEX suppression corpus (Task 27). The
// vulnscan.Service satisfies it.
type CorpusSource interface {
	VEXEnabled() bool
	VEXStatements() []vulnscan.VEXStatement
}

// FindingsSource exposes the retained per-artifact findings documents (Task 42).
// The findings.Store satisfies it.
type FindingsSource interface {
	Get(tenant, pkg string) (findings.Document, bool)
	Documents(tenant, q string) []findings.Document
}

// GrantsSource exposes the break-glass / quarantine-approval grants (Task 50).
// The approvals.Service satisfies it.
type GrantsSource interface {
	Enabled() bool
	List(status string, limit int) []approvals.Request
	Sweep(ctx context.Context) int
}

// SnapshotSource exposes the organization dependency snapshots (Task 70). The
// snapshot.Service satisfies it.
type SnapshotSource interface {
	Enabled() bool
	QueryFacts() []snapshot.QueryFact
	Get(id string) (*snapshot.Manifest, bool)
}

// Option configures a Service.
type Option func(*Service)

// WithCorpus wires the VEX suppression corpus source.
func WithCorpus(c CorpusSource) Option { return func(s *Service) { s.corpus = c } }

// WithFindings wires the findings source.
func WithFindings(f FindingsSource) Option { return func(s *Service) { s.findings = f } }

// WithGrants wires the break-glass grants source.
func WithGrants(g GrantsSource) Option { return func(s *Service) { s.grants = g } }

// WithSnapshots wires the snapshot source.
func WithSnapshots(sn SnapshotSource) Option { return func(s *Service) { s.snapshots = sn } }

// WithClock overrides the time source (tests).
func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

// Service authors outbound VEX documents from the proxy's triage posture.
type Service struct {
	cfg    Config
	signer *Signer
	logger *slog.Logger
	now    func() time.Time

	corpus    CorpusSource
	findings  FindingsSource
	grants    GrantsSource
	snapshots SnapshotSource

	// metrics (cumulative, exposed via Metrics()).
	mu           sync.Mutex
	exports      map[string]int64 // "format|signed" -> count
	exportsTotal atomic.Int64
	stmtTotal    atomic.Int64
	errTotal     atomic.Int64
}

// New constructs a Service. signer may be nil, in which case Sign requests are
// rejected. A nil logger defaults to slog.Default().
func New(cfg Config, signer *Signer, logger *slog.Logger, opts ...Option) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Author == "" {
		cfg.Author = defaultAuthor
	}
	if cfg.IDNamespace == "" {
		cfg.IDNamespace = defaultIDNamespace
	}
	s := &Service{
		cfg:     cfg,
		signer:  signer,
		logger:  logger,
		now:     time.Now,
		exports: make(map[string]int64),
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Enabled reports whether outbound VEX authoring is active.
func (s *Service) Enabled() bool { return s != nil && s.cfg.Enabled }

// CanSign reports whether a signing key is configured.
func (s *Service) CanSign() bool { return s != nil && s.signer != nil }

// Request describes an export: a scope (one coordinate, a captured snapshot, or
// the whole live posture), a serialization format, and whether to sign.
type Request struct {
	// Tenant scopes findings/grants lookups and snapshot/live enumeration. Empty
	// matches every tenant.
	Tenant string
	// Ecosystem/Name/Version identify a single artifact to export VEX for. When
	// Name is set the export is single-coordinate.
	Ecosystem string
	Name      string
	Version   string
	// Coordinate is an alternative single-artifact selector ("name@version" or a
	// digest); used for the findings lookup when Name is not split out.
	Coordinate string
	// SnapshotID exports the posture for a captured snapshot's coordinate set.
	// Ignored when a single coordinate is given.
	SnapshotID string
	// Format selects the serialization (defaults to OpenVEX).
	Format Format
	// Sign requests a detached cosign-compatible signature over the document.
	Sign bool
}

// Result is a produced VEX document plus its metadata.
type Result struct {
	Format      Format     `json:"format"`
	MediaType   string     `json:"mediaType"`
	Filename    string     `json:"filename"`
	Document    []byte     `json:"-"`
	Signature   *Signature `json:"signature,omitempty"`
	Statements  int        `json:"statements"`
	Coordinates int        `json:"coordinates"`
	Scope       string     `json:"scope"`
}

// Export gathers the VEX posture for the requested scope and renders a document.
func (s *Service) Export(ctx context.Context, req Request) (*Result, error) {
	if !s.Enabled() {
		return nil, fmt.Errorf("vexexport: outbound VEX authoring is not enabled")
	}
	format, ok := NormalizeFormat(string(req.Format))
	if !ok {
		s.errTotal.Add(1)
		return nil, fmt.Errorf("vexexport: unknown format %q (want openvex|cyclonedx)", req.Format)
	}
	if req.Sign && s.signer == nil {
		s.errTotal.Add(1)
		return nil, fmt.Errorf("vexexport: signing requested but no signing key is configured")
	}

	stmts, scope, coords := s.gather(ctx, req)
	meta := docMeta{Author: s.cfg.Author, IDNamespace: s.cfg.IDNamespace, Timestamp: s.now()}

	var (
		doc []byte
		err error
	)
	switch format {
	case FormatCycloneDX:
		doc, err = buildCycloneDX(stmts, meta)
	default:
		doc, err = buildOpenVEX(stmts, meta)
	}
	if err != nil {
		s.errTotal.Add(1)
		return nil, err
	}

	res := &Result{
		Format:      format,
		MediaType:   format.MediaType(),
		Filename:    filename(format, req),
		Document:    doc,
		Statements:  len(stmts),
		Coordinates: coords,
		Scope:       scope,
	}
	if req.Sign {
		sig, serr := s.signer.Sign(doc)
		if serr != nil {
			s.errTotal.Add(1)
			return nil, serr
		}
		res.Signature = &sig
	}
	s.recordExport(format, req.Sign, len(stmts))
	return res, nil
}

// gather collects the deduplicated VEX statements for a request's scope and
// returns them alongside a human-readable scope label and the number of
// coordinates considered.
func (s *Service) gather(ctx context.Context, req Request) ([]vulnscan.VEXStatement, string, int) {
	coords, scope := s.resolveScope(ctx, req)

	seen := make(map[string]bool)
	var out []vulnscan.VEXStatement

	add := func(st vulnscan.VEXStatement) {
		key := statementKey(st)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, st)
	}

	// 1) The authoritative not_affected/affected/fixed corpus (Task 27). For a
	//    single-coordinate export only statements covering that coordinate are
	//    included; a snapshot/whole-posture export includes the full set.
	if s.corpus != nil && s.corpus.VEXEnabled() {
		single := scope == scopeArtifact
		var target coordinate
		if single && len(coords) == 1 {
			target = coords[0]
		}
		for _, st := range s.corpus.VEXStatements() {
			if single && !statementCovers(st, target) {
				continue
			}
			add(stampCorpus(st))
		}
	}

	// 2) VEX-adjudicated suppressions observed in scan findings — captures
	//    per-artifact fetched VEX and inline adjudications not in the static
	//    corpus. not_affected / fixed.
	if s.findings != nil {
		for _, c := range coords {
			doc, ok := s.findings.Get(req.Tenant, c.lookup())
			if !ok {
				continue
			}
			for _, st := range findingSuppressions(doc) {
				add(st)
			}
		}
	}

	// 3) Active break-glass grants (Task 50) → under_investigation statements: the
	//    artifact is known-flagged but served under a time-boxed, dual-controlled
	//    exception. Cross-referenced to the coordinate's vuln findings for real
	//    advisory ids when available.
	if s.grants != nil && s.grants.Enabled() {
		for _, st := range s.grantStatements(ctx, req, coords) {
			add(st)
		}
	}

	sortStatements(out)
	return out, scope, len(coords)
}

const (
	scopeArtifact = "artifact"
	scopeSnapshot = "snapshot"
	scopeLive     = "live"
)

// resolveScope determines the coordinate set and a scope label for a request.
func (s *Service) resolveScope(ctx context.Context, req Request) ([]coordinate, string) {
	// Single artifact.
	if name := strings.TrimSpace(req.Name); name != "" {
		return []coordinate{newCoordinate(req.Ecosystem, name, req.Version, req.Coordinate)}, scopeArtifact
	}
	if coord := strings.TrimSpace(req.Coordinate); coord != "" {
		eco, name, version := splitCoordinate(coord)
		if req.Ecosystem != "" {
			eco = req.Ecosystem
		}
		return []coordinate{newCoordinate(eco, name, version, coord)}, scopeArtifact
	}

	// Captured snapshot.
	if id := strings.TrimSpace(req.SnapshotID); id != "" && s.snapshots != nil && s.snapshots.Enabled() {
		if m, ok := s.snapshots.Get(id); ok && m != nil {
			return coordinatesFromEntries(m.Entries, req.Tenant), scopeSnapshot
		}
		return nil, scopeSnapshot
	}

	// Whole live posture: union of snapshot live facts and retained findings docs.
	set := newCoordinateSet()
	if s.snapshots != nil && s.snapshots.Enabled() {
		for _, f := range s.snapshots.QueryFacts() {
			if !tenantMatches(req.Tenant, f.Tenant) {
				continue
			}
			set.add(newCoordinate(f.Ecosystem, f.Name, f.Version, f.Coordinate))
		}
	}
	if s.findings != nil {
		for _, d := range s.findings.Documents(req.Tenant, "") {
			set.add(newCoordinate(d.Artifact.Ecosystem, d.Artifact.Name, d.Artifact.Version, d.Artifact.Coordinate))
		}
	}
	return set.sorted(), scopeLive
}

// grantStatements turns the active break-glass grants covering the scope's
// coordinates into under_investigation VEX statements.
func (s *Service) grantStatements(ctx context.Context, req Request, coords []coordinate) []vulnscan.VEXStatement {
	// Sweep first so expired-but-unswept grants do not surface as active.
	s.grants.Sweep(ctx)
	now := s.now()
	want := make(map[string]bool, len(coords))
	for _, c := range coords {
		want[strings.ToLower(c.lookup())] = true
	}
	var out []vulnscan.VEXStatement
	for _, g := range s.grants.List(string(approvals.StatusApproved), 0) {
		if g.Status != approvals.StatusApproved || !now.Before(g.ExpiresAt) {
			continue
		}
		if !tenantMatches(req.Tenant, g.Tenant) {
			continue
		}
		if len(coords) > 0 && !want[strings.ToLower(strings.TrimSpace(g.Coordinate))] {
			continue
		}
		product := grantProduct(g)
		action := grantAction(g, now)
		// Resolve real advisory ids from the coordinate's vuln findings when the
		// gate that was broken is a vulnerability gate.
		ids := s.grantVulnIDs(req.Tenant, g)
		if len(ids) == 0 {
			ids = []string{grantSyntheticID(g)}
		}
		for _, id := range ids {
			out = append(out, vulnscan.VEXStatement{
				Vulnerability:   id,
				Products:        []vulnscan.VEXProductRef{product},
				Status:          vulnscan.VEXUnderInvestigation,
				ImpactStatement: grantImpact(g),
				ActionStatement: action,
				Timestamp:       grantTimestamp(g),
				Source:          "break-glass:" + g.ID,
				Format:          "openvex",
			})
		}
	}
	return out
}

// grantVulnIDs returns the advisory ids of the unsuppressed vulnerability
// findings for a grant's coordinate, so a break-glass statement cites the real
// CVEs the exception covers.
func (s *Service) grantVulnIDs(tenant string, g approvals.Request) []string {
	if s.findings == nil || !strings.EqualFold(strings.TrimSpace(g.Gate), "vulnscan") {
		return nil
	}
	doc, ok := s.findings.Get(tenant, strings.TrimSpace(g.Coordinate))
	if !ok {
		return nil
	}
	seen := make(map[string]bool)
	var ids []string
	for _, f := range doc.Findings {
		if f.Gate != findings.GateVulnscan || f.Suppressed {
			continue
		}
		id := strings.TrimSpace(f.Identifier)
		if id == "" || seen[strings.ToLower(id)] {
			continue
		}
		seen[strings.ToLower(id)] = true
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// recordExport updates the cumulative export counters.
func (s *Service) recordExport(format Format, signed bool, stmts int) {
	s.exportsTotal.Add(1)
	s.stmtTotal.Add(int64(stmts))
	key := string(format) + "|" + boolLabel(signed)
	s.mu.Lock()
	s.exports[key]++
	s.mu.Unlock()
}

// Metrics is a cumulative snapshot of export activity.
type Metrics struct {
	ExportsTotal    int64
	StatementsTotal int64
	ErrorsTotal     int64
	ByFormat        map[string]int64 // "format|signed" -> count
}

// Metrics returns a cumulative snapshot for the Prometheus bridge.
func (s *Service) Metrics() Metrics {
	m := Metrics{
		ExportsTotal:    s.exportsTotal.Load(),
		StatementsTotal: s.stmtTotal.Load(),
		ErrorsTotal:     s.errTotal.Load(),
		ByFormat:        make(map[string]int64),
	}
	s.mu.Lock()
	for k, v := range s.exports {
		m.ByFormat[k] = v
	}
	s.mu.Unlock()
	return m
}

func boolLabel(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
