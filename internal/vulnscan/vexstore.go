package vulnscan

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// VEXFetcher retrieves VEX statements scoped to a single artifact on demand (for
// example from an OCI referrers API or a per-package metadata endpoint). It is the
// optional, network-backed complement to the directory store; in air-gapped /
// offline mode it is never invoked. Implementations must be safe for concurrent
// use and honor context cancellation.
type VEXFetcher interface {
	// FetchVEX returns the VEX statements applicable to art. A backend with no
	// statements returns an empty slice and a nil error; a transport failure
	// returns the error (the caller logs and falls back to the directory store).
	FetchVEX(ctx context.Context, art Artifact) ([]VEXStatement, error)
}

// vexFetchTTL bounds how long a per-artifact fetch result is cached before it is
// re-fetched, so a revoked statement is picked up within a bounded window.
const vexFetchTTL = 15 * time.Minute

// VEXStats is a point-in-time view of the store's loaded content and runtime
// activity, surfaced through the metrics and admin layers.
type VEXStats struct {
	// Documents is the number of VEX files successfully loaded from the directory.
	Documents int `json:"documents"`
	// Malformed is the number of files that failed to parse and were skipped.
	Malformed int `json:"malformed"`
	// Statements is the number of normalized statements held in the static index.
	Statements int `json:"statements"`
	// Sources lists the loaded document sources (paths/URLs).
	Sources []string `json:"sources,omitempty"`
	// LoadedAt is when the directory was last (re)loaded.
	LoadedAt time.Time `json:"loadedAt,omitempty"`
}

// VEXStore holds the operator-supplied VEX statements that the scanning gate
// consults to suppress, escalate, or annotate findings. Statements are loaded
// from a configurable directory (offline-friendly) and/or fetched per artifact
// through an optional VEXFetcher. It is safe for concurrent use.
type VEXStore struct {
	logger  *slog.Logger
	offline bool

	mu         sync.RWMutex
	statements []VEXStatement // static, directory-loaded
	stats      VEXStats

	fetcher VEXFetcher
	fcMu    sync.Mutex
	fcache  map[string]vexFetchEntry // artifact digest/coordinate -> fetched
}

type vexFetchEntry struct {
	statements []VEXStatement
	at         time.Time
}

// VEXStoreOption configures a VEXStore.
type VEXStoreOption func(*VEXStore)

// WithVEXFetcher sets the optional per-artifact fetcher. Ignored in offline mode.
func WithVEXFetcher(f VEXFetcher) VEXStoreOption {
	return func(s *VEXStore) { s.fetcher = f }
}

// WithVEXOffline marks the store air-gapped: the per-artifact fetcher is never
// consulted, only the directory-loaded statements are used.
func WithVEXOffline(offline bool) VEXStoreOption {
	return func(s *VEXStore) { s.offline = offline }
}

// NewVEXStore constructs an empty store. Call LoadDir to populate it from a
// directory of VEX documents.
func NewVEXStore(logger *slog.Logger, opts ...VEXStoreOption) *VEXStore {
	if logger == nil {
		logger = slog.Default()
	}
	s := &VEXStore{
		logger: logger,
		fcache: make(map[string]vexFetchEntry),
	}
	for _, o := range opts {
		o(s)
	}
	if s.offline {
		s.fetcher = nil
	}
	return s
}

// LoadDir parses every VEX document under dir (recursively) and replaces the
// store's static statement set. Files that fail to parse are logged and skipped
// (a single malformed document never prevents the rest from loading). An empty
// dir clears the static set. A non-existent directory is reported as an error so
// a misconfiguration is visible; a directory that exists but holds no VEX files
// loads cleanly with zero statements.
func (s *VEXStore) LoadDir(dir string) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		s.replace(nil, VEXStats{LoadedAt: time.Now()})
		return nil
	}
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("vex: load path is not a directory: " + dir)
	}

	var (
		statements []VEXStatement
		sources    []string
		documents  int
		malformed  int
	)
	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !isVEXFile(path) {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			s.logger.Warn("vex: skipping unreadable document", "path", path, "error", readErr)
			malformed++
			return nil
		}
		doc, parseErr := ParseVEX(data, path)
		if parseErr != nil {
			s.logger.Warn("vex: skipping malformed document", "path", path, "error", parseErr)
			malformed++
			return nil
		}
		documents++
		sources = append(sources, path)
		statements = append(statements, doc.Statements...)
		return nil
	})
	if walkErr != nil {
		return walkErr
	}

	sort.Strings(sources)
	s.replace(statements, VEXStats{
		Documents:  documents,
		Malformed:  malformed,
		Statements: len(statements),
		Sources:    sources,
		LoadedAt:   time.Now(),
	})
	s.logger.Info("vex: loaded statements",
		"dir", dir, "documents", documents, "statements", len(statements), "malformed", malformed)
	return nil
}

// AddDocument merges an already-parsed document into the static set (used for
// air-gapped bulk import and tests).
func (s *VEXStore) AddDocument(doc *VEXDocument) {
	if doc == nil || len(doc.Statements) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statements = append(s.statements, doc.Statements...)
	s.stats.Documents++
	s.stats.Statements = len(s.statements)
	s.stats.Sources = append(s.stats.Sources, doc.Source)
	if s.stats.LoadedAt.IsZero() {
		s.stats.LoadedAt = time.Now()
	}
}

func (s *VEXStore) replace(statements []VEXStatement, stats VEXStats) {
	s.mu.Lock()
	s.statements = statements
	s.stats = stats
	s.mu.Unlock()
	// A reload invalidates per-artifact fetch caches so a revoked statement is not
	// masked by a stale fetch.
	s.fcMu.Lock()
	s.fcache = make(map[string]vexFetchEntry)
	s.fcMu.Unlock()
}

// Stats returns a snapshot of the store's loaded content.
func (s *VEXStore) Stats() VEXStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := s.stats
	out.Sources = append([]string(nil), s.stats.Sources...)
	return out
}

// Statements returns a copy of the static statement set (for the admin surface).
func (s *VEXStore) Statements() []VEXStatement {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]VEXStatement(nil), s.statements...)
}

// Match returns the governing VEX statement for a finding within an artifact,
// considering only the static (directory-loaded) statements. When several
// statements match, the most recent (by timestamp) wins, reproducing OpenVEX
// revocation semantics. It is the simple, network-free entry point used by tests
// and callers without a fetch context.
func (s *VEXStore) Match(art Artifact, v Vulnerability) (VEXStatement, bool) {
	s.mu.RLock()
	stmts := s.statements
	out, ok := matchStatement(stmts, art, v)
	s.mu.RUnlock()
	return out, ok
}

// statementsFor returns the statements relevant to an artifact: the static set
// plus, when a fetcher is configured and the store is online, any fetched
// per-artifact statements (cached with a short TTL). A fetch failure degrades to
// the static set.
func (s *VEXStore) statementsFor(ctx context.Context, art Artifact) []VEXStatement {
	s.mu.RLock()
	out := append([]VEXStatement(nil), s.statements...)
	s.mu.RUnlock()

	if s.fetcher == nil || s.offline {
		return out
	}
	if fetched, ok := s.fetch(ctx, art); ok {
		out = append(out, fetched...)
	}
	return out
}

// fetch returns the per-artifact statements, using the short-TTL cache.
func (s *VEXStore) fetch(ctx context.Context, art Artifact) ([]VEXStatement, bool) {
	key := vexArtifactKey(art)
	if key == "" {
		return nil, false
	}
	s.fcMu.Lock()
	if e, ok := s.fcache[key]; ok && time.Since(e.at) < vexFetchTTL {
		s.fcMu.Unlock()
		return e.statements, len(e.statements) > 0
	}
	s.fcMu.Unlock()

	stmts, err := s.fetcher.FetchVEX(ctx, art)
	if err != nil {
		s.logger.Warn("vex: per-artifact fetch failed; using directory statements only",
			"artifact", art.Name, "version", art.Version, "error", err)
		return nil, false
	}
	// Stamp a source/format on fetched statements that lack one for audit.
	for i := range stmts {
		if strings.TrimSpace(stmts[i].Source) == "" {
			stmts[i].Source = "fetch:" + key
		}
		stmts[i].newProductPurls()
	}
	s.fcMu.Lock()
	s.fcache[key] = vexFetchEntry{statements: stmts, at: time.Now()}
	s.fcMu.Unlock()
	return stmts, len(stmts) > 0
}

// matchStatement selects the governing statement from a candidate set for a
// finding within an artifact: the most recent statement whose product and
// vulnerability both match. Returns ok=false when none match.
func matchStatement(stmts []VEXStatement, art Artifact, v Vulnerability) (VEXStatement, bool) {
	var best *VEXStatement
	for i := range stmts {
		st := &stmts[i]
		if !st.matchesVuln(v) || !st.matchesProduct(art, v) {
			continue
		}
		if best == nil || statementNewer(st, best) {
			best = st
		}
	}
	if best == nil {
		return VEXStatement{}, false
	}
	return *best, true
}

// statementNewer reports whether a supersedes b: a later timestamp wins; on a tie
// (or both zero) a definitive status (not under_investigation) is preferred so an
// actionable assertion is not masked by a placeholder.
func statementNewer(a, b *VEXStatement) bool {
	if !a.Timestamp.Equal(b.Timestamp) {
		return a.Timestamp.After(b.Timestamp)
	}
	if a.Status != VEXUnderInvestigation && b.Status == VEXUnderInvestigation {
		return true
	}
	return false
}

// newProductPurls re-parses each product id into its structural purl form, used
// after a fetcher returns statements assembled without the parser.
func (st *VEXStatement) newProductPurls() {
	for i := range st.Products {
		if !st.Products[i].hasP {
			if pp, ok := parsePurl(st.Products[i].ID); ok {
				st.Products[i].purl, st.Products[i].hasP = pp, true
			}
		}
		for j := range st.Products[i].Subcomponents {
			sc := &st.Products[i].Subcomponents[j]
			if !sc.hasP {
				if pp, ok := parsePurl(sc.ID); ok {
					sc.purl, sc.hasP = pp, true
				}
			}
		}
	}
}

// vexArtifactKey derives a stable per-artifact cache key for fetched statements.
func vexArtifactKey(art Artifact) string {
	if art.Digest != "" {
		return art.Digest
	}
	if art.Name == "" {
		return ""
	}
	return art.Ecosystem + "/" + art.Name + "@" + art.Version
}

// isVEXFile reports whether a path looks like a JSON VEX document.
func isVEXFile(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".json") ||
		strings.HasSuffix(lower, ".vex") ||
		strings.HasSuffix(lower, ".vex.json")
}
