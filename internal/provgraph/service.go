package provgraph

import (
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Service is the supply-chain graph store. It is safe for concurrent use: ingest
// mutations take a write lock and queries take a read lock, so the proxy's hot
// path can ingest while operators query.
type Service struct {
	mu    sync.RWMutex
	g     *graph
	now   func() time.Time
	log   *slog.Logger
	count atomic.Int64 // total events ingested (for metrics)
}

// Options configures a Service.
type Options struct {
	// Logger is used for diagnostics. Defaults to slog.Default().
	Logger *slog.Logger
}

// New constructs an empty graph Service.
func New(opts Options) *Service {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Service{g: newGraph(), now: time.Now, log: log}
}

// --- stable node identities -------------------------------------------------

func packageID(ecosystem, name string) string {
	return "package:" + strings.ToLower(ecosystem) + "|" + name
}

func versionID(ecosystem, name, version string) string {
	return "version:" + strings.ToLower(ecosystem) + "|" + name + "|" + version
}

func commitID(sha string) string {
	return "commit:" + strings.ToLower(strings.TrimSpace(sha))
}

func cveID(id string) string {
	return "cve:" + strings.ToUpper(strings.TrimSpace(id))
}

func signerID(identity string) string {
	return "signer:" + strings.TrimSpace(identity)
}

// Ingest folds an Event into the graph, upserting nodes and edges idempotently.
// Repeated ingestion of the same artifact is safe and merges newly-learned
// detail (e.g. a later CVE finding) into the existing nodes. An event whose
// artifact has neither an ecosystem+name nor a version is dropped.
func (s *Service) Ingest(ev Event) {
	art := ev.Artifact
	if strings.TrimSpace(art.Name) == "" {
		return
	}
	now := ev.Time
	if now.IsZero() {
		now = s.now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	pkgID := packageID(art.Ecosystem, art.Name)
	s.g.upsertNode(pkgID, NodePackage, art.Name, map[string]string{
		"ecosystem": art.Ecosystem,
		"name":      art.Name,
	}, now)

	// Without a version we can still record the package node; everything below is
	// keyed by the concrete version, so stop here when none is known.
	if strings.TrimSpace(art.Version) == "" {
		s.count.Add(1)
		return
	}

	verID := versionID(art.Ecosystem, art.Name, art.Version)
	s.g.upsertNode(verID, NodeVersion, art.Name+"@"+art.Version, map[string]string{
		"ecosystem": art.Ecosystem,
		"name":      art.Name,
		"version":   art.Version,
		"digest":    art.Digest,
	}, now)
	s.g.upsertEdge(pkgID, EdgeHasVersion, verID, nil)

	// built-from-commit
	if c := ev.Commit; c != nil && strings.TrimSpace(c.SHA) != "" {
		cID := commitID(c.SHA)
		s.g.upsertNode(cID, NodeCommit, shortSHA(c.SHA), map[string]string{
			"sha":             c.SHA,
			"repositoryUrl":   c.RepositoryURL,
			"builderId":       c.BuilderID,
			"confidence":      c.Confidence,
			"riskScore":       itoaNonZero(c.RiskScore),
			"malicious":       boolAttr(c.Malicious),
			"highestSeverity": c.HighestSeverity,
		}, now)
		s.g.upsertEdge(verID, EdgeBuiltFromCommit, cID, map[string]string{
			"confidence": c.Confidence,
		})
	}

	// depends-on (SBOM components)
	for _, dep := range ev.Dependencies {
		if strings.TrimSpace(dep.Name) == "" {
			continue
		}
		depEco := dep.Ecosystem
		if depEco == "" {
			depEco = art.Ecosystem
		}
		depPkgID := packageID(depEco, dep.Name)
		s.g.upsertNode(depPkgID, NodePackage, dep.Name, map[string]string{
			"ecosystem": depEco,
			"name":      dep.Name,
		}, now)
		if strings.TrimSpace(dep.Version) == "" {
			// A versionless dependency still records the package-level edge.
			s.g.upsertEdge(verID, EdgeDependsOn, depPkgID, nil)
			continue
		}
		depVerID := versionID(depEco, dep.Name, dep.Version)
		s.g.upsertNode(depVerID, NodeVersion, dep.Name+"@"+dep.Version, map[string]string{
			"ecosystem": depEco,
			"name":      dep.Name,
			"version":   dep.Version,
			"digest":    dep.Digest,
		}, now)
		s.g.upsertEdge(depPkgID, EdgeHasVersion, depVerID, nil)
		s.g.upsertEdge(verID, EdgeDependsOn, depVerID, nil)
	}

	// affected-by-cve
	for _, v := range ev.CVEs {
		if strings.TrimSpace(v.ID) == "" {
			continue
		}
		cID := cveID(v.ID)
		s.g.upsertNode(cID, NodeCVE, strings.ToUpper(v.ID), map[string]string{
			"id":       v.ID,
			"severity": v.Severity,
			"cvss":     ftoaNonZero(v.CVSS),
		}, now)
		// Attribute the finding to the precise affected component when the CVE names
		// a different coordinate than the primary artifact (e.g. a transitive dep).
		affected := verID
		if v.Package != "" && (v.Package != art.Name || (v.Version != "" && v.Version != art.Version)) {
			affEco := art.Ecosystem
			affVer := v.Version
			affected = versionID(affEco, v.Package, affVer)
			s.g.upsertNode(affected, NodeVersion, v.Package+"@"+affVer, map[string]string{
				"ecosystem": affEco,
				"name":      v.Package,
				"version":   affVer,
			}, now)
			s.g.upsertEdge(packageID(affEco, v.Package), EdgeHasVersion, affected, nil)
		}
		s.g.upsertEdge(affected, EdgeAffectedByCVE, cID, map[string]string{
			"severity":   v.Severity,
			"suppressed": boolAttr(v.Suppressed),
		})
	}

	// signed-by
	for _, sg := range ev.Signers {
		if strings.TrimSpace(sg.Identity) == "" {
			continue
		}
		sID := signerID(sg.Identity)
		s.g.upsertNode(sID, NodeSigner, sg.Identity, map[string]string{
			"identity": sg.Identity,
			"issuer":   sg.Issuer,
			"keyless":  boolAttr(sg.Keyless),
		}, now)
		s.g.upsertEdge(verID, EdgeSignedBy, sID, map[string]string{
			"verified": boolAttr(sg.Verified),
		})
	}

	s.count.Add(1)
}

// --- small attribute helpers ------------------------------------------------

func boolAttr(b bool) string {
	if b {
		return "true"
	}
	return ""
}

func itoaNonZero(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}

func ftoaNonZero(f float64) string {
	if f == 0 {
		return ""
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

func shortSHA(sha string) string {
	sha = strings.TrimSpace(sha)
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
