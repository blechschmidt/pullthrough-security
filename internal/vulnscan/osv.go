package vulnscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultOSVBaseURL is the public OSV.dev API endpoint.
const DefaultOSVBaseURL = "https://api.osv.dev"

// osvBatchLimit bounds the number of queries sent in a single querybatch request
// (the OSV API accepts up to 1000).
const osvBatchLimit = 1000

// osvDetailWorkers bounds concurrent vulnerability-detail fetches.
const osvDetailWorkers = 8

// httpDoer is the subset of *http.Client the OSV scanner depends on, so a fake
// transport can be injected in tests.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// OSVScanner resolves SBOM components against the OSV.dev database. It implements
// the Scanner interface and is the subsystem's default backend. It uses the
// querybatch endpoint to enumerate affecting advisories, then fetches each unique
// advisory's details once to derive severity/CVSS.
type OSVScanner struct {
	baseURL string
	client  httpDoer
}

// OSVOption configures an OSVScanner.
type OSVOption func(*OSVScanner)

// WithOSVHTTPClient injects the HTTP client used for OSV requests.
func WithOSVHTTPClient(c httpDoer) OSVOption {
	return func(s *OSVScanner) {
		if c != nil {
			s.client = c
		}
	}
}

// NewOSVScanner constructs an OSVScanner. baseURL defaults to DefaultOSVBaseURL
// when empty; the default HTTP client carries a 30s timeout.
func NewOSVScanner(baseURL string, opts ...OSVOption) *OSVScanner {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = DefaultOSVBaseURL
	}
	s := &OSVScanner{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: 30 * time.Second},
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Name identifies the scanner backend.
func (s *OSVScanner) Name() string { return "osv" }

// Scan resolves every OSV-covered component of the SBOM. Components in ecosystems
// OSV does not index by coordinate (e.g. docker images) are skipped; the SBOM is
// still returned so a pluggable layer/OS scanner can handle them.
func (s *OSVScanner) Scan(ctx context.Context, sbom *SBOM) ([]Vulnerability, error) {
	if sbom == nil {
		return nil, nil
	}
	type queried struct {
		component Component
		osvEco    string
	}
	var queries []osvQuery
	var meta []queried
	for _, c := range sbom.scannableComponents() {
		osvEco, ok := OSVEcosystem(c.ecosystem)
		if !ok {
			continue
		}
		name := c.Name
		if c.Group != "" {
			name = c.Group + "/" + c.Name
		}
		queries = append(queries, osvQuery{
			Package: osvPackage{Name: name, Ecosystem: osvEco},
			Version: c.Version,
		})
		meta = append(meta, queried{component: c, osvEco: osvEco})
	}
	if len(queries) == 0 {
		return nil, nil
	}

	// Phase 1: batch-resolve affecting advisory IDs per query.
	batchResults, err := s.queryBatch(ctx, queries)
	if err != nil {
		return nil, err
	}

	// Collect the unique advisory IDs and the components each affects.
	idToComponents := make(map[string][]Component)
	var order []string
	for i, res := range batchResults {
		if i >= len(meta) {
			break
		}
		for _, v := range res.Vulns {
			if v.ID == "" {
				continue
			}
			if _, seen := idToComponents[v.ID]; !seen {
				order = append(order, v.ID)
			}
			idToComponents[v.ID] = append(idToComponents[v.ID], meta[i].component)
		}
	}
	if len(order) == 0 {
		return nil, nil
	}

	// Phase 2: fetch each unique advisory's details once, concurrently.
	details, err := s.fetchDetails(ctx, order)
	if err != nil {
		return nil, err
	}

	var out []Vulnerability
	for _, id := range order {
		rec := details[id]
		for _, comp := range idToComponents[id] {
			out = append(out, osvToVulnerability(id, rec, comp))
		}
	}
	return out, nil
}

// --- OSV wire types ---------------------------------------------------------

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version,omitempty"`
}

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvBatchResponse struct {
	Results []osvBatchResult `json:"results"`
}

type osvBatchResult struct {
	Vulns []struct {
		ID       string `json:"id"`
		Modified string `json:"modified"`
	} `json:"vulns"`
}

// osvRecord models the subset of the OSV schema we consume from /v1/vulns/{id}.
type osvRecord struct {
	ID         string        `json:"id"`
	Summary    string        `json:"summary"`
	Details    string        `json:"details"`
	Aliases    []string      `json:"aliases"`
	Withdrawn  string        `json:"withdrawn"`
	Severity   []osvSeverity `json:"severity"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	Affected         []osvAffected `json:"affected"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// osvAffected models one entry of an OSV record's "affected" list.
type osvAffected struct {
	Package osvPackage `json:"package"`
	Ranges  []struct {
		Events []map[string]string `json:"events"`
	} `json:"ranges"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	EcosystemSpecific struct {
		// Imports is the OSV ecosystem_specific.imports list: the module/package
		// import paths (and optionally the symbols) the advisory marks vulnerable.
		// Populated by the Go vulnerability database and some PyPI/Maven advisories;
		// consumed by reachability analysis to match the exact imported module.
		Imports []struct {
			Path    string   `json:"path"`
			Symbols []string `json:"symbols"`
		} `json:"imports"`
	} `json:"ecosystem_specific"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// queryBatch posts queries to /v1/querybatch, chunking to the API's batch limit,
// and returns the per-query results in the original order.
func (s *OSVScanner) queryBatch(ctx context.Context, queries []osvQuery) ([]osvBatchResult, error) {
	var all []osvBatchResult
	for start := 0; start < len(queries); start += osvBatchLimit {
		end := start + osvBatchLimit
		if end > len(queries) {
			end = len(queries)
		}
		body, err := json.Marshal(osvBatchRequest{Queries: queries[start:end]})
		if err != nil {
			return nil, fmt.Errorf("osv: encoding batch query: %w", err)
		}
		resp, err := s.post(ctx, "/v1/querybatch", body)
		if err != nil {
			return nil, err
		}
		var decoded osvBatchResponse
		if err := json.Unmarshal(resp, &decoded); err != nil {
			return nil, fmt.Errorf("osv: decoding batch response: %w", err)
		}
		all = append(all, decoded.Results...)
	}
	return all, nil
}

// fetchDetails retrieves each advisory's full record, concurrently and bounded.
func (s *OSVScanner) fetchDetails(ctx context.Context, ids []string) (map[string]*osvRecord, error) {
	out := make(map[string]*osvRecord, len(ids))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, osvDetailWorkers)
	errCh := make(chan error, len(ids))

	for _, id := range ids {
		wg.Add(1)
		sem <- struct{}{}
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()
			rec, err := s.fetchOne(ctx, id)
			if err != nil {
				errCh <- err
				return
			}
			mu.Lock()
			out[id] = rec
			mu.Unlock()
		}(id)
	}
	wg.Wait()
	close(errCh)
	if err := <-errCh; err != nil {
		return nil, err
	}
	return out, nil
}

// fetchOne retrieves a single advisory record.
func (s *OSVScanner) fetchOne(ctx context.Context, id string) (*osvRecord, error) {
	resp, err := s.get(ctx, "/v1/vulns/"+id)
	if err != nil {
		return nil, err
	}
	var rec osvRecord
	if err := json.Unmarshal(resp, &rec); err != nil {
		return nil, fmt.Errorf("osv: decoding advisory %s: %w", id, err)
	}
	return &rec, nil
}

func (s *OSVScanner) post(ctx context.Context, path string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return s.do(req)
}

func (s *OSVScanner) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	return s.do(req)
}

func (s *OSVScanner) do(req *http.Request) ([]byte, error) {
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("osv: reading response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv: %s %s: unexpected status %d: %s",
			req.Method, req.URL.Path, resp.StatusCode, truncate(string(data), 200))
	}
	return data, nil
}

// osvToVulnerability normalizes an OSV record (which may be nil if the detail
// fetch returned an empty body) into the subsystem's Vulnerability for a given
// affected component.
func osvToVulnerability(id string, rec *osvRecord, comp Component) Vulnerability {
	v := Vulnerability{
		ID:        id,
		Component: comp.PURL,
		Package:   comp.Name,
		Version:   comp.Version,
		Severity:  SeverityUnknown,
	}
	if comp.Group != "" {
		v.Package = comp.Group + "/" + comp.Name
	}
	if rec == nil {
		return v
	}
	v.Summary = rec.Summary
	v.Details = truncate(rec.Details, 2000)
	v.Aliases = rec.Aliases
	v.Withdrawn = rec.Withdrawn != ""
	for _, ref := range rec.References {
		if ref.URL != "" {
			v.References = append(v.References, ref.URL)
		}
	}

	// Derive the highest CVSS base score from any published vector.
	cvss, vector := highestCVSS(rec.Severity)
	if cvss > 0 {
		v.CVSS = cvss
		v.CVSSVector = vector
		v.Severity = SeverityFromCVSS(cvss)
	} else {
		// No vector: fall back to a database-supplied qualitative rating.
		v.Severity = NormalizeSeverity(firstNonEmpty(
			rec.DatabaseSpecific.Severity,
			firstAffectedSeverity(rec),
		))
	}
	v.FixedVersions = collectFixedVersions(rec, comp)
	v.AffectedModules = collectAffectedModules(rec, comp)
	return v
}

// collectAffectedModules gathers the distinct ecosystem_specific.imports[].path
// values the advisory declares for the matching package coordinate. These are the
// language-level module/package import paths reachability analysis matches
// against the consuming artifact's own imports. An advisory that publishes no
// import paths yields an empty slice (reachability then derives candidates from
// the package coordinate).
func collectAffectedModules(rec *osvRecord, comp Component) []string {
	want := comp.Name
	if comp.Group != "" {
		want = comp.Group + "/" + comp.Name
	}
	seen := make(map[string]bool)
	var paths []string
	for _, aff := range rec.Affected {
		// Restrict to the affected entry for this coordinate when the record names
		// one; an entry without a package name is treated as applying to the finding.
		if aff.Package.Name != "" && !strings.EqualFold(aff.Package.Name, want) {
			continue
		}
		for _, imp := range aff.EcosystemSpecific.Imports {
			p := strings.TrimSpace(imp.Path)
			if p != "" && !seen[p] {
				seen[p] = true
				paths = append(paths, p)
			}
		}
	}
	sort.Strings(paths)
	return paths
}

// highestCVSS returns the maximum base score (and its vector) across an OSV
// severity list, preferring CVSS_V3/V4 vectors.
func highestCVSS(sevs []osvSeverity) (float64, string) {
	var best float64
	var bestVector string
	for _, s := range sevs {
		switch strings.ToUpper(s.Type) {
		case "CVSS_V2", "CVSS_V3", "CVSS_V4":
			if score, ok := ParseCVSSBaseScore(s.Score); ok && score > best {
				best, bestVector = score, s.Score
			}
		}
	}
	return best, bestVector
}

// firstAffectedSeverity returns the first affected-entry database-specific
// severity string, if any.
func firstAffectedSeverity(rec *osvRecord) string {
	for _, aff := range rec.Affected {
		if aff.DatabaseSpecific.Severity != "" {
			return aff.DatabaseSpecific.Severity
		}
	}
	return ""
}

// collectFixedVersions extracts "fixed" range events for the matching package.
func collectFixedVersions(rec *osvRecord, comp Component) []string {
	want := comp.Name
	if comp.Group != "" {
		want = comp.Group + "/" + comp.Name
	}
	seen := make(map[string]bool)
	var fixed []string
	for _, aff := range rec.Affected {
		if aff.Package.Name != "" && !strings.EqualFold(aff.Package.Name, want) {
			continue
		}
		for _, rng := range aff.Ranges {
			for _, ev := range rng.Events {
				if f := ev["fixed"]; f != "" && !seen[f] {
					seen[f] = true
					fixed = append(fixed, f)
				}
			}
		}
	}
	sort.Strings(fixed)
	return fixed
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
