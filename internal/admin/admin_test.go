package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/provenance"
	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// --- fakes ------------------------------------------------------------------

type fakeCache struct {
	entries []cache.Stat
	deleted []string
}

func (f *fakeCache) Entries(context.Context) ([]cache.Stat, error) { return f.entries, nil }
func (f *fakeCache) Stat(_ context.Context, key string) (*cache.Stat, error) {
	for i := range f.entries {
		if f.entries[i].Key == key {
			return &f.entries[i], nil
		}
	}
	return nil, cache.ErrNotFound
}
func (f *fakeCache) Delete(_ context.Context, key string) error {
	for _, e := range f.entries {
		if e.Key == key {
			f.deleted = append(f.deleted, key)
			return nil
		}
	}
	return cache.ErrNotFound
}

type fakeCacheMetrics struct{ snap cache.MetricsSnapshot }

func (f fakeCacheMetrics) Metrics() cache.MetricsSnapshot { return f.snap }

type fakeScan struct {
	verdicts []*commit.Verdict
	queue    int
}

func (f *fakeScan) Verdict(_ context.Context, sha string) (*commit.Verdict, error) {
	for _, v := range f.verdicts {
		if v.SHA == sha {
			return v, nil
		}
	}
	return nil, commit.ErrNotFound
}
func (f *fakeScan) Verdicts(context.Context) ([]*commit.Verdict, error) { return f.verdicts, nil }
func (f *fakeScan) QueueDepth() int                                     { return f.queue }
func (f *fakeScan) PendingCount() int                                   { return f.queue }

type fakeBackends struct{ names []string }

func (f fakeBackends) Names() []string { return f.names }

type fakeProvenance struct{ link *provenance.Link }

func (f fakeProvenance) Name() string { return "fake" }
func (f fakeProvenance) Resolve(_ context.Context, _ provenance.Artifact) (*provenance.Link, error) {
	if f.link == nil {
		return nil, provenance.ErrNoProvenance
	}
	return f.link, nil
}

type fakeLinks struct{ links []*provenance.EnrichedLink }

func (f fakeLinks) LinksWithVerdicts(context.Context) ([]*provenance.EnrichedLink, error) {
	return f.links, nil
}

// --- helpers ----------------------------------------------------------------

func newTestServer(t *testing.T, opts Options) *Server {
	t.Helper()
	if opts.Cache == nil {
		opts.Cache = &fakeCache{}
	}
	srv, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

func getJSON(t *testing.T, srv *Server, path, token string, out any) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if out != nil && rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("decoding %s: %v\n%s", path, err, rec.Body.String())
		}
	}
	return rec.Code
}

// --- tests ------------------------------------------------------------------

func TestOverviewAggregates(t *testing.T) {
	srv := newTestServer(t, Options{
		Cache: &fakeCache{entries: []cache.Stat{
			{Key: "a", Size: 100}, {Key: "b", Size: 250},
		}},
		CacheMetrics: fakeCacheMetrics{snap: cache.MetricsSnapshot{Hits: 8, Misses: 2, BytesServed: 999}},
		Scan: &fakeScan{queue: 3, verdicts: []*commit.Verdict{
			{SHA: "c1", Malicious: true}, {SHA: "c2"},
		}},
		Backends: fakeBackends{names: []string{"npm", "pip"}},
		Info:     Info{Version: "test", CacheBackend: "memory"},
	})

	var resp overviewResponse
	if code := getJSON(t, srv, "/admin/api/overview", "", &resp); code != http.StatusOK {
		t.Fatalf("overview status = %d", code)
	}
	if resp.CacheEntryCount != 2 || resp.CacheTotalBytes != 350 {
		t.Errorf("cache totals = %d/%d, want 2/350", resp.CacheEntryCount, resp.CacheTotalBytes)
	}
	if resp.Cache == nil || resp.Cache.HitRatio != 0.8 {
		t.Errorf("hit ratio = %v, want 0.8", resp.Cache)
	}
	if resp.Scan == nil || resp.Scan.Total != 2 || resp.Scan.Malicious != 1 || resp.Scan.QueueDepth != 3 {
		t.Errorf("scan summary = %+v", resp.Scan)
	}
	if len(resp.Backends) != 2 {
		t.Errorf("backends = %v", resp.Backends)
	}
}

func TestCacheListFilterAndEntry(t *testing.T) {
	fc := &fakeCache{entries: []cache.Stat{
		{Key: "npm/left-pad", Size: 10, ModTime: time.Now(), Metadata: map[string]string{cache.MetaOrigin: "https://registry.npmjs.org/left-pad"}},
		{Key: "pip/requests", Size: 20, ModTime: time.Now().Add(-time.Hour)},
	}}
	srv := newTestServer(t, Options{Cache: fc})

	var list cacheListResponse
	getJSON(t, srv, "/admin/api/cache?q=left", "", &list)
	if list.Returned != 1 || list.Items[0].Key != "npm/left-pad" {
		t.Fatalf("filter result = %+v", list)
	}
	if list.Items[0].Origin == "" {
		t.Errorf("origin not surfaced: %+v", list.Items[0])
	}

	// Single-entry lookup.
	var entry cacheEntryDTO
	if code := getJSON(t, srv, "/admin/api/cache/entry?key=pip/requests", "", &entry); code != http.StatusOK {
		t.Fatalf("entry status = %d", code)
	}
	if entry.Size != 20 {
		t.Errorf("entry size = %d", entry.Size)
	}

	// Missing key → 404.
	if code := getJSON(t, srv, "/admin/api/cache/entry?key=missing", "", nil); code != http.StatusNotFound {
		t.Errorf("missing entry status = %d, want 404", code)
	}
}

func TestCacheDelete(t *testing.T) {
	fc := &fakeCache{entries: []cache.Stat{{Key: "doomed"}}}
	srv := newTestServer(t, Options{Cache: fc})

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/cache/entry?key=doomed", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d", rec.Code)
	}
	if len(fc.deleted) != 1 || fc.deleted[0] != "doomed" {
		t.Errorf("delete not recorded: %v", fc.deleted)
	}
}

func TestScansListSortedByRisk(t *testing.T) {
	srv := newTestServer(t, Options{
		Cache: &fakeCache{},
		Scan: &fakeScan{verdicts: []*commit.Verdict{
			{SHA: "low", RiskScore: 10, ScannedAt: time.Now()},
			{SHA: "high", RiskScore: 90, Malicious: true, ScannedAt: time.Now()},
		}},
	})
	var list scanListResponse
	if code := getJSON(t, srv, "/admin/api/scans", "", &list); code != http.StatusOK {
		t.Fatalf("scans status = %d", code)
	}
	if !list.Enabled || len(list.Items) != 2 {
		t.Fatalf("scan list = %+v", list)
	}
	if list.Items[0].SHA != "high" {
		t.Errorf("expected highest-risk first, got %q", list.Items[0].SHA)
	}
}

func TestScansDisabledWhenNoInspector(t *testing.T) {
	srv := newTestServer(t, Options{Cache: &fakeCache{}})
	var list scanListResponse
	getJSON(t, srv, "/admin/api/scans", "", &list)
	if list.Enabled {
		t.Errorf("scans should report disabled when no inspector is wired")
	}
}

func TestProvenanceLinks(t *testing.T) {
	srv := newTestServer(t, Options{
		Cache: &fakeCache{},
		ProvenanceLinks: fakeLinks{links: []*provenance.EnrichedLink{
			{
				Link: &provenance.Link{
					Artifact:   provenance.Artifact{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"},
					CommitSHA:  "deadbeef",
					Confidence: provenance.ConfidenceAttested,
				},
				Verdict: &provenance.CommitVerdict{SHA: "deadbeef", RiskScore: 5},
			},
		}},
	})
	var resp provenanceLinksResponse
	if code := getJSON(t, srv, "/admin/api/provenance/links", "", &resp); code != http.StatusOK {
		t.Fatalf("links status = %d", code)
	}
	if !resp.Enabled || len(resp.Items) != 1 || resp.Items[0].Name != "left-pad" {
		t.Fatalf("links resp = %+v", resp)
	}
	if resp.Items[0].Verdict == nil || resp.Items[0].Verdict.RiskScore != 5 {
		t.Errorf("verdict not joined: %+v", resp.Items[0])
	}
}

func TestTokenGuardsAPIButNotDashboard(t *testing.T) {
	srv := newTestServer(t, Options{Cache: &fakeCache{}, Token: "s3cret"})

	// API without a token → 401.
	if code := getJSON(t, srv, "/admin/api/overview", "", nil); code != http.StatusUnauthorized {
		t.Errorf("unauthenticated API status = %d, want 401", code)
	}
	// API with the right token → 200.
	if code := getJSON(t, srv, "/admin/api/overview", "s3cret", nil); code != http.StatusOK {
		t.Errorf("authenticated API status = %d, want 200", code)
	}
	// The dashboard shell stays open so the browser can load and prompt.
	req := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("dashboard status = %d, want 200", rec.Code)
	}
}

func TestDashboardServesEmbeddedAssets(t *testing.T) {
	srv := newTestServer(t, Options{Cache: &fakeCache{}})
	for _, tc := range []struct{ path, ctype string }{
		{"/admin/", "text/html"},
		{"/admin/app.js", "text/javascript"},
		{"/admin/styles.css", "text/css"},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s status = %d, want 200", tc.path, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got == "" || got[:len(tc.ctype)] != tc.ctype {
			t.Errorf("%s content-type = %q, want %s…", tc.path, got, tc.ctype)
		}
	}
}

func TestBarePrefixRedirects(t *testing.T) {
	srv := newTestServer(t, Options{Cache: &fakeCache{}})
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMovedPermanently {
		t.Errorf("bare prefix status = %d, want 301", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/admin/" {
		t.Errorf("redirect location = %q, want /admin/", loc)
	}
}

func TestNewRequiresCache(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Error("expected error when no cache inspector is supplied")
	}
}

// fakeVulns is a stub VulnInspector for the admin vuln/SBOM endpoint tests.
type fakeVulns struct {
	reports []*vulnscan.Report
	byID    map[string]*vulnscan.Report
}

func (f fakeVulns) Reports() []*vulnscan.Report { return f.reports }
func (f fakeVulns) Report(digest string) (*vulnscan.Report, bool) {
	r, ok := f.byID[digest]
	return r, ok
}
func (f fakeVulns) Metrics() vulnscan.Snapshot {
	return vulnscan.Snapshot{ScansTotal: int64(len(f.reports))}
}
func (f fakeVulns) Quarantined() []vulnscan.QuarantineEntry { return nil }
func (f fakeVulns) ReleaseQuarantine(string) bool           { return false }
func (f fakeVulns) VEXEnabled() bool                        { return false }
func (f fakeVulns) VEXStats() vulnscan.VEXStats             { return vulnscan.VEXStats{} }
func (f fakeVulns) VEXStatements() []vulnscan.VEXStatement  { return nil }

func TestVulnListAndSBOMEndpoints(t *testing.T) {
	sbom, _ := vulnscan.Extract(vulnscan.Artifact{Ecosystem: "npm", Name: "evil", Version: "1.0.0", Digest: "sha256:d1"}, nil)
	rep := &vulnscan.Report{
		Digest:      "sha256:d1",
		Artifact:    vulnscan.Artifact{Ecosystem: "npm", Name: "evil", Version: "1.0.0"},
		Scanner:     "osv",
		SBOM:        sbom,
		MaxSeverity: vulnscan.SeverityCritical,
		MaxCVSS:     9.8,
		Counts:      vulnscan.SeverityCounts{Critical: 1},
		Vulnerabilities: []vulnscan.Vulnerability{
			{ID: "CVE-2024-1", Severity: vulnscan.SeverityCritical, CVSS: 9.8, Package: "evil"},
		},
	}
	fv := fakeVulns{reports: []*vulnscan.Report{rep}, byID: map[string]*vulnscan.Report{"sha256:d1": rep}}
	srv := newTestServer(t, Options{Cache: &fakeCache{}, Vulnerabilities: fv})

	var list vulnListResponse
	if code := getJSON(t, srv, "/admin/api/vulns", "", &list); code != http.StatusOK {
		t.Fatalf("vulns status = %d", code)
	}
	if !list.Enabled || len(list.Items) != 1 || list.Items[0].MaxSeverity != "critical" {
		t.Fatalf("vuln list = %+v", list)
	}
	if list.Metrics == nil || list.Metrics.ScansTotal != 1 {
		t.Errorf("vuln metrics not surfaced: %+v", list.Metrics)
	}

	// Full report by digest.
	if code := getJSON(t, srv, "/admin/api/vulns/entry?digest=sha256:d1", "", nil); code != http.StatusOK {
		t.Errorf("vuln entry status = %d", code)
	}
	if code := getJSON(t, srv, "/admin/api/vulns/entry?digest=missing", "", nil); code != http.StatusNotFound {
		t.Errorf("missing vuln entry status = %d, want 404", code)
	}

	// SBOM endpoint returns the CycloneDX document with the right media type.
	req := httptest.NewRequest(http.MethodGet, "/admin/api/sbom?digest=sha256:d1", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("sbom status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/vnd.cyclonedx+json; version=1.5" {
		t.Errorf("sbom content-type = %q", ct)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("sbom not valid json: %v", err)
	}
	if doc["bomFormat"] != "CycloneDX" {
		t.Errorf("sbom bomFormat = %v", doc["bomFormat"])
	}
}

func TestVEXEndpoint(t *testing.T) {
	const doc = `{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"timestamp": "2026-01-01T00:00:00Z",
		"statements": [{
			"vulnerability": {"name": "CVE-2026-1111"},
			"products": [{"@id": "pkg:npm/lodash@4.17.20"}],
			"status": "not_affected",
			"justification": "vulnerable_code_not_present"
		}]
	}`
	parsed, err := vulnscan.ParseVEX([]byte(doc), "test.json")
	if err != nil {
		t.Fatal(err)
	}
	store := vulnscan.NewVEXStore(nil)
	store.AddDocument(parsed)
	// A real vulnscan.Service backed by the store satisfies VulnInspector.
	svc, err := vulnscan.NewService(vulnscan.Config{FailSeverity: vulnscan.SeverityHigh, VEX: store}, &noopScanner{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := newTestServer(t, Options{Cache: &fakeCache{}, Vulnerabilities: svc})

	var resp vexListResponse
	if code := getJSON(t, srv, "/admin/api/vex", "", &resp); code != http.StatusOK {
		t.Fatalf("vex status = %d", code)
	}
	if !resp.Enabled {
		t.Fatal("vex endpoint should report enabled")
	}
	if resp.Stats.Statements != 1 || len(resp.Statements) != 1 {
		t.Errorf("vex statements = %d / %d, want 1", resp.Stats.Statements, len(resp.Statements))
	}
	if resp.Statements[0].Vulnerability != "CVE-2026-1111" {
		t.Errorf("vex statement = %+v", resp.Statements[0])
	}
}

// noopScanner is a Scanner that finds nothing (the VEX endpoint test only needs a
// non-nil scanner for the Service to construct).
type noopScanner struct{}

func (noopScanner) Name() string { return "noop" }
func (noopScanner) Scan(ctx context.Context, sbom *vulnscan.SBOM) ([]vulnscan.Vulnerability, error) {
	return nil, nil
}

func TestVulnsDisabledWhenNoInspector(t *testing.T) {
	srv := newTestServer(t, Options{Cache: &fakeCache{}})
	var list vulnListResponse
	getJSON(t, srv, "/admin/api/vulns", "", &list)
	if list.Enabled {
		t.Error("vulns should report disabled without an inspector")
	}
	if code := getJSON(t, srv, "/admin/api/sbom?digest=x", "", nil); code != http.StatusNotFound {
		t.Errorf("sbom without inspector = %d, want 404", code)
	}
}
