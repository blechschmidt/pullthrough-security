package sbomexport

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

var updateGolden = flag.Bool("update-golden", false, "regenerate sbomexport golden fixtures")

// goldenReport is the canonical scan report the payload-shape tests render.
func goldenReport() *vulnscan.Report {
	sbom := &vulnscan.SBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		JSONSchema:   "http://cyclonedx.org/schema/bom-1.5.schema.json",
		SerialNumber: "urn:uuid:00000000-0000-0000-0000-000000000001",
		Version:      1,
		Metadata: &vulnscan.BOMMetadata{
			Timestamp: "2026-01-01T00:00:00Z",
			Tools:     []vulnscan.Tool{{Vendor: "pullthrough", Name: "pullthrough-vulnscan"}},
			Component: &vulnscan.Component{Type: "library", BOMRef: "pkg:npm/left-pad@1.3.0", Name: "left-pad", Version: "1.3.0", PURL: "pkg:npm/left-pad@1.3.0"},
		},
		Components: []vulnscan.Component{
			{Type: "library", BOMRef: "pkg:npm/left-pad@1.3.0", Name: "left-pad", Version: "1.3.0", PURL: "pkg:npm/left-pad@1.3.0"},
			{Type: "library", BOMRef: "pkg:npm/minimist@1.2.0", Name: "minimist", Version: "1.2.0", PURL: "pkg:npm/minimist@1.2.0"},
		},
	}
	return &vulnscan.Report{
		Digest:   "sha256:0000000000000000000000000000000000000000000000000000000000000abc",
		Artifact: vulnscan.Artifact{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Digest: "sha256:0000000000000000000000000000000000000000000000000000000000000abc"},
		Scanner:  "osv",
		SBOM:     sbom,
		Vulnerabilities: []vulnscan.Vulnerability{
			{
				ID:         "CVE-2024-0001",
				Summary:    "Prototype pollution in minimist",
				Details:    "A crafted argument can pollute Object.prototype.",
				Severity:   vulnscan.SeverityHigh,
				CVSS:       7.5,
				CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
				References: []string{"https://example.test/advisories/CVE-2024-0001"},
				Component:  "pkg:npm/minimist@1.2.0",
				Package:    "minimist",
				Version:    "1.2.0",
			},
			{
				ID:               "GHSA-aaaa-bbbb-cccc",
				Summary:          "ReDoS in left-pad",
				Severity:         vulnscan.SeverityMedium,
				Component:        "pkg:npm/left-pad@1.3.0",
				Package:          "left-pad",
				Version:          "1.3.0",
				VEXStatus:        vulnscan.VEXNotAffected,
				VEXJustification: vulnscan.VEXJustification("vulnerable_code_not_in_execute_path"),
				Suppressed:       true,
			},
		},
	}
}

// assertGolden compares got against the fixture at testdata/golden/<name>,
// regenerating it under -update-golden.
func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run with -update-golden to create): %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("golden mismatch for %s\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func TestExportDocumentGolden(t *testing.T) {
	item, ok, err := buildItem(goldenReport(), true, "")
	if err != nil {
		t.Fatalf("buildItem: %v", err)
	}
	if !ok {
		t.Fatal("expected a renderable item")
	}
	if item.ProjectName != "npm:left-pad" || item.ProjectVersion != "1.3.0" {
		t.Fatalf("project coords = %q / %q", item.ProjectName, item.ProjectVersion)
	}
	assertGolden(t, "export-document.json", item.BOM)
}

func TestExportDocumentWithoutFindings(t *testing.T) {
	item, ok, err := buildItem(goldenReport(), false, "")
	if err != nil || !ok {
		t.Fatalf("buildItem: %v ok=%v", err, ok)
	}
	var doc map[string]any
	if err := json.Unmarshal(item.BOM, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := doc["vulnerabilities"]; present {
		t.Fatal("vulnerabilities must be absent when findings are not included")
	}
	if _, present := doc["components"]; !present {
		t.Fatal("components must be present (SBOM fields promoted)")
	}
}

func TestMinSeverityFiltersFindings(t *testing.T) {
	// Floor at high: only the CVE (high) survives; the GHSA (medium) is dropped.
	item, _, err := buildItem(goldenReport(), true, vulnscan.SeverityHigh)
	if err != nil {
		t.Fatalf("buildItem: %v", err)
	}
	var doc struct {
		Vulnerabilities []struct {
			ID string `json:"id"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(item.BOM, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Vulnerabilities) != 1 || doc.Vulnerabilities[0].ID != "CVE-2024-0001" {
		t.Fatalf("expected only the high-severity CVE, got %+v", doc.Vulnerabilities)
	}
}

func TestDependencyTrackPayloadGolden(t *testing.T) {
	item, _, err := buildItem(goldenReport(), true, "")
	if err != nil {
		t.Fatalf("buildItem: %v", err)
	}

	var captured []byte
	var method, apiKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		apiKey = r.Header.Get("X-Api-Key")
		captured, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token":"abc"}`))
	}))
	defer srv.Close()

	sink := NewDependencyTrackSink(DependencyTrackConfig{
		URL:        srv.URL,
		APIKey:     "secret-key",
		AutoCreate: true,
	}, time.Second)
	if err := sink.Upload(context.Background(), item); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if method != http.MethodPut {
		t.Fatalf("method = %s, want PUT", method)
	}
	if apiKey != "secret-key" {
		t.Fatalf("X-Api-Key = %q", apiKey)
	}

	// Decode the envelope, verify the embedded BOM round-trips, then re-render the
	// whole payload with the decoded BOM for a stable golden (base64 is otherwise
	// opaque to a human reviewer).
	var req dtRequest
	if err := json.Unmarshal(captured, &req); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	bom, err := base64.StdEncoding.DecodeString(req.BOM)
	if err != nil {
		t.Fatalf("decode bom: %v", err)
	}
	if !bytes.Equal(bom, item.BOM) {
		t.Fatal("round-tripped BOM does not match the rendered document")
	}
	golden := struct {
		ProjectName    string          `json:"projectName"`
		ProjectVersion string          `json:"projectVersion"`
		AutoCreate     bool            `json:"autoCreate"`
		ParentName     string          `json:"parentName,omitempty"`
		BOM            json.RawMessage `json:"bom"`
	}{req.ProjectName, req.ProjectVersion, req.AutoCreate, req.ParentName, json.RawMessage(bom)}
	enc, _ := json.MarshalIndent(golden, "", "  ")
	assertGolden(t, "dependency-track-request.json", append(enc, '\n'))
}

func TestGUACPayloadGolden(t *testing.T) {
	item, _, err := buildItem(goldenReport(), true, "")
	if err != nil {
		t.Fatalf("buildItem: %v", err)
	}

	var captured []byte
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		captured, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	sink := NewGUACSink(GUACConfig{URL: srv.URL, Token: "guac-token"}, time.Second)
	if err := sink.Upload(context.Background(), item); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if auth != "Bearer guac-token" {
		t.Fatalf("Authorization = %q", auth)
	}

	var env guacDocument
	if err := json.Unmarshal(captured, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if env.Type != "CYCLONEDX" || env.Format != "JSON" {
		t.Fatalf("envelope type/format = %q/%q", env.Type, env.Format)
	}
	// The blob is embedded as raw JSON, so the encoder re-compacts it (dropping the
	// indentation/trailing newline of item.BOM). Compare semantically rather than
	// byte-for-byte.
	if !sameJSON(t, []byte(env.Blob), item.BOM) {
		t.Fatal("guac blob is not the rendered CycloneDX BOM")
	}
	// Re-render the envelope with the blob indented for a human-readable golden.
	golden := struct {
		Type      string          `json:"type"`
		Format    string          `json:"format"`
		Source    string          `json:"source"`
		Collector string          `json:"collector"`
		Blob      json.RawMessage `json:"blob"`
	}{env.Type, env.Format, env.Source, env.Collector, env.Blob}
	enc, _ := json.MarshalIndent(golden, "", "  ")
	assertGolden(t, "guac-document.json", append(enc, '\n'))
}

func TestGUACInTotoWrapping(t *testing.T) {
	item, _, err := buildItem(goldenReport(), true, "")
	if err != nil {
		t.Fatalf("buildItem: %v", err)
	}
	var captured []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink := NewGUACSink(GUACConfig{URL: srv.URL, DocumentType: "intoto"}, time.Second)
	if err := sink.Upload(context.Background(), item); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	var env guacDocument
	if err := json.Unmarshal(captured, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env.Type != "ITE6" {
		t.Fatalf("in-toto envelope type = %q, want ITE6", env.Type)
	}
	var stmt intotoStatement
	if err := json.Unmarshal(env.Blob, &stmt); err != nil {
		t.Fatalf("unmarshal statement: %v", err)
	}
	if stmt.PredicateType != "https://cyclonedx.org/bom" {
		t.Fatalf("predicateType = %q", stmt.PredicateType)
	}
	if len(stmt.Subject) != 1 || stmt.Subject[0].Digest["sha256"] == "" {
		t.Fatalf("subject digest not set: %+v", stmt.Subject)
	}
}

// sameJSON reports whether two JSON byte slices are semantically equal (ignoring
// whitespace/ordering of equivalent values).
func sameJSON(t *testing.T, a, b []byte) bool {
	t.Helper()
	var va, vb any
	if err := json.Unmarshal(a, &va); err != nil {
		t.Fatalf("unmarshal a: %v", err)
	}
	if err := json.Unmarshal(b, &vb); err != nil {
		t.Fatalf("unmarshal b: %v", err)
	}
	ja, _ := json.Marshal(va)
	jb, _ := json.Marshal(vb)
	return bytes.Equal(ja, jb)
}

// reportSource is a static ReportSource for Service tests.
type reportSource struct{ reports []*vulnscan.Report }

func (s reportSource) Reports() []*vulnscan.Report { return s.reports }

func TestExportDeliversToAllSinks(t *testing.T) {
	var dtHits, guacHits int32
	dt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&dtHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer dt.Close()
	guac := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&guacHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer guac.Close()

	svc := New(Config{IncludeFindings: true, Timeout: time.Second}, reportSource{reports: []*vulnscan.Report{goldenReport()}},
		[]Sink{
			NewDependencyTrackSink(DependencyTrackConfig{URL: dt.URL, APIKey: "k", AutoCreate: true}, time.Second),
			NewGUACSink(GUACConfig{URL: guac.URL}, time.Second),
		}, nil)
	if svc == nil {
		t.Fatal("New returned nil")
	}
	rep, _ := svc.Trigger(context.Background())
	if rep.Uploaded != 2 || rep.Failed != 0 || rep.Reports != 1 {
		t.Fatalf("run report = %+v", rep)
	}
	if atomic.LoadInt32(&dtHits) != 1 || atomic.LoadInt32(&guacHits) != 1 {
		t.Fatalf("hits dt=%d guac=%d", dtHits, guacHits)
	}
	m := svc.Metrics()
	if m.Uploads != 2 || m.UploadsByTarget["dependency-track"] != 1 || m.UploadsByTarget["guac"] != 1 {
		t.Fatalf("metrics = %+v", m)
	}
}

func TestDeliveryRetriesThenSucceeds(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := New(Config{Timeout: time.Second, MaxRetries: 3, RetryBaseDelay: time.Millisecond, RetryMaxDelay: 5 * time.Millisecond},
		reportSource{reports: []*vulnscan.Report{goldenReport()}},
		[]Sink{NewDependencyTrackSink(DependencyTrackConfig{URL: srv.URL, APIKey: "k"}, time.Second)}, nil)
	rep, _ := svc.Trigger(context.Background())
	if rep.Uploaded != 1 || rep.Failed != 0 {
		t.Fatalf("run report = %+v (attempts=%d)", rep, attempts)
	}
	m := svc.Metrics()
	if m.Retries != 2 {
		t.Fatalf("retries = %d, want 2", m.Retries)
	}
	if atomic.LoadInt32(&attempts) != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
}

func TestNonRetryableFailsImmediately(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusUnauthorized) // 401 is permanent
	}))
	defer srv.Close()

	svc := New(Config{Timeout: time.Second, MaxRetries: 3, RetryBaseDelay: time.Millisecond},
		reportSource{reports: []*vulnscan.Report{goldenReport()}},
		[]Sink{NewDependencyTrackSink(DependencyTrackConfig{URL: srv.URL, APIKey: "k"}, time.Second)}, nil)
	rep, _ := svc.Trigger(context.Background())
	if rep.Failed != 1 || rep.Uploaded != 0 {
		t.Fatalf("run report = %+v", rep)
	}
	if atomic.LoadInt32(&attempts) != 1 {
		t.Fatalf("attempts = %d, want 1 (no retry on 401)", attempts)
	}
	if svc.Metrics().FailuresByTarget["dependency-track"] != 1 {
		t.Fatalf("failure metric not recorded: %+v", svc.Metrics())
	}
}

func TestLeaderGateSkipsPeriodicSweep(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var leader atomic.Bool // starts false
	svc := New(Config{Interval: 10 * time.Millisecond, Timeout: time.Second},
		reportSource{reports: []*vulnscan.Report{goldenReport()}},
		[]Sink{NewGUACSink(GUACConfig{URL: srv.URL}, time.Second)}, nil)
	svc.SetLeaderGate(func() bool { return leader.Load() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.Start(ctx)
	time.Sleep(60 * time.Millisecond)
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("non-leader node exported %d times", hits)
	}

	// Manual trigger must bypass the leader gate even when not leader.
	if _, err := svc.Trigger(ctx); err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	if atomic.LoadInt32(&hits) == 0 {
		t.Fatal("manual trigger did not export")
	}

	// Becoming leader resumes the periodic sweep.
	before := atomic.LoadInt32(&hits)
	leader.Store(true)
	time.Sleep(60 * time.Millisecond)
	if atomic.LoadInt32(&hits) <= before {
		t.Fatal("leader node did not run periodic sweep")
	}
	_ = svc.Close()
}
