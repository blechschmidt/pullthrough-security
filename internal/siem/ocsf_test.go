package siem

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// updateGolden regenerates the OCSF golden fixtures instead of asserting against
// them. Run: go test ./internal/siem -run OCSF -update-golden
var updateGolden = flag.Bool("update-golden", false, "regenerate OCSF golden fixtures")

// goldenEvents returns the canonical set of events the golden fixtures cover:
// one per OCSF class the encoder emits.
func goldenEvents() map[string]Event {
	doc := sampleDocument()
	vuln := EventFromFinding(doc, doc.Findings[0])     // vulnscan -> Vulnerability Finding
	license := EventFromFinding(doc, doc.Findings[1])  // license  -> Compliance Finding
	audit := EventFromAuditRecord(sampleAuditRecord()) // policy_decision -> Detection Finding

	detection := Event{
		Source:   SourceFinding,
		Time:     time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC),
		Severity: SeverityHigh,
		Category: "installhooks",
		Name:     "Suspicious lifecycle hook",
		Outcome:  "error",
		Subject:  "team-a",
		Message:  "postinstall script downloads a remote payload",
		Fields: map[string]string{
			"ruleId":     "installhooks/remote-exec",
			"gate":       "installhooks",
			"coordinate": "npm/evil@2.0.0",
			"artifact":   "evil",
			"version":    "2.0.0",
			"ecosystem":  "npm",
		},
	}
	authn := Event{
		Source:   SourceAudit,
		Time:     time.Date(2026, 11, 4, 8, 15, 0, 0, time.UTC),
		Severity: SeverityMedium,
		Category: "auth",
		Name:     "auth deny",
		Outcome:  "deny",
		Subject:  "svc-ci",
		Message:  "invalid token",
		Fields: map[string]string{
			"seq":        "7",
			"remoteAddr": "10.0.0.9",
			"team":       "team-a",
		},
	}
	api := Event{
		Source:   SourceAudit,
		Time:     time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC),
		Severity: SeverityInfo,
		Category: "pull",
		Name:     "pull allow",
		Outcome:  "allow",
		Subject:  "svc-ci",
		Fields: map[string]string{
			"seq":       "101",
			"method":    "GET",
			"backend":   "npmjs",
			"ecosystem": "npm",
			"resource":  "lodash@1.0.0",
		},
	}
	return map[string]Event{
		"vulnerability_finding": vuln,
		"compliance_finding":    license,
		"detection_finding_audit": func() Event {
			audit.Name = "policy_decision deny"
			return audit
		}(),
		"detection_finding": detection,
		"authentication":    authn,
		"api_activity":      api,
	}
}

// TestOCSFEncodeGolden asserts the encoder produces byte-stable, conformant OCSF
// JSON for each event class. The expected documents live in
// testdata/ocsf/<name>.json and are regenerated with -update-golden.
func TestOCSFEncodeGolden(t *testing.T) {
	enc, err := newOCSFEncoder(OCSFConfig{})
	if err != nil {
		t.Fatalf("newOCSFEncoder: %v", err)
	}
	for name, ev := range goldenEvents() {
		name, ev := name, ev
		t.Run(name, func(t *testing.T) {
			obj := enc.encode(ev)
			got, err := json.MarshalIndent(obj, "", "  ")
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			got = append(got, '\n')
			path := filepath.Join("testdata", "ocsf", name+".json")
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
				t.Fatalf("read golden (run with -update-golden to create): %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("OCSF output mismatch for %s:\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
			}
		})
	}
}

// TestOCSFConformanceInvariants asserts the structural invariants every OCSF
// record must satisfy regardless of class, independent of the golden bytes.
func TestOCSFConformanceInvariants(t *testing.T) {
	enc, err := newOCSFEncoder(OCSFConfig{})
	if err != nil {
		t.Fatalf("newOCSFEncoder: %v", err)
	}
	for name, ev := range goldenEvents() {
		obj := enc.encode(ev)
		// Core required fields.
		for _, key := range []string{"activity_id", "category_uid", "class_uid", "type_uid", "severity_id", "time", "metadata", "class_name"} {
			if _, ok := obj[key]; !ok {
				t.Fatalf("%s: missing required OCSF field %q", name, key)
			}
		}
		// type_uid = class_uid*100 + activity_id.
		classUID := obj["class_uid"].(int)
		activityID := obj["activity_id"].(int)
		if got := obj["type_uid"].(int); got != classUID*100+activityID {
			t.Fatalf("%s: type_uid = %d, want %d", name, got, classUID*100+activityID)
		}
		// metadata.version present.
		md := obj["metadata"].(map[string]any)
		if md["version"] != DefaultOCSFSchemaVersion {
			t.Fatalf("%s: metadata.version = %v, want %s", name, md["version"], DefaultOCSFSchemaVersion)
		}
		// time is epoch milliseconds (int64).
		if _, ok := obj["time"].(int64); !ok {
			t.Fatalf("%s: time is %T, want int64 epoch-ms", name, obj["time"])
		}
	}
}

func TestOCSFDefaultClassRouting(t *testing.T) {
	enc, _ := newOCSFEncoder(OCSFConfig{})
	cases := []struct {
		name     string
		ev       Event
		classUID int
	}{
		{"vulnscan", Event{Source: SourceFinding, Category: "vulnscan"}, ocsfClassVulnerabilityFinding},
		{"vex", Event{Source: SourceFinding, Category: "vex"}, ocsfClassVulnerabilityFinding},
		{"license", Event{Source: SourceFinding, Category: "license"}, ocsfClassComplianceFinding},
		{"sigverify", Event{Source: SourceFinding, Category: "sigverify"}, ocsfClassDetectionFinding},
		{"auth", Event{Source: SourceAudit, Category: "auth"}, ocsfClassAuthentication},
		{"policy", Event{Source: SourceAudit, Category: "policy_decision"}, ocsfClassDetectionFinding},
		{"egress", Event{Source: SourceAudit, Category: "egress_blocked"}, ocsfClassDetectionFinding},
		{"pull", Event{Source: SourceAudit, Category: "pull"}, ocsfClassAPIActivity},
	}
	for _, tc := range cases {
		if got := enc.classFor(tc.ev).classUID; got != tc.classUID {
			t.Errorf("%s: class_uid = %d, want %d", tc.name, got, tc.classUID)
		}
	}
}

func TestOCSFClassMapOverride(t *testing.T) {
	enc, err := newOCSFEncoder(OCSFConfig{
		ClassMap: map[string]string{
			"pull":      "api_activity",
			"nameguard": "detection_finding",
			"custom":    "Vulnerability Finding", // display-name form
		},
	})
	if err != nil {
		t.Fatalf("newOCSFEncoder: %v", err)
	}
	// nameguard would default to detection_finding anyway; verify the override
	// path resolves and a display-name alias works.
	if got := enc.classFor(Event{Source: SourceFinding, Category: "custom"}).classUID; got != ocsfClassVulnerabilityFinding {
		t.Fatalf("custom override class_uid = %d, want %d", got, ocsfClassVulnerabilityFinding)
	}
	if got := enc.classFor(Event{Source: SourceAudit, Category: "pull"}).classUID; got != ocsfClassAPIActivity {
		t.Fatalf("pull override class_uid = %d, want %d", got, ocsfClassAPIActivity)
	}
}

func TestOCSFEncoderRejectsUnknownClass(t *testing.T) {
	_, err := newOCSFEncoder(OCSFConfig{ClassMap: map[string]string{"pull": "nonsense_class"}})
	if err == nil {
		t.Fatal("expected error for unknown class name")
	}
}

func TestOCSFSchemaVersionOverride(t *testing.T) {
	enc, _ := newOCSFEncoder(OCSFConfig{SchemaVersion: "1.3.0", ProductName: "p", VendorName: "v"})
	obj := enc.encode(Event{Source: SourceAudit, Category: "pull", Time: time.Unix(0, 0)})
	md := obj["metadata"].(map[string]any)
	if md["version"] != "1.3.0" {
		t.Fatalf("version = %v, want 1.3.0", md["version"])
	}
	prod := md["product"].(map[string]any)
	if prod["name"] != "p" || prod["vendor_name"] != "v" {
		t.Fatalf("product = %v", prod)
	}
}

func TestOCSFVulnerabilityFindingShape(t *testing.T) {
	enc, _ := newOCSFEncoder(OCSFConfig{})
	doc := sampleDocument()
	obj := enc.encode(EventFromFinding(doc, doc.Findings[0]))
	vulns, ok := obj["vulnerabilities"].([]any)
	if !ok || len(vulns) != 1 {
		t.Fatalf("vulnerabilities = %v", obj["vulnerabilities"])
	}
	v := vulns[0].(map[string]any)
	cve := v["cve"].(map[string]any)
	if cve["uid"] != "CVE-2026-0001" {
		t.Fatalf("cve.uid = %v", cve["uid"])
	}
	pkgs := v["affected_packages"].([]any)
	if len(pkgs) != 1 {
		t.Fatalf("affected_packages = %v", pkgs)
	}
	pkg := pkgs[0].(map[string]any)
	if pkg["purl"] != "pkg:npm/lodash@1.0.0" {
		t.Fatalf("purl = %v", pkg["purl"])
	}
}

// TestOCSFSinkDeliverNDJSON asserts the sink POSTs one OCSF object per line,
// authenticates with a bearer token, and records per-class encode telemetry.
func TestOCSFSinkDeliverNDJSON(t *testing.T) {
	enc, _ := newOCSFEncoder(OCSFConfig{})
	var captured *http.Request
	var body []byte
	sink, err := NewOCSFSink(OCSFOptions{
		Name:    "lake",
		URL:     "https://lake.example/ingest",
		Token:   "sekret",
		Encoder: enc,
		Client: doerFunc(func(req *http.Request) (*http.Response, error) {
			captured = req
			body, _ = readAll(req)
			return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
		}),
	})
	if err != nil {
		t.Fatalf("NewOCSFSink: %v", err)
	}
	doc := sampleDocument()
	batch := []Event{
		EventFromFinding(doc, doc.Findings[0]),
		EventFromAuditRecord(sampleAuditRecord()),
	}
	if err := sink.DeliverBatch(context.Background(), batch); err != nil {
		t.Fatalf("DeliverBatch: %v", err)
	}
	if got := captured.Header.Get("Authorization"); got != "Bearer sekret" {
		t.Fatalf("Authorization = %q", got)
	}
	if ct := captured.Header.Get("Content-Type"); ct != "application/x-ndjson" {
		t.Fatalf("Content-Type = %q", ct)
	}
	// Each line must be a standalone, valid OCSF JSON object.
	lines := 0
	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		lines++
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("line %d not valid JSON: %v", lines, err)
		}
		if _, ok := obj["class_uid"]; !ok {
			t.Fatalf("line %d missing class_uid", lines)
		}
	}
	if lines != 2 {
		t.Fatalf("got %d NDJSON lines, want 2", lines)
	}
	stats := sink.OCSFStats()
	if stats.ByClass["Vulnerability Finding"] != 1 || stats.ByClass["Detection Finding"] != 1 {
		t.Fatalf("by-class counts = %v", stats.ByClass)
	}
	if stats.EncodeErrors != 0 {
		t.Fatalf("encode errors = %d", stats.EncodeErrors)
	}
}

// TestOCSFForwarderMetrics asserts the forwarder aggregates OCSF telemetry from
// its sinks into the Snapshot the Prometheus bridge reads.
func TestOCSFForwarderMetrics(t *testing.T) {
	enc, _ := newOCSFEncoder(OCSFConfig{})
	sink, _ := NewOCSFSink(OCSFOptions{
		Name:    "lake",
		URL:     "https://lake.example/ingest",
		Encoder: enc,
		Client: doerFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
		}),
	})
	doc := sampleDocument()
	_ = sink.DeliverBatch(context.Background(), []Event{EventFromFinding(doc, doc.Findings[0])})

	f := New(Options{Sinks: []Sink{sink}})
	t.Cleanup(func() { _ = f.Close() })
	snap := f.Metrics()
	if snap.OCSF.ByClass["Vulnerability Finding"] != 1 {
		t.Fatalf("snapshot OCSF by-class = %v", snap.OCSF.ByClass)
	}
}

func TestOCSFSinkCustomAuthHeader(t *testing.T) {
	enc, _ := newOCSFEncoder(OCSFConfig{})
	var captured *http.Request
	sink, err := NewOCSFSink(OCSFOptions{
		Name:       "lake",
		URL:        "https://lake.example/ingest",
		Token:      "abc",
		AuthHeader: "X-Api-Key",
		AuthScheme: "",
		Encoder:    enc,
		Client: doerFunc(func(req *http.Request) (*http.Response, error) {
			captured = req
			_, _ = readAll(req)
			return &http.Response{StatusCode: 202, Body: http.NoBody}, nil
		}),
	})
	if err != nil {
		t.Fatalf("NewOCSFSink: %v", err)
	}
	_ = sink.DeliverBatch(context.Background(), []Event{{Source: SourceAudit, Category: "pull", Time: time.Unix(0, 0)}})
	if got := captured.Header.Get("X-Api-Key"); got != "abc" {
		t.Fatalf("X-Api-Key = %q, want bare token", got)
	}
	if captured.Header.Get("Authorization") != "" {
		t.Fatalf("unexpected Authorization header")
	}
}

// doerFunc adapts a function to the httpDoer interface for tests.
type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

func readAll(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	defer req.Body.Close()
	var buf bytes.Buffer
	_, err := buf.ReadFrom(req.Body)
	return buf.Bytes(), err
}
