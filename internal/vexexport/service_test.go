package vexexport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/approvals"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// --- test doubles -----------------------------------------------------------

type fakeCorpus struct {
	enabled bool
	stmts   []vulnscan.VEXStatement
}

func (f fakeCorpus) VEXEnabled() bool                       { return f.enabled }
func (f fakeCorpus) VEXStatements() []vulnscan.VEXStatement { return f.stmts }

type fakeFindings struct {
	docs []findings.Document
}

func (f fakeFindings) Get(tenant, pkg string) (findings.Document, bool) {
	for _, d := range f.docs {
		if !strings.EqualFold(d.Tenant, tenant) && tenant != "" {
			continue
		}
		if pkg == "" || strings.EqualFold(d.Artifact.Coordinate, pkg) || strings.EqualFold(d.Artifact.Name, pkg) {
			return d, true
		}
	}
	return findings.Document{}, false
}

func (f fakeFindings) Documents(tenant, q string) []findings.Document {
	var out []findings.Document
	for _, d := range f.docs {
		if tenant != "" && !strings.EqualFold(d.Tenant, tenant) {
			continue
		}
		out = append(out, d)
	}
	return out
}

type fakeGrants struct {
	enabled bool
	reqs    []approvals.Request
	swept   int
}

func (f *fakeGrants) Enabled() bool                 { return f.enabled }
func (f *fakeGrants) Sweep(ctx context.Context) int { f.swept++; return 0 }
func (f *fakeGrants) List(status string, limit int) []approvals.Request {
	var out []approvals.Request
	for _, r := range f.reqs {
		if status == "" || string(r.Status) == status {
			out = append(out, r)
		}
	}
	return out
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newService(t *testing.T, signer *Signer, opts ...Option) *Service {
	t.Helper()
	base := []Option{WithClock(func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) })}
	base = append(base, opts...)
	return New(Config{Enabled: true, Author: "pullthrough-test"}, signer, testLogger(), base...)
}

// --- round-trip: an exported OpenVEX doc re-ingests through the gate --------

func TestOpenVEXRoundTripThroughSuppressionGate(t *testing.T) {
	corpus := fakeCorpus{
		enabled: true,
		stmts: []vulnscan.VEXStatement{{
			Vulnerability: "CVE-2024-0001",
			Aliases:       []string{"GHSA-aaaa-bbbb-cccc"},
			Products:      []vulnscan.VEXProductRef{{ID: "pkg:npm/lodash@4.17.21"}},
			Status:        vulnscan.VEXNotAffected,
			Justification: vulnscan.JustificationVulnerableCodeNotPresent,
			Timestamp:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		}},
	}
	svc := newService(t, nil, WithCorpus(corpus))

	res, err := svc.Export(context.Background(), Request{
		Ecosystem: "npm", Name: "lodash", Version: "4.17.21", Format: FormatOpenVEX,
	})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if res.Statements != 1 {
		t.Fatalf("expected 1 statement, got %d", res.Statements)
	}

	// Re-parse through the real ingest path and feed the suppression matcher.
	doc, err := vulnscan.ParseVEX(res.Document, "exported.openvex.json")
	if err != nil {
		t.Fatalf("ParseVEX(exported): %v\n%s", err, res.Document)
	}
	if doc.Format != "openvex" {
		t.Fatalf("re-parsed format = %q, want openvex", doc.Format)
	}
	store := vulnscan.NewVEXStore(testLogger())
	store.AddDocument(doc)

	art := vulnscan.Artifact{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}
	vuln := vulnscan.Vulnerability{
		ID:        "CVE-2024-0001",
		Package:   "lodash",
		Version:   "4.17.21",
		Component: "pkg:npm/lodash@4.17.21",
	}
	st, ok := store.Match(art, vuln)
	if !ok {
		t.Fatalf("exported statement did not re-match the finding")
	}
	if st.Status != vulnscan.VEXNotAffected || !st.Status.Suppresses() {
		t.Fatalf("re-ingested status = %q (suppresses=%v), want not_affected", st.Status, st.Status.Suppresses())
	}
	if st.Justification != vulnscan.JustificationVulnerableCodeNotPresent {
		t.Errorf("re-ingested justification = %q", st.Justification)
	}
}

// --- CycloneDX VEX/VDR structural output ------------------------------------

func TestCycloneDXExportShape(t *testing.T) {
	corpus := fakeCorpus{
		enabled: true,
		stmts: []vulnscan.VEXStatement{{
			Vulnerability:   "CVE-2024-0002",
			Products:        []vulnscan.VEXProductRef{{ID: "pkg:pypi/requests@2.19.0"}},
			Status:          vulnscan.VEXNotAffected,
			Justification:   vulnscan.JustificationComponentNotPresent,
			ActionStatement: "No action required.",
		}},
	}
	svc := newService(t, nil, WithCorpus(corpus))
	res, err := svc.Export(context.Background(), Request{
		Ecosystem: "pip", Name: "requests", Version: "2.19.0", Format: FormatCycloneDX,
	})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	var bom struct {
		BOMFormat       string `json:"bomFormat"`
		SpecVersion     string `json:"specVersion"`
		SerialNumber    string `json:"serialNumber"`
		Vulnerabilities []struct {
			ID       string `json:"id"`
			Analysis struct {
				State         string   `json:"state"`
				Justification string   `json:"justification"`
				Response      []string `json:"response"`
			} `json:"analysis"`
			Affects []struct {
				Ref string `json:"ref"`
			} `json:"affects"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(res.Document, &bom); err != nil {
		t.Fatalf("unmarshal CycloneDX: %v", err)
	}
	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.5" {
		t.Errorf("bad BOM header: %q %q", bom.BOMFormat, bom.SpecVersion)
	}
	if !strings.HasPrefix(bom.SerialNumber, "urn:uuid:") {
		t.Errorf("bad serial number: %q", bom.SerialNumber)
	}
	if len(bom.Vulnerabilities) != 1 {
		t.Fatalf("want 1 vulnerability, got %d", len(bom.Vulnerabilities))
	}
	v := bom.Vulnerabilities[0]
	if v.ID != "CVE-2024-0002" {
		t.Errorf("id = %q", v.ID)
	}
	if v.Analysis.State != "not_affected" {
		t.Errorf("analysis.state = %q, want not_affected", v.Analysis.State)
	}
	if v.Analysis.Justification != "code_not_present" {
		t.Errorf("analysis.justification = %q, want code_not_present", v.Analysis.Justification)
	}
	if len(v.Affects) != 1 || v.Affects[0].Ref != "pkg:pypi/requests@2.19.0" {
		t.Errorf("affects = %+v", v.Affects)
	}
}

// --- signing: detached signature verifies and detects tampering -------------

func TestExportSignedDetachedSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	signer, err := LoadSigner(pemBytes)
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}

	corpus := fakeCorpus{enabled: true, stmts: []vulnscan.VEXStatement{{
		Vulnerability: "CVE-2024-0003",
		Products:      []vulnscan.VEXProductRef{{ID: "pkg:npm/left-pad@1.3.0"}},
		Status:        vulnscan.VEXFixed,
	}}}
	svc := newService(t, signer, WithCorpus(corpus))

	res, err := svc.Export(context.Background(), Request{Name: "left-pad", Ecosystem: "npm", Version: "1.3.0", Sign: true})
	if err != nil {
		t.Fatalf("Export(signed): %v", err)
	}
	if res.Signature == nil {
		t.Fatal("expected a signature on a signed export")
	}
	if res.Signature.Algorithm != "ed25519" {
		t.Errorf("algorithm = %q", res.Signature.Algorithm)
	}
	if err := VerifySignature(pub, res.Document, *res.Signature); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	// Tampering with the document must fail verification.
	tampered := append([]byte{}, res.Document...)
	tampered[len(tampered)/2] ^= 0xff
	if err := VerifySignature(pub, tampered, *res.Signature); err == nil {
		t.Fatal("verification accepted a tampered document")
	}

	// Signing without a key is rejected.
	nokey := newService(t, nil, WithCorpus(corpus))
	if _, err := nokey.Export(context.Background(), Request{Name: "left-pad", Version: "1.3.0", Sign: true}); err == nil {
		t.Fatal("expected error signing without a configured key")
	}
}

// --- break-glass grants become under_investigation statements ---------------

func TestGrantsBecomeUnderInvestigation(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	grants := &fakeGrants{
		enabled: true,
		reqs: []approvals.Request{{
			ID: "req-1", Tenant: "acme", Ecosystem: "npm", Coordinate: "evil@1.0.0",
			Gate: "malfeed", Reason: "known malware, serving under exception",
			Status: approvals.StatusApproved, GrantedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
			Approvers:     []approvals.Approver{{Subject: "alice"}, {Subject: "bob"}},
			Justification: "temporary, patch in flight",
		}},
	}
	svc := newService(t, nil, WithGrants(grants))

	res, err := svc.Export(context.Background(), Request{Tenant: "acme", Name: "evil", Ecosystem: "npm", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if grants.swept == 0 {
		t.Error("expected grants to be swept before listing")
	}
	doc, err := vulnscan.ParseVEX(res.Document, "grants.openvex.json")
	if err != nil {
		t.Fatalf("ParseVEX: %v", err)
	}
	if len(doc.Statements) != 1 {
		t.Fatalf("want 1 grant statement, got %d\n%s", len(doc.Statements), res.Document)
	}
	st := doc.Statements[0]
	if st.Status != vulnscan.VEXUnderInvestigation {
		t.Errorf("status = %q, want under_investigation", st.Status)
	}
	if !strings.Contains(st.ActionStatement, "alice") || !strings.Contains(st.ActionStatement, "break-glass") {
		t.Errorf("action statement missing approver/break-glass context: %q", st.ActionStatement)
	}

	// An expired grant is excluded.
	grants.reqs[0].ExpiresAt = now.Add(-time.Minute)
	res2, err := svc.Export(context.Background(), Request{Tenant: "acme", Name: "evil", Ecosystem: "npm", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("Export(expired): %v", err)
	}
	doc2, _ := vulnscan.ParseVEX(res2.Document, "x")
	if len(doc2.Statements) != 0 {
		t.Errorf("expired grant should not be exported, got %d statements", len(doc2.Statements))
	}
}

// --- metrics ----------------------------------------------------------------

func TestExportMetrics(t *testing.T) {
	corpus := fakeCorpus{enabled: true, stmts: []vulnscan.VEXStatement{{
		Vulnerability: "CVE-2024-0004",
		Products:      []vulnscan.VEXProductRef{{ID: "pkg:npm/a@1.0.0"}},
		Status:        vulnscan.VEXNotAffected,
	}}}
	svc := newService(t, nil, WithCorpus(corpus))
	for i := 0; i < 3; i++ {
		if _, err := svc.Export(context.Background(), Request{Name: "a", Ecosystem: "npm", Version: "1.0.0"}); err != nil {
			t.Fatalf("Export: %v", err)
		}
	}
	m := svc.Metrics()
	if m.ExportsTotal != 3 {
		t.Errorf("ExportsTotal = %d, want 3", m.ExportsTotal)
	}
	if m.StatementsTotal != 3 {
		t.Errorf("StatementsTotal = %d, want 3", m.StatementsTotal)
	}
	if m.ByFormat["openvex|false"] != 3 {
		t.Errorf("ByFormat = %+v", m.ByFormat)
	}
}

// --- disabled service rejects export ----------------------------------------

func TestDisabledServiceRejects(t *testing.T) {
	svc := New(Config{Enabled: false}, nil, testLogger())
	if svc.Enabled() {
		t.Fatal("service should be disabled")
	}
	if _, err := svc.Export(context.Background(), Request{Name: "x"}); err == nil {
		t.Fatal("disabled service should reject export")
	}
}
