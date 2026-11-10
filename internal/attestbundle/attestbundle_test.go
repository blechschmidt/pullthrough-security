package attestbundle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

var update = flag.Bool("update", false, "regenerate golden testdata files")

// fixedSigner returns a deterministic Ed25519 signer derived from a fixed seed,
// so signatures (and therefore the whole bundle) are byte-reproducible in tests.
func fixedSigner(t *testing.T) *Signer {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	s, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

// sampleInput is a representative aggregated admission document exercising every
// gate section, with a resolved digest and source commit.
func sampleInput() policyengine.Input {
	return policyengine.Input{
		Tenant: "acme",
		Artifact: policyengine.ArtifactInput{
			Ecosystem: "npm",
			Backend:   "npm-proxy",
			Name:      "left-pad",
			Version:   "1.3.0",
			Digest:    "sha256:" + "ab" + "cd" + "ef00" + "112233445566778899aabbccddeeff00112233445566778899aabbcc",
		},
		Vuln: &policyengine.VulnInput{
			Scanned: true, Scanner: "osv", MaxSeverity: "medium",
			Total: 2, HighCount: 0, MediumCount: 2, VEXSuppressed: 1,
		},
		License: &policyengine.LicenseInput{
			Evaluated: true, Action: "allow", Code: "ok", Allowed: true,
		},
		Signature: &policyengine.SignatureInput{
			Checked: true, Verified: true, Attested: true, Keyless: true,
			ChainTrusted: true, SLSAProvenance: true,
			Identity: "https://github.com/acme/left-pad/.github/workflows/release.yml@refs/tags/v1.3.0",
			Issuer:   "https://token.actions.githubusercontent.com",
		},
		Provenance: &policyengine.ProvenanceInput{
			Found: true, Confidence: "attested", SignatureVerified: true, ChainTrusted: true,
			CommitSHA:     "0123456789abcdef0123456789abcdef01234567",
			RepositoryURL: "https://github.com/acme/left-pad",
		},
	}
}

func sampleAttester() Attester {
	return Attester{ID: "pullthrough-proxy", Name: "pullthrough-security", Version: "test", Instance: "proxy-1"}
}

func TestBuildStatement_Deterministic(t *testing.T) {
	in := sampleInput()
	opts := Options{
		Risk:     &findings.RiskSignal{Score: 12, Band: "low", Action: "allow", Summary: "low risk"},
		Policy:   &findings.PolicySignal{Action: "allow", Reason: "all rules passed"},
		ServedAt: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC),
	}
	a := BuildStatement(sampleAttester(), in, opts)
	b := BuildStatement(sampleAttester(), in, opts)

	ab, err := canonicalStatement(a)
	if err != nil {
		t.Fatalf("canonical a: %v", err)
	}
	bb, err := canonicalStatement(b)
	if err != nil {
		t.Fatalf("canonical b: %v", err)
	}
	if !bytes.Equal(ab, bb) {
		t.Fatalf("statement marshaling is not deterministic")
	}

	// Subject must bind the served digest.
	if len(a.Subject) != 1 {
		t.Fatalf("want 1 subject, got %d", len(a.Subject))
	}
	if got := a.Subject[0].Digest["sha256"]; got == "" {
		t.Fatalf("subject missing sha256 digest: %#v", a.Subject[0].Digest)
	}
	if a.Predicate.Source == nil || a.Predicate.Source.CommitSHA != in.Provenance.CommitSHA {
		t.Fatalf("source commit not carried into predicate: %#v", a.Predicate.Source)
	}
	if a.Predicate.Admission.VEX == nil || a.Predicate.Admission.VEX.Suppressed != 1 {
		t.Fatalf("VEX summary not folded in: %#v", a.Predicate.Admission.VEX)
	}
}

func TestStatementGolden(t *testing.T) {
	in := sampleInput()
	opts := Options{
		Risk:     &findings.RiskSignal{Score: 12, Band: "low", Action: "allow", Summary: "low risk"},
		Policy:   &findings.PolicySignal{Action: "allow", Reason: "all rules passed"},
		ServedAt: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC),
	}
	stmt := BuildStatement(sampleAttester(), in, opts)
	got, err := json.MarshalIndent(stmt, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')

	golden := filepath.Join("testdata", "statement.golden.json")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("reading golden (run with -update to create): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("statement golden mismatch.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestSignAndVerify_RoundTrip(t *testing.T) {
	signer := fixedSigner(t)
	svc, err := NewService(Config{
		Signer:   signer,
		Attester: sampleAttester(),
		Now:      func() time.Time { return time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	bundle, err := svc.Attest(sampleInput(), Options{ServedAt: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if bundle.Digest == "" || bundle.SubjectDigest == "" {
		t.Fatalf("bundle missing digests: %#v", bundle)
	}
	if bundle.KeyID != signer.KeyID() {
		t.Fatalf("bundle keyId %q != signer %q", bundle.KeyID, signer.KeyID())
	}

	// Verifying against the correct public key returns the statement.
	stmt, err := VerifyEnvelope(signer.PublicKey(), bundle.Envelope)
	if err != nil {
		t.Fatalf("VerifyEnvelope: %v", err)
	}
	if stmt.Predicate.Artifact.Name != "left-pad" {
		t.Fatalf("verified statement wrong artifact: %#v", stmt.Predicate.Artifact)
	}

	// Tampering with the payload must fail verification.
	tampered := bundle.Envelope
	tampered.Payload = tampered.Payload[:len(tampered.Payload)-4] + "AAAA"
	if _, err := VerifyEnvelope(signer.PublicKey(), tampered); err == nil {
		t.Fatalf("verification accepted a tampered payload")
	}

	// A different key must fail verification.
	other := fixedSignerOther(t)
	if _, err := VerifyEnvelope(other.PublicKey(), bundle.Envelope); err == nil {
		t.Fatalf("verification accepted the wrong public key")
	}
}

func fixedSignerOther(t *testing.T) *Signer {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(255 - i)
	}
	s, err := NewSigner(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestBundleGolden_Ed25519Deterministic(t *testing.T) {
	signer := fixedSigner(t)
	svc, err := NewService(Config{
		Signer:   signer,
		Attester: sampleAttester(),
		Now:      func() time.Time { return time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	bundle, err := svc.Attest(sampleInput(), Options{ServedAt: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	got, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')

	golden := filepath.Join("testdata", "bundle.golden.json")
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("reading golden (run with -update to create): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("bundle golden mismatch (Ed25519 signatures must be deterministic).\n--- got ---\n%s", got)
	}
}

func TestStore_GetAndByDigest(t *testing.T) {
	signer := fixedSigner(t)
	svc, err := NewService(Config{Signer: signer, Attester: sampleAttester()})
	if err != nil {
		t.Fatal(err)
	}
	b, err := svc.Attest(sampleInput(), Options{})
	if err != nil {
		t.Fatal(err)
	}

	// Exact coordinate.
	if got, ok := svc.Get("acme", "left-pad@1.3.0"); !ok || got.Digest != b.Digest {
		t.Fatalf("Get by coordinate failed: ok=%v", ok)
	}
	// Bare name (latest).
	if _, ok := svc.Get("acme", "left-pad"); !ok {
		t.Fatalf("Get by bare name failed")
	}
	// Wrong tenant misses.
	if _, ok := svc.Get("other", "left-pad@1.3.0"); ok {
		t.Fatalf("Get returned a bundle for the wrong tenant")
	}
	// Referrers by subject digest.
	idx, ok := svc.Referrers(b.SubjectDigest)
	if !ok {
		t.Fatalf("Referrers returned ok=false")
	}
	if len(idx.Manifests) != 1 {
		t.Fatalf("want 1 referrer manifest, got %d", len(idx.Manifests))
	}
	if idx.Manifests[0].Digest != b.Digest {
		t.Fatalf("referrer digest %q != bundle digest %q", idx.Manifests[0].Digest, b.Digest)
	}
	if idx.Manifests[0].ArtifactType != ArtifactType {
		t.Fatalf("referrer artifactType = %q", idx.Manifests[0].ArtifactType)
	}
}

func TestNilService_NoOp(t *testing.T) {
	var svc *Service
	b, err := svc.Attest(sampleInput(), Options{})
	if err != nil || b != nil {
		t.Fatalf("nil service Attest = (%v, %v), want (nil, nil)", b, err)
	}
	if svc.Snapshot().Enabled {
		t.Fatalf("nil service should report disabled")
	}
	if _, ok := svc.Get("a", "b"); ok {
		t.Fatalf("nil service Get should miss")
	}
}

func TestNewService_RequiresSigner(t *testing.T) {
	if _, err := NewService(Config{}); err == nil {
		t.Fatalf("NewService without a signer should error")
	}
}

func TestAttest_OmitsSourceWhenAbsent(t *testing.T) {
	in := sampleInput()
	in.Provenance = nil
	signer := fixedSigner(t)
	svc, _ := NewService(Config{Signer: signer, Attester: sampleAttester()})
	b, err := svc.Attest(in, Options{})
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := b.Statement()
	if err != nil {
		t.Fatal(err)
	}
	if stmt.Predicate.Source != nil {
		t.Fatalf("source should be omitted when no provenance: %#v", stmt.Predicate.Source)
	}
}
