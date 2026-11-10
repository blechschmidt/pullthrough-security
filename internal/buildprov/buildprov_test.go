package buildprov

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
)

var errBoom = errors.New("boom: attestation registry unreachable")

// ids builds an allowed-identity policy for the verifier.
func ids(issuer, pattern string) []sigverify.Identity {
	return []sigverify.Identity{{Issuer: issuer, SubjectPattern: pattern}}
}

// newService builds a service over a fixed material source with the given config
// defaults applied.
func newService(t *testing.T, cfg Config, mat *Material) *Service {
	t.Helper()
	svc, err := NewService(cfg, &fixedSource{mat: mat}, nil)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func npmArtifact(claim Claim) Artifact {
	return Artifact{Ecosystem: "npm", Backend: "npm", Name: "@acme/widgets", Version: "1.0.0", Digest: testDigest, Claim: claim}
}

// TestVerifyMatchingProvenance: a valid npm provenance whose proven commit
// matches the claimed association verifies cleanly and allows.
func TestVerifyMatchingProvenance(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, testWorkflow, testIssuer)
	doc := npmBundleDoc(t, leaf, leafKey, testDigest, testRepo, testCommit, false)
	mat := materialFromDoc(t, "npm-provenance", doc)

	svc := newService(t, Config{
		Mode:       ModeEnforce,
		Roots:      pool,
		Identities: ids(testIssuer, `^https://github\.com/acme/.*`),
	}, mat)

	claim := Claim{CommitSHA: testCommit, RepositoryURL: testRepo, Confidence: "claimed", Source: "npm-metadata"}
	report, err := svc.Verify(context.Background(), npmArtifact(claim))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.Present || !report.Verified || !report.SourceVerified {
		t.Fatalf("expected present/verified/source-verified, got %+v", report)
	}
	if report.Mismatch {
		t.Fatalf("unexpected mismatch; proven=%s claimed=%s", report.CommitSHA, claim.CommitSHA)
	}
	if report.CommitSHA != testCommit {
		t.Fatalf("proven commit = %q, want %q", report.CommitSHA, testCommit)
	}
	if report.WorkflowRef != testWorkflow {
		t.Fatalf("workflowRef = %q, want %q", report.WorkflowRef, testWorkflow)
	}
	if d := svc.Gate(report, ""); d.Action != policy.ActionAllow {
		t.Fatalf("expected allow, got %s: %s", d.Action, d.Reason)
	}
}

// TestSourceMismatch: a valid provenance proving a DIFFERENT commit than the
// metadata claims is the headline finding — critical, blocked in enforce mode,
// warned in observe mode.
func TestSourceMismatch(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, testWorkflow, testIssuer)
	// Attestation proves testCommit; metadata claims a different commit.
	doc := npmBundleDoc(t, leaf, leafKey, testDigest, testRepo, testCommit, false)
	mat := materialFromDoc(t, "npm-provenance", doc)

	claimedCommit := "ffffffffffffffffffffffffffffffffffffffff"
	claim := Claim{CommitSHA: claimedCommit, RepositoryURL: testRepo, Source: "npm-metadata"}

	enforce := newService(t, Config{Mode: ModeEnforce, Roots: pool,
		Identities: ids(testIssuer, `^https://github\.com/acme/.*`)}, mat)
	report, err := enforce.Verify(context.Background(), npmArtifact(claim))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.Mismatch {
		t.Fatalf("expected mismatch, got %+v", report)
	}
	w := report.Worst()
	if w == nil || w.Kind != KindSourceMismatch || w.Severity != SeverityCritical {
		t.Fatalf("expected critical source-mismatch finding, got %+v", w)
	}
	if d := enforce.Gate(report, ""); !d.Action.Blocked() {
		t.Fatalf("enforce mode should block a mismatch, got %s", d.Action)
	}

	// Observe mode: same report, never blocks — at most warns.
	observe := newService(t, Config{Mode: ModeObserve, Roots: pool,
		Identities: ids(testIssuer, `^https://github\.com/acme/.*`)}, mat)
	r2, _ := observe.Verify(context.Background(), npmArtifact(claim))
	d := observe.Gate(r2, "")
	if d.Action != policy.ActionWarn {
		t.Fatalf("observe mode should warn (never block), got %s", d.Action)
	}
}

// TestTamperedAttestationUnverified: a present attestation whose signature does
// not validate is flagged unverified (high), not source-verified.
func TestTamperedAttestationUnverified(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, testWorkflow, testIssuer)
	doc := npmBundleDoc(t, leaf, leafKey, testDigest, testRepo, testCommit, true) // tampered sig
	mat := materialFromDoc(t, "npm-provenance", doc)

	svc := newService(t, Config{Mode: ModeEnforce, Roots: pool}, mat)
	report, err := svc.Verify(context.Background(), npmArtifact(Claim{CommitSHA: testCommit, RepositoryURL: testRepo}))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.Present {
		t.Fatal("expected present")
	}
	if report.Verified || report.SourceVerified {
		t.Fatalf("tampered attestation must not verify, got %+v", report)
	}
	w := report.Worst()
	if w == nil || w.Kind != KindUnverifiedProvenance {
		t.Fatalf("expected unverified-provenance finding, got %+v", w)
	}
}

// TestUntrustedSourceWithoutRoots: without trust roots, a valid npm provenance is
// crypto-valid (verified) and yields the proven source for the cross-check, but
// is NOT source-verified. With RequireTrustedSource it is flagged; without it,
// the matching source allows.
func TestUntrustedSourceWithoutRoots(t *testing.T) {
	root, rootKey, _ := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, testWorkflow, testIssuer)
	doc := npmBundleDoc(t, leaf, leafKey, testDigest, testRepo, testCommit, false)
	mat := materialFromDoc(t, "npm-provenance", doc)
	claim := Claim{CommitSHA: testCommit, RepositoryURL: testRepo}

	svc := newService(t, Config{Mode: ModeEnforce /* no roots */}, mat)
	report, _ := svc.Verify(context.Background(), npmArtifact(claim))
	if !report.Verified {
		t.Fatalf("expected crypto-verified, got %+v", report)
	}
	if report.SourceVerified {
		t.Fatal("must not be source-verified without trust roots")
	}
	if report.CommitSHA != testCommit {
		t.Fatalf("proven commit not extracted: %q", report.CommitSHA)
	}
	if d := svc.Gate(report, ""); d.Action != policy.ActionAllow {
		t.Fatalf("without RequireTrustedSource a matching source should allow, got %s", d.Action)
	}

	strict := newService(t, Config{Mode: ModeEnforce, RequireTrustedSource: true}, mat)
	r2, _ := strict.Verify(context.Background(), npmArtifact(claim))
	if w := r2.Worst(); w == nil || w.Kind != KindUntrustedSource {
		t.Fatalf("expected untrusted-source finding, got %+v", w)
	}
}

// TestMissingProvenance: no attestation present. Allowed unless required.
func TestMissingProvenance(t *testing.T) {
	svc := newService(t, Config{Mode: ModeEnforce}, nil)
	report, err := svc.Verify(context.Background(), npmArtifact(Claim{}))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Present {
		t.Fatal("expected not present")
	}
	if len(report.Findings) != 0 {
		t.Fatalf("missing provenance should not be a finding by default, got %+v", report.Findings)
	}
	if d := svc.Gate(report, ""); d.Action != policy.ActionAllow {
		t.Fatalf("expected allow, got %s", d.Action)
	}

	req := newService(t, Config{Mode: ModeEnforce, RequireProvenance: true}, nil)
	r2, _ := req.Verify(context.Background(), npmArtifact(Claim{}))
	if w := r2.Worst(); w == nil || w.Kind != KindMissingProvenance {
		t.Fatalf("expected missing-provenance finding, got %+v", w)
	}
}

// TestTenantModeOverride: a tenant set to enforce blocks while the global mode
// observes.
func TestTenantModeOverride(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, testWorkflow, testIssuer)
	doc := npmBundleDoc(t, leaf, leafKey, testDigest, testRepo, testCommit, false)
	mat := materialFromDoc(t, "npm-provenance", doc)
	claim := Claim{CommitSHA: "ffffffffffffffffffffffffffffffffffffffff", RepositoryURL: testRepo}

	svc := newService(t, Config{
		Mode:       ModeObserve,
		Roots:      pool,
		Identities: ids(testIssuer, `^https://github\.com/acme/.*`),
		Tenants:    map[string]TenantConfig{"team-a": {Mode: ModeEnforce}},
	}, mat)
	report, _ := svc.Verify(context.Background(), npmArtifact(claim))

	if d := svc.Gate(report, ""); d.Action != policy.ActionWarn {
		t.Fatalf("global observe should warn, got %s", d.Action)
	}
	if d := svc.Gate(report, "team-a"); !d.Action.Blocked() {
		t.Fatalf("tenant enforce should block, got %s", d.Action)
	}
}

// TestHTTPNPMSourceAndCache: end-to-end through the HTTP npm source, exercising
// the result cache.
func TestHTTPNPMSourceAndCache(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, testWorkflow, testIssuer)
	doc := npmBundleDoc(t, leaf, leafKey, testDigest, testRepo, testCommit, false)

	src := NewNPMSource(&fakeDoer{status: 200, body: doc}, "https://registry.npmjs.org")
	svc, err := NewService(Config{Mode: ModeEnforce, Roots: pool,
		Identities: ids(testIssuer, `^https://github\.com/acme/.*`)}, src, nil)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	art := npmArtifact(Claim{CommitSHA: testCommit, RepositoryURL: testRepo})
	r1, err := svc.Verify(context.Background(), art)
	if err != nil || !r1.SourceVerified {
		t.Fatalf("first verify failed: %+v err=%v", r1, err)
	}
	r2, _ := svc.Verify(context.Background(), art)
	if r2 != r1 {
		t.Fatal("expected cached report on second verify")
	}
	if m := svc.Metrics(); m.CacheHits != 1 || m.Mismatch != 0 || m.SourceVerified != 1 {
		t.Fatalf("unexpected metrics: %+v", m)
	}
	st := svc.Status(10)
	if !st.Enabled || st.Mode != ModeEnforce || len(st.Recent) == 0 {
		t.Fatalf("unexpected status: %+v", st)
	}
	if st.ByEcosystem["npm"].SourceVerified != 1 {
		t.Fatalf("expected per-eco source-verified, got %+v", st.ByEcosystem)
	}
}

// TestNPMSource404IsNoMaterial: a 404 means no published provenance, not an error.
func TestNPMSource404IsNoMaterial(t *testing.T) {
	src := NewNPMSource(&fakeDoer{status: 404}, "https://registry.npmjs.org")
	m, err := src.Fetch(context.Background(), Artifact{Ecosystem: "npm", Name: "x", Version: "1.0.0", Digest: testDigest})
	if err != nil {
		t.Fatalf("404 should not error: %v", err)
	}
	if m != nil {
		t.Fatalf("expected nil material, got %+v", m)
	}
}

// TestFetchErrorFailOpenClosed: a fetch failure is fail-open (warn) by default and
// fail-closed (block) in enforce mode with FailOnError.
func TestFetchErrorFailOpenClosed(t *testing.T) {
	failing := &fixedSource{err: errBoom}
	open, _ := NewService(Config{Mode: ModeEnforce}, failing, nil)
	r, _ := open.Verify(context.Background(), npmArtifact(Claim{}))
	if d := open.Gate(r, ""); d.Action != policy.ActionWarn {
		t.Fatalf("fail-open should warn, got %s", d.Action)
	}
	closed, _ := NewService(Config{Mode: ModeEnforce, FailOnError: true}, failing, nil)
	r2, _ := closed.Verify(context.Background(), npmArtifact(Claim{}))
	if d := closed.Gate(r2, ""); !d.Action.Blocked() {
		t.Fatalf("fail-closed should block, got %s", d.Action)
	}
}

// TestBindingAlgorithmMismatchIsNotCheckable: the proxy's content digest uses a
// different algorithm (sha256) than the npm provenance subject (sha512). Binding
// is "not checkable", so a valid attestation still verifies (no false unverified).
func TestBindingAlgorithmMismatchIsNotCheckable(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, testWorkflow, testIssuer)
	doc := npmBundleDoc(t, leaf, leafKey, testDigest /* sha512 subject */, testRepo, testCommit, false)
	mat := materialFromDoc(t, "npm-provenance", doc)

	svc := newService(t, Config{Mode: ModeEnforce, Roots: pool,
		Identities: ids(testIssuer, `^https://github\.com/acme/.*`)}, mat)
	// Artifact digest is a sha256 — a different algorithm than the subject's sha512.
	art := Artifact{Ecosystem: "npm", Name: "@acme/widgets", Version: "1.0.0",
		Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		Claim:  Claim{CommitSHA: testCommit, RepositoryURL: testRepo}}
	report, _ := svc.Verify(context.Background(), art)
	if !report.Verified || !report.SourceVerified {
		t.Fatalf("algorithm-mismatched digest should be treated as not-checkable, got %+v", report)
	}
}

// TestBindingViolationRejected: the artifact's digest algorithm IS present in the
// subject but with a different value — the attestation is for a different
// artifact and must not verify.
func TestBindingViolationRejected(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, testWorkflow, testIssuer)
	doc := npmBundleDoc(t, leaf, leafKey, testDigest, testRepo, testCommit, false)
	mat := materialFromDoc(t, "npm-provenance", doc)

	svc := newService(t, Config{Mode: ModeEnforce, Roots: pool,
		Identities: ids(testIssuer, `^https://github\.com/acme/.*`)}, mat)
	// Same algorithm (sha512) as the subject, but a different digest value.
	art := Artifact{Ecosystem: "npm", Name: "@acme/widgets", Version: "1.0.0",
		Digest: "sha512:0000000000000000000000000000000000000000000000000000000000000000",
		Claim:  Claim{CommitSHA: testCommit, RepositoryURL: testRepo}}
	report, _ := svc.Verify(context.Background(), art)
	if report.Verified || report.SourceVerified {
		t.Fatalf("binding violation must not verify, got %+v", report)
	}
	if w := report.Worst(); w == nil || w.Kind != KindUnverifiedProvenance {
		t.Fatalf("expected unverified-provenance finding, got %+v", w)
	}
}

// TestGoldenNPMProvenanceFixture parses the committed real-shape npm provenance
// document and asserts the parser recovers the DSSE envelope and signing
// certificate.
func TestGoldenNPMProvenanceFixture(t *testing.T) {
	path := filepath.Join("testdata", "npm-provenance.json")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	atts, err := ParseAttestations(body)
	if err != nil {
		t.Fatalf("ParseAttestations: %v", err)
	}
	if len(atts) == 0 {
		t.Fatal("expected at least one attestation from the npm provenance fixture")
	}
	a := atts[0]
	if a.Envelope == nil || a.Envelope.Payload == "" {
		t.Fatal("expected a DSSE envelope with a payload")
	}
	if a.Cert == nil {
		t.Fatal("expected a signing certificate extracted from verificationMaterial")
	}
}
