package buildprov

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
)

// This file exercises the GitLab and Bitbucket forge extensions (Task 126): the
// per-forge attestation-discovery Sources, the per-forge trust routing, and the
// shared verification/cross-check/gating logic, with valid, expired, and forged
// attestations for each forge.

const (
	gitlabIssuer   = "https://gitlab.com"
	gitlabWorkflow = "https://gitlab.com/acme-group/widgets//.gitlab-ci.yml@refs/heads/main"
	gitlabRepo     = "https://gitlab.com/acme-group/widgets"
	gitlabCommit   = "abcdef0123456789abcdef0123456789abcdef01"

	bitbucketIssuer   = "https://api.bitbucket.org/2.0/workspaces/acme/pipelines-config/identity/oidc"
	bitbucketWorkflow = "https://bitbucket.org/acme/widgets/pipelines"
	bitbucketRepo     = "https://bitbucket.org/acme/widgets"
	bitbucketCommit   = "fedcba9876543210fedcba9876543210fedcba98"

	// forgeDigest is a sha256 content digest the forge attestation binds (forge
	// attestations bind the artifact content digest, unlike npm's tarball sha512).
	forgeDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
)

// makeLeafWithValidity mints a Fulcio-like leaf with an explicit validity window
// (so a test can mint an expired certificate), carrying the signer identity SAN
// and the OIDC-issuer extension.
func makeLeafWithValidity(t *testing.T, root *x509.Certificate, rootKey *ecdsa.PrivateKey, identity, issuer string, notBefore, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key := newKey(t)
	issuerExt := pkix.Extension{Id: fulcioOIDC}
	b, err := asn1.Marshal(issuer)
	if err != nil {
		t.Fatalf("marshal issuer: %v", err)
	}
	issuerExt.Value = b
	u, err := url.Parse(identity)
	if err != nil {
		t.Fatalf("parse identity: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(3),
		Subject:         pkix.Name{CommonName: "forge-signer"},
		NotBefore:       notBefore,
		NotAfter:        notAfter,
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		URIs:            []*url.URL{u},
		ExtraExtensions: []pkix.Extension{issuerExt},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return cert, key
}

// forgeBundleDoc wraps a SLSA statement in the Sigstore-bundle attestations
// document shape ({"attestations":[{"bundle":...}]}), signing the DSSE envelope
// with the leaf key. When tamper is true the signature is corrupted.
func forgeBundleDoc(t *testing.T, leaf *x509.Certificate, leafKey *ecdsa.PrivateKey, statement []byte, tamper bool) []byte {
	t.Helper()
	pae := dssePAE("application/vnd.in-toto+json", statement)
	sig := signECDSA(t, leafKey, pae)
	if tamper {
		sig = append([]byte(nil), sig...)
		sig[len(sig)-1] ^= 0xff
	}
	env := map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(statement),
		"signatures":  []map[string]any{{"sig": base64.StdEncoding.EncodeToString(sig)}},
	}
	bundle := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
		"verificationMaterial": map[string]any{
			"certificate": map[string]any{"rawBytes": base64.StdEncoding.EncodeToString(leaf.Raw)},
			"tlogEntries": []any{},
		},
		"dsseEnvelope": env,
	}
	doc := map[string]any{
		"attestations": []map[string]any{
			{"predicateType": "https://slsa.dev/provenance/v1", "bundle": bundle},
		},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal doc: %v", err)
	}
	return data
}

func forgeArtifact(ecosystem, repo string, claim Claim) Artifact {
	return Artifact{Ecosystem: ecosystem, Backend: ecosystem, Name: "widgets", Version: "2.1.0",
		Digest: forgeDigest, RepositoryURL: repo, Claim: claim}
}

// TestGitLabValidProvenance: a valid GitLab CI/CD SLSA attestation verified under
// GitLab's per-forge trust (root + gitlab.com issuer) is source-verified and
// allows, with the proven commit extracted.
func TestGitLabValidProvenance(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, gitlabWorkflow, gitlabIssuer)
	doc := forgeBundleDoc(t, leaf, leafKey, slsaStatement(forgeDigest, gitlabRepo, gitlabCommit), false)
	mat := materialFromDoc(t, "gitlab-attestations", doc)
	mat.Forge = ForgeGitLab

	svc := newService(t, Config{
		Mode: ModeEnforce,
		// Default trust is empty: GitLab is trusted ONLY via its per-forge material.
		Forges: []ForgeTrust{{
			Name:       ForgeGitLab,
			Roots:      pool,
			Identities: ids(gitlabIssuer, `^https://gitlab\.com/acme-group/.*`),
		}},
	}, mat)

	claim := Claim{CommitSHA: gitlabCommit, RepositoryURL: gitlabRepo, Confidence: "claimed", Source: "gitlab-metadata"}
	report, err := svc.Verify(context.Background(), forgeArtifact("npm", gitlabRepo, claim))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.Present || !report.Verified || !report.SourceVerified {
		t.Fatalf("expected present/verified/source-verified, got %+v", report)
	}
	if report.Mismatch {
		t.Fatalf("unexpected mismatch; proven=%s claimed=%s", report.CommitSHA, claim.CommitSHA)
	}
	if report.CommitSHA != gitlabCommit {
		t.Fatalf("proven commit = %q, want %q", report.CommitSHA, gitlabCommit)
	}
	if report.Forge != ForgeGitLab {
		t.Fatalf("report forge = %q, want %q", report.Forge, ForgeGitLab)
	}
	if d := svc.Gate(report, ""); d.Action != policy.ActionAllow {
		t.Fatalf("expected allow, got %s: %s", d.Action, d.Reason)
	}
}

// TestBitbucketValidProvenance: a valid Bitbucket Pipelines SLSA attestation is
// source-verified under Bitbucket's per-forge trust and allows.
func TestBitbucketValidProvenance(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, bitbucketWorkflow, bitbucketIssuer)
	doc := forgeBundleDoc(t, leaf, leafKey, slsaStatement(forgeDigest, bitbucketRepo, bitbucketCommit), false)
	mat := materialFromDoc(t, "bitbucket-attestations", doc)
	mat.Forge = ForgeBitbucket

	svc := newService(t, Config{
		Mode: ModeEnforce,
		Forges: []ForgeTrust{{
			Name:       ForgeBitbucket,
			Roots:      pool,
			Identities: ids(bitbucketIssuer, `^https://bitbucket\.org/acme/.*`),
		}},
	}, mat)

	claim := Claim{CommitSHA: bitbucketCommit, RepositoryURL: bitbucketRepo, Source: "bitbucket-metadata"}
	report, err := svc.Verify(context.Background(), forgeArtifact("npm", bitbucketRepo, claim))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.SourceVerified || report.Mismatch {
		t.Fatalf("expected source-verified, no mismatch, got %+v", report)
	}
	if report.CommitSHA != bitbucketCommit {
		t.Fatalf("proven commit = %q, want %q", report.CommitSHA, bitbucketCommit)
	}
	if report.Forge != ForgeBitbucket {
		t.Fatalf("report forge = %q, want %q", report.Forge, ForgeBitbucket)
	}
	if d := svc.Gate(report, ""); d.Action != policy.ActionAllow {
		t.Fatalf("expected allow, got %s: %s", d.Action, d.Reason)
	}
}

// TestPerForgeTrustIsolation: an attestation signed by a GitLab identity but
// discovered as a Bitbucket attestation must NOT be source-verified — each forge
// is verified against its own issuer policy (and its own root), so one forge's
// trust never launders another's attestation.
func TestPerForgeTrustIsolation(t *testing.T) {
	gitlabRootCert, gitlabRootKey, gitlabPool := makeRoot(t)
	_, _, bitbucketPool := makeRoot(t)

	// A GitLab-signed attestation (gitlab root + gitlab issuer).
	glLeaf, glKey := makeLeaf(t, gitlabRootCert, gitlabRootKey, gitlabWorkflow, gitlabIssuer)
	glDoc := forgeBundleDoc(t, glLeaf, glKey, slsaStatement(forgeDigest, gitlabRepo, gitlabCommit), false)
	glMat := materialFromDoc(t, "gitlab-attestations", glDoc)

	cfg := Config{
		Mode: ModeEnforce,
		Forges: []ForgeTrust{
			{Name: ForgeGitLab, Roots: gitlabPool, Identities: ids(gitlabIssuer, `^https://gitlab\.com/.*`)},
			{Name: ForgeBitbucket, Roots: bitbucketPool, Identities: ids(bitbucketIssuer, `^https://bitbucket\.org/.*`)},
		},
	}

	// Correctly-labeled forges verify.
	glMat.Forge = ForgeGitLab
	glSvc := newService(t, cfg, glMat)
	glReport, _ := glSvc.Verify(context.Background(), forgeArtifact("npm", gitlabRepo, Claim{CommitSHA: gitlabCommit, RepositoryURL: gitlabRepo}))
	if !glReport.SourceVerified {
		t.Fatalf("gitlab attestation should verify under gitlab trust, got %+v", glReport)
	}

	// A GitLab-signed attestation presented as a Bitbucket attestation fails under
	// Bitbucket's root (different CA) and issuer policy — crypto-valid but NOT
	// source-verified.
	glMat.Forge = ForgeBitbucket
	crossSvc := newService(t, cfg, glMat)
	crossReport, _ := crossSvc.Verify(context.Background(), forgeArtifact("npm", gitlabRepo, Claim{CommitSHA: gitlabCommit, RepositoryURL: gitlabRepo}))
	if crossReport.SourceVerified {
		t.Fatalf("a gitlab attestation must not be source-verified under bitbucket trust, got %+v", crossReport)
	}
	if !crossReport.Verified {
		t.Fatalf("expected crypto-valid (signature still validates), got %+v", crossReport)
	}
}

// TestForgeExpiredAttestation: an expired GitLab signing certificate yields a
// crypto-valid attestation whose chain is NOT trusted (the cert is outside its
// validity window), so it is not source-verified; with RequireTrustedSource it is
// flagged untrusted-source.
func TestForgeExpiredAttestation(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	leaf, leafKey := makeLeafWithValidity(t, root, rootKey, gitlabWorkflow, gitlabIssuer,
		time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)) // expired yesterday
	doc := forgeBundleDoc(t, leaf, leafKey, slsaStatement(forgeDigest, gitlabRepo, gitlabCommit), false)
	mat := materialFromDoc(t, "gitlab-attestations", doc)
	mat.Forge = ForgeGitLab

	cfg := Config{
		Mode:                 ModeEnforce,
		RequireTrustedSource: true,
		Forges: []ForgeTrust{{
			Name:       ForgeGitLab,
			Roots:      pool,
			Identities: ids(gitlabIssuer, `^https://gitlab\.com/.*`),
		}},
	}
	svc := newService(t, cfg, mat)
	report, _ := svc.Verify(context.Background(), forgeArtifact("npm", gitlabRepo, Claim{CommitSHA: gitlabCommit, RepositoryURL: gitlabRepo}))
	if !report.Verified {
		t.Fatalf("expired-cert attestation should still be crypto-valid, got %+v", report)
	}
	if report.SourceVerified {
		t.Fatalf("expired certificate must not chain-trust, got %+v", report)
	}
	if w := report.Worst(); w == nil || w.Kind != KindUntrustedSource {
		t.Fatalf("expected untrusted-source finding for expired attestation, got %+v", w)
	}
}

// TestForgeForgedAttestation: a forged (tampered-signature) Bitbucket attestation
// does not verify and is flagged unverified-provenance.
func TestForgeForgedAttestation(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, bitbucketWorkflow, bitbucketIssuer)
	doc := forgeBundleDoc(t, leaf, leafKey, slsaStatement(forgeDigest, bitbucketRepo, bitbucketCommit), true) // tampered
	mat := materialFromDoc(t, "bitbucket-attestations", doc)
	mat.Forge = ForgeBitbucket

	svc := newService(t, Config{
		Mode: ModeEnforce,
		Forges: []ForgeTrust{{
			Name:       ForgeBitbucket,
			Roots:      pool,
			Identities: ids(bitbucketIssuer, `^https://bitbucket\.org/.*`),
		}},
	}, mat)
	report, _ := svc.Verify(context.Background(), forgeArtifact("npm", bitbucketRepo, Claim{CommitSHA: bitbucketCommit, RepositoryURL: bitbucketRepo}))
	if report.Verified || report.SourceVerified {
		t.Fatalf("forged attestation must not verify, got %+v", report)
	}
	if w := report.Worst(); w == nil || w.Kind != KindUnverifiedProvenance {
		t.Fatalf("expected unverified-provenance finding, got %+v", w)
	}
	if d := svc.Gate(report, ""); !d.Action.Blocked() {
		t.Fatalf("enforce mode should block a forged attestation, got %s", d.Action)
	}
}

// TestForgeSourceMismatch: a valid GitLab attestation proving a different commit
// than the metadata claims is the headline critical source-mismatch finding.
func TestForgeSourceMismatch(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, gitlabWorkflow, gitlabIssuer)
	doc := forgeBundleDoc(t, leaf, leafKey, slsaStatement(forgeDigest, gitlabRepo, gitlabCommit), false)
	mat := materialFromDoc(t, "gitlab-attestations", doc)
	mat.Forge = ForgeGitLab

	svc := newService(t, Config{
		Mode:   ModeEnforce,
		Forges: []ForgeTrust{{Name: ForgeGitLab, Roots: pool, Identities: ids(gitlabIssuer, `^https://gitlab\.com/.*`)}},
	}, mat)
	claim := Claim{CommitSHA: "0000000000000000000000000000000000000000", RepositoryURL: gitlabRepo}
	report, _ := svc.Verify(context.Background(), forgeArtifact("npm", gitlabRepo, claim))
	if !report.Mismatch {
		t.Fatalf("expected mismatch, got %+v", report)
	}
	if w := report.Worst(); w == nil || w.Kind != KindSourceMismatch || w.Severity != SeverityCritical {
		t.Fatalf("expected critical source-mismatch, got %+v", w)
	}
	if d := svc.Gate(report, ""); !d.Action.Blocked() {
		t.Fatalf("enforce mode should block a mismatch, got %s", d.Action)
	}
}

// recordingDoer records the request URL and returns a canned response.
type recordingDoer struct {
	status  int
	body    []byte
	lastURL string
}

func (d *recordingDoer) Do(req *http.Request) (*http.Response, error) {
	d.lastURL = req.URL.String()
	return (&fakeDoer{status: d.status, body: d.body}).Do(req)
}

// TestGitLabSourceDiscovery: the GitLab source builds the correct API URL
// (URL-encoding the nested project path) and stamps the forge on the material.
func TestGitLabSourceDiscovery(t *testing.T) {
	root, rootKey, _ := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, gitlabWorkflow, gitlabIssuer)
	doc := forgeBundleDoc(t, leaf, leafKey, slsaStatement(forgeDigest, gitlabRepo, gitlabCommit), false)

	rec := &recordingDoer{status: 200, body: doc}
	src := NewGitLabSource(rec, "", "", "")
	art := Artifact{Ecosystem: "npm", Name: "widgets", Version: "2.1.0", Digest: forgeDigest, RepositoryURL: gitlabRepo}
	mat, err := src.Fetch(context.Background(), art)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if mat == nil || mat.Forge != ForgeGitLab || mat.Source != "gitlab-attestations" {
		t.Fatalf("unexpected material: %+v", mat)
	}
	wantURL := "https://gitlab.com/api/v4/projects/acme-group%2Fwidgets/attestations/" + url.PathEscape(forgeDigest)
	if rec.lastURL != wantURL {
		t.Fatalf("gitlab URL = %q, want %q", rec.lastURL, wantURL)
	}

	// A non-gitlab repository is not applicable to the gitlab source.
	if _, err := src.Fetch(context.Background(), Artifact{Digest: forgeDigest, RepositoryURL: "https://github.com/acme/widgets"}); err != ErrNotApplicable {
		t.Fatalf("github repo should be not-applicable to gitlab source, got %v", err)
	}
}

// TestBitbucketSourceDiscovery: the Bitbucket source builds the correct
// workspace/repo API URL and stamps the forge.
func TestBitbucketSourceDiscovery(t *testing.T) {
	root, rootKey, _ := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, bitbucketWorkflow, bitbucketIssuer)
	doc := forgeBundleDoc(t, leaf, leafKey, slsaStatement(forgeDigest, bitbucketRepo, bitbucketCommit), false)

	rec := &recordingDoer{status: 200, body: doc}
	src := NewBitbucketSource(rec, "", "", "")
	art := Artifact{Ecosystem: "npm", Name: "widgets", Version: "2.1.0", Digest: forgeDigest, RepositoryURL: bitbucketRepo}
	mat, err := src.Fetch(context.Background(), art)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if mat == nil || mat.Forge != ForgeBitbucket {
		t.Fatalf("unexpected material: %+v", mat)
	}
	wantURL := "https://api.bitbucket.org/2.0/repositories/acme/widgets/attestations/" + url.PathEscape(forgeDigest)
	if rec.lastURL != wantURL {
		t.Fatalf("bitbucket URL = %q, want %q", rec.lastURL, wantURL)
	}
}

// TestMultiSourceForgeRouting: a MultiSource over npm + gitlab + bitbucket routes
// a gitlab-repo artifact to the gitlab source (skipping the inapplicable ones).
func TestMultiSourceForgeRouting(t *testing.T) {
	root, rootKey, _ := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, gitlabWorkflow, gitlabIssuer)
	doc := forgeBundleDoc(t, leaf, leafKey, slsaStatement(forgeDigest, gitlabRepo, gitlabCommit), false)

	npm := NewNPMSource(&fakeDoer{status: 404}, "https://registry.npmjs.org")
	gitlab := NewGitLabSource(&fakeDoer{status: 200, body: doc}, "", "", "")
	bitbucket := NewBitbucketSource(&fakeDoer{status: 404}, "", "", "")
	multi := NewMultiSource(npm, gitlab, bitbucket)

	// Artifact has no npm name/version but a gitlab repo hint + digest.
	art := Artifact{Ecosystem: "generic", Digest: forgeDigest, RepositoryURL: gitlabRepo}
	mat, err := multi.Fetch(context.Background(), art)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if mat == nil || mat.Forge != ForgeGitLab {
		t.Fatalf("expected gitlab material, got %+v", mat)
	}
}

// TestForgeRepoPath covers repository-path extraction across forge URL forms.
func TestForgeRepoPath(t *testing.T) {
	cases := []struct {
		name     string
		repo     string
		host     string
		wantPath string
		wantOK   bool
	}{
		{"gitlab https", "https://gitlab.com/acme-group/widgets", "gitlab.com", "acme-group/widgets", true},
		{"gitlab subgroup", "https://gitlab.com/acme-group/team/widgets.git", "gitlab.com", "acme-group/team/widgets", true},
		{"gitlab git+pin", "git+https://gitlab.com/acme-group/widgets@refs/heads/main", "gitlab.com", "acme-group/widgets", true},
		{"gitlab scp", "git@gitlab.com:acme-group/widgets.git", "gitlab.com", "acme-group/widgets", true},
		{"gitlab creds", "https://user:tok@gitlab.com/acme-group/widgets", "gitlab.com", "acme-group/widgets", true},
		{"bitbucket https", "https://bitbucket.org/acme/widgets", "bitbucket.org", "acme/widgets", true},
		{"wrong host", "https://github.com/acme/widgets", "gitlab.com", "", false},
		{"single segment", "https://gitlab.com/acme", "gitlab.com", "", false},
		{"bare host", "https://gitlab.com/", "gitlab.com", "", false},
		{"empty", "", "gitlab.com", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := forgeRepoPath(tc.repo, tc.host)
			if ok != tc.wantOK || got != tc.wantPath {
				t.Fatalf("forgeRepoPath(%q,%q) = (%q,%v), want (%q,%v)", tc.repo, tc.host, got, ok, tc.wantPath, tc.wantOK)
			}
		})
	}
}

// TestGoldenGitLabFixture parses the committed GitLab provenance fixture (Sigstore
// bundle shape) and asserts the DSSE envelope, signing certificate, and SLSA
// source reference are recovered.
func TestGoldenGitLabFixture(t *testing.T) {
	assertGoldenForgeFixture(t, "gitlab-provenance.json",
		"https://gitlab.com/acme-group/widgets", "abcdef0123456789abcdef0123456789abcdef01")
}

// TestGoldenBitbucketFixture parses the committed Bitbucket provenance fixture
// (PEP 740 inline attestation_bundles shape) and asserts the same.
func TestGoldenBitbucketFixture(t *testing.T) {
	assertGoldenForgeFixture(t, "bitbucket-provenance.json",
		"https://bitbucket.org/acme/widgets", "fedcba9876543210fedcba9876543210fedcba98")
}

func assertGoldenForgeFixture(t *testing.T, file, wantRepo, wantCommit string) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", file))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	atts, err := ParseAttestations(body)
	if err != nil {
		t.Fatalf("ParseAttestations: %v", err)
	}
	if len(atts) == 0 {
		t.Fatalf("expected at least one attestation from %s", file)
	}
	a := atts[0]
	if a.Envelope == nil || a.Envelope.Payload == "" {
		t.Fatalf("%s: expected a DSSE envelope with a payload", file)
	}
	if a.Cert == nil {
		t.Fatalf("%s: expected a signing certificate", file)
	}
	// Verify the parsed material surfaces the SLSA source via the shared verifier
	// (no trust roots: we assert extraction, not trust).
	v, err := sigverify.NewVerifier(nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	res, st := v.VerifyAttestation(a, "")
	if st == nil || !res.SLSAProvenance {
		t.Fatalf("%s: expected SLSA provenance statement, got %+v", file, res)
	}
	if res.RepositoryURL != wantRepo || res.CommitSHA != wantCommit {
		t.Fatalf("%s: source = %q@%q, want %q@%q", file, res.RepositoryURL, res.CommitSHA, wantRepo, wantCommit)
	}
}
