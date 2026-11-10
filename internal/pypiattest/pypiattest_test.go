package pypiattest

import (
	"context"
	"crypto"
	"net/http"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/rekor"
	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
)

func trustedIdentities() []sigverify.Identity {
	return []sigverify.Identity{{Issuer: testIssuer, SubjectPattern: `^https://github\.com/acme/widgets/`}}
}

func newService(t *testing.T, cfg Config, mat *Material) *Service {
	t.Helper()
	svc, err := NewService(cfg, &fixedSource{mat: mat}, nil)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func TestVerify_TrustedPublisher(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, testPublisher, testIssuer)
	_ = root

	doc := buildProvenanceDoc(t, provOpts{
		leaf: leaf, leafKey: leafKey, filename: testFilename, sha256hex: testHex, repo: testRepo,
	})
	mat := materialFromDoc(t, doc)

	svc := newService(t, Config{
		Roots:                   pool,
		Identities:              trustedIdentities(),
		RequireTrustedPublisher: true,
	}, mat)

	rep, err := svc.Verify(context.Background(), Artifact{Ecosystem: "pypi", Name: "widgets", Version: "1.0.0", Digest: testDigest})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.Present || !rep.Verified || !rep.PublisherTrusted {
		t.Fatalf("want present+verified+publisherTrusted, got %+v", rep)
	}
	if rep.DigestMismatch {
		t.Fatal("unexpected digest mismatch")
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("want no findings, got %+v", rep.Findings)
	}
	if rep.Publisher.Identity != testPublisher {
		t.Fatalf("publisher identity = %q", rep.Publisher.Identity)
	}
	if d := svc.Gate(rep, ""); d.Action != ActionAnnotate {
		t.Fatalf("clean report should annotate, got %q", d.Action)
	}
}

func TestVerify_DigestMismatch(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, testPublisher, testIssuer)

	// The attestation binds a DIFFERENT digest than the one served.
	otherHex := "0000000000000000000000000000000000000000000000000000000000000000"
	doc := buildProvenanceDoc(t, provOpts{
		leaf: leaf, leafKey: leafKey, filename: testFilename, sha256hex: otherHex, repo: testRepo,
	})
	mat := materialFromDoc(t, doc)

	svc := newService(t, Config{Roots: pool, Identities: trustedIdentities(), Action: ActionBlock}, mat)
	rep, err := svc.Verify(context.Background(), Artifact{Ecosystem: "pypi", Name: "widgets", Version: "1.0.0", Digest: testDigest})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.DigestMismatch {
		t.Fatalf("want digest mismatch, got %+v", rep)
	}
	if rep.Verified {
		t.Fatal("a mismatched attestation must not count as verified")
	}
	w := rep.Worst()
	if w == nil || w.Kind != KindDigestMismatch || w.Severity != SeverityCritical {
		t.Fatalf("want critical digest-mismatch finding, got %+v", w)
	}
	if d := svc.Gate(rep, ""); d.Action != ActionBlock {
		t.Fatalf("digest mismatch with action=block should block, got %q", d.Action)
	}
}

func TestVerify_Tampered(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, testPublisher, testIssuer)
	doc := buildProvenanceDoc(t, provOpts{
		leaf: leaf, leafKey: leafKey, filename: testFilename, sha256hex: testHex, repo: testRepo, tamper: true,
	})
	mat := materialFromDoc(t, doc)

	svc := newService(t, Config{Roots: pool, Identities: trustedIdentities()}, mat)
	rep, err := svc.Verify(context.Background(), Artifact{Ecosystem: "pypi", Name: "widgets", Version: "1.0.0", Digest: testDigest})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.Present || rep.Verified {
		t.Fatalf("tampered attestation: want present && !verified, got %+v", rep)
	}
	w := rep.Worst()
	if w == nil || w.Kind != KindUnverifiedAttestation {
		t.Fatalf("want unverified-attestation finding, got %+v", w)
	}
}

func TestVerify_UntrustedPublisher(t *testing.T) {
	// A valid signature but no configured trust root => cryptographically valid and
	// digest-bound (Verified) but not PublisherTrusted. With RequireTrustedPublisher
	// that is a finding.
	root, rootKey, _ := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, testPublisher, testIssuer)
	doc := buildProvenanceDoc(t, provOpts{
		leaf: leaf, leafKey: leafKey, filename: testFilename, sha256hex: testHex, repo: testRepo,
	})
	mat := materialFromDoc(t, doc)

	svc := newService(t, Config{RequireTrustedPublisher: true}, mat) // no Roots
	rep, err := svc.Verify(context.Background(), Artifact{Ecosystem: "pypi", Name: "widgets", Version: "1.0.0", Digest: testDigest})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.Verified || rep.PublisherTrusted {
		t.Fatalf("want verified && !publisherTrusted, got %+v", rep)
	}
	w := rep.Worst()
	if w == nil || w.Kind != KindUntrustedPublisher {
		t.Fatalf("want untrusted-publisher finding, got %+v", w)
	}
}

func TestVerify_MissingRequired(t *testing.T) {
	svc := newService(t, Config{RequireAttestation: true}, nil) // no material
	rep, err := svc.Verify(context.Background(), Artifact{Ecosystem: "pypi", Name: "widgets", Version: "1.0.0", Digest: testDigest})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Present {
		t.Fatal("want not present")
	}
	w := rep.Worst()
	if w == nil || w.Kind != KindMissingAttestation {
		t.Fatalf("want missing-attestation finding, got %+v", w)
	}
}

func TestVerify_Transparency(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, testPublisher, testIssuer)

	fake := rekor.NewFakeLog(nil)
	entry := fake.Append([]byte("widgets-attestation-leaf"))

	doc := buildProvenanceDoc(t, provOpts{
		leaf: leaf, leafKey: leafKey, filename: testFilename, sha256hex: testHex, repo: testRepo, logEntry: entry,
	})
	mat := materialFromDoc(t, doc)

	svc := newService(t, Config{
		Roots:                 pool,
		Identities:            trustedIdentities(),
		RekorKeys:             []crypto.PublicKey{fake.PublicKey()},
		RequireInclusionProof: true,
	}, mat)
	rep, err := svc.Verify(context.Background(), Artifact{Ecosystem: "pypi", Name: "widgets", Version: "1.0.0", Digest: testDigest})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.Verified || !rep.TransparencyVerified {
		t.Fatalf("want verified && transparencyVerified, got %+v", rep)
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("require-inclusion satisfied, want no findings, got %+v", rep.Findings)
	}
}

func TestVerify_RequireInclusionProofUnsatisfied(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, testPublisher, testIssuer)
	// No transparency entry, but inclusion proof required.
	doc := buildProvenanceDoc(t, provOpts{
		leaf: leaf, leafKey: leafKey, filename: testFilename, sha256hex: testHex, repo: testRepo,
	})
	mat := materialFromDoc(t, doc)
	svc := newService(t, Config{Roots: pool, Identities: trustedIdentities(), RequireInclusionProof: true}, mat)
	rep, _ := svc.Verify(context.Background(), Artifact{Ecosystem: "pypi", Name: "widgets", Version: "1.0.0", Digest: testDigest})
	w := rep.Worst()
	if w == nil || w.Kind != KindMissingTransparency {
		t.Fatalf("want missing-transparency finding, got %+v", w)
	}
}

func TestGate_ActionMapping(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, testPublisher, testIssuer)
	doc := buildProvenanceDoc(t, provOpts{leaf: leaf, leafKey: leafKey, filename: testFilename, sha256hex: testHex, repo: testRepo, tamper: true})
	mat := materialFromDoc(t, doc)

	for _, tc := range []struct {
		action Action
		want   Action
	}{
		{ActionAnnotate, ActionAnnotate},
		{ActionDowngrade, ActionDowngrade},
		{ActionBlock, ActionBlock},
	} {
		svc := newService(t, Config{Roots: pool, Identities: trustedIdentities(), Action: tc.action}, mat)
		rep, _ := svc.Verify(context.Background(), Artifact{Ecosystem: "pypi", Name: "widgets", Version: "1.0.0", Digest: testDigest})
		if d := svc.Gate(rep, ""); d.Action != tc.want {
			t.Fatalf("action %q: want decision %q, got %q", tc.action, tc.want, d.Action)
		}
	}
}

func TestGate_TenantOverride(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, testPublisher, testIssuer)
	doc := buildProvenanceDoc(t, provOpts{leaf: leaf, leafKey: leafKey, filename: testFilename, sha256hex: testHex, repo: testRepo, tamper: true})
	mat := materialFromDoc(t, doc)

	svc := newService(t, Config{
		Roots:      pool,
		Identities: trustedIdentities(),
		Action:     ActionAnnotate,
		Tenants:    map[string]TenantConfig{"strict": {Action: ActionBlock}},
	}, mat)
	rep, _ := svc.Verify(context.Background(), Artifact{Ecosystem: "pypi", Name: "widgets", Version: "1.0.0", Digest: testDigest})
	if d := svc.Gate(rep, ""); d.Action != ActionAnnotate {
		t.Fatalf("default tenant: want annotate, got %q", d.Action)
	}
	if d := svc.Gate(rep, "strict"); d.Action != ActionBlock {
		t.Fatalf("strict tenant: want block, got %q", d.Action)
	}
}

func TestVerifyError_FailOpenClosed(t *testing.T) {
	// Use a source that returns a hard (non-context) error.
	src := &fixedSource{err: errBoom}

	open, err := NewService(Config{Action: ActionBlock}, src, nil)
	if err != nil {
		t.Fatal(err)
	}
	rep, verr := open.Verify(context.Background(), Artifact{Ecosystem: "pypi", Name: "x", Version: "1", Digest: testDigest})
	if verr != nil {
		t.Fatalf("Verify: %v", verr)
	}
	if d := open.Gate(rep, ""); d.Action != ActionAnnotate {
		t.Fatalf("fail-open: want annotate, got %q", d.Action)
	}

	closed, _ := NewService(Config{Action: ActionBlock, FailOnError: true}, &fixedSource{err: errBoom}, nil)
	rep2, _ := closed.Verify(context.Background(), Artifact{Ecosystem: "pypi", Name: "x", Version: "1", Digest: testDigest})
	if d := closed.Gate(rep2, ""); d.Action != ActionBlock {
		t.Fatalf("fail-closed: want block, got %q", d.Action)
	}
}

func TestPyPISource_Fetch(t *testing.T) {
	root, rootKey, _ := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, testPublisher, testIssuer)
	prov := buildProvenanceDoc(t, provOpts{leaf: leaf, leafKey: leafKey, filename: testFilename, sha256hex: testHex, repo: testRepo})

	doer := &muxDoer{routes: map[string]cannedResp{
		"/pypi/widgets/1.0.0/json": {status: http.StatusOK, body: indexJSON(testFilename, testHex, true)},
		"/integrity/":              {status: http.StatusOK, body: prov},
	}}
	src := NewPyPISource(doer, "https://pypi.org", "")

	mat, err := src.Fetch(context.Background(), Artifact{Name: "widgets", Version: "1.0.0", Digest: testDigest})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if mat.IsEmpty() {
		t.Fatal("want material")
	}
	if mat.Attestations[0].Publisher.Kind != "GitHub" {
		t.Fatalf("publisher kind = %q", mat.Attestations[0].Publisher.Kind)
	}
}

func TestPyPISource_NoProvenance(t *testing.T) {
	doer := &muxDoer{routes: map[string]cannedResp{
		"/pypi/widgets/1.0.0/json": {status: http.StatusOK, body: indexJSON(testFilename, testHex, false)},
	}}
	src := NewPyPISource(doer, "https://pypi.org", "")
	mat, err := src.Fetch(context.Background(), Artifact{Name: "widgets", Version: "1.0.0", Digest: testDigest})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !mat.IsEmpty() {
		t.Fatalf("want empty material, got %+v", mat)
	}
}

func TestPyPISource_NotApplicable(t *testing.T) {
	src := NewPyPISource(&muxDoer{}, "", "")
	if _, err := src.Fetch(context.Background(), Artifact{Name: "", Version: ""}); err != ErrNotApplicable {
		t.Fatalf("want ErrNotApplicable, got %v", err)
	}
}
