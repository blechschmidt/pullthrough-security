package sigverify

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/policy"
)

// newService is a test convenience that wires a Service over fixed material.
func newService(t *testing.T, cfg Config, material *Material) *Service {
	t.Helper()
	svc, err := NewService(cfg, &fakeSource{material: material}, nil)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func artifact() Artifact {
	return Artifact{Ecosystem: "docker", Name: "acme/widgets", Digest: testDigest}
}

func TestKeylessSignatureTrustedAllows(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, testIdentity, testIssuer)

	material := &Material{
		Source:     "oci-cosign",
		Signatures: []SimpleSignature{keylessSignature(t, leafKey, leaf, testDigest)},
	}
	svc := newService(t, Config{
		RequireSignature: true,
		Roots:            pool,
		Identities:       []Identity{{Issuer: testIssuer, SubjectPattern: `^https://github\.com/acme/.*`}},
	}, material)

	report, err := svc.Verify(context.Background(), artifact())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.VerifiedSignature {
		t.Fatalf("expected verified signature, got findings %+v", report.Findings)
	}
	d := svc.Gate(report)
	if d.Action != policy.ActionAllow {
		t.Fatalf("expected allow, got %s: %s", d.Action, d.Reason)
	}
}

func TestKeylessUntrustedRootBlocks(t *testing.T) {
	// Signer chains to a root the gate does not trust (different pool).
	root, rootKey, _ := makeRoot(t)
	_, _, otherPool := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, testIdentity, testIssuer)

	material := &Material{Signatures: []SimpleSignature{keylessSignature(t, leafKey, leaf, testDigest)}}
	svc := newService(t, Config{
		RequireSignature: true,
		Roots:            otherPool,
		Identities:       []Identity{{Issuer: testIssuer}},
	}, material)

	report, _ := svc.Verify(context.Background(), artifact())
	if report.VerifiedSignature {
		t.Fatal("expected untrusted chain to not verify")
	}
	d := svc.Gate(report)
	if d.Action != policy.ActionBlock {
		t.Fatalf("expected block, got %s", d.Action)
	}
	if d.Code != string(KindUntrustedIdentity) {
		t.Fatalf("expected untrusted-identity, got %s", d.Code)
	}
}

func TestKeylessIdentityPolicyMismatchBlocks(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, testIdentity, testIssuer)

	material := &Material{Signatures: []SimpleSignature{keylessSignature(t, leafKey, leaf, testDigest)}}
	svc := newService(t, Config{
		RequireSignature: true,
		Roots:            pool,
		// Allowed identity restricted to a different org.
		Identities: []Identity{{Issuer: testIssuer, SubjectPattern: `^https://github\.com/evilcorp/.*`}},
	}, material)

	report, _ := svc.Verify(context.Background(), artifact())
	if report.VerifiedSignature {
		t.Fatal("expected identity mismatch to not be trusted")
	}
	if d := svc.Gate(report); d.Action != policy.ActionBlock || d.Code != string(KindUntrustedIdentity) {
		t.Fatalf("expected untrusted-identity block, got %s/%s", d.Action, d.Code)
	}
}

func TestTamperedSignatureIsInvalid(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, testIdentity, testIssuer)

	sig := keylessSignature(t, leafKey, leaf, testDigest)
	sig.Signature[len(sig.Signature)-1] ^= 0xff // corrupt the signature

	svc := newService(t, Config{RequireSignature: true, Roots: pool}, &Material{Signatures: []SimpleSignature{sig}})
	report, _ := svc.Verify(context.Background(), artifact())
	if report.VerifiedSignature {
		t.Fatal("tampered signature must not verify")
	}
	d := svc.Gate(report)
	if d.Code != string(KindInvalidSignature) {
		t.Fatalf("expected invalid-signature, got %s", d.Code)
	}
	if d.Action != policy.ActionBlock {
		t.Fatalf("expected block for invalid signature, got %s", d.Action)
	}
}

func TestDigestBindingMismatchRejected(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, testIdentity, testIssuer)

	// Signature binds a different digest than the artifact being served.
	otherDigest := "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	material := &Material{Signatures: []SimpleSignature{keylessSignature(t, leafKey, leaf, otherDigest)}}
	svc := newService(t, Config{RequireSignature: true, Roots: pool, Identities: []Identity{{Issuer: testIssuer}}}, material)

	report, _ := svc.Verify(context.Background(), artifact())
	if report.VerifiedSignature {
		t.Fatal("a signature binding a different digest must not verify the artifact")
	}
}

func TestMissingSignatureRequiredBlocks(t *testing.T) {
	svc := newService(t, Config{RequireSignature: true}, nil)
	report, err := svc.Verify(context.Background(), artifact())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	d := svc.Gate(report)
	if d.Action != policy.ActionBlock || d.Code != string(KindMissingSignature) {
		t.Fatalf("expected missing-signature block, got %s/%s", d.Action, d.Code)
	}
}

func TestMissingSignatureAdvisoryAllowsWhenNotRequired(t *testing.T) {
	svc := newService(t, Config{RequireSignature: false}, nil)
	report, _ := svc.Verify(context.Background(), artifact())
	if d := svc.Gate(report); d.Action != policy.ActionAllow {
		t.Fatalf("expected allow when signatures not required, got %s", d.Action)
	}
}

func TestAdvisoryModeWarnsInsteadOfBlocks(t *testing.T) {
	svc := newService(t, Config{RequireSignature: true, Action: policy.ActionWarn}, nil)
	report, _ := svc.Verify(context.Background(), artifact())
	if d := svc.Gate(report); d.Action != policy.ActionWarn {
		t.Fatalf("expected advisory warn, got %s", d.Action)
	}
}

func TestKeyedSignatureTrustedAllows(t *testing.T) {
	key := newKey(t)
	material := &Material{Signatures: []SimpleSignature{keyedSignature(t, key, testDigest)}}
	svc := newService(t, Config{
		RequireSignature: true,
		Keys:             []TrustedKey{{Name: "release-key", Public: crypto.PublicKey(&key.PublicKey)}},
	}, material)

	report, _ := svc.Verify(context.Background(), artifact())
	if !report.VerifiedSignature {
		t.Fatalf("expected keyed signature to verify, findings %+v", report.Findings)
	}
	if d := svc.Gate(report); d.Action != policy.ActionAllow {
		t.Fatalf("expected allow, got %s", d.Action)
	}
}

func TestKeyedSignatureWrongKeyBlocks(t *testing.T) {
	key := newKey(t)
	other := newKey(t)
	material := &Material{Signatures: []SimpleSignature{keyedSignature(t, key, testDigest)}}
	svc := newService(t, Config{
		RequireSignature: true,
		Keys:             []TrustedKey{{Name: "wrong", Public: &other.PublicKey}},
	}, material)

	report, _ := svc.Verify(context.Background(), artifact())
	if report.VerifiedSignature {
		t.Fatal("keyed signature must not verify against the wrong key")
	}
	if d := svc.Gate(report); d.Code != string(KindUntrustedKey) {
		t.Fatalf("expected untrusted-key, got %s", d.Code)
	}
}

func TestAttestationVerifiedAndSourceExtracted(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, testIdentity, testIssuer)

	att := dsseAttestation(t, leafKey, leaf, slsaPayload(t, testDigest, testRepo, testCommit))
	material := &Material{Source: "oci-referrers", Attestations: []DSSEAttestation{att}}
	svc := newService(t, Config{
		RequireSignature:   true,
		RequireAttestation: true,
		Roots:              pool,
		Identities:         []Identity{{Issuer: testIssuer, SubjectPattern: `^https://github\.com/acme/.*`}},
	}, material)

	report, _ := svc.Verify(context.Background(), artifact())
	if !report.VerifiedAttestation {
		t.Fatalf("expected verified SLSA attestation, findings %+v", report.Findings)
	}
	if len(report.Attestations) != 1 {
		t.Fatalf("expected 1 attestation result, got %d", len(report.Attestations))
	}
	got := report.Attestations[0]
	if got.RepositoryURL != testRepo || got.CommitSHA != testCommit {
		t.Fatalf("source ref not extracted: repo=%q commit=%q", got.RepositoryURL, got.CommitSHA)
	}
	if d := svc.Gate(report); d.Action != policy.ActionAllow {
		t.Fatalf("expected allow, got %s: %s", d.Action, d.Reason)
	}
}

func TestRequireAttestationWithOnlySignatureFlags(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, testIdentity, testIssuer)

	material := &Material{Signatures: []SimpleSignature{keylessSignature(t, leafKey, leaf, testDigest)}}
	svc := newService(t, Config{
		RequireSignature:   true,
		RequireAttestation: true,
		WarnSeverity:       SeverityMedium,
		FailSeverity:       SeverityHigh,
		Roots:              pool,
		Identities:         []Identity{{Issuer: testIssuer}},
	}, material)

	report, _ := svc.Verify(context.Background(), artifact())
	worst := report.Worst()
	if worst == nil || worst.Kind != KindMissingAttestation {
		t.Fatalf("expected missing-attestation finding, got %+v", report.Findings)
	}
	// medium severity -> warn (below high fail threshold).
	if d := svc.Gate(report); d.Action != policy.ActionWarn {
		t.Fatalf("expected warn for missing attestation at medium severity, got %s", d.Action)
	}
}

func TestRekorProofRequired(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, testIdentity, testIssuer)
	rekorKey := newKey(t)

	base := Config{
		RequireSignature:  true,
		RequireRekorProof: true,
		Roots:             pool,
		Identities:        []Identity{{Issuer: testIssuer}},
		RekorKeys:         []crypto.PublicKey{&rekorKey.PublicKey},
	}

	// Without a Rekor bundle: missing-rekor-proof.
	noProof := keylessSignature(t, leafKey, leaf, testDigest)
	svc := newService(t, base, &Material{Signatures: []SimpleSignature{noProof}})
	report, _ := svc.Verify(context.Background(), artifact())
	if d := svc.Gate(report); d.Code != string(KindMissingRekorProof) {
		t.Fatalf("expected missing-rekor-proof, got %s", d.Code)
	}

	// With a Rekor bundle whose SET verifies: allowed.
	withProof := keylessSignature(t, leafKey, leaf, testDigest)
	withProof.RekorBundle = makeRekorBundle(t, rekorKey)
	svc2 := newService(t, base, &Material{Signatures: []SimpleSignature{withProof}})
	report2, _ := svc2.Verify(context.Background(), artifact())
	if !report2.Signatures[0].RekorVerified {
		t.Fatal("expected Rekor SET to verify")
	}
	if d := svc2.Gate(report2); d.Action != policy.ActionAllow {
		t.Fatalf("expected allow with verified Rekor proof, got %s: %s", d.Action, d.Reason)
	}
}

func TestFetchErrorFailOpenAndClosed(t *testing.T) {
	fetchErr := errors.New("registry unreachable")

	// Fail-open (default): warn, served.
	open, err := NewService(Config{RequireSignature: true}, &fakeSource{err: fetchErr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	report, _ := open.Verify(context.Background(), artifact())
	if d := open.Gate(report); d.Action != policy.ActionWarn {
		t.Fatalf("fail-open should warn, got %s", d.Action)
	}

	// Fail-closed: block.
	closed, err := NewService(Config{RequireSignature: true, FailOnError: true}, &fakeSource{err: fetchErr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	report2, _ := closed.Verify(context.Background(), artifact())
	if d := closed.Gate(report2); d.Action != policy.ActionBlock {
		t.Fatalf("fail-closed should block, got %s", d.Action)
	}
}

func TestNotApplicableWhenNoSource(t *testing.T) {
	svc, err := NewService(Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Verify(context.Background(), artifact()); !errors.Is(err, ErrNotApplicable) {
		t.Fatalf("expected ErrNotApplicable, got %v", err)
	}
}

func TestMultiSourceRoutingAndAliases(t *testing.T) {
	docker := &fakeSource{material: &Material{Source: "docker"}}
	npm := &fakeSource{material: &Material{Source: "npm"}}
	ms := NewMultiSource(map[string]Source{"docker": docker, "npm": npm})

	// "oci" aliases to "docker".
	m, err := ms.Fetch(context.Background(), Artifact{Ecosystem: "oci", Name: "x", Digest: testDigest})
	if err != nil || m.Source != "docker" {
		t.Fatalf("oci should route to docker source: %v %+v", err, m)
	}
	// Unknown ecosystem -> not applicable.
	if _, err := ms.Fetch(context.Background(), Artifact{Ecosystem: "cargo"}); !errors.Is(err, ErrNotApplicable) {
		t.Fatalf("expected ErrNotApplicable for cargo, got %v", err)
	}
}

func TestResultCacheReused(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, testIdentity, testIssuer)
	material := &Material{Signatures: []SimpleSignature{keylessSignature(t, leafKey, leaf, testDigest)}}
	svc := newService(t, Config{RequireSignature: true, Roots: pool, Identities: []Identity{{Issuer: testIssuer}}}, material)

	if _, err := svc.Verify(context.Background(), artifact()); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Verify(context.Background(), artifact()); err != nil {
		t.Fatal(err)
	}
	if got := svc.Metrics().CacheHits; got != 1 {
		t.Fatalf("expected 1 cache hit, got %d", got)
	}
	if got := svc.Metrics().Verifications; got != 1 {
		t.Fatalf("expected 1 verification (second served from cache), got %d", got)
	}
}

func TestInvalidIdentityPatternRejected(t *testing.T) {
	_, err := NewVerifier(x509.NewCertPool(), []Identity{{SubjectPattern: "("}}, nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid identity regular expression")
	}
}
