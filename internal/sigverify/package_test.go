package sigverify

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/policy"
)

// fakeDoer returns a canned HTTP response for any request.
type fakeDoer struct {
	status int
	body   []byte
}

func (f *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: f.status,
		Body:       io.NopCloser(bytes.NewReader(f.body)),
		Header:     make(http.Header),
	}, nil
}

func TestNPMSourceVerifiesPublishAttestation(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	npmIdentity := "https://github.com/acme/widgets/.github/workflows/publish.yml@refs/heads/main"
	leaf, leafKey := makeLeaf(t, root, rootKey, npmIdentity, testIssuer)

	pkgDigest := "sha512:abc" // npm attestations bind a sha512 subject
	// Build an in-toto statement binding the package digest.
	payload := []byte(`{"_type":"` + inTotoStatementV1 + `","predicateType":"` + predicateSLSAv1 +
		`","subject":[{"name":"pkg:npm/acme/widgets@1.0.0","digest":{"sha512":"abc"}}],"predicate":{}}`)
	att := dsseAttestation(t, leafKey, leaf, payload)

	// Wrap the envelope + certificate in a Sigstore bundle, as npm serves it.
	bundle := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
		"verificationMaterial": map[string]any{
			"certificate": map[string]any{
				"rawBytes": base64.StdEncoding.EncodeToString(leaf.Raw),
			},
		},
		"dsseEnvelope": att.Envelope,
	}
	doc := map[string]any{
		"attestations": []map[string]any{
			{"predicateType": predicateSLSAv1, "bundle": bundle},
		},
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	src := NewNPMSource(&fakeDoer{status: 200, body: body}, "https://registry.npmjs.org")
	svc, err := NewService(Config{
		RequireSignature: true,
		Roots:            pool,
		Identities:       []Identity{{Issuer: testIssuer, SubjectPattern: `^https://github\.com/acme/.*`}},
	}, src, nil)
	if err != nil {
		t.Fatal(err)
	}

	report, err := svc.Verify(context.Background(), Artifact{Ecosystem: "npm", Name: "@acme/widgets", Version: "1.0.0", Digest: pkgDigest})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.VerifiedSignature {
		t.Fatalf("expected verified npm attestation, findings=%+v", report.Findings)
	}
	if d := svc.Gate(report); d.Action != policy.ActionAllow {
		t.Fatalf("expected allow, got %s: %s", d.Action, d.Reason)
	}
}

func TestNPMSourceNoAttestationsIsNil(t *testing.T) {
	src := NewNPMSource(&fakeDoer{status: 404}, "https://registry.npmjs.org")
	m, err := src.Fetch(context.Background(), Artifact{Ecosystem: "npm", Name: "x", Version: "1.0.0", Digest: "sha512:z"})
	if err != nil {
		t.Fatalf("404 should not error: %v", err)
	}
	if m != nil {
		t.Fatalf("expected nil material for 404, got %+v", m)
	}
}

func TestNPMSourceRequiresNameVersion(t *testing.T) {
	src := NewNPMSource(&fakeDoer{status: 200, body: []byte("{}")}, "https://registry.npmjs.org")
	if _, err := src.Fetch(context.Background(), Artifact{Ecosystem: "npm", Name: "x"}); err == nil {
		t.Fatal("expected ErrNotApplicable without a version")
	}
}

func TestParsePublicKeyPEMRoundTrip(t *testing.T) {
	key := newKey(t)
	pemStr := publicKeyPEM(t, key)
	pub, err := ParsePublicKeyPEM([]byte(pemStr))
	if err != nil {
		t.Fatalf("ParsePublicKeyPEM: %v", err)
	}
	// Verify the parsed key validates a signature made with the private key.
	msg := []byte("hello")
	sig := signECDSA(t, key, msg)
	if !verifyRawSignature(pub, msg, sig) {
		t.Fatal("parsed public key failed to verify a signature")
	}
}
