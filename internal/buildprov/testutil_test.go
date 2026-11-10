package buildprov

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// This file builds in-process fixture provenance bundles with REAL cryptography
// (a self-signed Fulcio-like root, a leaf certificate carrying the publishing CI
// workflow as its SAN identity, and a DSSE-signed SLSA provenance statement
// wrapped in a Sigstore bundle exactly as npm serves it), so the gate is
// exercised end-to-end without network access. It mirrors the signature gate's
// testutil so the two stay consistent.

const (
	testIssuer = "https://token.actions.githubusercontent.com"
	// testWorkflow is the npm publish workflow identity the leaf cert carries.
	testWorkflow = "https://github.com/acme/widgets/.github/workflows/publish.yml@refs/heads/main"
	testRepo     = "https://github.com/acme/widgets"
	testCommit   = "0123456789abcdef0123456789abcdef01234567"
	testDigest   = "sha512:" + "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
)

// fulcioOIDC is the Fulcio OIDC-issuer extension OID (DER-string form).
var fulcioOIDC = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func makeRoot(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-fulcio-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return cert, key, pool
}

func makeLeaf(t *testing.T, root *x509.Certificate, rootKey *ecdsa.PrivateKey, identity, issuer string) (*x509.Certificate, *ecdsa.PrivateKey) {
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
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: "test-signer"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(10 * 365 * 24 * time.Hour),
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

func signECDSA(t *testing.T, key *ecdsa.PrivateKey, message []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(message)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sig
}

// dssePAE reproduces the DSSE pre-authentication encoding the signature binds.
func dssePAE(payloadType string, payload []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("DSSEv1 ")
	buf.WriteString(itoa(len(payloadType)))
	buf.WriteByte(' ')
	buf.WriteString(payloadType)
	buf.WriteByte(' ')
	buf.WriteString(itoa(len(payload)))
	buf.WriteByte(' ')
	buf.Write(payload)
	return buf.Bytes()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// slsaStatement builds an npm-flavoured SLSA v1 provenance statement binding
// digest and naming repo+commit in resolvedDependencies (npm's layout).
func slsaStatement(digest, repo, commit string) []byte {
	algo, hex, _ := cut(digest, ':')
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": []map[string]any{
			{"name": "pkg:npm/acme/widgets@1.0.0", "digest": map[string]string{algo: hex}},
		},
		"predicate": map[string]any{
			"buildDefinition": map[string]any{
				"buildType": "https://github.com/npm/cli/gha/v2",
				"resolvedDependencies": []map[string]any{
					{"uri": "git+" + repo + "@refs/heads/main", "digest": map[string]string{"gitCommit": commit}},
				},
			},
			"runDetails": map[string]any{
				"builder": map[string]any{"id": "https://github.com/actions/runner/github-hosted"},
			},
		},
	}
	data, _ := json.Marshal(st)
	return data
}

func cut(s string, sep byte) (a, b string, ok bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

// npmBundleDoc builds the npm attestations response document: a Sigstore bundle
// (leaf cert + DSSE envelope over the SLSA statement) wrapped as npm serves it.
// When tamper is true the signature is corrupted (present but unverifiable).
func npmBundleDoc(t *testing.T, leaf *x509.Certificate, leafKey *ecdsa.PrivateKey, digest, repo, commit string, tamper bool) []byte {
	t.Helper()
	payload := slsaStatement(digest, repo, commit)
	pae := dssePAE("application/vnd.in-toto+json", payload)
	sig := signECDSA(t, leafKey, pae)
	if tamper {
		sig = append([]byte(nil), sig...)
		sig[len(sig)-1] ^= 0xff
	}
	env := map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(payload),
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

// fixedSource returns prebuilt material for any artifact.
type fixedSource struct {
	mat *Material
	err error
}

func (s *fixedSource) Fetch(ctx context.Context, art Artifact) (*Material, error) {
	return s.mat, s.err
}

// materialFromDoc parses a provider document into Material for direct service
// tests (bypassing HTTP).
func materialFromDoc(t *testing.T, source string, doc []byte) *Material {
	t.Helper()
	atts, err := ParseAttestations(doc)
	if err != nil {
		t.Fatalf("ParseAttestations: %v", err)
	}
	if len(atts) == 0 {
		t.Fatal("no attestations parsed")
	}
	return &Material{Source: source, Attestations: atts}
}
