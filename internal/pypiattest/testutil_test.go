package pypiattest

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
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/rekor"
)

// This file builds in-process PEP 740 provenance fixtures with REAL cryptography:
// a self-signed Fulcio-like root, a leaf certificate carrying the PyPI Trusted
// Publisher workflow as its SAN identity, and a DSSE-signed in-toto publish
// statement serialized into the PEP 740 {statement, signature} envelope exactly
// as PyPI serves it. The gate is exercised end-to-end without network access.

const (
	testIssuer = "https://token.actions.githubusercontent.com"
	// testPublisher is the Trusted Publisher workflow identity the leaf carries.
	testPublisher = "https://github.com/acme/widgets/.github/workflows/release.yml@refs/heads/main"
	testRepo      = "acme/widgets"
	testFilename  = "widgets-1.0.0-py3-none-any.whl"
	testHex       = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	testDigest    = "sha256:" + testHex
	predicatePyPI = "https://docs.pypi.org/attestations/publish/v1"
)

var fulcioOIDC = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}

// errBoom is a hard (non-context) error used to exercise the fail-open/closed
// posture on an infrastructure failure.
var errBoom = errBoomType("boom")

type errBoomType string

func (e errBoomType) Error() string { return string(e) }

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
	buf.WriteString(strconv.Itoa(len(payloadType)))
	buf.WriteByte(' ')
	buf.WriteString(payloadType)
	buf.WriteByte(' ')
	buf.WriteString(strconv.Itoa(len(payload)))
	buf.WriteByte(' ')
	buf.Write(payload)
	return buf.Bytes()
}

// pep740Statement builds a PyPI publish in-toto statement binding the sha256
// digest of the named distribution. It is deliberately NOT SLSA provenance (the
// predicate type is the PyPI publish attestation), matching real PEP 740.
func pep740Statement(filename, sha256hex string) []byte {
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": predicatePyPI,
		"subject": []map[string]any{
			{"name": filename, "digest": map[string]string{"sha256": sha256hex}},
		},
		"predicate": map[string]any{},
	}
	data, _ := json.Marshal(st)
	return data
}

// provOpts parameterizes a synthetic PEP 740 provenance object.
type provOpts struct {
	leaf      *x509.Certificate
	leafKey   *ecdsa.PrivateKey
	filename  string
	sha256hex string
	kind      string
	repo      string
	tamper    bool
	// logEntry, when set, is serialized into the attestation's transparency entries.
	logEntry *rekor.LogEntry
	// omitCert drops the signing certificate (keyed-attestation shape).
	omitCert bool
}

// buildProvenanceDoc builds a PEP 740 provenance object JSON exactly as PyPI's
// Integrity API serves it: a signing certificate, a {statement, signature}
// envelope over the in-toto publish statement, and optional transparency entries.
func buildProvenanceDoc(t *testing.T, o provOpts) []byte {
	t.Helper()
	statement := pep740Statement(o.filename, o.sha256hex)
	pae := dssePAE(inTotoPayloadType, statement)
	sig := signECDSA(t, o.leafKey, pae)
	if o.tamper {
		sig = append([]byte(nil), sig...)
		sig[len(sig)-1] ^= 0xff
	}
	vm := map[string]any{}
	if !o.omitCert {
		vm["certificate"] = base64.StdEncoding.EncodeToString(o.leaf.Raw)
	}
	if o.logEntry != nil {
		vm["transparency_entries"] = []any{encodeTransparencyEntry(o.logEntry)}
	}
	att := map[string]any{
		"version":               1,
		"verification_material": vm,
		"envelope": map[string]any{
			"statement": base64.StdEncoding.EncodeToString(statement),
			"signature": base64.StdEncoding.EncodeToString(sig),
		},
	}
	kind := o.kind
	if kind == "" {
		kind = "GitHub"
	}
	doc := map[string]any{
		"version": 1,
		"attestation_bundles": []map[string]any{
			{
				"publisher": map[string]any{
					"kind":       kind,
					"repository": o.repo,
					"workflow":   "release.yml",
				},
				"attestations": []map[string]any{att},
			},
		},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal provenance: %v", err)
	}
	return data
}

// encodeTransparencyEntry serializes a rekor.LogEntry into the PEP 740
// (Sigstore protobuf-JSON) transparency-entry shape, inverting the base64/hex
// re-encodings the parser applies, so the round trip verifies.
func encodeTransparencyEntry(e *rekor.LogEntry) map[string]any {
	hexToB64 := func(h string) string {
		b, _ := hex.DecodeString(h)
		return base64.StdEncoding.EncodeToString(b)
	}
	out := map[string]any{
		"logIndex":          strconv.FormatInt(e.LogIndex, 10),
		"logId":             map[string]any{"keyId": hexToB64(e.LogID)},
		"integratedTime":    strconv.FormatInt(e.IntegratedTime, 10),
		"inclusionPromise":  map[string]any{"signedEntryTimestamp": e.SET},
		"canonicalizedBody": e.Body,
	}
	if ip := e.InclusionProof; ip != nil {
		hashes := make([]string, len(ip.Hashes))
		for i, h := range ip.Hashes {
			hashes[i] = hexToB64(h)
		}
		out["inclusionProof"] = map[string]any{
			"logIndex":   strconv.FormatInt(ip.LogIndex, 10),
			"rootHash":   hexToB64(ip.RootHash),
			"treeSize":   strconv.FormatInt(ip.TreeSize, 10),
			"hashes":     hashes,
			"checkpoint": map[string]any{"envelope": ip.Checkpoint},
		}
	}
	return out
}

// materialFromDoc parses a provenance document into Material for direct service
// tests (bypassing HTTP).
func materialFromDoc(t *testing.T, doc []byte) *Material {
	t.Helper()
	atts, err := parseProvenance(doc)
	if err != nil {
		t.Fatalf("parseProvenance: %v", err)
	}
	if len(atts) == 0 {
		t.Fatal("no attestations parsed")
	}
	return &Material{Source: "pypi-attestations", Attestations: atts}
}

// fixedSource returns prebuilt material for any artifact.
type fixedSource struct {
	mat *Material
	err error
}

func (s *fixedSource) Fetch(ctx context.Context, art Artifact) (*Material, error) {
	return s.mat, s.err
}

// muxDoer routes requests to canned responses keyed by URL substring, so the
// PyPISource's two-hop fetch (index JSON then Integrity provenance) is exercised.
type muxDoer struct {
	routes map[string]cannedResp // matched by substring of the request URL
}

type cannedResp struct {
	status int
	body   []byte
}

func (m *muxDoer) Do(req *http.Request) (*http.Response, error) {
	for substr, resp := range m.routes {
		if bytes.Contains([]byte(req.URL.String()), []byte(substr)) {
			return &http.Response{
				StatusCode: resp.status,
				Body:       io.NopCloser(bytes.NewReader(resp.body)),
				Header:     make(http.Header),
			}, nil
		}
	}
	return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
}

// indexJSON builds a minimal PyPI JSON release record listing one file with the
// given sha256 and provenance presence.
func indexJSON(filename, sha256hex string, hasProvenance bool) []byte {
	var prov any
	if hasProvenance {
		prov = "https://pypi.org/integrity/widgets/1.0.0/" + filename + "/provenance"
	}
	rec := map[string]any{
		"urls": []map[string]any{
			{
				"filename":   filename,
				"digests":    map[string]string{"sha256": sha256hex},
				"provenance": prov,
			},
		},
	}
	data, _ := json.Marshal(rec)
	return data
}
