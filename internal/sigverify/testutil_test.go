package sigverify

import (
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
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"
)

// This file builds in-process fixture signatures (no external test data files):
// a self-signed Fulcio-like root, leaf certificates carrying a SAN identity and
// an OIDC-issuer extension, and helpers that produce cosign simple-signing
// signatures and DSSE/SLSA attestations over them. The cryptography is real, so
// the verifier is exercised end-to-end.

const (
	testDigest   = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	testIssuer   = "https://token.actions.githubusercontent.com"
	testIdentity = "https://github.com/acme/widgets/.github/workflows/release.yml@refs/tags/v1.0.0"
	testRepo     = "https://github.com/acme/widgets"
	testCommit   = "0123456789abcdef0123456789abcdef01234567"
)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

// makeRoot creates a self-signed CA certificate and a pool trusting it.
func makeRoot(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-fulcio-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
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

// makeLeaf creates a leaf certificate signed by root, carrying the given SAN URI
// identity and Fulcio OIDC-issuer extension.
func makeLeaf(t *testing.T, root *x509.Certificate, rootKey *ecdsa.PrivateKey, identity, issuer string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key := newKey(t)

	issuerExt := pkix.Extension{Id: oidFulcioIssuerV2}
	b, err := asn1.Marshal(issuer)
	if err != nil {
		t.Fatalf("marshal issuer: %v", err)
	}
	issuerExt.Value = b

	u, err := url.Parse(identity)
	if err != nil {
		t.Fatalf("parse identity uri: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: "test-signer"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(24 * time.Hour),
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

// simpleSigningPayloadJSON builds a cosign simple-signing payload binding digest.
func simpleSigningPayloadJSON(t *testing.T, digest string) []byte {
	t.Helper()
	var p simpleSigningPayload
	p.Critical.Image.DockerManifestDigest = digest
	p.Critical.Type = simpleSigningType
	p.Critical.Identity.DockerReference = "registry/acme/widgets"
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return data
}

// signECDSA signs message (its SHA-256 digest) with key, returning ASN.1 DER.
func signECDSA(t *testing.T, key *ecdsa.PrivateKey, message []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(message)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sig
}

// keylessSignature builds a cosign keyless image signature over digest.
func keylessSignature(t *testing.T, signKey *ecdsa.PrivateKey, cert *x509.Certificate, digest string) SimpleSignature {
	t.Helper()
	payload := simpleSigningPayloadJSON(t, digest)
	return SimpleSignature{
		Payload:   payload,
		Signature: signECDSA(t, signKey, payload),
		Cert:      cert,
	}
}

// keyedSignature builds a keyed cosign image signature over digest (no cert).
func keyedSignature(t *testing.T, signKey *ecdsa.PrivateKey, digest string) SimpleSignature {
	t.Helper()
	payload := simpleSigningPayloadJSON(t, digest)
	return SimpleSignature{Payload: payload, Signature: signECDSA(t, signKey, payload)}
}

// slsaPayload builds an in-toto SLSA provenance statement binding digest.
func slsaPayload(t *testing.T, digest, repo, commit string) []byte {
	t.Helper()
	algo, hex, _ := splitDigest(digest)
	st := map[string]any{
		"_type":         inTotoStatementV1,
		"predicateType": predicateSLSAv1,
		"subject": []map[string]any{
			{"name": "image", "digest": map[string]string{algo: hex}},
		},
		"predicate": map[string]any{
			"buildDefinition": map[string]any{
				"resolvedDependencies": []map[string]any{
					{"uri": "git+" + repo + "@refs/tags/v1.0.0", "digest": map[string]string{"gitCommit": commit}},
				},
			},
			"runDetails": map[string]any{
				"builder": map[string]any{"id": "https://github.com/actions/runner"},
			},
		},
	}
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	return data
}

func splitDigest(d string) (algo, hex string, ok bool) {
	for i := 0; i < len(d); i++ {
		if d[i] == ':' {
			return d[:i], d[i+1:], true
		}
	}
	return "", "", false
}

// dsseAttestation builds a DSSE attestation over the given in-toto payload,
// keyless (cert != nil) or keyed.
func dsseAttestation(t *testing.T, signKey *ecdsa.PrivateKey, cert *x509.Certificate, payload []byte) DSSEAttestation {
	t.Helper()
	pae := dssePAE(dssePayloadType, payload)
	env := &Envelope{
		PayloadType: dssePayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []EnvelopeSignature{
			{Sig: base64.StdEncoding.EncodeToString(signECDSA(t, signKey, pae))},
		},
	}
	return DSSEAttestation{Envelope: env, Cert: cert}
}

// makeRekorBundle builds a cosign Rekor bundle whose SET verifies against
// rekorKey.
func makeRekorBundle(t *testing.T, rekorKey *ecdsa.PrivateKey) *rekorBundle {
	t.Helper()
	b := &rekorBundle{}
	b.Payload.Body = "eyJhcGlWZXJzaW9uIjoiMC4wLjEifQ==" // arbitrary base64 body
	b.Payload.IntegratedTime = 1700000000
	b.Payload.LogIndex = 42
	b.Payload.LogID = "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"
	set := signECDSA(t, rekorKey, b.canonicalPayload())
	b.SignedEntryTimestamp = base64.StdEncoding.EncodeToString(set)
	return b
}

func rootPoolPEM(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

func publicKeyPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// fakeSource returns fixed material (or an error) for any artifact.
type fakeSource struct {
	material *Material
	err      error
}

func (f *fakeSource) Fetch(ctx context.Context, art Artifact) (*Material, error) {
	return f.material, f.err
}
