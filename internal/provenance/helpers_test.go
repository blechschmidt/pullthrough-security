package provenance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/url"
	"testing"
	"time"
)

// signingIdentity is a self-signed code-signing certificate plus its key, used to
// stand in for a Fulcio-issued keyless signing identity in tests. The certificate
// carries a URI SAN so signerIdentity extraction can be exercised.
type signingIdentity struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	der  []byte
}

// newSigningIdentity mints a fresh self-signed signing identity with the given
// SAN URI.
func newSigningIdentity(t *testing.T, sanURI string) *signingIdentity {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sigstore-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  true, // self-signed leaf doubling as its own root in tests
	}
	if sanURI != "" {
		u, err := url.Parse(sanURI)
		if err != nil {
			t.Fatalf("parsing SAN URI: %v", err)
		}
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return &signingIdentity{key: key, cert: cert, der: der}
}

// rootPool returns a cert pool trusting this identity (it is its own root).
func (s *signingIdentity) rootPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(s.cert)
	return pool
}

// statementFor builds an in-toto SLSA-provenance statement binding the given
// subject digest to a repository and commit.
func statementFor(subjectDigest, repoURL, commit string) []byte {
	algo, hex, _ := splitDigest(subjectDigest)
	stmt := map[string]any{
		"_type":         inTotoStatementV1,
		"predicateType": predicateSLSAv1,
		"subject": []map[string]any{
			{"name": "pkg:test", "digest": map[string]string{algo: hex}},
		},
		"predicate": map[string]any{
			"buildDefinition": map[string]any{
				"resolvedDependencies": []map[string]any{
					{"uri": "git+" + repoURL + "@" + commit, "digest": map[string]string{"gitCommit": commit}},
				},
			},
			"runDetails": map[string]any{
				"builder": map[string]any{"id": "https://github.com/actions/runner"},
			},
		},
	}
	b, _ := json.Marshal(stmt)
	return b
}

// signBundle wraps a statement payload in a signed DSSE envelope inside a
// Sigstore bundle (the format GitHub's attestation API and cosign emit).
func (s *signingIdentity) signBundle(t *testing.T, statement []byte) []byte {
	t.Helper()
	pae := dssePAE(dssePayloadType, statement)
	digest := sha256Sum(pae)
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, digest)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	bundle := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": map[string]any{
			"certificate": map[string]any{
				"rawBytes": base64.StdEncoding.EncodeToString(s.der),
			},
		},
		"dsseEnvelope": map[string]any{
			"payloadType": dssePayloadType,
			"payload":     base64.StdEncoding.EncodeToString(statement),
			"signatures": []map[string]any{
				{"sig": base64.StdEncoding.EncodeToString(sig)},
			},
		},
	}
	b, _ := json.Marshal(bundle)
	return b
}

// signEnvelope produces a bare DSSE envelope JSON (cosign layer blob form).
func (s *signingIdentity) signEnvelope(t *testing.T, statement []byte) []byte {
	t.Helper()
	pae := dssePAE(dssePayloadType, statement)
	digest := sha256Sum(pae)
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, digest)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	env := map[string]any{
		"payloadType": dssePayloadType,
		"payload":     base64.StdEncoding.EncodeToString(statement),
		"signatures":  []map[string]any{{"sig": base64.StdEncoding.EncodeToString(sig)}},
	}
	b, _ := json.Marshal(env)
	return b
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
