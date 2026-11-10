package sigverify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/cloudflare/circl/sign"
)

// TrustBundle is a portable, integrity-verified container for the gate's trust
// material — Fulcio root certificates, Rekor log public keys, operator-configured
// signing keys, and the allowed keyless-identity policy. For air-gapped
// deployments an operator builds it on a connected host and transfers it to the
// sealed instance, exactly as the air-gapped cache mirror (internal/mirror) is
// transferred. Its design mirrors the mirror bundle's: a deterministic,
// canonical-JSON manifest whose SHA-256 digest is the bundle's stable identity,
// transferred out-of-band and verified on load.
type TrustBundle struct {
	// FormatVersion is the on-disk schema version; loaders refuse a version they
	// do not understand.
	FormatVersion int `json:"formatVersion"`
	// Generator identifies the producing tool, for auditability.
	Generator string `json:"generator"`
	// CreatedAt is when the bundle was produced.
	CreatedAt time.Time `json:"createdAt"`
	// Roots holds Fulcio root CA certificates as PEM, for keyless chain trust.
	Roots []string `json:"roots,omitempty"`
	// RekorKeys holds Rekor transparency-log public keys as PEM.
	RekorKeys []string `json:"rekorKeys,omitempty"`
	// Keys holds named public keys (PEM) for keyed verification.
	Keys []TrustBundleKey `json:"keys,omitempty"`
	// Identities holds the allowed keyless signer identity policy.
	Identities []TrustBundleIdentity `json:"identities,omitempty"`
}

// TrustBundleKey is a named public key carried in a trust bundle.
type TrustBundleKey struct {
	Name string `json:"name"`
	PEM  string `json:"pem"`
}

// TrustBundleIdentity is an allowed keyless signer policy entry.
type TrustBundleIdentity struct {
	Issuer         string `json:"issuer,omitempty"`
	SubjectPattern string `json:"subjectPattern,omitempty"`
}

const (
	// TrustBundleFormatVersion is the on-disk schema version.
	TrustBundleFormatVersion = 1
	// trustBundleGenerator labels the producing tool in the manifest.
	trustBundleGenerator = "pullthrough-sigverify"
)

// sortBundle orders the bundle's slices deterministically so the canonical
// encoding (and thus the digest) is stable for a given logical content.
func (b *TrustBundle) sortBundle() {
	sort.Strings(b.Roots)
	sort.Strings(b.RekorKeys)
	sort.Slice(b.Keys, func(i, j int) bool {
		if b.Keys[i].Name != b.Keys[j].Name {
			return b.Keys[i].Name < b.Keys[j].Name
		}
		return b.Keys[i].PEM < b.Keys[j].PEM
	})
	sort.Slice(b.Identities, func(i, j int) bool {
		if b.Identities[i].Issuer != b.Identities[j].Issuer {
			return b.Identities[i].Issuer < b.Identities[j].Issuer
		}
		return b.Identities[i].SubjectPattern < b.Identities[j].SubjectPattern
	})
}

// canonicalJSON encodes the bundle deterministically (slices sorted first), so
// the byte output is stable for a given logical content.
func (b *TrustBundle) canonicalJSON() ([]byte, error) {
	b.sortBundle()
	data, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("sigverify: encoding trust bundle: %w", err)
	}
	return data, nil
}

// Digest returns the "sha256:<hex>" digest of the bundle's canonical encoding —
// its stable identity and integrity root, transferred out-of-band and verified
// on load.
func (b *TrustBundle) Digest() (string, error) {
	data, err := b.canonicalJSON()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Write serializes the bundle (canonical JSON) to w.
func (b *TrustBundle) Write(w io.Writer) error {
	data, err := b.canonicalJSON()
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// LoadTrustBundle reads and validates a trust bundle, optionally verifying its
// canonical digest against an out-of-band expected value ("sha256:<hex>"; empty
// to skip). An unrecognized format version is rejected.
func LoadTrustBundle(r io.Reader, expectedDigest string) (*TrustBundle, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("sigverify: reading trust bundle: %w", err)
	}
	var b TrustBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("sigverify: decoding trust bundle: %w", err)
	}
	if b.FormatVersion != TrustBundleFormatVersion {
		return nil, fmt.Errorf("sigverify: unsupported trust bundle format version %d (want %d)", b.FormatVersion, TrustBundleFormatVersion)
	}
	if expectedDigest != "" {
		got, derr := b.Digest()
		if derr != nil {
			return nil, derr
		}
		if got != expectedDigest {
			return nil, fmt.Errorf("sigverify: trust bundle digest mismatch: got %s, want %s", got, expectedDigest)
		}
	}
	return &b, nil
}

// Material converts a trust bundle into the verifier's in-memory trust material:
// a certificate pool of roots, parsed Rekor keys, parsed named keys, and the
// identity policy. It is used by the offline/air-gapped configuration path.
func (b *TrustBundle) Material() (roots *x509.CertPool, rekorKeys []crypto.PublicKey, keys []TrustedKey, identities []Identity, err error) {
	if len(b.Roots) > 0 {
		roots = x509.NewCertPool()
		for _, p := range b.Roots {
			if !roots.AppendCertsFromPEM([]byte(p)) {
				return nil, nil, nil, nil, fmt.Errorf("sigverify: trust bundle contains an unparseable root certificate")
			}
		}
	}
	for _, p := range b.RekorKeys {
		pub, perr := ParsePublicKeyPEM([]byte(p))
		if perr != nil {
			return nil, nil, nil, nil, fmt.Errorf("sigverify: trust bundle rekor key: %w", perr)
		}
		rekorKeys = append(rekorKeys, pub)
	}
	for _, k := range b.Keys {
		pub, perr := ParsePublicKeyPEM([]byte(k.PEM))
		if perr != nil {
			return nil, nil, nil, nil, fmt.Errorf("sigverify: trust bundle key %q: %w", k.Name, perr)
		}
		keys = append(keys, TrustedKey{Name: k.Name, Public: pub})
	}
	for _, id := range b.Identities {
		identities = append(identities, Identity{Issuer: id.Issuer, SubjectPattern: id.SubjectPattern})
	}
	return roots, rekorKeys, keys, identities, nil
}

// ParsePublicKeyPEM parses a PEM-encoded public key (PKIX) or certificate,
// returning the contained public key. It accepts ECDSA, RSA, and Ed25519 keys.
func ParsePublicKeyPEM(pemData []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	switch block.Type {
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return assertPublicKey(pub)
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return assertPublicKey(cert.PublicKey)
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	case pqcPEMType:
		// Post-quantum / hybrid public key (ML-DSA, SLH-DSA, hybrid), carrying its
		// scheme in the block header (Task 151).
		return parsePQCPublicKey(block)
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}

// assertPublicKey confirms the parsed key is a supported signature-verification
// key type.
func assertPublicKey(pub crypto.PublicKey) (crypto.PublicKey, error) {
	switch pub.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
		return pub, nil
	case sign.PublicKey:
		// Post-quantum / hybrid key (ML-DSA, SLH-DSA, hybrid composite).
		return pub, nil
	default:
		return nil, fmt.Errorf("unsupported public key type %T", pub)
	}
}
