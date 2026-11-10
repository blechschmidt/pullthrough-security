package malfeed

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"time"
)

// BundleVersion is the schema version of the offline bundle envelope. It is
// embedded so a future format change can be detected and rejected cleanly.
const BundleVersion = 1

// bundlePayload is the signed inner document of an offline bundle: the loaded
// known-malicious entries plus provenance. Its canonical JSON bytes are exactly
// what the signature covers, so the importer can re-verify them byte-for-byte.
type bundlePayload struct {
	Version   int     `json:"version"`
	CreatedAt string  `json:"createdAt"`
	Source    string  `json:"source"`
	Count     int     `json:"count"`
	Entries   []Entry `json:"entries"`
}

// SignedBundle is the on-disk/transport envelope: the canonical payload bytes,
// the Ed25519 signature over them, the signer's public key, and a content
// digest. It is the artifact moved into an air-gapped environment.
type SignedBundle struct {
	// Payload is the base64-encoded canonical JSON of the signed bundlePayload,
	// retained verbatim so verification uses the exact signed bytes. Base64 (rather
	// than an embedded JSON object) keeps the bytes byte-stable through the
	// pretty-printed envelope, which would otherwise re-indent a raw JSON payload
	// and invalidate the signature.
	Payload string `json:"payload"`
	// Algorithm is always "ed25519" in this version.
	Algorithm string `json:"algorithm"`
	// PublicKey is the base64-encoded raw (32-byte) Ed25519 public key of the
	// signer, for display and for self-verification when no trusted key is pinned.
	PublicKey string `json:"publicKey"`
	// Signature is the base64-encoded Ed25519 signature over Payload.
	Signature string `json:"signature"`
	// Digest is "sha256:<hex>" of Payload, an out-of-band integrity check.
	Digest string `json:"digest"`
}

// ExportBundle serializes entries into a signed offline bundle. createdAt is
// recorded verbatim (pass a fixed time for reproducible output); source labels
// the export provenance. The entries are sorted deterministically so the same
// input always produces byte-identical, signature-stable output.
func ExportBundle(entries []Entry, source string, createdAt time.Time, signer ed25519.PrivateKey) ([]byte, error) {
	if len(signer) != ed25519.PrivateKeySize {
		return nil, errors.New("malfeed: export requires a valid Ed25519 private key")
	}
	// Normalize and sort via a Matcher so exported entries are canonical and
	// de-duplicated, then emit in stable order.
	canonical := NewMatcher(entries).Entries()
	sortEntries(canonical)

	payload := bundlePayload{
		Version:   BundleVersion,
		CreatedAt: createdAt.UTC().Format(time.RFC3339),
		Source:    source,
		Count:     len(canonical),
		Entries:   canonical,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("malfeed: marshal bundle payload: %w", err)
	}

	sig := ed25519.Sign(signer, payloadBytes)
	pub := signer.Public().(ed25519.PublicKey)
	digest := sha256.Sum256(payloadBytes)

	env := SignedBundle{
		Payload:   base64.StdEncoding.EncodeToString(payloadBytes),
		Algorithm: "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Signature: base64.StdEncoding.EncodeToString(sig),
		Digest:    fmt.Sprintf("sha256:%x", digest),
	}
	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("malfeed: marshal bundle envelope: %w", err)
	}
	return out, nil
}

// ImportBundle verifies and decodes a signed offline bundle. When trusted is
// non-nil the signature must verify against it (authenticity: the bundle was
// produced by the holder of the corresponding private key). When trusted is nil
// the signature is verified against the embedded public key (integrity only: the
// bundle is internally consistent and untampered, but its origin is unpinned) —
// the caller is responsible for deciding whether that is acceptable.
func ImportBundle(data []byte, trusted ed25519.PublicKey) ([]Entry, error) {
	var env SignedBundle
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("malfeed: parse bundle envelope: %w", err)
	}
	if env.Algorithm != "ed25519" {
		return nil, fmt.Errorf("malfeed: unsupported bundle algorithm %q", env.Algorithm)
	}
	if len(env.Payload) == 0 {
		return nil, errors.New("malfeed: bundle has an empty payload")
	}

	payloadBytes, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("malfeed: decode bundle payload: %w", err)
	}

	// Integrity: the recomputed digest must match the claimed one.
	digest := sha256.Sum256(payloadBytes)
	if got := fmt.Sprintf("sha256:%x", digest); env.Digest != "" && got != env.Digest {
		return nil, fmt.Errorf("malfeed: bundle digest mismatch (claimed %s, computed %s)", env.Digest, got)
	}

	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		return nil, fmt.Errorf("malfeed: decode bundle signature: %w", err)
	}

	verifyKey := trusted
	if verifyKey == nil {
		embedded, derr := base64.StdEncoding.DecodeString(env.PublicKey)
		if derr != nil {
			return nil, fmt.Errorf("malfeed: decode bundle public key: %w", derr)
		}
		if len(embedded) != ed25519.PublicKeySize {
			return nil, errors.New("malfeed: bundle public key is not a valid Ed25519 key")
		}
		verifyKey = ed25519.PublicKey(embedded)
	}
	if len(verifyKey) != ed25519.PublicKeySize {
		return nil, errors.New("malfeed: trusted key is not a valid Ed25519 public key")
	}
	if !ed25519.Verify(verifyKey, payloadBytes, sig) {
		return nil, errors.New("malfeed: bundle signature verification failed")
	}

	var payload bundlePayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("malfeed: parse bundle payload: %w", err)
	}
	if payload.Version != BundleVersion {
		return nil, fmt.Errorf("malfeed: unsupported bundle version %d (want %d)", payload.Version, BundleVersion)
	}
	// Stamp the source so imported entries are attributable even if the payload
	// omitted per-entry sources.
	for i := range payload.Entries {
		if payload.Entries[i].Source == "" {
			payload.Entries[i].Source = bundleSource(payload.Source)
		}
	}
	return payload.Entries, nil
}

// bundleSource returns a stable source label for imported entries.
func bundleSource(s string) string {
	if s == "" {
		return "bundle"
	}
	return "bundle:" + s
}

// sortEntries orders entries deterministically for reproducible bundles.
func sortEntries(entries []Entry) {
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		an, bn := normalizeName(a.Ecosystem, a.Name), normalizeName(b.Ecosystem, b.Name)
		if an != bn {
			return an < bn
		}
		return a.ID < b.ID
	})
}

// LoadSignerPEM parses an Ed25519 private key from PEM (PKCS#8). It is used by
// the offline-export CLI.
func LoadSignerPEM(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("malfeed: no PEM block found in private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("malfeed: parse PKCS#8 private key: %w", err)
	}
	ed, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("malfeed: private key is %T, want Ed25519", key)
	}
	return ed, nil
}

// LoadVerifierPEM parses an Ed25519 public key from PEM (PKIX). It is used to
// pin the trusted signer for offline-bundle import.
func LoadVerifierPEM(pemBytes []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("malfeed: no PEM block found in public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("malfeed: parse PKIX public key: %w", err)
	}
	ed, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("malfeed: public key is %T, want Ed25519", key)
	}
	return ed, nil
}
