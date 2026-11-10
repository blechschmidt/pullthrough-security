package rekor

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
)

// Verifier verifies Rekor log entries: the Merkle inclusion proof (that the
// entry is in a tree with the proof's root hash) and the Signed Entry Timestamp
// (that a trusted log key witnessed the entry). It is immutable after
// construction and safe for concurrent use. A nil *Verifier verifies nothing.
type Verifier struct {
	keys []crypto.PublicKey
}

// NewVerifier builds a Verifier from a set of trusted Rekor log public keys
// (used to check Signed Entry Timestamps). An empty key set is allowed: SET
// verification will always report false, which callers that require a SET treat
// as a failure.
func NewVerifier(keys []crypto.PublicKey) *Verifier {
	return &Verifier{keys: append([]crypto.PublicKey(nil), keys...)}
}

// NewVerifierFromPEM builds a Verifier from one or more PEM blobs each holding a
// PUBLIC KEY (or a certificate). It is the config-facing constructor.
func NewVerifierFromPEM(pems ...[]byte) (*Verifier, error) {
	var keys []crypto.PublicKey
	for i, p := range pems {
		k, err := parsePublicKeyPEM(p)
		if err != nil {
			return nil, fmt.Errorf("rekor: parsing public key[%d]: %w", i, err)
		}
		keys = append(keys, k)
	}
	return NewVerifier(keys), nil
}

// HasKeys reports whether any trusted log key is configured (SET verification is
// possible).
func (v *Verifier) HasKeys() bool { return v != nil && len(v.keys) > 0 }

// Verification is the outcome of checking a log entry.
type Verification struct {
	// InclusionVerified reports the Merkle audit path reconstructed to the proof's
	// signed root hash. False when no proof was present or it did not validate.
	InclusionVerified bool
	// SETVerified reports the Signed Entry Timestamp validated against a trusted
	// Rekor log public key. False when no SET/keys were present or it did not
	// validate.
	SETVerified bool
	// LeafMatched reports that, when a subject leaf preimage was supplied, the
	// entry body hashed to the proof's leaf. It guards against a valid proof for a
	// DIFFERENT entry being presented alongside an unrelated body.
	LeafMatched bool
	// Err carries the first verification problem encountered, for diagnostics.
	Err string
}

// Options tunes a single VerifyEntry call.
type Options struct {
	// RequireInclusionProof fails verification unless the Merkle inclusion proof
	// validated.
	RequireInclusionProof bool
	// RequireSET fails verification unless the SET validated against a trusted key.
	RequireSET bool
}

// OK reports whether the verification satisfied opts: every required check
// passed and no error was recorded.
func (r Verification) OK(opts Options) bool {
	if r.Err != "" {
		return false
	}
	if opts.RequireInclusionProof && !r.InclusionVerified {
		return false
	}
	if opts.RequireSET && !r.SETVerified {
		return false
	}
	return true
}

// VerifyEntry verifies a log entry's inclusion proof and SET. It is pure (no
// I/O) so it runs identically on freshly-submitted entries and on entries
// presented by an inbound artifact. A nil Verifier verifies nothing and returns
// a zero Verification.
func (v *Verifier) VerifyEntry(entry *LogEntry) Verification {
	var out Verification
	if v == nil || entry == nil {
		out.Err = "rekor: nil verifier or entry"
		return out
	}

	// --- Signed Entry Timestamp ---------------------------------------------
	if entry.SET != "" && len(v.keys) > 0 {
		if ok, err := v.verifySET(entry); ok {
			out.SETVerified = true
		} else if err != "" && out.Err == "" {
			out.Err = err
		}
	}

	// --- Merkle inclusion proof ---------------------------------------------
	if entry.InclusionProof != nil {
		leafMatched, err := v.verifyInclusionProof(entry)
		out.LeafMatched = leafMatched
		if err == "" {
			out.InclusionVerified = true
		} else if out.Err == "" {
			out.Err = err
		}
	}
	return out
}

// verifySET reconstructs the canonical SET payload and checks the log signature
// over it against each configured key. The canonical payload is the entry's
// (body, integratedTime, logID, logIndex) serialized as canonical JSON with
// sorted keys — the exact bytes Rekor signs, matching the cosign bundle format
// the inbound sigverify gate already understands.
func (v *Verifier) verifySET(entry *LogEntry) (bool, string) {
	set, err := base64.StdEncoding.DecodeString(entry.SET)
	if err != nil {
		return false, "rekor: signed entry timestamp is not valid base64"
	}
	msg := canonicalSETPayload(entry)
	for _, k := range v.keys {
		if verifyRawSignature(k, msg, set) {
			return true, ""
		}
	}
	return false, "rekor: signed entry timestamp did not verify against any trusted log key"
}

// verifyInclusionProof validates the Merkle audit path to the signed root and,
// when the entry carries a body, confirms the body hashes to the proof leaf.
func (v *Verifier) verifyInclusionProof(entry *LogEntry) (leafMatched bool, errMsg string) {
	p := entry.InclusionProof
	root, err := hex.DecodeString(strings.TrimSpace(p.RootHash))
	if err != nil || len(root) != hashSize {
		return false, "rekor: inclusion proof root hash is not a 32-byte hex value"
	}
	hashes, herr := decodeHexHashes(p.Hashes)
	if herr != "" {
		return false, herr
	}
	if p.TreeSize <= 0 || p.LogIndex < 0 {
		return false, "rekor: inclusion proof has an invalid tree size or index"
	}

	// Derive the Merkle leaf hash from the entry body when present. Without a
	// body we cannot bind the proof to this entry's content, so a proof-only
	// check is rejected (a valid proof for an arbitrary leaf proves nothing about
	// this entry).
	if strings.TrimSpace(entry.Body) == "" {
		return false, "rekor: entry has no body; cannot bind the inclusion proof to its content"
	}
	leafBytes, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(entry.Body))
	if derr != nil {
		return false, "rekor: entry body is not valid base64"
	}
	leaf := hashLeaf(leafBytes)

	if err := verifyInclusion(uint64(p.LogIndex), uint64(p.TreeSize), leaf, hashes, root); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// canonicalSETPayload reproduces the byte sequence the Rekor SET is computed
// over: the entry metadata serialized as canonical JSON with keys sorted
// (body, integratedTime, logID, logIndex). Encoding it by hand (rather than via
// a canonical-JSON library) matches Rekor's marshaling and avoids a dependency;
// it is byte-identical to the inbound sigverify gate's cosign-bundle logic.
func canonicalSETPayload(entry *LogEntry) []byte {
	type canon struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogID          string `json:"logID"`
		LogIndex       int64  `json:"logIndex"`
	}
	out, _ := json.Marshal(canon{
		Body:           entry.Body,
		IntegratedTime: entry.IntegratedTime,
		LogID:          entry.LogID,
		LogIndex:       entry.LogIndex,
	})
	return out
}

func decodeHexHashes(in []string) ([][]byte, string) {
	out := make([][]byte, 0, len(in))
	for i, h := range in {
		b, err := hex.DecodeString(strings.TrimSpace(h))
		if err != nil {
			return nil, fmt.Sprintf("rekor: inclusion proof hash[%d] is not valid hex", i)
		}
		out = append(out, b)
	}
	return out, ""
}

// verifyRawSignature verifies a signature over a message, dispatching on key
// type. ECDSA and RSA sign the SHA-256 digest; Ed25519 signs the message
// directly. ECDSA signatures are ASN.1 DER (Rekor's form).
func verifyRawSignature(pub crypto.PublicKey, message, sig []byte) bool {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(message)
		return ecdsa.VerifyASN1(key, digest[:], sig)
	case *rsa.PublicKey:
		digest := sha256.Sum256(message)
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig) == nil
	case ed25519.PublicKey:
		return ed25519.Verify(key, message, sig)
	default:
		return false
	}
}

// parsePublicKeyPEM parses a PEM PUBLIC KEY block, or a CERTIFICATE block
// (using its SubjectPublicKey), into a crypto.PublicKey.
func parsePublicKeyPEM(pemData []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	switch block.Type {
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return cert.PublicKey, nil
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}
