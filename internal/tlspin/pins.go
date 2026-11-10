package tlspin

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// Kind is the category of a certificate pin: which part of the peer's presented
// certificate chain the pin's SHA-256 hash is computed over.
type Kind int

const (
	// KindSPKI pins the SHA-256 of the leaf certificate's DER-encoded
	// SubjectPublicKeyInfo (the RFC 7469 / HPKP pin). It survives a certificate
	// re-issue that keeps the same key pair, so it is the recommended default.
	KindSPKI Kind = iota
	// KindCert pins the SHA-256 of the full DER-encoded leaf certificate. It is
	// the strictest form and must be rotated on every re-issue.
	KindCert
	// KindCA pins the SHA-256 of the full DER encoding of a certificate that must
	// appear somewhere in the peer's (verified, else presented) chain — typically
	// an intermediate or root CA. It survives leaf rotation under the same CA.
	KindCA
)

// String renders the kind for diagnostics and the audit/metrics vocabulary.
func (k Kind) String() string {
	switch k {
	case KindSPKI:
		return "spki-sha256"
	case KindCert:
		return "cert-sha256"
	case KindCA:
		return "ca-sha256"
	default:
		return "unknown"
	}
}

// Pin is a single compiled certificate pin: a kind plus the 32-byte SHA-256 the
// peer must match. The original spec string is retained for diagnostics.
type Pin struct {
	Kind Kind
	Hash [32]byte
	Spec string
}

// ParsePins compiles a list of pin specs into Pins. Blank entries are skipped.
// Each spec is "<kind>:<hash>" where kind is spki-sha256, cert-sha256, or
// ca-sha256 (the RFC 7469 "sha256//<base64>" syntax is accepted as an alias for
// spki-sha256). The hash is 64 hex characters or the base64 encoding of 32 raw
// bytes (standard or URL alphabet, with or without padding).
func ParsePins(specs []string) ([]Pin, error) {
	out := make([]Pin, 0, len(specs))
	for _, raw := range specs {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		p, err := parsePin(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func parsePin(s string) (Pin, error) {
	var kind Kind
	var payload string
	switch {
	case strings.HasPrefix(strings.ToLower(s), "sha256//"):
		kind, payload = KindSPKI, s[len("sha256//"):]
	case hasPrefixFold(s, "spki-sha256:"), hasPrefixFold(s, "pin-sha256:"):
		kind, payload = KindSPKI, afterColon(s)
	case hasPrefixFold(s, "cert-sha256:"):
		kind, payload = KindCert, afterColon(s)
	case hasPrefixFold(s, "ca-sha256:"):
		kind, payload = KindCA, afterColon(s)
	default:
		return Pin{}, fmt.Errorf("tlspin: unrecognized pin %q: want one of spki-sha256:/cert-sha256:/ca-sha256:<hash> (or sha256//<base64>)", s)
	}
	h, err := decodeHash(payload)
	if err != nil {
		return Pin{}, fmt.Errorf("tlspin: pin %q: %w", s, err)
	}
	return Pin{Kind: kind, Hash: h, Spec: s}, nil
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

func afterColon(s string) string {
	if i := strings.IndexByte(s, ':'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// decodeHash decodes a 32-byte SHA-256 from hex (64 chars) or base64 (standard
// or URL alphabet, padded or not).
func decodeHash(s string) ([32]byte, error) {
	s = strings.TrimSpace(s)
	var out [32]byte
	if len(s) == 64 {
		if b, err := hex.DecodeString(s); err == nil {
			copy(out[:], b)
			return out, nil
		}
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == 32 {
			copy(out[:], b)
			return out, nil
		}
	}
	return out, fmt.Errorf("not a valid SHA-256 (want 64 hex chars or base64 of 32 bytes), got %d chars", len(s))
}

// Presented summarizes the pins the peer actually presented, so an operator can
// copy the correct value when staging a rotation. The hashes are of the leaf
// certificate only.
type Presented struct {
	SPKISHA256 string // base64(sha256(leaf.RawSubjectPublicKeyInfo)) — the RFC 7469 pin
	CertSHA256 string // hex(sha256(leaf.Raw))
}

// LeafSPKIPin returns the canonical spki-sha256 pin spec for a leaf certificate,
// suitable for pasting into config. It is exported for tooling and tests.
func LeafSPKIPin(leaf *x509.Certificate) string {
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return "spki-sha256:" + base64.StdEncoding.EncodeToString(sum[:])
}

// LeafCertPin returns the canonical cert-sha256 pin spec for a leaf certificate.
func LeafCertPin(leaf *x509.Certificate) string {
	sum := sha256.Sum256(leaf.Raw)
	return "cert-sha256:" + hex.EncodeToString(sum[:])
}

// CertPin returns the canonical ca-sha256 pin spec for a (CA) certificate.
func CertPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return "ca-sha256:" + hex.EncodeToString(sum[:])
}

// matchPins reports whether the peer's presented certificate state satisfies any
// of pins, and returns the presented leaf hashes for diagnostics. A connection
// is accepted when ANY pin matches (supporting key rotation by listing both the
// current and the next pin). For KindCA pins it prefers the verified chains
// (populated by normal verification) and falls back to the raw presented chain
// when verification was skipped (InsecureSkipVerify) so a leaf/SPKI pin can still
// anchor trust on its own.
func matchPins(cs tls.ConnectionState, pins []Pin) (matched bool, present Presented) {
	if len(cs.PeerCertificates) == 0 {
		return false, Presented{}
	}
	leaf := cs.PeerCertificates[0]
	leafSPKI := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	leafCert := sha256.Sum256(leaf.Raw)
	present = Presented{
		SPKISHA256: base64.StdEncoding.EncodeToString(leafSPKI[:]),
		CertSHA256: hex.EncodeToString(leafCert[:]),
	}

	chains := cs.VerifiedChains
	if len(chains) == 0 {
		chains = [][]*x509.Certificate{cs.PeerCertificates}
	}

	for _, p := range pins {
		switch p.Kind {
		case KindSPKI:
			if p.Hash == leafSPKI {
				return true, present
			}
		case KindCert:
			if p.Hash == leafCert {
				return true, present
			}
		case KindCA:
			for _, chain := range chains {
				for _, c := range chain {
					if sha256.Sum256(c.Raw) == p.Hash {
						return true, present
					}
				}
			}
		}
	}
	return false, present
}
