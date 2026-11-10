package attestbundle

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/rekor"
)

// randReader is the entropy source for signing; a package-level var so tests can
// stub it for deterministic Ed25519 signatures if needed.
var randReader io.Reader = rand.Reader

// Bundle is the proxy's signed attestation for one served artifact: the DSSE
// envelope plus the metadata a store/endpoint needs to index and serve it. The
// envelope is the portable, verifiable unit; the surrounding fields are
// derived/denormalized for lookup and never part of the signed material.
type Bundle struct {
	// Envelope is the signed DSSE envelope wrapping the in-toto statement.
	Envelope Envelope `json:"envelope"`
	// Digest is the SHA-256 of the canonical envelope JSON ("sha256:<hex>"). This
	// is the value embedded in the audit log: it commits the tamper-evident chain
	// to the exact bytes of the attestation the proxy produced.
	Digest string `json:"digest"`
	// SubjectDigest is the served artifact's content digest ("<algo>:<hex>"), the
	// key the OCI referrers endpoint looks the bundle up by.
	SubjectDigest string `json:"subjectDigest,omitempty"`
	// PredicateType restates the in-toto predicate type for indexing/filtering.
	PredicateType string `json:"predicateType"`
	// Coordinate / Tenant restate the artifact identity for the admin/CLI lookup.
	Coordinate string `json:"coordinate,omitempty"`
	Tenant     string `json:"tenant,omitempty"`
	// KeyID is the signing key's identifier (also inside each Signature).
	KeyID string `json:"keyId,omitempty"`
	// CreatedAt is when the bundle was produced (UTC), for the store's recency
	// ordering and the admin view. Not part of the signed statement.
	CreatedAt time.Time `json:"createdAt"`
	// Rekor is the transparency-log pointer recorded when the bundle was submitted
	// to a Sigstore Rekor log (Task 142): the log index and inclusion-proof /
	// SET verification status. Nil when submission is disabled or has not completed.
	// It is populated asynchronously, so a bundle value is never mutated in place:
	// the submit path records a fresh copy carrying the pointer.
	Rekor *rekor.Pointer `json:"rekor,omitempty"`
}

// withRekor returns a shallow copy of the bundle carrying the given
// transparency-log pointer. Copy-on-write keeps the originally-returned bundle
// immutable, so the async submit path can publish the enriched bundle into the
// store without racing readers of the first one.
func (b *Bundle) withRekor(p *rekor.Pointer) *Bundle {
	cp := *b
	cp.Rekor = p
	return &cp
}

// newBundle assembles a Bundle from a signed envelope and the statement it wraps,
// computing the envelope digest. createdAt stamps the non-signed metadata.
func newBundle(env Envelope, stmt Statement, createdAt time.Time) (*Bundle, error) {
	raw, err := canonicalJSON(env)
	if err != nil {
		return nil, fmt.Errorf("attestbundle: marshaling envelope: %w", err)
	}
	b := &Bundle{
		Envelope:      env,
		Digest:        digestBytes(raw),
		PredicateType: stmt.PredicateType,
		Coordinate:    stmt.Predicate.Artifact.Coordinate,
		Tenant:        stmt.Predicate.Artifact.Tenant,
		KeyID:         stmt.Predicate.Attester.KeyID,
		CreatedAt:     createdAt.UTC(),
	}
	if len(stmt.Subject) > 0 {
		for algo, hexv := range stmt.Subject[0].Digest {
			b.SubjectDigest = algo + ":" + hexv
			break
		}
	}
	if b.Coordinate == "" {
		b.Coordinate = stmt.Predicate.Artifact.Name
	}
	return b, nil
}

// Statement decodes and returns the in-toto statement carried by the bundle's
// envelope. It does NOT verify the signature; use VerifyEnvelope for that.
func (b *Bundle) Statement() (Statement, error) {
	payload, err := decodeEnvelopePayload(b.Envelope)
	if err != nil {
		return Statement{}, err
	}
	return decodeStatement(payload)
}

// EnvelopeJSON returns the canonical JSON of the DSSE envelope — the portable
// artifact a downstream consumer verifies and the bytes b.Digest commits to.
func (b *Bundle) EnvelopeJSON() ([]byte, error) {
	return canonicalJSON(b.Envelope)
}

func decodeEnvelopePayload(env Envelope) ([]byte, error) {
	if env.Payload == "" {
		return nil, fmt.Errorf("attestbundle: envelope has empty payload")
	}
	return base64.StdEncoding.DecodeString(env.Payload)
}

func decodeStatement(payload []byte) (Statement, error) {
	var stmt Statement
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return Statement{}, fmt.Errorf("attestbundle: decoding in-toto statement: %w", err)
	}
	return stmt, nil
}
