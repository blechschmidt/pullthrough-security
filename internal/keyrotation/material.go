// Package keyrotation is a unified rotation/expiry subsystem over the proxy's
// long-lived secrets and trust material: the audit-log HMAC/Merkle keys (Task
// 31), the cache key-encryption key (Task 141), outbound attestation signing
// keys (Tasks 46/135), upstream credentials resolved through the secrets
// provider (Task 133), and pinned TLS certificates/CAs (Task 128).
//
// It is deliberately decoupled from those subsystems: each registers a Source
// (a closure built in the wiring layer) that reports the current state of the
// material it owns — identifiers and timestamps only, never key bytes or secret
// values. The subsystem then (a) scans on a leader-gated schedule, grading each
// material's remaining lifetime and emitting warnings via the notification
// subsystem before material expires, (b) exposes a pullthrough_key_expiry_seconds
// gauge, and (c) drives the subset of rotations that can be performed safely in
// place (today, the cache KEK) through a dual-key overlap state machine that
// refuses an unsafe second rotation and suppresses drift/expiry false-positives
// while a staged rotation's overlap window is open.
package keyrotation

import (
	"context"
	"time"
)

// Kind classifies a piece of long-lived trust material. It is a stable,
// lowercase identifier used for grouping and display; it never carries secret
// state.
type Kind string

const (
	// KindAuditHMAC is the audit log's hash-chain HMAC secret (Task 31).
	KindAuditHMAC Kind = "audit-hmac"
	// KindAuditCheckpoint is the Merkle checkpoint (STH) signing key (Task 31).
	KindAuditCheckpoint Kind = "audit-checkpoint"
	// KindCacheKEK is the at-rest cache key-encryption key (Task 141). This is
	// the one material with a first-class, safe in-place rotation API.
	KindCacheKEK Kind = "cache-kek"
	// KindAttestSigner is the outbound attestation signing key (Tasks 46/135).
	KindAttestSigner Kind = "attest-signer"
	// KindUpstreamCred is an upstream credential resolved via the secrets
	// provider (Task 133).
	KindUpstreamCred Kind = "upstream-credential"
	// KindTLSPin is a pinned upstream certificate/CA fingerprint (Task 128).
	KindTLSPin Kind = "tls-pin"
	// KindTLSCert is a monitored x509 leaf certificate (carries a NotAfter).
	KindTLSCert Kind = "tls-cert"
	// KindCA is a monitored x509 CA certificate (carries a NotAfter).
	KindCA Kind = "ca-certificate"
)

// Material is the observed state of one piece of trust material at scan time. It
// is JSON-safe and redaction-safe: it carries only identifiers, timestamps, and
// rotation policy — never key bytes, certificate private material, or resolved
// secret values.
type Material struct {
	// ID is the stable, unique identifier for the material slot, e.g.
	// "cache.kek", "audit.checkpoint", or "upstream.github.token".
	ID string `json:"id"`
	// Kind classifies the material.
	Kind Kind `json:"kind"`
	// KeyID is the provider/key identifier if the material exposes one (e.g. the
	// KEK id, or the first 8 bytes of SHA-256 over a signing key's public DER).
	KeyID string `json:"keyId,omitempty"`
	// Description is a short human-readable label for operator-facing surfaces.
	Description string `json:"description,omitempty"`
	// NotAfter is a hard cryptographic expiry (e.g. an x509 NotAfter). It is zero
	// when the material has no inherent expiry (bare key pairs, HMAC secrets).
	NotAfter time.Time `json:"notAfter,omitempty"`
	// LastRotated is when the material was last rotated/installed, if known. It
	// anchors the RotateEvery policy.
	LastRotated time.Time `json:"lastRotated,omitempty"`
	// RotateEvery is a policy-driven maximum age after which the material should
	// be rotated even though it never cryptographically expires. Zero disables the
	// soft-expiry policy.
	RotateEvery time.Duration `json:"rotateEvery,omitempty"`
	// Overlap reports that a staged dual-key overlap window is currently active
	// for this slot: a previous key is intentionally still accepted alongside the
	// primary. It suppresses expiry/drift false-positives during a rotation.
	Overlap bool `json:"overlap,omitempty"`
	// PreviousKeyIDs lists prior key ids still accepted during an overlap window.
	PreviousKeyIDs []string `json:"previousKeyIds,omitempty"`
	// RotationSupported indicates a Rotator is registered for this material and an
	// automated in-place rotation is safe to drive via the admin API / ptctl.
	RotationSupported bool `json:"rotationSupported"`
}

// Source reports the current state of every piece of material it owns. A Source
// is consulted on each scan; a transient error is logged and counted but never
// fails the overall scan, so one unreadable source cannot blind the monitor to
// the others.
type Source interface {
	Scan(ctx context.Context) ([]Material, error)
}

// SourceFunc adapts a plain function to the Source interface, so the wiring layer
// can register a closure over a subsystem's snapshot without a bespoke type.
type SourceFunc func(ctx context.Context) ([]Material, error)

// Scan implements Source.
func (f SourceFunc) Scan(ctx context.Context) ([]Material, error) { return f(ctx) }

// Rotator performs an in-place rotation of a single material slot. Only material
// with a safe automated rotation path (today the cache KEK) registers one;
// everything else is rotated out-of-band and reports RotationSupported=false.
type Rotator interface {
	Rotate(ctx context.Context) (RotationOutcome, error)
}

// RotatorFunc adapts a plain function to the Rotator interface.
type RotatorFunc func(ctx context.Context) (RotationOutcome, error)

// Rotate implements Rotator.
func (f RotatorFunc) Rotate(ctx context.Context) (RotationOutcome, error) { return f(ctx) }

// RotationOutcome summarizes a single rotation attempt. It is redaction-safe: it
// carries only counts, timestamps, and (non-secret) key identifiers.
type RotationOutcome struct {
	MaterialID string `json:"materialId"`
	// Supported is false when the material has no automated in-place rotation; the
	// Detail then describes the out-of-band procedure.
	Supported bool `json:"supported"`
	// Performed is true when a rotation actually ran and completed.
	Performed       bool      `json:"performed"`
	NewPrimaryKeyID string    `json:"newPrimaryKeyId,omitempty"`
	StartedAt       time.Time `json:"startedAt,omitempty"`
	Duration        string    `json:"duration,omitempty"`
	// Scanned/Rewrapped are populated for KEK-style re-wrap rotations.
	Scanned   int    `json:"scanned,omitempty"`
	Rewrapped int    `json:"rewrapped,omitempty"`
	Detail    string `json:"detail,omitempty"`
}
