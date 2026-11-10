package keyrotation

import (
	"errors"
	"time"
)

// Rotation state-machine errors.
var (
	// ErrRotationInFlight is returned by Begin when a prior rotation is still
	// within its overlap window: starting another would leave three live keys and
	// make drift/expiry evaluation ambiguous.
	ErrRotationInFlight = errors.New("keyrotation: a previous rotation is still within its overlap window")
	// ErrSameKey is returned by Begin when the new key id equals the current
	// primary — a no-op rotation that must not consume an overlap slot.
	ErrSameKey = errors.New("keyrotation: new key id equals the current primary")
	// ErrEmptyKeyID is returned by Begin when the new key id is empty.
	ErrEmptyKeyID = errors.New("keyrotation: key id must not be empty")
)

// Phase names where a logical key slot sits in a staged dual-key rotation.
type Phase string

const (
	// PhaseUninitialized is a slot that has never had a primary key.
	PhaseUninitialized Phase = "uninitialized"
	// PhaseStable is a single active key with no retained previous keys.
	PhaseStable Phase = "stable"
	// PhaseOverlap is an active rotation: a new primary is in place and at least
	// one previous key is still accepted because its overlap window is still open.
	PhaseOverlap Phase = "overlap"
	// PhaseDraining is the window-elapsed-but-not-yet-pruned state: every previous
	// key's overlap window has closed and they should be retired (via Prune).
	PhaseDraining Phase = "draining"
)

// PreviousKey is a prior primary key still tracked during (and just after) an
// overlap window.
type PreviousKey struct {
	KeyID string `json:"keyId"`
	// RetiredAt is when the key stopped being primary (the rotation that replaced
	// it).
	RetiredAt time.Time `json:"retiredAt"`
	// ExpiresAt is RetiredAt + the overlap window: after this instant the key is
	// no longer accepted and should be pruned.
	ExpiresAt time.Time `json:"expiresAt"`
}

// OverlapState models a staged dual-key rotation for a single logical key slot.
// A rotation installs a new primary while continuing to accept the prior key(s)
// for a bounded overlap window, so in-flight artifacts signed/encrypted under
// the old key still verify. Once the window elapses the prior keys are retired.
//
// The state machine enforces one safety invariant — a second rotation cannot
// begin while a prior one is still inside its overlap window — so an operator
// (or an automated schedule) cannot accidentally stack rotations into key sprawl
// that would make drift detection ambiguous. It is a pure, deterministic value
// driven by an injected clock; it holds no secret material.
type OverlapState struct {
	PrimaryKeyID  string        `json:"primaryKeyId"`
	PreviousKeys  []PreviousKey `json:"previousKeys,omitempty"`
	RotatedAt     time.Time     `json:"rotatedAt,omitempty"`
	OverlapWindow time.Duration `json:"overlapWindow"`
}

// NewOverlapState constructs a state for a slot whose current primary is
// primaryKeyID (which may be empty for a not-yet-initialized slot) with the given
// overlap window. A non-positive window is clamped to zero, which makes every
// rotation take effect immediately with no overlap.
func NewOverlapState(primaryKeyID string, window time.Duration) *OverlapState {
	if window < 0 {
		window = 0
	}
	return &OverlapState{PrimaryKeyID: primaryKeyID, OverlapWindow: window}
}

// Phase reports where the slot sits at time now.
func (s *OverlapState) Phase(now time.Time) Phase {
	if s == nil || s.PrimaryKeyID == "" {
		return PhaseUninitialized
	}
	if s.InOverlap(now) {
		return PhaseOverlap
	}
	if len(s.PreviousKeys) > 0 {
		return PhaseDraining
	}
	return PhaseStable
}

// InOverlap reports whether any previous key is still within its overlap window
// at now (i.e. still accepted).
func (s *OverlapState) InOverlap(now time.Time) bool {
	if s == nil {
		return false
	}
	for _, pk := range s.PreviousKeys {
		if pk.ExpiresAt.After(now) {
			return true
		}
	}
	return false
}

// ActiveKeyIDs returns the primary plus every previous key still accepted at now,
// in order (primary first).
func (s *OverlapState) ActiveKeyIDs(now time.Time) []string {
	if s == nil || s.PrimaryKeyID == "" {
		return nil
	}
	out := []string{s.PrimaryKeyID}
	for _, pk := range s.PreviousKeys {
		if pk.ExpiresAt.After(now) {
			out = append(out, pk.KeyID)
		}
	}
	return out
}

// LivePreviousKeyIDs returns just the previous key ids still accepted at now.
func (s *OverlapState) LivePreviousKeyIDs(now time.Time) []string {
	if s == nil {
		return nil
	}
	var out []string
	for _, pk := range s.PreviousKeys {
		if pk.ExpiresAt.After(now) {
			out = append(out, pk.KeyID)
		}
	}
	return out
}

// CanBegin reports whether a rotation may start at now without violating the
// single-in-flight invariant. A slot is free to rotate when it is not within an
// overlap window (elapsed-but-unpruned previous keys do not block a new
// rotation, since Begin prunes them first).
func (s *OverlapState) CanBegin(now time.Time) bool {
	return s == nil || !s.InOverlap(now)
}

// Begin starts a rotation to newKeyID at time now. It first prunes any previous
// keys whose overlap window has already elapsed, then:
//
//   - returns ErrEmptyKeyID if newKeyID is empty;
//   - returns ErrSameKey if newKeyID equals the current primary;
//   - returns ErrRotationInFlight if a previous key is still within its overlap
//     window (an unsafe stacked rotation);
//
// otherwise it demotes the current primary to a previous key with
// ExpiresAt = now + OverlapWindow, installs newKeyID as primary, and records
// RotatedAt = now. The pruned key ids are returned for the caller to log/audit.
func (s *OverlapState) Begin(newKeyID string, now time.Time) (pruned []string, err error) {
	if newKeyID == "" {
		return nil, ErrEmptyKeyID
	}
	pruned = s.Prune(now)
	if newKeyID == s.PrimaryKeyID {
		return pruned, ErrSameKey
	}
	if s.InOverlap(now) {
		return pruned, ErrRotationInFlight
	}
	if s.PrimaryKeyID != "" {
		s.PreviousKeys = append(s.PreviousKeys, PreviousKey{
			KeyID:     s.PrimaryKeyID,
			RetiredAt: now,
			ExpiresAt: now.Add(s.OverlapWindow),
		})
	}
	s.PrimaryKeyID = newKeyID
	s.RotatedAt = now
	return pruned, nil
}

// Prune drops previous keys whose overlap window has elapsed at now, returning
// the retired key ids in the order they were dropped. It is the safe transition
// out of the overlap window and is idempotent.
func (s *OverlapState) Prune(now time.Time) []string {
	if s == nil || len(s.PreviousKeys) == 0 {
		return nil
	}
	var pruned []string
	kept := s.PreviousKeys[:0:0]
	for _, pk := range s.PreviousKeys {
		if pk.ExpiresAt.After(now) {
			kept = append(kept, pk)
		} else {
			pruned = append(pruned, pk.KeyID)
		}
	}
	s.PreviousKeys = kept
	return pruned
}
