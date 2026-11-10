package snapshot

import (
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/notify"
)

// FreezeOptions parameterizes activating a freeze.
type FreezeOptions struct {
	SnapshotID    string
	Mode          FreezeMode
	Reason        string
	ActivatedBy   string
	EnforceDigest bool
	// rollback marks the freeze as the result of a rollback action.
	rollback bool
}

// Freeze pins the organization to the snapshot identified by opts.SnapshotID:
// subsequent pulls are gated against that snapshot's coordinate set. It is
// idempotent in effect — re-freezing to the same snapshot just refreshes the
// metadata. The freeze state is persisted so it survives a restart.
func (s *Service) Freeze(opts FreezeOptions) (FreezeState, error) {
	if !s.Enabled() {
		return FreezeState{}, fmt.Errorf("snapshot: subsystem is disabled")
	}
	mode := normalizeMode(opts.Mode)
	s.mu.Lock()
	m, ok := s.snaps[opts.SnapshotID]
	if !ok {
		s.mu.Unlock()
		return FreezeState{}, fmt.Errorf("snapshot: unknown snapshot %q", opts.SnapshotID)
	}
	s.freeze = FreezeState{
		Active:        true,
		SnapshotID:    m.ID,
		SnapshotName:  m.Name,
		Mode:          mode,
		Reason:        strings.TrimSpace(opts.Reason),
		EnforceDigest: opts.EnforceDigest,
		Rollback:      opts.rollback,
		ActivatedAt:   s.now().UTC(),
		ActivatedBy:   strings.TrimSpace(opts.ActivatedBy),
	}
	s.buildFrozenSetLocked(m)
	s.freeze.SetSize = len(s.frozenSet)
	s.mFreezes++
	if err := s.store.saveFreeze(s.freeze); err != nil {
		s.mu.Unlock()
		return FreezeState{}, err
	}
	fs := s.freeze
	s.mu.Unlock()
	s.logger.Warn("organization frozen to snapshot",
		"snapshotId", m.ID, "name", m.Name, "mode", mode, "setSize", fs.SetSize,
		"rollback", opts.rollback, "by", opts.ActivatedBy)
	// A rollback emits its own "rollback" action event/audit; suppress the
	// intermediate "frozen" one to avoid a duplicate.
	if !opts.rollback {
		s.recordAudit("frozen", fs.ActivatedBy, fs.Reason, map[string]any{
			"snapshotId":   fs.SnapshotID,
			"snapshotName": fs.SnapshotName,
			"mode":         string(fs.Mode),
			"setSize":      fs.SetSize,
		})
		s.emitNotify(notify.SnapshotActionEvent("frozen", fs.SnapshotID, fs.SnapshotName, fs.ActivatedBy, fs.Reason, fs.SetSize))
	}
	return fs, nil
}

// Unfreeze lifts the active freeze. It is a no-op when none is active.
func (s *Service) Unfreeze(by string) (FreezeState, error) {
	if !s.Enabled() {
		return FreezeState{}, fmt.Errorf("snapshot: subsystem is disabled")
	}
	s.mu.Lock()
	if !s.freeze.Active {
		s.mu.Unlock()
		return FreezeState{}, nil
	}
	prev := s.freeze
	s.freeze = FreezeState{}
	s.frozenSet = nil
	if err := s.store.saveFreeze(s.freeze); err != nil {
		s.mu.Unlock()
		return FreezeState{}, err
	}
	s.mu.Unlock()
	by = strings.TrimSpace(by)
	s.logger.Warn("organization freeze lifted", "previousSnapshotId", prev.SnapshotID, "by", by)
	s.recordAudit("unfrozen", by, "organization dependency freeze lifted", map[string]any{
		"previousSnapshotId": prev.SnapshotID,
	})
	s.emitNotify(notify.SnapshotActionEvent("unfrozen", prev.SnapshotID, prev.SnapshotName, by, "organization dependency freeze lifted", 0))
	return FreezeState{}, nil
}

// Rollback is the one-action incident response: pin the organization back to the
// last-known-good snapshot, forcing every client to the previously-served safe
// digests. It selects the most recently created snapshot that is marked good and
// is not the currently-active freeze target (so rolling back from a freeze that
// was itself found bad still advances). When no good snapshot is available it
// returns an error rather than silently freezing to nothing.
func (s *Service) Rollback(by, reason string) (FreezeState, *Manifest, error) {
	if !s.Enabled() {
		return FreezeState{}, nil, fmt.Errorf("snapshot: subsystem is disabled")
	}
	target := s.lastKnownGood()
	if target == nil {
		return FreezeState{}, nil, fmt.Errorf("snapshot: no known-good snapshot available to roll back to")
	}
	r := strings.TrimSpace(reason)
	if r == "" {
		r = "instant rollback to last-known-good snapshot"
	}
	fs, err := s.Freeze(FreezeOptions{
		SnapshotID:    target.ID,
		Mode:          FreezeModeBlock,
		Reason:        r,
		ActivatedBy:   by,
		EnforceDigest: true,
		rollback:      true,
	})
	if err != nil {
		return FreezeState{}, nil, err
	}
	s.mu.Lock()
	s.mRollbacks++
	out := cloneManifest(s.snaps[target.ID])
	s.mu.Unlock()
	by = strings.TrimSpace(by)
	s.logger.Warn("instant rollback executed",
		"snapshotId", target.ID, "name", target.Name, "by", by)
	s.recordAudit("rollback", by, r, map[string]any{
		"snapshotId":   target.ID,
		"snapshotName": target.Name,
		"setSize":      fs.SetSize,
	})
	s.emitNotify(notify.SnapshotActionEvent("rollback", target.ID, target.Name, by, r, fs.SetSize))
	return fs, out, nil
}

// lastKnownGood returns the newest good snapshot that is not the active freeze
// target. Callers must not hold s.mu (it takes a read lock).
func (s *Service) lastKnownGood() *Manifest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	active := s.freeze.SnapshotID
	for i := len(s.order) - 1; i >= 0; i-- {
		id := s.order[i]
		if id == active {
			continue
		}
		if m := s.snaps[id]; m != nil && m.Good {
			return m
		}
	}
	return nil
}

// FreezeState returns a copy of the current freeze state.
func (s *Service) FreezeState() FreezeState {
	if s == nil {
		return FreezeState{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	fs := s.freeze
	fs.SetSize = len(s.frozenSet)
	return fs
}

// buildFrozenSetLocked rebuilds the fast coordKey->digest lookup from a manifest.
// Called under s.mu.
func (s *Service) buildFrozenSetLocked(m *Manifest) {
	set := make(map[string]string, len(m.Entries))
	for _, e := range m.Entries {
		// Keep the first-seen digest for a coordinate; entries are de-duplicated by
		// coordinate in the live state so collisions are not expected.
		if _, ok := set[e.key()]; !ok {
			set[e.key()] = e.Digest
		}
	}
	s.frozenSet = set
}

// CheckFreeze is the pull-path gate consult. Given a resolved coordinate (and,
// when known, the served digest), it returns whether the freeze blocks it. When
// no freeze is active, or the gate is in observe-only mode, Blocked is false. A
// coordinate absent from the frozen set is refused (the whole point of a freeze);
// a coordinate present but served with a different digest than the frozen one is
// refused as a tamper signal when digest enforcement is on. Safe on nil.
func (s *Service) CheckFreeze(ecosystem, name, version, digest string) FreezeDecision {
	if !s.Enabled() {
		return FreezeDecision{Code: CodeNotFrozen}
	}
	if name == "" || version == "" {
		// Listing/index request: no single artifact to gate.
		return FreezeDecision{Code: CodeNoConcreteCoord}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.freeze.Active {
		return FreezeDecision{Code: CodeNotFrozen}
	}
	dec := FreezeDecision{
		Frozen:       true,
		Mode:         s.freeze.Mode,
		SnapshotID:   s.freeze.SnapshotID,
		SnapshotName: s.freeze.SnapshotName,
	}
	k := coordKey(ecosystem, name, version)
	expected, inSet := s.frozenSet[k]
	switch {
	case !inSet:
		dec.Code = CodeNotInSet
		dec.Reason = fmt.Sprintf("%s@%s is not part of the frozen snapshot %s", name, version, s.freeze.shortID())
	case s.freeze.EnforceDigest && expected != "" && digest != "" && !digestEqual(expected, digest):
		dec.Code = CodeDigestMismatch
		dec.ExpectedDigest = expected
		dec.Reason = fmt.Sprintf("%s@%s served digest %s differs from the frozen digest %s", name, version, shortDigest(digest), shortDigest(expected))
	default:
		dec.Code = CodeFrozenAllowed
		dec.ExpectedDigest = expected
		s.mGateAllow++
		return dec
	}
	// The coordinate is outside the frozen set (or tampered). Enforce per mode.
	if !s.cfg.FreezeEnforceGate {
		// Observe-only: record the decision but do not block.
		s.mGateAllow++
		return dec
	}
	if s.freeze.Mode == FreezeModeQuarantine {
		dec.Quarantine = true
		s.mGateQuar++
	} else {
		s.mGateBlock++
	}
	dec.Blocked = true
	return dec
}

func (fs FreezeState) shortID() string { return shortDigest(fs.SnapshotID) }

func normalizeMode(m FreezeMode) FreezeMode {
	switch FreezeMode(strings.ToLower(strings.TrimSpace(string(m)))) {
	case FreezeModeQuarantine:
		return FreezeModeQuarantine
	default:
		return FreezeModeBlock
	}
}

// digestEqual compares two content digests tolerantly of an algorithm prefix and
// case, so "sha256:ABC" and "abc" compare equal.
func digestEqual(a, b string) bool {
	return strings.EqualFold(stripAlgo(a), stripAlgo(b))
}

func stripAlgo(d string) string {
	if i := strings.IndexByte(d, ':'); i >= 0 {
		return d[i+1:]
	}
	return d
}

func shortDigest(d string) string {
	h := stripAlgo(d)
	if len(h) > 12 {
		return h[:12]
	}
	if h == "" {
		return "(none)"
	}
	return h
}

// ScheduleInterval exposes the configured automatic-capture cadence for the
// scheduler wiring (0 when disabled).
func (s *Service) ScheduleInterval() time.Duration {
	if s == nil {
		return 0
	}
	return s.cfg.ScheduleInterval
}
