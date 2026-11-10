// Package snapshot implements the organization-wide dependency snapshot, freeze &
// instant-rollback subsystem (Task 70) — the supply-chain "time machine".
//
// It captures the complete resolved dependency state actually served across all
// backends — for each coordinate the served digest, its source commit, the
// admission verdict it passed, its risk band, and the digest of the proxy's
// outbound attestation bundle — into a signed, content-addressed point-in-time
// manifest. Operators can:
//
//   - Take named snapshots on demand or on a coord-guarded schedule (Task 56).
//   - Diff two snapshots (reusing the sbomdiff drift-scoring concepts) to see what
//     changed between two points in time: added/removed coordinates, digest
//     changes for the same version (a tamper signal), and verdict/risk regressions.
//   - Freeze the organization to a snapshot: a new pull-path gate (composing with
//     the dependency firewall, Task 65) then blocks or quarantines any pull whose
//     coordinate is outside the frozen set, or whose served digest differs from the
//     frozen one.
//   - Instantly roll back: when a newly-published version is later found malicious
//     (malfeed / cve-drift), pin the org back to the last-known-good snapshot in
//     one action, forcing every client back to the previously-served safe digests.
//
// Snapshots are persisted durably (JSON on disk, atomic writes), signed with the
// audit signing key, and their content digest is recorded in the Merkle audit log
// so the captured state is tamper-evident.
package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
)

// FreezeMode is how the freeze gate treats a pull outside the frozen set.
type FreezeMode string

const (
	// FreezeModeBlock refuses an out-of-set (or digest-mismatched) pull outright.
	FreezeModeBlock FreezeMode = "block"
	// FreezeModeQuarantine refuses it but consults the break-glass workflow first,
	// so an operator can grant a one-off exception while the freeze stands.
	FreezeModeQuarantine FreezeMode = "quarantine"
)

// Freeze decision codes.
const (
	CodeNotInSet        = "not-in-frozen-set"
	CodeDigestMismatch  = "digest-mismatch"
	CodeFrozenAllowed   = "frozen-allowed"
	CodeNotFrozen       = "not-frozen"
	CodeNoConcreteCoord = "no-concrete-coordinate"
)

// Entry is the resolved, served state of one coordinate at capture time. It is
// the per-coordinate row of a snapshot manifest.
type Entry struct {
	Tenant            string    `json:"tenant,omitempty"`
	Ecosystem         string    `json:"ecosystem"`
	Name              string    `json:"name"`
	Version           string    `json:"version"`
	Coordinate        string    `json:"coordinate"` // normalized "ecosystem:name@version"
	Digest            string    `json:"digest,omitempty"`
	SourceCommit      string    `json:"sourceCommit,omitempty"`
	RepositoryURL     string    `json:"repositoryUrl,omitempty"`
	Verdict           string    `json:"verdict,omitempty"` // admit|warn
	RiskScore         int       `json:"riskScore,omitempty"`
	RiskBand          string    `json:"riskBand,omitempty"`
	AttestationDigest string    `json:"attestationDigest,omitempty"`
	ServedAt          time.Time `json:"servedAt"`
}

// coordKey is the org-wide identity used to index entries and the frozen set:
// (ecosystem, name, version), tenant-independent because a public artifact's
// content is the same for every tenant. It is the key the freeze gate looks up.
func coordKey(ecosystem, name, version string) string {
	return strings.ToLower(ecosystem) + "\x00" + name + "\x00" + version
}

func (e Entry) key() string { return coordKey(e.Ecosystem, e.Name, e.Version) }

// makeCoordinate renders the human-readable "ecosystem:name@version" coordinate.
func makeCoordinate(ecosystem, name, version string) string {
	c := name
	if version != "" {
		c = name + "@" + version
	}
	if ecosystem != "" {
		c = ecosystem + ":" + c
	}
	return c
}

// Manifest is a signed, content-addressed point-in-time snapshot of the served
// dependency state.
type Manifest struct {
	// ID equals ContentDigest: the snapshot is content-addressed by the SHA-256 of
	// its canonical content, so two captures of an identical state share an ID.
	ID        string    `json:"id"`
	Name      string    `json:"name,omitempty"`
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	CreatedBy string    `json:"createdBy,omitempty"`
	// Scheduled is true when the snapshot was taken by the background scheduler
	// rather than an on-demand operator action.
	Scheduled bool `json:"scheduled,omitempty"`
	// Good marks the snapshot as a known-good rollback target. A freshly captured
	// state is presumed good; an operator (or an automated malfeed/cve-drift hook)
	// clears it once a snapshot is found to contain a compromised artifact.
	Good       bool    `json:"good"`
	Entries    []Entry `json:"entries"`
	EntryCount int     `json:"entryCount"`

	// ContentDigest is the SHA-256 ("sha256:<hex>") over the canonical content
	// (everything above except the signature fields). It is what is signed and
	// what is recorded in the audit log.
	ContentDigest string `json:"contentDigest"`
	KeyID         string `json:"keyId,omitempty"`
	Signature     string `json:"signature,omitempty"`
}

// content is the canonical, signed portion of a manifest. Field order and the
// sorted entries make the encoding deterministic so the digest is stable.
type manifestContent struct {
	Name       string  `json:"name,omitempty"`
	Note       string  `json:"note,omitempty"`
	CreatedAt  string  `json:"createdAt"`
	CreatedBy  string  `json:"createdBy,omitempty"`
	Scheduled  bool    `json:"scheduled,omitempty"`
	Entries    []Entry `json:"entries"`
	EntryCount int     `json:"entryCount"`
}

// computeDigest derives the content-addressed digest of the manifest. It is pure
// and deterministic: entries are sorted and timestamps are RFC3339Nano UTC.
func (m *Manifest) computeDigest() string {
	entries := append([]Entry(nil), m.Entries...)
	sortEntries(entries)
	c := manifestContent{
		Name:       m.Name,
		Note:       m.Note,
		CreatedAt:  m.CreatedAt.UTC().Format(time.RFC3339Nano),
		CreatedBy:  m.CreatedBy,
		Scheduled:  m.Scheduled,
		Entries:    entries,
		EntryCount: len(entries),
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// sortEntries orders entries deterministically by coordinate then tenant.
func sortEntries(entries []Entry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].key() != entries[j].key() {
			return entries[i].key() < entries[j].key()
		}
		return entries[i].Tenant < entries[j].Tenant
	})
}

// Summary is the listing projection of a manifest (no entries).
type Summary struct {
	ID            string    `json:"id"`
	Name          string    `json:"name,omitempty"`
	Note          string    `json:"note,omitempty"`
	CreatedAt     time.Time `json:"createdAt"`
	CreatedBy     string    `json:"createdBy,omitempty"`
	Scheduled     bool      `json:"scheduled,omitempty"`
	Good          bool      `json:"good"`
	EntryCount    int       `json:"entryCount"`
	ContentDigest string    `json:"contentDigest"`
	KeyID         string    `json:"keyId,omitempty"`
	Signed        bool      `json:"signed"`
	Frozen        bool      `json:"frozen"`
}

// Summary returns the listing projection of the manifest (no entries), marking
// it frozen when its id matches frozenID.
func (m *Manifest) Summary(frozenID string) Summary { return m.summary(frozenID) }

func (m *Manifest) summary(frozenID string) Summary {
	return Summary{
		ID:            m.ID,
		Name:          m.Name,
		Note:          m.Note,
		CreatedAt:     m.CreatedAt,
		CreatedBy:     m.CreatedBy,
		Scheduled:     m.Scheduled,
		Good:          m.Good,
		EntryCount:    m.EntryCount,
		ContentDigest: m.ContentDigest,
		KeyID:         m.KeyID,
		Signed:        m.Signature != "",
		Frozen:        frozenID != "" && frozenID == m.ID,
	}
}

// FreezeState is the currently-active organization freeze (if any).
type FreezeState struct {
	Active        bool       `json:"active"`
	SnapshotID    string     `json:"snapshotId,omitempty"`
	SnapshotName  string     `json:"snapshotName,omitempty"`
	Mode          FreezeMode `json:"mode,omitempty"`
	Reason        string     `json:"reason,omitempty"`
	EnforceDigest bool       `json:"enforceDigest,omitempty"`
	Rollback      bool       `json:"rollback,omitempty"`
	ActivatedAt   time.Time  `json:"activatedAt,omitempty"`
	ActivatedBy   string     `json:"activatedBy,omitempty"`
	SetSize       int        `json:"setSize,omitempty"`
}

// FreezeDecision is what the pull-path gate gets back from a freeze consult.
type FreezeDecision struct {
	Frozen         bool       `json:"frozen"`
	Blocked        bool       `json:"blocked"`
	Quarantine     bool       `json:"quarantine"`
	Code           string     `json:"code,omitempty"`
	Reason         string     `json:"reason,omitempty"`
	Mode           FreezeMode `json:"mode,omitempty"`
	SnapshotID     string     `json:"snapshotId,omitempty"`
	SnapshotName   string     `json:"snapshotName,omitempty"`
	ExpectedDigest string     `json:"expectedDigest,omitempty"`
}

// Config configures the snapshot subsystem.
type Config struct {
	// Enabled turns the subsystem (capture, admin surface, scheduler) on.
	Enabled bool
	// Dir is the directory snapshots, the index, and the freeze state are
	// persisted under. Empty keeps everything in memory (snapshots are lost on
	// restart) — useful for tests.
	Dir string
	// MaxLiveEntries bounds the in-memory live-state map (distinct coordinates).
	// Oldest-served entries are evicted past the cap. 0 uses the default.
	MaxLiveEntries int
	// MaxSnapshots bounds the retained snapshot manifests. The oldest
	// non-frozen, non-good snapshots are pruned first. 0 uses the default.
	MaxSnapshots int
	// ScheduleInterval, when > 0, takes an automatic scheduled snapshot on this
	// cadence (coord-guarded in HA). 0 disables scheduling.
	ScheduleInterval time.Duration
	// FreezeEnforceGate, when true, lets the freeze gate block/quarantine pulls.
	// When false the gate is observe-only (records the decision, never refuses) —
	// a safety valve for staging a freeze before enforcing it.
	FreezeEnforceGate bool
}

const (
	defaultMaxLiveEntries = 50000
	defaultMaxSnapshots   = 200
)

// Service is the snapshot subsystem.
type Service struct {
	cfg      Config
	logger   *slog.Logger
	signer   *Signer
	store    *store
	now      func() time.Time
	audit    *audit.Logger
	notifier notify.Emitter

	mu sync.RWMutex
	// live is the most-recent served state per coordinate, the source for Take().
	live map[string]*Entry
	// snaps holds loaded manifests by id.
	snaps map[string]*Manifest
	// order preserves snapshot creation order (oldest first) for listing/pruning.
	order []string
	// freeze is the active freeze state.
	freeze FreezeState
	// frozenSet is the fast lookup index (coordKey -> digest) built from the
	// frozen manifest's entries; nil when no freeze is active.
	frozenSet map[string]string

	// metrics counters (atomic-free; guarded by mu where mutated under it).
	mRecorded  uint64
	mTaken     uint64
	mFreezes   uint64
	mRollbacks uint64
	mGateAllow uint64
	mGateBlock uint64
	mGateQuar  uint64
}

// New constructs the service, loading any persisted snapshots and freeze state
// from cfg.Dir. The signer (which may be nil for unsigned manifests) is reused
// from the audit signing key.
func New(cfg Config, signer *Signer, logger *slog.Logger, opts ...Option) (*Service, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.MaxLiveEntries <= 0 {
		cfg.MaxLiveEntries = defaultMaxLiveEntries
	}
	if cfg.MaxSnapshots <= 0 {
		cfg.MaxSnapshots = defaultMaxSnapshots
	}
	s := &Service{
		cfg:    cfg,
		logger: logger,
		signer: signer,
		store:  newStore(cfg.Dir),
		now:    time.Now,
		live:   make(map[string]*Entry),
		snaps:  make(map[string]*Manifest),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Enabled reports whether the subsystem is active. Safe on a nil receiver.
func (s *Service) Enabled() bool { return s != nil && s.cfg.Enabled }

// load restores persisted manifests and freeze state at startup.
func (s *Service) load() error {
	manifests, err := s.store.loadAll()
	if err != nil {
		return err
	}
	sort.Slice(manifests, func(i, j int) bool {
		return manifests[i].CreatedAt.Before(manifests[j].CreatedAt)
	})
	for _, m := range manifests {
		s.snaps[m.ID] = m
		s.order = append(s.order, m.ID)
	}
	fs, ok, err := s.store.loadFreeze()
	if err != nil {
		return err
	}
	if ok && fs.Active {
		if m, exists := s.snaps[fs.SnapshotID]; exists {
			s.freeze = fs
			s.buildFrozenSetLocked(m)
		} else {
			s.logger.Warn("snapshot: active freeze references missing snapshot; clearing", "snapshotId", fs.SnapshotID)
			_ = s.store.saveFreeze(FreezeState{})
		}
	}
	return nil
}

// Record folds one served coordinate into the live state. It is called on the
// admitted/served pull path and is best-effort: a no-op on a nil/disabled
// service or an entry with no concrete (name, version). Safe for concurrent use.
func (s *Service) Record(e Entry) {
	if !s.Enabled() {
		return
	}
	if e.Name == "" || e.Version == "" {
		return
	}
	if e.Coordinate == "" {
		e.Coordinate = makeCoordinate(e.Ecosystem, e.Name, e.Version)
	}
	if e.ServedAt.IsZero() {
		e.ServedAt = s.now().UTC()
	} else {
		e.ServedAt = e.ServedAt.UTC()
	}
	k := e.key()
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := e
	s.live[k] = &cp
	s.mRecorded++
	s.evictLiveLocked()
}

// evictLiveLocked enforces the live-state cap by dropping the oldest-served
// entries. Called under s.mu.
func (s *Service) evictLiveLocked() {
	over := len(s.live) - s.cfg.MaxLiveEntries
	if over <= 0 {
		return
	}
	type kv struct {
		k string
		t time.Time
	}
	all := make([]kv, 0, len(s.live))
	for k, e := range s.live {
		all = append(all, kv{k, e.ServedAt})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
	for i := 0; i < over && i < len(all); i++ {
		delete(s.live, all[i].k)
	}
}

// LiveCount returns the number of distinct coordinates in the live state.
func (s *Service) LiveCount() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.live)
}

// liveEntriesLocked returns a sorted copy of the current live entries.
func (s *Service) liveEntriesLocked() []Entry {
	out := make([]Entry, 0, len(s.live))
	for _, e := range s.live {
		out = append(out, *e)
	}
	sortEntries(out)
	return out
}

// TakeOptions parameterizes a snapshot capture.
type TakeOptions struct {
	Name      string
	Note      string
	CreatedBy string
	Scheduled bool
}

// Take captures the current live state into a new signed, content-addressed
// manifest, persists it, and returns it. The caller is expected to record the
// manifest's content digest into the audit log (the proxy wiring does this).
func (s *Service) Take(opts TakeOptions) (*Manifest, error) {
	if !s.Enabled() {
		return nil, fmt.Errorf("snapshot: subsystem is disabled")
	}
	s.mu.Lock()
	entries := s.liveEntriesLocked()
	m := &Manifest{
		Name:       strings.TrimSpace(opts.Name),
		Note:       strings.TrimSpace(opts.Note),
		CreatedAt:  s.now().UTC(),
		CreatedBy:  strings.TrimSpace(opts.CreatedBy),
		Scheduled:  opts.Scheduled,
		Good:       true,
		Entries:    entries,
		EntryCount: len(entries),
	}
	m.ContentDigest = m.computeDigest()
	m.ID = m.ContentDigest
	if s.signer != nil {
		sig, err := s.signer.sign([]byte(m.ContentDigest))
		if err != nil {
			s.mu.Unlock()
			return nil, err
		}
		m.Signature = sig
		m.KeyID = s.signer.KeyID()
	}
	// A re-capture of an identical state shares the ID; replace in place so the
	// snapshot set stays content-addressed (no duplicates).
	if _, exists := s.snaps[m.ID]; !exists {
		s.order = append(s.order, m.ID)
	}
	s.snaps[m.ID] = m
	s.mTaken++
	if err := s.store.saveManifest(m); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	s.pruneLocked()
	out := cloneManifest(m)
	s.mu.Unlock()
	s.logger.Info("snapshot captured",
		"id", out.ID, "name", out.Name, "entries", out.EntryCount, "scheduled", out.Scheduled, "keyId", out.KeyID)
	s.recordAudit("captured", out.CreatedBy, "dependency snapshot captured", map[string]any{
		"snapshotId":    out.ID,
		"snapshotName":  out.Name,
		"entries":       out.EntryCount,
		"contentDigest": out.ContentDigest,
		"scheduled":     out.Scheduled,
		"keyId":         out.KeyID,
	})
	s.emitNotify(notify.SnapshotActionEvent("captured", out.ID, out.Name, out.CreatedBy, "dependency snapshot captured", out.EntryCount))
	return out, nil
}

// pruneLocked enforces the snapshot retention cap, dropping the oldest snapshots
// that are neither the active freeze target nor marked good. Called under s.mu.
func (s *Service) pruneLocked() {
	for len(s.order) > s.cfg.MaxSnapshots {
		victim := ""
		idx := -1
		for i, id := range s.order {
			m := s.snaps[id]
			if m == nil {
				idx = i
				victim = id
				break
			}
			if id == s.freeze.SnapshotID || m.Good {
				continue
			}
			idx = i
			victim = id
			break
		}
		if idx < 0 {
			// Everything left is protected (good or frozen); stop pruning.
			return
		}
		s.order = append(s.order[:idx], s.order[idx+1:]...)
		delete(s.snaps, victim)
		_ = s.store.deleteManifest(victim)
	}
}

// Get returns a copy of the manifest with the given id.
func (s *Service) Get(id string) (*Manifest, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.snaps[id]
	if !ok {
		return nil, false
	}
	return cloneManifest(m), true
}

// List returns snapshot summaries, newest first.
func (s *Service) List() []Summary {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Summary, 0, len(s.order))
	for i := len(s.order) - 1; i >= 0; i-- {
		if m := s.snaps[s.order[i]]; m != nil {
			out = append(out, m.summary(s.freeze.SnapshotID))
		}
	}
	return out
}

// MarkGood sets (or clears) the known-good rollback-target flag on a snapshot.
func (s *Service) MarkGood(id string, good bool) error {
	if !s.Enabled() {
		return fmt.Errorf("snapshot: subsystem is disabled")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.snaps[id]
	if !ok {
		return fmt.Errorf("snapshot: unknown snapshot %q", id)
	}
	m.Good = good
	return s.store.saveManifest(m)
}

func cloneManifest(m *Manifest) *Manifest {
	if m == nil {
		return nil
	}
	cp := *m
	cp.Entries = append([]Entry(nil), m.Entries...)
	return &cp
}

// Metrics is a point-in-time counter snapshot for observability.
type Metrics struct {
	LiveEntries    int
	Snapshots      int
	Recorded       uint64
	Taken          uint64
	Freezes        uint64
	Rollbacks      uint64
	FreezeActive   bool
	FrozenSetSize  int
	GateAllowed    uint64
	GateBlocked    uint64
	GateQuarantine uint64
}

// Metrics returns the current counters. Safe on a nil receiver.
func (s *Service) Metrics() Metrics {
	if s == nil {
		return Metrics{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Metrics{
		LiveEntries:    len(s.live),
		Snapshots:      len(s.order),
		Recorded:       s.mRecorded,
		Taken:          s.mTaken,
		Freezes:        s.mFreezes,
		Rollbacks:      s.mRollbacks,
		FreezeActive:   s.freeze.Active,
		FrozenSetSize:  len(s.frozenSet),
		GateAllowed:    s.mGateAllow,
		GateBlocked:    s.mGateBlock,
		GateQuarantine: s.mGateQuar,
	}
}
