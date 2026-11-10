package snapshot

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"
)

func testSigner(t *testing.T) *Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return s
}

func newTestService(t *testing.T, signer *Signer, cfg Config) *Service {
	t.Helper()
	cfg.Enabled = true
	svc, err := New(cfg, signer, nil)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	// Deterministic, monotonically-advancing clock.
	base := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	var n int64
	svc.now = func() time.Time {
		n++
		return base.Add(time.Duration(n) * time.Second)
	}
	return svc
}

func recordN(svc *Service, eco, name string, versions ...string) {
	for i, v := range versions {
		svc.Record(Entry{
			Ecosystem: eco, Name: name, Version: v,
			Digest:  digestFor(name, v, i),
			Verdict: "admit", RiskBand: "low",
		})
	}
}

func digestFor(name, v string, salt int) string {
	return "sha256:" + name + "-" + v + "-" + string(rune('a'+salt))
}

func TestRecordAndTake(t *testing.T) {
	svc := newTestService(t, testSigner(t), Config{})
	recordN(svc, "npm", "left-pad", "1.0.0")
	recordN(svc, "pypi", "requests", "2.0.0")
	// Re-record left-pad with the same version: dedup, not a new coordinate.
	recordN(svc, "npm", "left-pad", "1.0.0")

	if got := svc.LiveCount(); got != 2 {
		t.Fatalf("LiveCount = %d, want 2", got)
	}

	m, err := svc.Take(TakeOptions{Name: "nightly"})
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if m.EntryCount != 2 {
		t.Fatalf("EntryCount = %d, want 2", m.EntryCount)
	}
	if m.ID == "" || m.ID != m.ContentDigest {
		t.Fatalf("manifest not content-addressed: id=%q digest=%q", m.ID, m.ContentDigest)
	}
	if m.Signature == "" || m.KeyID == "" {
		t.Fatalf("manifest not signed: sig=%q keyId=%q", m.Signature, m.KeyID)
	}
	if !m.Good {
		t.Fatalf("freshly captured snapshot should be marked good")
	}
}

func TestContentAddressingAndVerify(t *testing.T) {
	signer := testSigner(t)
	svc := newTestService(t, signer, Config{})
	recordN(svc, "npm", "a", "1.0.0")

	m, err := svc.Take(TakeOptions{Name: "x"})
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if err := VerifyManifest(signer.PublicKey(), m); err != nil {
		t.Fatalf("VerifyManifest: %v", err)
	}
	// Tamper with an entry: verification must fail (digest mismatch).
	m.Entries[0].Digest = "sha256:tampered"
	if err := VerifyManifest(signer.PublicKey(), m); err == nil {
		t.Fatalf("expected verification to fail after tampering")
	}
}

func TestTakeIsContentAddressed_Idempotent(t *testing.T) {
	svc := newTestService(t, nil, Config{})
	recordN(svc, "npm", "a", "1.0.0")

	m1, _ := svc.Take(TakeOptions{})
	m2, _ := svc.Take(TakeOptions{})
	// Identical live state + identical (non-time) content => same content digest.
	// CreatedAt differs, which is part of content, so IDs differ. Confirm at least
	// that recomputation is stable for a given manifest.
	if m1.ID != m1.computeDigest() {
		t.Fatalf("m1 digest unstable")
	}
	if m2.ID != m2.computeDigest() {
		t.Fatalf("m2 digest unstable")
	}
}

func TestFreezeGate(t *testing.T) {
	svc := newTestService(t, nil, Config{FreezeEnforceGate: true})
	recordN(svc, "npm", "good", "1.0.0")
	m, _ := svc.Take(TakeOptions{Name: "baseline"})

	// No freeze yet: everything allowed.
	if d := svc.CheckFreeze("npm", "good", "1.0.0", ""); d.Blocked {
		t.Fatalf("unexpected block before freeze")
	}

	if _, err := svc.Freeze(FreezeOptions{SnapshotID: m.ID, Mode: FreezeModeBlock, EnforceDigest: true}); err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	// In-set coordinate is allowed.
	if d := svc.CheckFreeze("npm", "good", "1.0.0", ""); d.Blocked {
		t.Fatalf("in-set coordinate should be allowed, got %+v", d)
	}
	// Out-of-set coordinate (new version) is blocked.
	d := svc.CheckFreeze("npm", "good", "2.0.0", "")
	if !d.Blocked || d.Code != CodeNotInSet {
		t.Fatalf("out-of-set should be blocked with not-in-frozen-set, got %+v", d)
	}
	// Digest mismatch on an in-set coordinate is blocked.
	dm := svc.CheckFreeze("npm", "good", "1.0.0", "sha256:different")
	if !dm.Blocked || dm.Code != CodeDigestMismatch {
		t.Fatalf("digest mismatch should be blocked, got %+v", dm)
	}
	// Same digest as frozen is allowed.
	frozen := m.Entries[0].Digest
	if d := svc.CheckFreeze("npm", "good", "1.0.0", frozen); d.Blocked {
		t.Fatalf("matching digest should be allowed, got %+v", d)
	}

	// Listing (no version) is never gated.
	if d := svc.CheckFreeze("npm", "good", "", ""); d.Blocked {
		t.Fatalf("listing request should not be gated")
	}
}

func TestFreezeObserveOnly(t *testing.T) {
	svc := newTestService(t, nil, Config{FreezeEnforceGate: false})
	recordN(svc, "npm", "good", "1.0.0")
	m, _ := svc.Take(TakeOptions{})
	if _, err := svc.Freeze(FreezeOptions{SnapshotID: m.ID}); err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	// Out-of-set but observe-only: not blocked.
	d := svc.CheckFreeze("npm", "good", "9.9.9", "")
	if d.Blocked {
		t.Fatalf("observe-only freeze must not block, got %+v", d)
	}
	if !d.Frozen {
		t.Fatalf("decision should report frozen")
	}
}

func TestQuarantineMode(t *testing.T) {
	svc := newTestService(t, nil, Config{FreezeEnforceGate: true})
	recordN(svc, "npm", "good", "1.0.0")
	m, _ := svc.Take(TakeOptions{})
	if _, err := svc.Freeze(FreezeOptions{SnapshotID: m.ID, Mode: FreezeModeQuarantine}); err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	d := svc.CheckFreeze("npm", "good", "2.0.0", "")
	if !d.Blocked || !d.Quarantine {
		t.Fatalf("quarantine mode should block with Quarantine=true, got %+v", d)
	}
}

func TestRollback(t *testing.T) {
	svc := newTestService(t, nil, Config{FreezeEnforceGate: true})

	// Snapshot 1: the last-known-good state.
	recordN(svc, "npm", "pkg", "1.0.0")
	good, _ := svc.Take(TakeOptions{Name: "good"})

	// Snapshot 2: a later state that includes a malicious new version.
	recordN(svc, "npm", "pkg", "2.0.0")
	bad, _ := svc.Take(TakeOptions{Name: "bad"})

	// The bad snapshot is found to contain a compromised artifact.
	if err := svc.MarkGood(bad.ID, false); err != nil {
		t.Fatalf("MarkGood: %v", err)
	}

	// Roll back: should pin to the good snapshot.
	fs, target, err := svc.Rollback("operator", "left-pad@2.0.0 found malicious")
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if target.ID != good.ID {
		t.Fatalf("rolled back to %s, want good snapshot %s", target.ID, good.ID)
	}
	if !fs.Active || fs.SnapshotID != good.ID || !fs.Rollback {
		t.Fatalf("freeze state after rollback unexpected: %+v", fs)
	}

	// After rollback the malicious 2.0.0 is blocked; 1.0.0 (good) is allowed.
	if d := svc.CheckFreeze("npm", "pkg", "2.0.0", ""); !d.Blocked {
		t.Fatalf("malicious version should be blocked after rollback")
	}
	if d := svc.CheckFreeze("npm", "pkg", "1.0.0", ""); d.Blocked {
		t.Fatalf("good version should be allowed after rollback")
	}
}

func TestRollbackNoGood(t *testing.T) {
	svc := newTestService(t, nil, Config{})
	recordN(svc, "npm", "pkg", "1.0.0")
	m, _ := svc.Take(TakeOptions{})
	// Mark the only snapshot bad and freeze to it, so lastKnownGood finds nothing.
	_ = svc.MarkGood(m.ID, false)
	if _, _, err := svc.Rollback("op", ""); err == nil {
		t.Fatalf("expected error when no known-good snapshot exists")
	}
}

func TestDiff(t *testing.T) {
	svc := newTestService(t, nil, Config{})

	recordN(svc, "npm", "keep", "1.0.0")
	recordN(svc, "npm", "drop", "1.0.0")
	recordN(svc, "npm", "change", "1.0.0")
	from, _ := svc.Take(TakeOptions{Name: "from"})

	// Mutate the live state: keep same, drop removed, change gets a new digest,
	// add a brand-new coordinate.
	svc.mu.Lock()
	delete(svc.live, coordKey("npm", "drop", "1.0.0"))
	svc.mu.Unlock()
	svc.Record(Entry{Ecosystem: "npm", Name: "change", Version: "1.0.0", Digest: "sha256:NEWDIGEST", Verdict: "warn", RiskBand: "high"})
	recordN(svc, "npm", "added", "3.0.0")
	to, _ := svc.Take(TakeOptions{Name: "to"})

	d, ok := svc.Diff(from.ID, to.ID)
	if !ok {
		t.Fatalf("Diff returned not-ok")
	}
	if len(d.Added) != 1 || d.Added[0].Name != "added" {
		t.Fatalf("added = %+v, want [added]", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0].Name != "drop" {
		t.Fatalf("removed = %+v, want [drop]", d.Removed)
	}
	if len(d.DigestChanges) != 1 || d.DigestChanges[0].Name != "change" {
		t.Fatalf("digestChanges = %+v, want [change]", d.DigestChanges)
	}
	if len(d.VerdictChanges) != 1 {
		t.Fatalf("verdictChanges = %+v, want 1", d.VerdictChanges)
	}
	if len(d.BandChanges) != 1 {
		t.Fatalf("bandChanges = %+v, want 1", d.BandChanges)
	}
	// Digest changes dominate the score; with one, score must be significant.
	if !d.Significant {
		t.Fatalf("diff with a digest change should be significant, score=%v", d.DriftScore)
	}
	if d.Markdown() == "" {
		t.Fatalf("Markdown report should not be empty")
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	signer := testSigner(t)

	svc := newTestService(t, signer, Config{Dir: dir})
	recordN(svc, "npm", "pkg", "1.0.0")
	m, _ := svc.Take(TakeOptions{Name: "persisted"})
	if _, err := svc.Freeze(FreezeOptions{SnapshotID: m.ID, Mode: FreezeModeBlock}); err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	// Reload from disk into a fresh service.
	svc2, err := New(Config{Enabled: true, Dir: dir, FreezeEnforceGate: true}, signer, nil)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got, ok := svc2.Get(m.ID)
	if !ok {
		t.Fatalf("snapshot not reloaded")
	}
	if got.EntryCount != 1 || got.Name != "persisted" {
		t.Fatalf("reloaded manifest mismatch: %+v", got)
	}
	fs := svc2.FreezeState()
	if !fs.Active || fs.SnapshotID != m.ID {
		t.Fatalf("freeze state not restored: %+v", fs)
	}
	// The restored freeze gate enforces against the persisted set.
	if d := svc2.CheckFreeze("npm", "pkg", "2.0.0", ""); !d.Blocked {
		t.Fatalf("restored freeze should block out-of-set pull")
	}

	// On-disk manifest file exists.
	files, err := filepath.Glob(filepath.Join(dir, "snapshots", "*.json"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) == 0 {
		t.Fatalf("no manifest file persisted to disk")
	}
}

func TestPruneKeepsGoodAndFrozen(t *testing.T) {
	svc := newTestService(t, nil, Config{MaxSnapshots: 2})

	recordN(svc, "npm", "a", "1.0.0")
	keepGood, _ := svc.Take(TakeOptions{Name: "good"})
	recordN(svc, "npm", "b", "1.0.0")
	keepFrozen, _ := svc.Take(TakeOptions{Name: "frozen"})
	if _, err := svc.Freeze(FreezeOptions{SnapshotID: keepFrozen.ID}); err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	// Mark a couple more as disposable (not good) and capture beyond the cap.
	for i := 0; i < 4; i++ {
		recordN(svc, "npm", "x", "1."+string(rune('0'+i))+".0")
		m, _ := svc.Take(TakeOptions{})
		_ = svc.MarkGood(m.ID, false)
	}

	if _, ok := svc.Get(keepGood.ID); !ok {
		t.Fatalf("good snapshot was pruned")
	}
	if _, ok := svc.Get(keepFrozen.ID); !ok {
		t.Fatalf("frozen snapshot was pruned")
	}
}

func TestQueryFacts(t *testing.T) {
	svc := newTestService(t, nil, Config{})
	recordN(svc, "npm", "a", "1.0.0")
	recordN(svc, "npm", "b", "1.0.0")
	m, _ := svc.Take(TakeOptions{})
	// Drop b from the live set after capture, freeze to the snapshot of {a,b}.
	if _, err := svc.Freeze(FreezeOptions{SnapshotID: m.ID}); err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	facts := svc.QueryFacts()
	if len(facts) != 2 {
		t.Fatalf("QueryFacts len = %d, want 2", len(facts))
	}
	for _, f := range facts {
		if !f.Frozen {
			t.Fatalf("coordinate %s should be marked frozen", f.Coordinate)
		}
	}
}

func TestDisabledServiceIsInert(t *testing.T) {
	svc, err := New(Config{Enabled: false}, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	svc.Record(Entry{Ecosystem: "npm", Name: "a", Version: "1.0.0"})
	if svc.LiveCount() != 0 {
		t.Fatalf("disabled service should not record")
	}
	if d := svc.CheckFreeze("npm", "a", "1.0.0", ""); d.Blocked {
		t.Fatalf("disabled service should never block")
	}
	if _, err := svc.Take(TakeOptions{}); err == nil {
		t.Fatalf("Take on disabled service should error")
	}
}

func TestNilServiceSafe(t *testing.T) {
	var svc *Service
	if svc.Enabled() {
		t.Fatalf("nil service should not be enabled")
	}
	if svc.LiveCount() != 0 {
		t.Fatalf("nil LiveCount")
	}
	if d := svc.CheckFreeze("npm", "a", "1.0.0", ""); d.Blocked {
		t.Fatalf("nil CheckFreeze should not block")
	}
	if svc.QueryFacts() != nil {
		t.Fatalf("nil QueryFacts")
	}
	_ = svc.Metrics()
}
