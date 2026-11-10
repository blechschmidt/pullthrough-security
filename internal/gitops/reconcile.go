package gitops

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blechschmidt/pullthrough-security/internal/approvals"
	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/presets"
	"github.com/blechschmidt/pullthrough-security/internal/simreplay"
)

// Outcome is the structured result of one reconcile pass.
type Outcome struct {
	Trigger      string `json:"trigger"`
	Revision     string `json:"revision,omitempty"`
	Digest       string `json:"digest,omitempty"`
	Verified     bool   `json:"verified"`
	VerifyReason string `json:"verifyReason,omitempty"`
	InSync       bool   `json:"inSync"`
	Changed      int    `json:"changed"`
	Applied      bool   `json:"applied"`
	Pending      bool   `json:"pending"`
	RequestID    string `json:"requestId,omitempty"`
	Drift        bool   `json:"drift"`
	Valid        bool   `json:"valid"`
	// Result is the terminal classification: in_sync | applied | pending_approval |
	// verify_failed | invalid | error.
	Result  string    `json:"result"`
	Error   string    `json:"error,omitempty"`
	At      time.Time `json:"at"`
	Preview *Preview  `json:"preview,omitempty"`
}

// RollbackResult reports the outcome of rolling back the most recent apply.
type RollbackResult struct {
	RolledBackFrom string    `json:"rolledBackFrom"`
	RestoredTo     string    `json:"restoredTo"`
	BackupPath     string    `json:"backupPath,omitempty"`
	By             string    `json:"by,omitempty"`
	RolledBackAt   time.Time `json:"rolledBackAt"`
}

// Reconcile performs one reconciliation pass: fetch the desired-state bundle,
// verify it, compute the diff/blast-radius preview against the live configuration,
// and apply it (apply mode) or surface it for approval (suggest mode). trigger and
// by are recorded for audit attribution ("scheduler"/"manual" and the operator).
//
// Business outcomes (in_sync, pending_approval, verify_failed, invalid) return a
// non-error Outcome; only infrastructure failures (fetch/parse/IO) return an error.
func (s *Service) Reconcile(ctx context.Context, trigger, by string) (Outcome, error) {
	if !s.Enabled() {
		return Outcome{}, fmt.Errorf("gitops: reconciler is not enabled")
	}
	s.mu.Lock()
	s.reconciles++
	live := s.live
	s.mu.Unlock()

	out := Outcome{Trigger: trigger, At: s.now().UTC()}

	fetched, err := s.src.Fetch(ctx)
	if err != nil {
		return s.failOutcome(out, err)
	}
	out.Revision = fetched.Revision
	out.Digest = Digest(fetched.Bundle)

	vr := s.verifier.Verify(fetched.Bundle, fetched.Signature)
	out.Verified = vr.Verified
	out.VerifyReason = vr.Reason
	if !vr.Verified {
		s.mu.Lock()
		s.verifyFailures++
		s.mu.Unlock()
		if s.cfg.FailClosed {
			return s.recordVerifyFailure(ctx, out, fetched, vr), nil
		}
		s.logger.Warn("gitops bundle failed verification but fail-open is set; continuing",
			"reason", vr.Reason, "revision", fetched.Revision)
	}

	bundle, err := ParseBundle(fetched.Bundle)
	if err != nil {
		return s.failOutcome(out, err)
	}
	revision := fetched.Revision
	preset := bundle.Preset(revision)

	if live == nil {
		return s.failOutcome(out, fmt.Errorf("gitops: no running configuration available to reconcile against"))
	}
	diff, err := preset.Diff(live)
	if err != nil {
		return s.failOutcome(out, err)
	}

	prev := s.buildPreview(fetched, diff)
	if s.records != nil {
		if recs := s.records(); len(recs) > 0 {
			if rep, serr := preset.Simulate(recs, simreplay.Options{OnlyChanged: true}); serr == nil {
				prev.BlastRadius = blastFrom(rep.Summary)
			}
		}
	}
	out.Valid = diff.Validation == nil || diff.Validation.OK
	out.Changed = diff.Changed
	out.InSync = diff.Changed == 0
	out.Preview = prev

	s.mu.Lock()
	s.preview = prev
	s.st.LastSyncAt = out.At
	s.st.LastRevision = revision
	s.st.LastBundleHash = out.Digest
	s.st.LastError = ""
	s.mu.Unlock()

	if out.InSync {
		return s.finishInSync(out), nil
	}

	// The live config diverges from the source of truth.
	out.Drift = true

	if !out.Valid {
		return s.recordInvalid(ctx, out, fetched, diff), nil
	}

	if s.cfg.Mode == ModeSuggest {
		allowed, reqID := s.consultApproval(ctx, fetched, diff, by)
		out.RequestID = reqID
		if !allowed {
			return s.recordPending(ctx, out, fetched, diff, reqID), nil
		}
		applied, aerr := s.apply(ctx, out, fetched, preset, diff, live, by, true, reqID)
		if aerr != nil {
			return s.failOutcome(out, aerr)
		}
		return applied, nil
	}

	applied, aerr := s.apply(ctx, out, fetched, preset, diff, live, by, false, "")
	if aerr != nil {
		return s.failOutcome(out, aerr)
	}
	return applied, nil
}

// buildPreview converts a presets.Diff into the operator-facing Preview.
func (s *Service) buildPreview(fetched Fetched, diff presets.Diff) *Preview {
	settings := make([]SettingChange, 0, len(diff.Settings))
	for _, sd := range diff.Settings {
		settings = append(settings, SettingChange{
			Path:     sd.Path,
			Desc:     sd.Desc,
			Current:  sd.Current,
			Proposed: sd.Proposed,
			Changed:  sd.Changed,
		})
	}
	p := &Preview{
		Revision:            fetched.Revision,
		Origin:              fetched.Origin,
		BundleDigest:        Digest(fetched.Bundle),
		Changed:             diff.Changed,
		Settings:            settings,
		RunningFingerprint:  diff.RunningFingerprint,
		ProposedFingerprint: diff.ProposedFingerprint,
		Valid:               diff.Validation == nil || diff.Validation.OK,
		ComputedAt:          s.now().UTC(),
	}
	if diff.Validation != nil {
		p.ValidationErrors = diff.Validation.Errors
	}
	return p
}

func (s *Service) finishInSync(out Outcome) Outcome {
	s.mu.Lock()
	s.st.InSync = true
	s.st.Drift = false
	s.st.Pending = nil
	s.st.LastOutcome = "in_sync"
	s.persistLocked()
	s.mu.Unlock()
	out.Result = "in_sync"
	return out
}

func (s *Service) recordVerifyFailure(ctx context.Context, out Outcome, fetched Fetched, vr VerifyResult) Outcome {
	reason := vr.Reason
	if reason == "" {
		reason = "bundle verification failed"
	}
	s.mu.Lock()
	newRev := s.st.LastOutcome != "verify_failed" || s.st.LastRevision != fetched.Revision
	s.st.LastSyncAt = out.At
	s.st.LastRevision = fetched.Revision
	s.st.LastOutcome = "verify_failed"
	s.st.LastError = reason
	s.st.InSync = false
	s.persistLocked()
	s.mu.Unlock()
	s.logger.Error("gitops refusing to apply unverified bundle (fail-closed)",
		"revision", fetched.Revision, "reason", reason)
	if newRev {
		s.emit(ctx, gitopsVerifyFailedEvent(shortRev(fetched.Revision), fetched.Origin, reason))
	}
	out.Result = "verify_failed"
	out.Error = reason
	return out
}

func (s *Service) recordInvalid(ctx context.Context, out Outcome, fetched Fetched, diff presets.Diff) Outcome {
	n := 0
	if diff.Validation != nil {
		n = diff.Validation.Errors
	}
	reason := fmt.Sprintf("projected configuration is invalid (%d error(s)); refusing to apply", n)
	s.mu.Lock()
	newRev := s.st.LastOutcome != "invalid" || s.st.LastRevision != fetched.Revision
	s.st.LastOutcome = "invalid"
	s.st.LastError = reason
	s.st.InSync = false
	s.st.Drift = true
	s.persistLocked()
	s.mu.Unlock()
	s.logger.Error("gitops desired-state bundle would produce an invalid config", "revision", fetched.Revision, "errors", n)
	if newRev {
		s.emit(ctx, gitopsDriftEvent(shortRev(fetched.Revision), fetched.Origin, diff.Changed, reason, "invalid"))
	}
	out.Result = "invalid"
	out.Error = reason
	return out
}

func (s *Service) consultApproval(ctx context.Context, fetched Fetched, diff presets.Diff, by string) (bool, string) {
	if s.approvals == nil || !s.approvals.Enabled() {
		return false, ""
	}
	disp := s.approvals.Consult(ctx, approvals.Scope{
		Ecosystem:  "config",
		Coordinate: shortRev(fetched.Revision),
		Gate:       "gitops",
		Reason:     fmt.Sprintf("apply %d GitOps config change(s) from %s", diff.Changed, fetched.Origin),
		Backend:    "gitops",
		Requester:  by,
	})
	return disp.Allow, disp.RequestID
}

func (s *Service) recordPending(ctx context.Context, out Outcome, fetched Fetched, diff presets.Diff, reqID string) Outcome {
	pc := &PendingChange{
		Revision:     fetched.Revision,
		Origin:       fetched.Origin,
		BundleDigest: Digest(fetched.Bundle),
		Changed:      diff.Changed,
		Paths:        changedPaths(diff),
		RequestID:    reqID,
		Reason:       "awaiting dual-control approval",
		DetectedAt:   out.At,
	}
	s.mu.Lock()
	newRev := s.st.Pending == nil || s.st.Pending.Revision != fetched.Revision
	s.st.Pending = pc
	s.st.InSync = false
	s.st.Drift = true
	s.st.LastOutcome = "pending_approval"
	s.persistLocked()
	s.mu.Unlock()
	s.logger.Info("gitops change pending approval (suggest mode)",
		"revision", fetched.Revision, "changed", diff.Changed, "requestId", reqID)
	if newRev {
		s.emit(ctx, gitopsDriftEvent(shortRev(fetched.Revision), fetched.Origin, diff.Changed,
			"GitOps config change pending dual-control approval", "pending"))
	}
	out.Pending = true
	out.Result = "pending_approval"
	return out
}

// apply patches the on-disk config with the desired-state bundle, validates it,
// snapshots the prior config, records the apply (audit + state + notify), and
// updates the in-memory running config so the reconciler converges (no re-apply
// loop). approved/reqID mark a suggest-mode apply authorised via approvals.
func (s *Service) apply(ctx context.Context, out Outcome, fetched Fetched, preset presets.Preset, diff presets.Diff, live *config.Config, by string, approved bool, reqID string) (Outcome, error) {
	if s.cfg.ConfigPath == "" {
		return out, fmt.Errorf("gitops: cannot apply: the process runs from defaults with no config file (start it with -config <path>)")
	}
	raw, err := os.ReadFile(s.cfg.ConfigPath)
	if err != nil {
		return out, fmt.Errorf("gitops: reading config %q: %w", s.cfg.ConfigPath, err)
	}
	patched, err := preset.PatchOnDisk(raw)
	if err != nil {
		return out, err
	}
	if rep := config.CheckBytes(patched); !rep.OK {
		return out, fmt.Errorf("gitops: refusing to apply: patched config failed validation (%d error(s))", rep.Errors)
	}

	backup := fmt.Sprintf("%s.gitops.bak.%s", s.cfg.ConfigPath, s.now().UTC().Format("20060102T150405Z"))
	if err := os.WriteFile(backup, raw, 0o600); err != nil {
		return out, fmt.Errorf("gitops: writing backup %q: %w", backup, err)
	}
	mode := fileMode(s.cfg.ConfigPath)
	if err := atomicWrite(s.cfg.ConfigPath, patched, mode); err != nil {
		return out, fmt.Errorf("gitops: writing config %q: %w", s.cfg.ConfigPath, err)
	}

	projected, _ := preset.Project(live)

	entry := AppliedEntry{
		Revision:        fetched.Revision,
		Origin:          fetched.Origin,
		FromFingerprint: diff.RunningFingerprint,
		ToFingerprint:   diff.ProposedFingerprint,
		BundleDigest:    Digest(fetched.Bundle),
		Changed:         diff.Changed,
		Paths:           changedPaths(diff),
		BackupPath:      backup,
		By:              by,
		AppliedAt:       s.now().UTC(),
		Approved:        approved,
		RequestID:       reqID,
	}

	s.mu.Lock()
	if projected != nil {
		s.live = projected
	}
	s.st.append(entry)
	s.st.InSync = true
	s.st.Drift = false
	s.st.Pending = nil
	s.st.LastOutcome = "applied"
	s.st.LastError = ""
	s.applies++
	s.persistLocked()
	s.mu.Unlock()

	s.auditApply(ctx, entry, diff, approved, by)
	s.emit(ctx, gitopsApplyEvent(entry))
	s.logger.Info("gitops applied desired-state bundle",
		"revision", entry.Revision, "changed", entry.Changed, "approved", approved, "by", by)

	out.Applied = true
	out.InSync = true
	out.Drift = false
	out.Result = "applied"
	return out, nil
}

// Rollback restores the configuration to the state before the most recent apply
// (the last-known-good revision), records it, and reports the change. The current
// config is snapshotted to a fresh backup first.
func (s *Service) Rollback(ctx context.Context, by, reason string) (RollbackResult, error) {
	if !s.Enabled() {
		return RollbackResult{}, fmt.Errorf("gitops: reconciler is not enabled")
	}
	if s.cfg.ConfigPath == "" {
		return RollbackResult{}, fmt.Errorf("gitops: cannot roll back: no config file backs this process")
	}
	s.mu.Lock()
	head := s.st.head()
	if head == nil {
		s.mu.Unlock()
		return RollbackResult{}, fmt.Errorf("gitops: nothing to roll back (no apply has been recorded)")
	}
	headCopy := *head
	s.mu.Unlock()

	if headCopy.BackupPath == "" {
		return RollbackResult{}, fmt.Errorf("gitops: cannot roll back revision %s: no pre-apply backup was recorded", headCopy.Revision)
	}
	restoreData, err := os.ReadFile(headCopy.BackupPath)
	if err != nil {
		return RollbackResult{}, fmt.Errorf("gitops: reading last-known-good backup %q: %w", headCopy.BackupPath, err)
	}
	if rep := config.CheckBytes(restoreData); !rep.OK {
		return RollbackResult{}, fmt.Errorf("gitops: refusing to roll back: the last-known-good config failed validation (%d error(s))", rep.Errors)
	}

	current, err := os.ReadFile(s.cfg.ConfigPath)
	if err != nil {
		return RollbackResult{}, fmt.Errorf("gitops: reading current config: %w", err)
	}
	backup := fmt.Sprintf("%s.gitops.rollback.%s", s.cfg.ConfigPath, s.now().UTC().Format("20060102T150405Z"))
	if err := os.WriteFile(backup, current, 0o600); err != nil {
		return RollbackResult{}, fmt.Errorf("gitops: writing rollback backup: %w", err)
	}
	if err := atomicWrite(s.cfg.ConfigPath, restoreData, fileMode(s.cfg.ConfigPath)); err != nil {
		return RollbackResult{}, fmt.Errorf("gitops: restoring config: %w", err)
	}
	restored, derr := decodeConfig(restoreData)

	s.mu.Lock()
	if derr == nil && restored != nil {
		s.live = restored
	}
	// Pop the rolled-back apply; the prior entry becomes the head (last-known-good).
	s.st.History = s.st.History[:len(s.st.History)-1]
	restoredTo := "pre-gitops baseline"
	if newHead := s.st.head(); newHead != nil {
		restoredTo = newHead.Revision
	}
	s.st.InSync = false
	s.st.Drift = true
	s.st.Pending = nil
	s.st.LastOutcome = "rolled_back"
	s.preview = nil
	s.rollbacks++
	s.persistLocked()
	s.mu.Unlock()

	res := RollbackResult{
		RolledBackFrom: headCopy.Revision,
		RestoredTo:     restoredTo,
		BackupPath:     backup,
		By:             by,
		RolledBackAt:   s.now().UTC(),
	}
	s.auditRollback(ctx, res, reason, by)
	s.emit(ctx, gitopsRollbackEvent(res, reason))
	s.logger.Warn("gitops rolled back to last-known-good config",
		"from", res.RolledBackFrom, "to", res.RestoredTo, "by", by, "reason", reason)
	return res, nil
}

func (s *Service) failOutcome(out Outcome, err error) (Outcome, error) {
	s.mu.Lock()
	s.errs++
	s.st.LastSyncAt = out.At
	s.st.LastOutcome = "error"
	s.st.LastError = err.Error()
	s.persistLocked()
	s.mu.Unlock()
	out.Result = "error"
	out.Error = err.Error()
	return out, err
}

// --- audit ----------------------------------------------------------------

func (s *Service) auditApply(ctx context.Context, e AppliedEntry, diff presets.Diff, approved bool, by string) {
	if s.audit == nil {
		return
	}
	detail := map[string]any{
		"event":           "apply",
		"revision":        e.Revision,
		"origin":          e.Origin,
		"bundleDigest":    e.BundleDigest,
		"changed":         e.Changed,
		"paths":           e.Paths,
		"fromFingerprint": e.FromFingerprint,
		"toFingerprint":   e.ToFingerprint,
		"backup":          e.BackupPath,
		"approved":        approved,
		"mode":            string(s.cfg.Mode),
	}
	if e.RequestID != "" {
		detail["requestId"] = e.RequestID
	}
	if changes := changedSummary(diff); len(changes) > 0 {
		detail["changes"] = changes
	}
	ev := audit.Event{
		Type:     audit.EventGitOps,
		Subject:  by,
		Resource: e.Revision,
		Decision: audit.DecisionAllow,
		Reason:   "gitops:apply",
		Detail:   detail,
	}
	s.logAudit(ctx, ev)
}

func (s *Service) auditRollback(ctx context.Context, res RollbackResult, reason, by string) {
	if s.audit == nil {
		return
	}
	ev := audit.Event{
		Type:     audit.EventGitOps,
		Subject:  by,
		Resource: res.RolledBackFrom,
		Decision: audit.DecisionAllow,
		Reason:   "gitops:rollback",
		Detail: map[string]any{
			"event":          "rollback",
			"rolledBackFrom": res.RolledBackFrom,
			"restoredTo":     res.RestoredTo,
			"backup":         res.BackupPath,
			"reason":         reason,
		},
	}
	s.logAudit(ctx, ev)
}

func (s *Service) logAudit(ctx context.Context, ev audit.Event) {
	if err := s.audit.Log(ctx, ev); err != nil {
		s.logger.Error("gitops audit log write failed", "reason", ev.Reason, "error", err)
	}
}

// --- helpers --------------------------------------------------------------

// changedPaths returns the dotted config paths the diff actually changes.
func changedPaths(diff presets.Diff) []string {
	out := make([]string, 0, diff.Changed)
	for _, sd := range diff.Settings {
		if sd.Changed {
			out = append(out, sd.Path)
		}
	}
	return out
}

// changedSummary returns a compact before/after map for the changed paths, kept
// small and primitive for the audit detail.
func changedSummary(diff presets.Diff) []map[string]string {
	out := make([]map[string]string, 0, diff.Changed)
	for _, sd := range diff.Settings {
		if sd.Changed {
			out = append(out, map[string]string{"path": sd.Path, "from": sd.Current, "to": sd.Proposed})
		}
	}
	return out
}

// decodeConfig layers a (possibly partial) YAML document over the defaults, the
// same way the proxy loads configuration, so the result is the effective config.
func decodeConfig(data []byte) (*config.Config, error) {
	cfg := config.Default()
	if len(strings.TrimSpace(string(data))) > 0 {
		dec := yaml.NewDecoder(bytes.NewReader(data))
		if err := dec.Decode(&cfg); err != nil {
			return nil, fmt.Errorf("gitops: decoding config: %w", err)
		}
	}
	return &cfg, nil
}

func fileMode(path string) os.FileMode {
	if info, err := os.Stat(path); err == nil {
		return info.Mode().Perm()
	}
	return 0o600
}

// atomicWrite writes data to path via a temp file + rename so a crash mid-write
// cannot leave a truncated config.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".gitops-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// --- notify events --------------------------------------------------------

func gitopsApplyEvent(e AppliedEntry) notify.Event {
	return notify.GitOpsEvent("applied", shortRev(e.Revision), e.Origin, e.Changed,
		fmt.Sprintf("Applied %d config change(s) from %s", e.Changed, e.Origin))
}

func gitopsDriftEvent(rev, origin string, changed int, reason, kind string) notify.Event {
	return notify.GitOpsEvent("drift", rev, origin, changed, reason).WithField("driftKind", kind)
}

func gitopsVerifyFailedEvent(rev, origin, reason string) notify.Event {
	return notify.GitOpsEvent("verify_failed", rev, origin, 0, reason)
}

func gitopsRollbackEvent(res RollbackResult, reason string) notify.Event {
	summary := fmt.Sprintf("Rolled back %s → %s", shortRev(res.RolledBackFrom), shortRev(res.RestoredTo))
	if reason != "" {
		summary += ": " + reason
	}
	return notify.GitOpsEvent("rolled_back", shortRev(res.RolledBackFrom), "", 0, summary)
}
