package proxy

import (
	"encoding/json"
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/snapshot"
)

// The organization-wide dependency snapshot / freeze / instant-rollback subsystem
// (Task 70) integrates with the pull path in two places:
//
//   - gateSnapshotFreeze runs early, right after the dependency firewall, as a
//     freeze gate. When a freeze is active and enforcement is on, it refuses any
//     pull whose concrete (ecosystem, name, version) is outside the frozen
//     snapshot's coordinate set, or whose served digest differs from the frozen
//     one — forcing the whole organization to the exact set of safe digests a
//     snapshot captured. It composes with the break-glass workflow.
//
//   - recordSnapshot runs after admission (alongside the outbound attestation),
//     folding every served coordinate's resolved state into the live state from
//     which a point-in-time snapshot is later captured.

// gateSnapshotFreeze runs the freeze gate on a resolved coordinate. Like the
// dependency firewall it needs no artifact content — only the concrete
// (ecosystem, name, version) and (best-effort) the served digest — so it runs
// early, between resolution and retrieval. It returns true when the request may
// proceed and false when it has been blocked and a response written.
func (g *Gateway) gateSnapshotFreeze(w http.ResponseWriter, r *http.Request, name, ecosystem string, resolved *backends.Resolved) bool {
	if g.deps.Snapshot == nil || !g.deps.Snapshot.Enabled() {
		return true
	}
	c := resolved.Coordinate
	if c.Name == "" || c.Version == "" {
		// Listing/index request: nothing concrete to freeze against.
		return true
	}

	dec := g.deps.Snapshot.CheckFreeze(ecosystem, c.Name, c.Version, resolved.Digest)
	if !dec.Frozen || !dec.Blocked {
		return true
	}

	coordinate := c.Name + "@" + c.Version

	// Human-in-the-loop break-glass (Task 50): in quarantine mode an operator may
	// have granted a time-boxed exception for this exact coordinate while the
	// freeze stands; serve it instead of refusing.
	if dec.Quarantine && g.breakGlass(w, r, approvalGateSnapshot, name, ecosystem, coordinate, dec.Code) {
		return true
	}

	g.metrics().IncPolicyDecision(ecosystem, "block")
	g.auditSnapshotFreeze(r, name, ecosystem, coordinate, dec)
	g.notifySnapshotFreeze(r, name, ecosystem, coordinate, dec)
	g.deps.Logger.Warn("organization freeze blocked pull outside the frozen set",
		"backend", name, "ecosystem", ecosystem, "package", c.Name, "version", c.Version,
		"code", dec.Code, "snapshotId", dec.SnapshotID, "reason", dec.Reason)
	writeSnapshotFreezeBlock(w, dec, ecosystem, c.Name, c.Version)
	return false
}

// snapshotFreezeError is the actionable JSON body returned when the freeze gate
// refuses a pull.
type snapshotFreezeError struct {
	Error          string `json:"error"`
	Code           string `json:"code"`
	Reason         string `json:"reason"`
	Ecosystem      string `json:"ecosystem,omitempty"`
	Package        string `json:"package,omitempty"`
	Version        string `json:"version,omitempty"`
	SnapshotID     string `json:"snapshotId,omitempty"`
	SnapshotName   string `json:"snapshotName,omitempty"`
	ExpectedDigest string `json:"expectedDigest,omitempty"`
}

func writeSnapshotFreezeBlock(w http.ResponseWriter, dec snapshot.FreezeDecision, ecosystem, name, version string) {
	body := snapshotFreezeError{
		Error:          "pull refused: the organization is frozen to a dependency snapshot and this coordinate is outside the frozen set",
		Code:           dec.Code,
		Reason:         dec.Reason,
		Ecosystem:      ecosystem,
		Package:        name,
		Version:        version,
		SnapshotID:     dec.SnapshotID,
		SnapshotName:   dec.SnapshotName,
		ExpectedDigest: dec.ExpectedDigest,
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Snapshot-Freeze", "block")
	h.Set("X-Snapshot-Freeze-Code", dec.Code)
	h.Set("X-Snapshot-Id", dec.SnapshotID)
	h.Set("X-Cache", "BLOCKED")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}

func (g *Gateway) auditSnapshotFreeze(r *http.Request, backend, ecosystem, coordinate string, dec snapshot.FreezeDecision) {
	if g.deps.Audit == nil {
		return
	}
	ev := audit.Event{
		Type:       audit.EventPolicy,
		Method:     r.Method,
		Backend:    backend,
		Ecosystem:  ecosystem,
		Resource:   r.URL.Path,
		RemoteAddr: clientIP(r),
		Decision:   audit.DecisionDeny,
		Status:     http.StatusForbidden,
		Reason:     "snapshot-freeze:" + dec.Code,
		Detail: map[string]any{
			"coordinate":     coordinate,
			"code":           dec.Code,
			"snapshotId":     dec.SnapshotID,
			"snapshotName":   dec.SnapshotName,
			"expectedDigest": dec.ExpectedDigest,
		},
	}
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
		ev.Team = p.Team
	}
	g.logAudit(r.Context(), ev)
}

func (g *Gateway) notifySnapshotFreeze(r *http.Request, backend, ecosystem, coordinate string, dec snapshot.FreezeDecision) {
	if g.deps.Notify == nil {
		return
	}
	ev := notify.SnapshotFreezeBlockEvent(ecosystem, backend, coordinate, dec.Code, dec.SnapshotID, dec.Reason)
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
	}
	g.emit(r.Context(), ev)
}

// recordSnapshot folds the served coordinate's resolved state into the snapshot
// live state. It runs on the admitted/served path (alongside the outbound
// attestation), reusing the same per-request signal accumulator so it adds no
// scanning work. It is best-effort and never affects serving.
func (g *Gateway) recordSnapshot(r *http.Request, backend, ecosystem string) {
	if g.deps.Snapshot == nil || !g.deps.Snapshot.Enabled() {
		return
	}
	s := signalsFrom(r.Context())
	if s == nil {
		return
	}
	s.mu.Lock()
	in := s.input
	risk := s.risk
	s.mu.Unlock()

	art := in.Artifact
	if art.Name == "" || art.Version == "" {
		// No concrete coordinate (a listing/index request) — nothing to record.
		return
	}

	entry := snapshot.Entry{
		Tenant:    in.Tenant,
		Ecosystem: ecosystem,
		Name:      art.Name,
		Version:   art.Version,
		Digest:    art.Digest,
		Verdict:   "admit",
	}
	if entry.Ecosystem == "" {
		entry.Ecosystem = art.Ecosystem
	}
	if p := in.Provenance; p != nil {
		entry.SourceCommit = p.CommitSHA
		entry.RepositoryURL = p.RepositoryURL
	}
	if risk != nil {
		entry.RiskScore = risk.Score
		entry.RiskBand = risk.Band
		if risk.Action == "warn" {
			entry.Verdict = "warn"
		}
	}
	// Bind the proxy's outbound attestation bundle digest for this artifact, when
	// one was produced (Task 46), so a snapshot row carries the verifiable
	// attestation reference alongside the served digest.
	if g.deps.Attestor != nil {
		if b, ok := g.deps.Attestor.Get(in.Tenant, art.Name+"@"+art.Version); ok && b != nil {
			entry.AttestationDigest = b.Digest
			if entry.Digest == "" {
				entry.Digest = b.SubjectDigest
			}
		}
	}

	g.deps.Snapshot.Record(entry)
}
