package proxy

import (
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/approvals"
	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
)

// approvalGate names a pull-path admission gate for the break-glass workflow. The
// value is the (tenant, ecosystem, coordinate, gate, reason) key's "gate"
// component and the audit/notify gate label.
type approvalGate string

const (
	approvalGateVulnscan      approvalGate = "vulnscan"
	approvalGateCVEDrift      approvalGate = "cve-drift"
	approvalGateMalfeed       approvalGate = "malfeed"
	approvalGateMaturity      approvalGate = "maturity"
	approvalGateDepFirewall   approvalGate = "depfirewall"
	approvalGateSigverify     approvalGate = "sigverify"
	approvalGatePolicy        approvalGate = "policy"
	approvalGateInstallHooks  approvalGate = "installhooks"
	approvalGateMLGuard       approvalGate = "mlguard"
	approvalGateAVScan        approvalGate = "avscan"
	approvalGateContentScan   approvalGate = "contentscan"
	approvalGateSbomDrift     approvalGate = "sbomdrift"
	approvalGateRebuildVerify approvalGate = "rebuildverify"
	approvalGateBuildProv     approvalGate = "buildprov"
	approvalGatePyPIAttest    approvalGate = "pypiattest"
	approvalGateSnapshot      approvalGate = "snapshot-freeze"
	approvalGateLockdown      approvalGate = "lockdown"
	approvalGateContinuity    approvalGate = "continuity"
)

// breakGlass consults the human-in-the-loop approval workflow for a block a gate
// is about to return. It returns true when an active, time-boxed break-glass
// grant covers the (tenant, ecosystem, coordinate, gate, reason) scope — in which
// case the gate should serve the artifact instead of refusing it. When it returns
// false (no grant, or the workflow is disabled), the workflow has recorded/updated
// a pending review for an operator and the gate must proceed to block.
//
// On an allowed (served-under-grant) outcome it records a tamper-evident audit
// entry and sets an advisory response header so the override is visible to the
// client and in the logs.
func (g *Gateway) breakGlass(w http.ResponseWriter, r *http.Request, gate approvalGate, backend, ecosystem, coordinate, reason string) bool {
	if g.deps.Approvals == nil || !g.deps.Approvals.Enabled() {
		return false
	}
	if coordinate == "" {
		// No concrete coordinate to scope an exception to; never override.
		return false
	}
	tenant, requester := "", ""
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		tenant = p.Team
		requester = p.Subject
	}
	disp := g.deps.Approvals.Consult(r.Context(), approvals.Scope{
		Tenant:     tenant,
		Ecosystem:  ecosystem,
		Coordinate: coordinate,
		Gate:       string(gate),
		Reason:     reason,
		Backend:    backend,
		Requester:  requester,
	})
	if !disp.Allow {
		return false
	}
	w.Header().Set("X-Approval-Decision", "break-glass")
	w.Header().Set("X-Approval-Request", disp.RequestID)
	g.metrics().IncPolicyDecision(ecosystem, "break-glass")
	g.auditBreakGlass(r, gate, backend, ecosystem, coordinate, reason, disp.RequestID)
	return true
}

// auditBreakGlass records that a blocked/quarantined artifact was served under an
// active break-glass grant, so the override is in the tamper-evident, Merkle-
// linked audit trail alongside the original gate decisions.
func (g *Gateway) auditBreakGlass(r *http.Request, gate approvalGate, backend, ecosystem, coordinate, reason, requestID string) {
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
		Decision:   audit.DecisionAllow,
		Reason:     "approvals:break-glass:" + string(gate),
		Detail: map[string]any{
			"event":       "break-glass-serve",
			"gate":        string(gate),
			"coordinate":  coordinate,
			"requestId":   requestID,
			"blockReason": reason,
		},
	}
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
		ev.Team = p.Team
	}
	g.logAudit(r.Context(), ev)
}
