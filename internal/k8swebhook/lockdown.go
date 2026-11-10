package k8swebhook

import "github.com/blechschmidt/pullthrough-security/internal/lockdown"

// LockdownAdapter adapts the emergency-lockdown service (Task 74) to the narrow
// LockdownOracle the webhook consults. It is nil-safe end to end: a nil service
// (the subsystem disabled or unwired) reports no lockdown, so the webhook's
// kill-switch integration is simply inert.
type LockdownAdapter struct {
	svc *lockdown.Service
}

// NewLockdownAdapter wraps a *lockdown.Service. A nil service yields an adapter
// that always reports "no lockdown".
func NewLockdownAdapter(svc *lockdown.Service) *LockdownAdapter {
	return &LockdownAdapter{svc: svc}
}

// BlockedCoordinate consults the targeted-block list exactly as the pull path's
// FIRST-check gate does (internal/proxy/lockdown.go), so a coordinate denied at
// the pull boundary is denied at the cluster boundary too.
func (a *LockdownAdapter) BlockedCoordinate(ecosystem, name, version string) (bool, string, string) {
	if a == nil || a.svc == nil {
		return false, "", ""
	}
	dec := a.svc.Check(lockdown.Coordinate{Ecosystem: ecosystem, Name: name, Version: version})
	if !dec.Blocked {
		return false, "", dec.IncidentID
	}
	return true, dec.Reason, dec.IncidentID
}

// Active reports whether any lockdown posture is engaged. While engaged, the
// webhook denies un-vetted ("unknown") images regardless of the configured
// unknownAction — the cluster boundary flips fail-open to fail-closed during an
// incident.
func (a *LockdownAdapter) Active() (bool, string, string) {
	if a == nil || a.svc == nil || !a.svc.Enabled() {
		return false, "", ""
	}
	mode := a.svc.Mode()
	if mode == lockdown.ModeOff {
		return false, "", ""
	}
	return true, string(mode), a.svc.IncidentID()
}
