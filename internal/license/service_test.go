package license

import (
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/policy"
)

func newTestService(t *testing.T, cfg Config) *Service {
	t.Helper()
	svc, err := NewService(cfg, nil)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func TestService_Evaluate_AllowDenyFlag(t *testing.T) {
	svc := newTestService(t, Config{
		Base: PolicyConfig{
			Allow: []string{"MIT", "Apache-2.0"},
			Deny:  []string{"@strong-copyleft", "@network-copyleft"},
		},
	})

	// Allowed.
	d := svc.Evaluate("", []Component{{Ecosystem: "npm", Name: "lodash", Version: "1.0.0", Expression: "MIT", Primary: true}})
	if d.Action != policy.ActionAllow || d.Code != "ok" {
		t.Errorf("MIT decision = %+v, want allow/ok", d)
	}

	// Denied (GPL).
	d = svc.Evaluate("", []Component{{Ecosystem: "npm", Name: "copyleft-pkg", Version: "1.0.0", Expression: "GPL-3.0-only", Primary: true}})
	if d.Action != policy.ActionBlock || d.Code != "denied" {
		t.Errorf("GPL decision = %+v, want block/denied", d)
	}
	if len(d.Findings) != 1 || d.Findings[0].License != "GPL-3.0-only" {
		t.Errorf("findings = %+v", d.Findings)
	}

	// Unknown -> flagged (warn).
	d = svc.Evaluate("", []Component{{Ecosystem: "npm", Name: "mystery", Version: "1.0.0", Expression: "", Primary: true}})
	if d.Action != policy.ActionWarn || d.Code != "unknown" {
		t.Errorf("NOASSERTION decision = %+v, want warn/unknown", d)
	}

	m := svc.Metrics()
	if m.Evaluated != 3 || m.Allowed != 1 || m.Denied != 1 || m.Flagged != 1 {
		t.Errorf("metrics = %+v, want evaluated=3 allowed=1 denied=1 flagged=1", m)
	}
	if m.DeniedByLicense["GPL-3.0-only"] != 1 {
		t.Errorf("deniedByLicense = %+v", m.DeniedByLicense)
	}
}

func TestService_PerTenantOverride(t *testing.T) {
	svc := newTestService(t, Config{
		Base: PolicyConfig{
			Allow: []string{"MIT", "GPL-3.0-only"}, // base permits GPL
		},
		Tenants: map[string]PolicyConfig{
			"proprietary": {Deny: []string{"@strong-copyleft", "@network-copyleft"}},
		},
	})

	comp := []Component{{Ecosystem: "npm", Name: "x", Version: "1.0.0", Expression: "GPL-3.0-only", Primary: true}}

	// Base tenant: GPL allowed.
	if d := svc.Evaluate("oss", comp); d.Action != policy.ActionAllow {
		t.Errorf("oss GPL = %+v, want allow", d)
	}
	// Proprietary tenant: GPL denied (deny beats the base allow).
	if d := svc.Evaluate("proprietary", comp); d.Action != policy.ActionBlock {
		t.Errorf("proprietary GPL = %+v, want block", d)
	}
}

func TestService_DualLicensingAcrossComponents(t *testing.T) {
	svc := newTestService(t, Config{
		Base: PolicyConfig{
			Allow: []string{"MIT", "Apache-2.0"},
			Deny:  []string{"GPL-*"},
		},
	})
	// One component is dual-licensed (acceptable via OR); another is pure permissive.
	comps := []Component{
		{Ecosystem: "npm", Name: "dual", Version: "1.0.0", Expression: "GPL-3.0-only OR MIT", Primary: true},
		{Ecosystem: "npm", Name: "perm", Version: "2.0.0", Expression: "Apache-2.0"},
	}
	d := svc.Evaluate("", comps)
	if d.Action != policy.ActionAllow || d.Code != "ok" {
		t.Errorf("dual-licensing decision = %+v, want allow/ok", d)
	}
}

func TestService_DriftDetection(t *testing.T) {
	svc := newTestService(t, Config{
		Base:           PolicyConfig{Allow: []string{"MIT", "Apache-2.0", "GPL-3.0-only"}},
		DriftDetection: true,
	})
	clock := time.Unix(1_700_000_000, 0)
	svc.now = func() time.Time { clock = clock.Add(time.Second); return clock }

	// First version: MIT, no drift.
	d := svc.Evaluate("", []Component{{Ecosystem: "npm", Name: "shifty", Version: "1.0.0", Expression: "MIT", Primary: true}})
	if d.Code != "ok" {
		t.Fatalf("v1 decision = %+v, want ok", d)
	}
	// Second version: relicensed to GPL -> drift detected (and still warns even though GPL is allow-listed here).
	d = svc.Evaluate("", []Component{{Ecosystem: "npm", Name: "shifty", Version: "2.0.0", Expression: "GPL-3.0-only", Primary: true}})
	if d.Code != "drift" || d.Action != policy.ActionWarn {
		t.Errorf("v2 drift decision = %+v, want drift/warn", d)
	}
	if len(d.Findings) != 1 || !d.Findings[0].Drift || d.Findings[0].FromLicense != "mit" {
		t.Errorf("drift finding = %+v", d.Findings)
	}

	// Re-pulling v2 again: no new drift.
	d = svc.Evaluate("", []Component{{Ecosystem: "npm", Name: "shifty", Version: "2.0.0", Expression: "GPL-3.0-only", Primary: true}})
	if d.Code == "drift" {
		t.Errorf("re-pull should not re-flag drift: %+v", d)
	}

	if m := svc.Metrics(); m.DriftDetected != 1 {
		t.Errorf("driftDetected = %d, want 1", m.DriftDetected)
	}
	if got := svc.Drifts(); len(got) != 1 || got[0].ToLicense != "gpl-3.0-only" {
		t.Errorf("Drifts() = %+v", got)
	}
}

func TestService_DriftEscalatesDeniedNotDowngraded(t *testing.T) {
	// A denied license that also drifted must remain blocked, not be softened to a
	// drift-warn.
	svc := newTestService(t, Config{
		Base:           PolicyConfig{Allow: []string{"MIT"}, Deny: []string{"GPL-*"}},
		DriftDetection: true,
	})
	svc.Evaluate("", []Component{{Ecosystem: "npm", Name: "p", Version: "1.0.0", Expression: "MIT", Primary: true}})
	d := svc.Evaluate("", []Component{{Ecosystem: "npm", Name: "p", Version: "2.0.0", Expression: "GPL-3.0-only", Primary: true}})
	if d.Action != policy.ActionBlock || d.Code != "denied" {
		t.Errorf("denied+drift decision = %+v, want block/denied", d)
	}
	if len(d.Findings) != 1 || !d.Findings[0].Drift {
		t.Errorf("expected the denied finding to also carry the drift flag: %+v", d.Findings)
	}
}

func TestService_NilSafe(t *testing.T) {
	var svc *Service
	if d := svc.Evaluate("", nil); d.Action != policy.ActionAllow {
		t.Errorf("nil service Evaluate = %+v, want allow", d)
	}
}
