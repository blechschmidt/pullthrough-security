package admin

import (
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/uiaudit"
)

// TestAdminUIAccessibility enforces the WCAG 2.1 AA baseline documented in
// docs/accessibility.md against the embedded admin dashboard assets (the SPA
// shell, the SOC/dossier/timeline views and the supply-chain graph page). It is
// the lightweight, always-runnable "axe-core equivalent" check the task calls
// for: no browser or Node toolchain required.
func TestAdminUIAccessibility(t *testing.T) {
	findings, err := uiaudit.Audit(dashboardFS)
	if err != nil {
		t.Fatalf("auditing embedded admin UI: %v", err)
	}
	for _, f := range findings {
		t.Logf("[%s] %s: %s (%s)", f.Severity, f.File, f.Detail, f.Rule)
	}
	if errs := uiaudit.Errors(findings); len(errs) != 0 {
		for _, f := range errs {
			t.Errorf("accessibility: %s: %s (%s)", f.File, f.Detail, f.Rule)
		}
	}
}
