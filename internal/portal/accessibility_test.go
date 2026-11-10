package portal

import (
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/uiaudit"
)

// TestPortalUIAccessibility enforces the documented WCAG 2.1 AA baseline
// against the embedded tenant self-service portal assets, mirroring the admin
// dashboard check. See docs/accessibility.md.
func TestPortalUIAccessibility(t *testing.T) {
	findings, err := uiaudit.Audit(portalFS)
	if err != nil {
		t.Fatalf("auditing embedded portal UI: %v", err)
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
