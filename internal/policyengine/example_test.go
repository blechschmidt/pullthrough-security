package policyengine

import (
	"os"
	"testing"
)

// TestShippedExampleBundleCompiles guards the example bundle we ship under
// deploy/policies against drift: it must always parse and compile cleanly when
// layered over the embedded default bundle, exactly as a deployment would load it.
func TestShippedExampleBundleCompiles(t *testing.T) {
	const path = "../../deploy/policies/org-rules.example.yaml"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	b, err := ParseBundle(data)
	if err != nil {
		t.Fatalf("parse example bundle: %v", err)
	}
	def, err := DefaultBundle()
	if err != nil {
		t.Fatalf("default bundle: %v", err)
	}
	rs, err := CompileRuleSet([]*Bundle{def, b}, CompileOptions{})
	if err != nil {
		t.Fatalf("compile example bundle over default: %v", err)
	}
	if rs.RuleCount() == 0 {
		t.Fatal("expected compiled rules")
	}
}
