package config

import (
	"strings"
	"testing"
)

// baseSigverify returns a Default config with a minimally-valid enabled
// sigverify gate, for exercising the PQC validation branches.
func baseSigverify() Config {
	c := Default()
	c.Sigverify.Enabled = true
	c.Sigverify.Action = "block"
	c.Sigverify.FailSeverity = "high"
	c.Sigverify.WarnSeverity = "medium"
	return c
}

func TestValidateSigverifyPQCPolicy(t *testing.T) {
	for _, policy := range []string{"", "classical-only", "allow-hybrid", "require-pqc"} {
		c := baseSigverify()
		c.Sigverify.PQC.Enabled = true
		c.Sigverify.PQC.Policy = policy
		if err := c.Validate(); err != nil {
			t.Errorf("policy %q: unexpected error %v", policy, err)
		}
	}
	c := baseSigverify()
	c.Sigverify.PQC.Enabled = true
	c.Sigverify.PQC.Policy = "bogus"
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "sigverify.pqc.policy") {
		t.Fatalf("expected pqc.policy validation error, got %v", err)
	}
}

func TestValidateSigverifyPQCUnderFIPS(t *testing.T) {
	// PQC enabled while FIPS is enabled must fail preflight: the provider is not
	// FIPS 140-3 validated.
	c := baseSigverify()
	c.FIPS.Enabled = true
	c.Outbound.TLS.MinVersion = "1.2"
	c.Sigverify.PQC.Enabled = true
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "fips.enabled") {
		t.Fatalf("expected FIPS/PQC incompatibility error, got %v", err)
	}

	// PQC disabled under FIPS is fine.
	c2 := baseSigverify()
	c2.FIPS.Enabled = true
	c2.Outbound.TLS.MinVersion = "1.2"
	c2.Sigverify.PQC.Enabled = false
	if err := c2.Validate(); err != nil {
		t.Fatalf("FIPS without PQC should validate, got %v", err)
	}

	// PQC enabled without FIPS is fine.
	c3 := baseSigverify()
	c3.Sigverify.PQC.Enabled = true
	if err := c3.Validate(); err != nil {
		t.Fatalf("PQC without FIPS should validate, got %v", err)
	}
}
