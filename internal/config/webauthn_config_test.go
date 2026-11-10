package config

import (
	"strings"
	"testing"
	"time"
)

func TestWebAuthnValidation(t *testing.T) {
	// Defaults keep the subsystem disabled, so the default config validates.
	def := Default()
	if err := def.Validate(); err != nil {
		t.Fatalf("default config (webauthn) rejected: %v", err)
	}

	valid := func() *Config {
		c := Default()
		c.WebAuthn = WebAuthnConfig{
			Enabled:      true,
			RPID:         "example.com",
			RPName:       "Pullthrough Admin",
			Origins:      []string{"https://admin.example.com"},
			ChallengeTTL: 2 * time.Minute,
			StepUpTTL:    5 * time.Minute,
			StorePath:    "/var/lib/pt/webauthn.json",
		}
		return &c
	}
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid webauthn config rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"missing rpId", func(c *Config) { c.WebAuthn.RPID = "" }, "webauthn.rpId is required"},
		{"no origins", func(c *Config) { c.WebAuthn.Origins = nil }, "webauthn.origins"},
		{"empty origin", func(c *Config) { c.WebAuthn.Origins = []string{""} }, "must not be empty"},
		{"http origin", func(c *Config) { c.WebAuthn.Origins = []string{"http://admin.example.com"} }, "must be an https://"},
		{"negative ttl", func(c *Config) { c.WebAuthn.StepUpTTL = -time.Second }, "TTLs must not be negative"},
		{"ttl too long", func(c *Config) { c.WebAuthn.StepUpTTL = 2 * time.Hour }, "must not exceed 1h"},
		{"bad protected action", func(c *Config) { c.WebAuthn.ProtectedActions = []string{"/admin/api/x"} }, "must be an admin API path"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := valid()
			tc.mutate(c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}

	// localhost over http is permitted (developer convenience).
	c := valid()
	c.WebAuthn.RPID = "localhost"
	c.WebAuthn.Origins = []string{"http://localhost:8080"}
	if err := c.Validate(); err != nil {
		t.Errorf("localhost http origin should be allowed: %v", err)
	}
}

// TestWebAuthnDisabledSkipsValidation confirms a disabled subsystem is not
// validated, so a half-specified disabled block does not block startup.
func TestWebAuthnDisabledSkipsValidation(t *testing.T) {
	body := `
webauthn:
  enabled: false
  origins: []
`
	if _, err := Load(writeConfig(t, body)); err != nil {
		t.Fatalf("disabled webauthn should not be validated: %v", err)
	}
}

// TestWebAuthnDefaults confirms the OrDefault helpers default on.
func TestWebAuthnDefaults(t *testing.T) {
	var c WebAuthnConfig
	if !c.EnforceOrDefault() {
		t.Error("enforce should default to true")
	}
	if !c.RequireUserVerificationOrDefault() {
		t.Error("requireUserVerification should default to true")
	}
	if !c.AllowUnverifiedAttestationOrDefault() {
		t.Error("allowUnverifiedAttestation should default to true")
	}
	f := false
	c.Enforce = &f
	c.RequireUserVerification = &f
	c.AllowUnverifiedAttestation = &f
	if c.EnforceOrDefault() || c.RequireUserVerificationOrDefault() || c.AllowUnverifiedAttestationOrDefault() {
		t.Error("explicit false must be honored")
	}
}
