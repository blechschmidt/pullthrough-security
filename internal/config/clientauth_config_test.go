package config

import (
	"strings"
	"testing"
	"time"
)

// validMTLSConfig is a baseline clientAuth.mtls config body with auth + TLS set,
// to which individual tests introduce a single defect.
const validMTLSConfig = `
server:
  httpAddr: ":8443"
  tlsCertFile: /tls/cert.pem
  tlsKeyFile: /tls/key.pem
auth:
  enabled: true
  roles:
    - name: reader
      ecosystems: ["*"]
      upstreams: ["*"]
clientAuth:
  mtls:
    enabled: true
    trustBundle: /spiffe/bundle.pem
    trustDomain: example.org
    reloadInterval: 1m
    rules:
      - pattern: "spiffe://example.org/ns/prod/sa/*"
        tenant: prod
        roles: ["reader"]
`

func TestClientAuthValidConfigLoads(t *testing.T) {
	path := writeConfig(t, validMTLSConfig)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	m := cfg.ClientAuth.MTLS
	if !m.Enabled || m.TrustDomain != "example.org" || len(m.Rules) != 1 {
		t.Fatalf("parsed mtls = %+v", m)
	}
	if m.ReloadInterval != time.Minute {
		t.Fatalf("reloadInterval = %v", m.ReloadInterval)
	}
	if m.Rules[0].Tenant != "prod" || m.Rules[0].Roles[0] != "reader" {
		t.Fatalf("rule = %+v", m.Rules[0])
	}
}

func TestClientAuthRequiresAuthEnabled(t *testing.T) {
	body := `
server:
  tlsCertFile: /tls/cert.pem
  tlsKeyFile: /tls/key.pem
clientAuth:
  mtls:
    enabled: true
    trustBundle: /spiffe/bundle.pem
    trustDomain: example.org
    rules:
      - pattern: "spiffe://example.org/**"
        tenant: prod
`
	if _, err := Load(writeConfig(t, body)); err == nil || !strings.Contains(err.Error(), "requires auth.enabled") {
		t.Fatalf("expected auth.enabled error, got %v", err)
	}
}

func TestClientAuthRequiresTrustBundle(t *testing.T) {
	body := strings.Replace(validMTLSConfig, "    trustBundle: /spiffe/bundle.pem\n", "", 1)
	if _, err := Load(writeConfig(t, body)); err == nil || !strings.Contains(err.Error(), "trustBundle is required") {
		t.Fatalf("expected trustBundle error, got %v", err)
	}
}

func TestClientAuthRequiresTLS(t *testing.T) {
	body := strings.Replace(validMTLSConfig,
		"  tlsCertFile: /tls/cert.pem\n  tlsKeyFile: /tls/key.pem\n", "", 1)
	if _, err := Load(writeConfig(t, body)); err == nil || !strings.Contains(err.Error(), "tlsCertFile") {
		t.Fatalf("expected TLS-required error, got %v", err)
	}
}

func TestClientAuthRejectsUndefinedRole(t *testing.T) {
	body := strings.Replace(validMTLSConfig, `roles: ["reader"]`, `roles: ["ghost"]`, 1)
	if _, err := Load(writeConfig(t, body)); err == nil || !strings.Contains(err.Error(), "undefined role") {
		t.Fatalf("expected undefined-role error, got %v", err)
	}
}

func TestClientAuthRejectsInvalidFormat(t *testing.T) {
	body := strings.Replace(validMTLSConfig,
		"    trustDomain: example.org\n",
		"    trustDomain: example.org\n    trustBundleFormat: bogus\n", 1)
	if _, err := Load(writeConfig(t, body)); err == nil || !strings.Contains(err.Error(), "trustBundleFormat") {
		t.Fatalf("expected format error, got %v", err)
	}
}

func TestClientAuthRequiresRules(t *testing.T) {
	body := `
server:
  tlsCertFile: /tls/cert.pem
  tlsKeyFile: /tls/key.pem
auth:
  enabled: true
  roles:
    - name: reader
      ecosystems: ["*"]
      upstreams: ["*"]
clientAuth:
  mtls:
    enabled: true
    trustBundle: /spiffe/bundle.pem
    trustDomain: example.org
`
	if _, err := Load(writeConfig(t, body)); err == nil || !strings.Contains(err.Error(), "at least one mapping rule") {
		t.Fatalf("expected rules-required error, got %v", err)
	}
}

func TestClientAuthDisabledIgnoresMTLS(t *testing.T) {
	body := `
auth:
  enabled: true
  allowAnonymous: true
clientAuth:
  mtls:
    enabled: false
    rules: []
`
	if _, err := Load(writeConfig(t, body)); err != nil {
		t.Fatalf("disabled mtls should not be validated: %v", err)
	}
}
