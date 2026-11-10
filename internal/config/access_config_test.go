package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/secrets"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestAuthValidationRejectsUndefinedRole(t *testing.T) {
	path := writeConfig(t, `
auth:
  enabled: true
  roles:
    - name: npm-reader
      ecosystems: ["npm"]
      upstreams: ["*"]
  tokens:
    - name: bot
      token: a-sufficiently-long-token-value
      roles: ["does-not-exist"]
`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "undefined role") {
		t.Fatalf("expected undefined-role error, got %v", err)
	}
}

func TestAuthValidationRequiresAuthMethod(t *testing.T) {
	path := writeConfig(t, `
auth:
  enabled: true
  roles:
    - name: r
      ecosystems: ["*"]
      upstreams: ["*"]
`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "no tokens") {
		t.Fatalf("expected no-auth-method error, got %v", err)
	}
}

func TestTokenRequiresExactlyOneSecret(t *testing.T) {
	path := writeConfig(t, `
auth:
  enabled: true
  roles:
    - {name: r, ecosystems: ["*"], upstreams: ["*"]}
  tokens:
    - name: bot
      token: a-long-token-value-here-1234
      tokenHash: "sha256:deadbeef"
      roles: ["r"]
`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("expected exactly-one error, got %v", err)
	}
}

func TestAuditValidationRequiresKey(t *testing.T) {
	path := writeConfig(t, `
audit:
  enabled: true
  file: /tmp/audit.log
`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "hmacKey") {
		t.Fatalf("expected hmac key error, got %v", err)
	}
}

func TestEncryptedSecretDecryptedAtRest(t *testing.T) {
	// Derive the same key the config will, then encrypt an upstream token.
	passphrase, salt := "test-passphrase", "stable-salt-value"
	key, err := secrets.DeriveKey(passphrase, []byte(salt))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	cipher, err := secrets.NewCipher(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	encToken, err := cipher.EncryptString("super-secret-upstream-token")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	path := writeConfig(t, `
secrets:
  passphrase: `+passphrase+`
  salt: `+salt+`
upstreams:
  corp-npm:
    type: npm
    url: https://registry.npmjs.org
    credentials:
      token: "`+encToken+`"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got := cfg.Upstreams["corp-npm"].Credentials.Token
	if got != "super-secret-upstream-token" {
		t.Fatalf("token not decrypted at rest: %q", got)
	}
}

func TestEncryptedSecretWithoutKeyFails(t *testing.T) {
	path := writeConfig(t, `
upstreams:
  corp-npm:
    type: npm
    url: https://registry.npmjs.org
    credentials:
      token: "enc:v1:AAAAAAAAAAAAAAAAAAAA"
`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "decrypt") {
		t.Fatalf("expected decryption error when no key configured, got %v", err)
	}
}

func TestExampleConfigLoads(t *testing.T) {
	// The shipped example must always be loadable so it stays a good starting
	// point. With auth/audit disabled it requires no environment.
	if _, err := Load("../../configs/config.example.yaml"); err != nil {
		t.Fatalf("example config failed to load: %v", err)
	}
}

func TestAuthDisabledSkipsValidation(t *testing.T) {
	// A token with an undefined role is fine when auth is disabled.
	path := writeConfig(t, `
auth:
  enabled: false
  tokens:
    - name: bot
      token: short
      roles: ["whatever"]
`)
	if _, err := Load(path); err != nil {
		t.Fatalf("disabled auth should skip validation, got %v", err)
	}
}
