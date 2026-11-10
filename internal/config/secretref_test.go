package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/secrets"
)

func TestValidateSecretsVault(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{
			name:   "disabled skips validation",
			mutate: func(c *Config) { c.Secrets.Vault = VaultConfig{Enabled: false, AuthMethod: "bogus"} },
			want:   "",
		},
		{
			name:   "enabled requires address",
			mutate: func(c *Config) { c.Secrets.Vault = VaultConfig{Enabled: true, Token: "t"} },
			want:   "secrets.vault.address",
		},
		{
			name: "token auth requires token",
			mutate: func(c *Config) {
				c.Secrets.Vault = VaultConfig{Enabled: true, Address: "https://v:8200", AuthMethod: "token"}
			},
			want: "requires secrets.vault.token",
		},
		{
			name: "approle requires roleId and secretId",
			mutate: func(c *Config) {
				c.Secrets.Vault = VaultConfig{Enabled: true, Address: "https://v:8200", AuthMethod: "approle", RoleID: "r"}
			},
			want: "roleId and secretId",
		},
		{
			name: "unknown auth method",
			mutate: func(c *Config) {
				c.Secrets.Vault = VaultConfig{Enabled: true, Address: "https://v:8200", AuthMethod: "ldap", Token: "t"}
			},
			want: "unknown secrets.vault.authMethod",
		},
		{
			name: "valid token auth",
			mutate: func(c *Config) {
				c.Secrets.Vault = VaultConfig{Enabled: true, Address: "https://v:8200", Token: "t"}
			},
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Default()
			c.Server.HTTPAddr = ":8080"
			tc.mutate(&c)
			err := c.validateSecrets()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("want valid, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestResolveRefsEnvAndFile(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "s3secret")
	if err := os.WriteFile(keyFile, []byte("file-secret-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PTS_TEST_APIKEY", "env-llm-key")

	c := Default()
	c.Server.HTTPAddr = ":8080"
	c.Scanning.APIKey = "env://PTS_TEST_APIKEY"
	c.Cache.S3.SecretAccessKey = "file://" + keyFile
	c.Cache.S3.AccessKeyID = "literal-access-id" // plain literal unchanged
	c.Upstreams = map[string]UpstreamConfig{
		"npm": {Type: "npm", URL: "https://registry.npmjs.org", Credentials: Credentials{Token: "env://PTS_TEST_APIKEY"}},
	}

	resolver := secrets.NewResolver(nil)
	defer resolver.Close()
	if err := ResolveRefs(context.Background(), &c, resolver); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if c.Scanning.APIKey != "env-llm-key" {
		t.Fatalf("apiKey: %q", c.Scanning.APIKey)
	}
	if c.Cache.S3.SecretAccessKey != "file-secret-key" {
		t.Fatalf("s3 secret: %q", c.Cache.S3.SecretAccessKey)
	}
	if c.Cache.S3.AccessKeyID != "literal-access-id" {
		t.Fatalf("literal mutated: %q", c.Cache.S3.AccessKeyID)
	}
	if got := c.Upstreams["npm"].Credentials.Token; got != "env-llm-key" {
		t.Fatalf("upstream token: %q", got)
	}
}

func TestResolveRefsErrorNamesFieldNotValue(t *testing.T) {
	c := Default()
	c.Server.HTTPAddr = ":8080"
	c.Scanning.APIKey = "env://PTS_TEST_DEFINITELY_MISSING"

	resolver := secrets.NewResolver(nil)
	defer resolver.Close()
	err := ResolveRefs(context.Background(), &c, resolver)
	if err == nil {
		t.Fatalf("expected error for missing env var")
	}
	if !strings.Contains(err.Error(), "scanning.apiKey") {
		t.Fatalf("error should name the field, got %v", err)
	}
}

func TestFingerprintRedactsSecretValues(t *testing.T) {
	base := Default()
	base.Server.HTTPAddr = ":8080"
	base.Scanning.APIKey = "secret-one"

	rotated := Default()
	rotated.Server.HTTPAddr = ":8080"
	rotated.Scanning.APIKey = "secret-two" // only the secret value differs

	if Fingerprint(&base) != Fingerprint(&rotated) {
		t.Fatalf("a changed secret value must not change the fingerprint (redaction)")
	}

	// Adding/removing a secret (empty vs set) is still structural drift.
	empty := Default()
	empty.Server.HTTPAddr = ":8080"
	if Fingerprint(&base) == Fingerprint(&empty) {
		t.Fatalf("setting vs clearing a secret must change the fingerprint")
	}

	// A non-secret change is still detected.
	nonSecret := Default()
	nonSecret.Server.HTTPAddr = ":9090"
	nonSecret.Scanning.APIKey = "secret-one"
	if Fingerprint(&base) == Fingerprint(&nonSecret) {
		t.Fatalf("a non-secret change must change the fingerprint")
	}
}

func TestFingerprintDoesNotMutateConfig(t *testing.T) {
	c := Default()
	c.Server.HTTPAddr = ":8080"
	c.Scanning.APIKey = "keep-me"
	c.Upstreams = map[string]UpstreamConfig{
		"npm": {Type: "npm", URL: "https://registry.npmjs.org", Credentials: Credentials{Token: "tok"}},
	}
	_ = Fingerprint(&c)
	if c.Scanning.APIKey != "keep-me" {
		t.Fatalf("Fingerprint mutated a secret field: %q", c.Scanning.APIKey)
	}
	if c.Upstreams["npm"].Credentials.Token != "tok" {
		t.Fatalf("Fingerprint mutated an upstream credential")
	}
}
