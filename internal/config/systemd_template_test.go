package config

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The systemd deployment (deploy/systemd, docs/systemd.md) renders its
// configuration from a template: deploy/systemd/install.sh drops the template's
// "#@" lines and replaces its @PLACEHOLDERS@ with sed. These tests render it the
// same way and hold the result to the validation the unit runs before every
// start (`pullthrough verify-config`), so a schema change that breaks the
// template fails here instead of on a host.

const (
	systemdTemplate  = "../../deploy/systemd/config.yaml.in"
	systemdInstaller = "../../deploy/systemd/install.sh"
)

var placeholderRE = regexp.MustCompile(`@[A-Z_]+@`)

// renderSystemdTemplate does what install.sh's sed does.
func renderSystemdTemplate(t *testing.T, values map[string]string) string {
	t.Helper()
	raw, err := os.ReadFile(systemdTemplate)
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for _, line := range strings.SplitAfter(string(raw), "\n") {
		if !strings.HasPrefix(line, "#@") {
			kept = append(kept, line)
		}
	}
	out := strings.Join(kept, "")
	for k, v := range values {
		out = strings.ReplaceAll(out, k, v)
	}
	if left := placeholderRE.FindAllString(out, -1); len(left) > 0 {
		t.Fatalf("placeholders left after rendering: %v", left)
	}
	return out
}

func sortedSet(items []string) []string {
	slices.Sort(items)
	return slices.Compact(items)
}

// TestSystemdTemplatePlaceholdersMatchTheInstaller: every placeholder the
// template uses is filled in by the installer and documented in the template,
// and the installer fills in nothing the template lacks.
func TestSystemdTemplatePlaceholdersMatchTheInstaller(t *testing.T) {
	raw, err := os.ReadFile(systemdTemplate)
	if err != nil {
		t.Fatal(err)
	}
	var used, documented []string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "#@") {
			documented = append(documented, placeholderRE.FindAllString(line, -1)...)
		} else {
			used = append(used, placeholderRE.FindAllString(line, -1)...)
		}
	}
	installer, err := os.ReadFile(systemdInstaller)
	if err != nil {
		t.Fatal(err)
	}
	var filled []string
	for _, m := range regexp.MustCompile(`s\|(@[A-Z_]+@)\|`).FindAllStringSubmatch(string(installer), -1) {
		filled = append(filled, m[1])
	}
	used, documented, filled = sortedSet(used), sortedSet(documented), sortedSet(filled)
	if len(used) == 0 {
		t.Fatal("the template uses no placeholders; is the path right?")
	}
	if !slices.Equal(used, filled) {
		t.Errorf("template uses %v, install.sh fills in %v", used, filled)
	}
	if !slices.Equal(used, documented) {
		t.Errorf("template uses %v, its #@ lines document %v", used, documented)
	}
}

func TestSystemdTemplateRendersToAValidConfig(t *testing.T) {
	hash := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	base := map[string]string{
		"@LISTEN@":            ":8443",
		"@PUBLIC_URL@":        "https://proxy.example.com:8443",
		"@CACHE_MAX_BYTES@":   "107374182400",
		"@CLIENT_TOKEN_HASH@": hash("client token"),
		"@ADMIN_TOKEN_HASH@":  hash("admin token"),
	}
	for _, tc := range []struct {
		name          string
		cert, key     string
		wantTLS       bool
		wantPublicURL string
	}{
		{name: "tls", cert: "/etc/pullthrough/tls/fullchain.pem", key: "/etc/pullthrough/tls/privkey.pem", wantTLS: true},
		// --tls-source not given: a load balancer in front terminates TLS.
		{name: "plain-http"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]string{"@TLS_CERT_FILE@": tc.cert, "@TLS_KEY_FILE@": tc.key}
			for k, v := range base {
				values[k] = v
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(renderSystemdTemplate(t, values)), 0o600); err != nil {
				t.Fatal(err)
			}

			// What `pullthrough verify-config` reports: nothing at all, not
			// even a warning.
			report, err := CheckFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !report.OK || len(report.Issues) > 0 {
				for _, is := range report.Issues {
					t.Errorf("%s %s: %s", is.Severity, is.Path, is.Message)
				}
				t.Fatalf("rendered template does not validate cleanly (ok=%v)", report.OK)
			}

			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			// The properties docs/systemd.md promises.
			if got := cfg.Server.TLSCertFile != "" && cfg.Server.TLSKeyFile != ""; got != tc.wantTLS {
				t.Errorf("TLS configured = %v, want %v", got, tc.wantTLS)
			}
			if cfg.Server.PublicURL != "https://proxy.example.com:8443" || cfg.Server.HTTPAddr != ":8443" {
				t.Errorf("server = %q / %q", cfg.Server.HTTPAddr, cfg.Server.PublicURL)
			}
			if !cfg.Auth.Enabled || cfg.Auth.AllowAnonymous {
				t.Errorf("auth.enabled=%v allowAnonymous=%v: every request must need a token", cfg.Auth.Enabled, cfg.Auth.AllowAnonymous)
			}
			if !cfg.AdminAuth.Enabled || len(cfg.AdminAuth.StaticTokens) == 0 {
				t.Error("the admin console must require the admin token")
			}
			for _, tok := range cfg.AdminAuth.StaticTokens {
				if tok.Token != "" {
					t.Errorf("admin token %q is stored in plaintext", tok.Name)
				}
			}
			for _, tok := range cfg.Auth.Tokens {
				if tok.Token != "" {
					t.Errorf("client token %q is stored in plaintext", tok.Name)
				}
			}
			if cfg.Observability.Metrics {
				t.Error("the unauthenticated metrics endpoint must stay off on a public listener")
			}
			if !strings.HasPrefix(cfg.Audit.HMACKey, "file:///etc/pullthrough/secrets/") {
				t.Errorf("audit.hmacKey = %q, want a file reference the installer creates", cfg.Audit.HMACKey)
			}
			if cfg.Cache.Backend != "filesystem" || !strings.HasPrefix(cfg.Cache.Dir, "/var/lib/pullthrough/") {
				t.Errorf("cache = %s %s, want the filesystem under /var/lib/pullthrough", cfg.Cache.Backend, cfg.Cache.Dir)
			}
			if cfg.Cache.MaxSizeBytes != 107374182400 {
				t.Errorf("cache.maxSizeBytes = %d", cfg.Cache.MaxSizeBytes)
			}
		})
	}
}
