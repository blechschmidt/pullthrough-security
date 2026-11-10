package config

import (
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends/generic"
)

// TestValidateGenericBackend_Valid confirms a well-formed generic upstream — a
// metadata rewrite route plus a checksum-verified artifact route — passes
// configuration validation (the load-time gate the backend also enforces).
func TestValidateGenericBackend_Valid(t *testing.T) {
	c := Default()
	c.Upstreams = map[string]UpstreamConfig{
		"mysource": {
			Type: "generic",
			URL:  "https://repo.example.com",
			Generic: &generic.BackendConfig{
				PublicBaseURL: "https://proxy.example.com/v1/mysource",
				Routes: []generic.RouteConfig{
					{Name: "meta", Match: `^/index/.+\.json$`, Rewrite: true},
					{
						Name: "artifact", Match: `^/dist/.+\.tar\.gz$`, Cacheable: true,
						Gates:  []string{"contentscan", "avscan"},
						Verify: &generic.VerifyConfig{Algorithm: "sha256", SidecarSuffix: ".sha256"},
					},
					{
						Name: "cas", Match: `^/cas/([0-9a-f]{64})$`, Cacheable: true,
						Verify: &generic.VerifyConfig{Algorithm: "sha256", Source: "path", DigestGroup: 1},
					},
				},
			},
		},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("expected valid generic config, got %v", err)
	}
}

// TestValidateGenericBackend_Errors confirms unsafe/incoherent generic configs
// are rejected at load time.
func TestValidateGenericBackend_Errors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{
			name: "missing generic block",
			mutate: func(c *Config) {
				c.Upstreams = map[string]UpstreamConfig{
					"x": {Type: "generic", URL: "https://x.example.com"},
				}
			},
			want: "configuration block is required",
		},
		{
			name: "bad regexp",
			mutate: func(c *Config) {
				c.Upstreams = map[string]UpstreamConfig{
					"x": {Type: "generic", URL: "https://x.example.com", Generic: &generic.BackendConfig{
						Routes: []generic.RouteConfig{{Match: "("}},
					}},
				}
			},
			want: "invalid match regexp",
		},
		{
			name: "rewrite plus cacheable",
			mutate: func(c *Config) {
				c.Upstreams = map[string]UpstreamConfig{
					"x": {Type: "generic", URL: "https://x.example.com", Generic: &generic.BackendConfig{
						Routes: []generic.RouteConfig{{Match: "^/x$", Rewrite: true, Cacheable: true}},
					}},
				}
			},
			want: "mutually exclusive",
		},
		{
			name: "unknown gate",
			mutate: func(c *Config) {
				c.Upstreams = map[string]UpstreamConfig{
					"x": {Type: "generic", URL: "https://x.example.com", Generic: &generic.BackendConfig{
						Routes: []generic.RouteConfig{{Match: "^/x$", Gates: []string{"nonsense"}}},
					}},
				}
			},
			want: "unknown content gate",
		},
		{
			name: "generic block on non-generic type",
			mutate: func(c *Config) {
				c.Upstreams = map[string]UpstreamConfig{
					"x": {Type: "npm", URL: "https://registry.npmjs.org", Generic: &generic.BackendConfig{
						Routes: []generic.RouteConfig{{Match: "^/x$"}},
					}},
				}
			},
			want: "only applies to type",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Default()
			tc.mutate(&c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

// TestGenericBackend_StrictDecode confirms the generic block round-trips through
// the strict (unknown-key-rejecting) YAML decoder used by preflight validation,
// so the declarative schema is accepted end-to-end.
func TestGenericBackend_StrictDecode(t *testing.T) {
	yaml := `
server:
  httpAddr: ":8080"
cache:
  backend: memory
upstreams:
  mysource:
    type: generic
    url: https://repo.example.com
    generic:
      publicBaseURL: https://proxy.example.com/v1/mysource
      maxRewriteBytes: 1048576
      routes:
        - name: meta
          match: '^/index/.+\.json$'
          rewrite: true
        - name: artifact
          match: '^/dist/.+\.tar\.gz$'
          cacheable: true
          mediaType: application/gzip
          gates: [contentscan, avscan]
          verify:
            algorithm: sha256
            source: sidecar
            sidecarSuffix: .sha256
`
	report := CheckBytes([]byte(yaml))
	if report.Errors > 0 {
		t.Fatalf("strict decode reported errors: %+v", report.Issues)
	}
}
