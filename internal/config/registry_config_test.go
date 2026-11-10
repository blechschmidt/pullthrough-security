package config

import (
	"strings"
	"testing"
)

func baseRegistryConfig() *Config {
	c := Default()
	c.Upstreams = map[string]UpstreamConfig{
		"dockerhub": {Type: "docker", URL: "https://registry-1.docker.io"},
		"charts":    {Type: "helm", URL: "https://registry-1.docker.io", Settings: map[string]string{"oci": "true"}},
		"npm":       {Type: "npm", URL: "https://registry.npmjs.org"},
	}
	return &c
}

func TestRegistryEnabledOrDefault(t *testing.T) {
	if !(RegistryConfig{}).EnabledOrDefault() {
		t.Error("the registry alias must default to enabled")
	}
	on, off := true, false
	if !(RegistryConfig{Enabled: &on}).EnabledOrDefault() {
		t.Error("enabled: true must enable the alias")
	}
	if (RegistryConfig{Enabled: &off}).EnabledOrDefault() {
		t.Error("enabled: false must disable the alias")
	}
}

func TestIsRegistryUpstream(t *testing.T) {
	cases := []struct {
		up   UpstreamConfig
		want bool
	}{
		{UpstreamConfig{Type: "docker"}, true},
		{UpstreamConfig{Type: "helm", Settings: map[string]string{"oci": "true"}}, true},
		{UpstreamConfig{Type: "helm", Settings: map[string]string{"oci": " TRUE "}}, true},
		{UpstreamConfig{Type: "helm"}, false}, // classic chart repository
		{UpstreamConfig{Type: "helm", Settings: map[string]string{"oci": "false"}}, false},
		{UpstreamConfig{Type: "npm"}, false},
	}
	for _, tc := range cases {
		if got := tc.up.IsRegistryUpstream(); got != tc.want {
			t.Errorf("IsRegistryUpstream(%+v) = %v, want %v", tc.up, got, tc.want)
		}
	}
}

func TestValidateRegistry_OK(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"defaults":                func(*Config) {},
		"docker default upstream": func(c *Config) { c.Server.Registry.DefaultUpstream = "dockerhub" },
		"oci-helm default":        func(c *Config) { c.Server.Registry.DefaultUpstream = "charts" },
		"disabled":                func(c *Config) { off := false; c.Server.Registry.Enabled = &off },
		"no registry upstream": func(c *Config) {
			c.Upstreams = map[string]UpstreamConfig{"npm": {Type: "npm", URL: "https://registry.npmjs.org"}}
		},
		"v2 admin without docker": func(c *Config) {
			delete(c.Upstreams, "dockerhub")
			delete(c.Upstreams, "charts")
			c.Observability.AdminPathPrefix = "/v2"
		},
		"v2 admin, alias disabled": func(c *Config) {
			off := false
			c.Server.Registry.Enabled = &off
			c.Observability.AdminPathPrefix = "/v2"
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := baseRegistryConfig()
			mutate(c)
			if err := c.Validate(); err != nil {
				t.Fatalf("expected a valid config, got %v", err)
			}
		})
	}
}

func TestValidateRegistry_Errors(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"unknown default upstream", func(c *Config) { c.Server.Registry.DefaultUpstream = "nope" }, "unknown upstream"},
		{"default upstream is not a registry", func(c *Config) { c.Server.Registry.DefaultUpstream = "npm" }, "not a registry upstream"},
		{"default upstream is disabled", func(c *Config) {
			off := false
			up := c.Upstreams["dockerhub"]
			up.Enabled = &off
			c.Upstreams["dockerhub"] = up
			c.Server.Registry.DefaultUpstream = "dockerhub"
		}, "disabled upstream"},
		{"default upstream with the alias disabled", func(c *Config) {
			off := false
			c.Server.Registry.Enabled = &off
			c.Server.Registry.DefaultUpstream = "dockerhub"
		}, "enabled is false"},
		{"admin prefix inside the alias", func(c *Config) { c.Observability.AdminPathPrefix = "/v2" }, "collides"},
		{"admin prefix below the alias", func(c *Config) { c.Observability.AdminPathPrefix = "/v2/admin/" }, "collides"},
		{"metrics path inside the alias", func(c *Config) { c.Observability.MetricsPath = "/v2/metrics" }, "collides"},
		{"webhook path inside the alias", func(c *Config) { c.Scanning.Watch.WebhookPath = "/v2/hooks" }, "collides"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := baseRegistryConfig()
			tc.mutate(c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected a validation error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}
