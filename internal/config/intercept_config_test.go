package config

import "testing"

func baseInterceptConfig() *Config {
	c := Default()
	c.Upstreams = map[string]UpstreamConfig{
		"npm": {Type: "npm", URL: "https://registry.npmjs.org"},
	}
	c.Server.Intercept = InterceptConfig{
		Enabled:    true,
		ListenAddr: ":3128",
		CACertFile: "/etc/pt/ca.crt",
		CAKeyFile:  "/etc/pt/ca.key",
		GenerateCA: true,
	}
	return &c
}

func TestValidateIntercept_OK(t *testing.T) {
	c := baseInterceptConfig()
	if err := c.Validate(); err != nil {
		t.Fatalf("expected valid intercept config, got %v", err)
	}
}

func TestValidateIntercept_DisabledSkipsChecks(t *testing.T) {
	c := Default()
	c.Server.Intercept = InterceptConfig{Enabled: false} // nothing else set
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled intercept should not require fields: %v", err)
	}
}

func TestValidateIntercept_Errors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"missing listenAddr", func(c *Config) { c.Server.Intercept.ListenAddr = "" }},
		{"listenAddr equals httpAddr", func(c *Config) { c.Server.Intercept.ListenAddr = c.Server.HTTPAddr }},
		{"missing caCertFile", func(c *Config) { c.Server.Intercept.CACertFile = "" }},
		{"missing caKeyFile", func(c *Config) { c.Server.Intercept.CAKeyFile = "" }},
		{"negative leafTtl", func(c *Config) { c.Server.Intercept.LeafTTL = -1 }},
		{"negative cacheSize", func(c *Config) { c.Server.Intercept.CertCacheSize = -5 }},
		{"empty host key", func(c *Config) { c.Server.Intercept.Hosts = map[string]string{"": "npm"} }},
		{"empty backend", func(c *Config) { c.Server.Intercept.Hosts = map[string]string{"files.pythonhosted.org": ""} }},
		{"unknown upstream", func(c *Config) {
			c.Server.Intercept.Hosts = map[string]string{"files.pythonhosted.org": "nope"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := baseInterceptConfig()
			tc.mutate(c)
			if err := c.Validate(); err == nil {
				t.Fatalf("expected validation error for %q", tc.name)
			}
		})
	}
}

func TestValidateIntercept_KnownHostMapping(t *testing.T) {
	c := baseInterceptConfig()
	c.Server.Intercept.Hosts = map[string]string{"files.pythonhosted.org": "npm"} // npm exists
	if err := c.Validate(); err != nil {
		t.Fatalf("mapping to a known upstream should validate: %v", err)
	}
}
