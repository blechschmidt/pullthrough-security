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
		{"host key without a host", func(c *Config) {
			c.Server.Intercept.Hosts = map[string]string{"/debian-security": "npm"}
		}},
		{"NAT TLS listener on the HTTP address", func(c *Config) { c.Server.Intercept.NAT.HTTPSAddr = c.Server.HTTPAddr }},
		{"NAT listeners on one address", func(c *Config) {
			c.Server.Intercept.NAT.HTTPSAddr = ":8443"
			c.Server.Intercept.NAT.HTTPAddr = "0.0.0.0:8443"
		}},
		{"NAT HTTP listener on the forward proxy's port", func(c *Config) { c.Server.Intercept.NAT.HTTPAddr = "127.0.0.1:3128" }},
		{"NAT listener on the SSH address", func(c *Config) {
			c.Server.SSHAddr = ":2222"
			c.Server.Intercept.NAT.HTTPSAddr = ":2222"
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

func TestValidateIntercept_NATOnly(t *testing.T) {
	// NAT mode needs no forward proxy: the network brings the connections.
	c := baseInterceptConfig()
	c.Server.Intercept.ListenAddr = ""
	c.Server.Intercept.NAT = InterceptNATConfig{HTTPSAddr: ":8443", HTTPAddr: ":8081"}
	if err := c.Validate(); err != nil {
		t.Fatalf("a NAT-only configuration should validate: %v", err)
	}
	if !c.Server.Intercept.Listening() {
		t.Fatal("Listening() = false with NAT listeners configured")
	}
	// Listeners on distinct addresses of one port do not clash.
	c.Server.Intercept.NAT = InterceptNATConfig{HTTPSAddr: "127.0.0.2:443", HTTPAddr: "127.0.0.3:443"}
	if err := c.Validate(); err != nil {
		t.Fatalf("listeners on distinct addresses should validate: %v", err)
	}
}

func TestValidateIntercept_HostRulesWithPaths(t *testing.T) {
	c := baseInterceptConfig()
	c.Upstreams["apt-security"] = UpstreamConfig{Type: "apt", URL: "https://deb.debian.org/debian-security"}
	c.Server.Intercept.Hosts = map[string]string{
		"deb.debian.org/debian-security": "apt-security",
		"https://mirror.example/npm/":    "npm",
		"*.npm.example.com":              "npm",
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("host rules with paths should validate: %v", err)
	}
}
