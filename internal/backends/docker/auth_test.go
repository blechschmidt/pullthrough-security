package docker

import "testing"

func TestParseChallenge(t *testing.T) {
	cases := []struct {
		name    string
		header  string
		wantOK  bool
		scheme  string
		realm   string
		service string
		scope   string
	}{
		{
			name:    "docker hub bearer",
			header:  `Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull"`,
			wantOK:  true,
			scheme:  "bearer",
			realm:   "https://auth.docker.io/token",
			service: "registry.docker.io",
			scope:   "repository:library/nginx:pull",
		},
		{
			name:    "bearer without scope",
			header:  `Bearer realm="https://ghcr.io/token",service="ghcr.io"`,
			wantOK:  true,
			scheme:  "bearer",
			realm:   "https://ghcr.io/token",
			service: "ghcr.io",
			scope:   "",
		},
		{
			name:   "basic",
			header: `Basic realm="Registry"`,
			wantOK: true,
			scheme: "basic",
			realm:  "Registry",
		},
		{
			name:   "scope value containing a comma is preserved",
			header: `Bearer realm="https://auth.example.com/token",scope="repository:a:pull,repository:b:pull"`,
			wantOK: true,
			scheme: "bearer",
			realm:  "https://auth.example.com/token",
			scope:  "repository:a:pull,repository:b:pull",
		},
		{
			name:   "empty header",
			header: "",
			wantOK: false,
		},
		{
			name:   "unsupported scheme",
			header: `Digest realm="x"`,
			wantOK: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ch, ok := parseChallenge(c.header)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v", ok, c.wantOK)
			}
			if !ok {
				return
			}
			if ch.scheme != c.scheme {
				t.Errorf("scheme = %q, want %q", ch.scheme, c.scheme)
			}
			if ch.realm != c.realm {
				t.Errorf("realm = %q, want %q", ch.realm, c.realm)
			}
			if ch.service != c.service {
				t.Errorf("service = %q, want %q", ch.service, c.service)
			}
			if ch.scope != c.scope {
				t.Errorf("scope = %q, want %q", ch.scope, c.scope)
			}
		})
	}
}

func TestBuildTokenURL(t *testing.T) {
	c := authChallenge{
		scheme:  "bearer",
		realm:   "https://auth.docker.io/token",
		service: "registry.docker.io",
		scope:   "repository:library/nginx:pull",
	}
	got, err := buildTokenURL(c)
	if err != nil {
		t.Fatal(err)
	}
	const want = "https://auth.docker.io/token?scope=repository%3Alibrary%2Fnginx%3Apull&service=registry.docker.io"
	if got != want {
		t.Errorf("buildTokenURL = %q, want %q", got, want)
	}

	if _, err := buildTokenURL(authChallenge{scheme: "bearer", realm: "ftp://evil/token"}); err == nil {
		t.Error("expected error for non-http(s) realm")
	}
	if _, err := buildTokenURL(authChallenge{scheme: "bearer"}); err == nil {
		t.Error("expected error for missing realm")
	}
}
