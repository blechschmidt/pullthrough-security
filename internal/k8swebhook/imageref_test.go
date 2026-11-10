package k8swebhook

import "testing"

func TestParseImageRef(t *testing.T) {
	cases := []struct {
		in       string
		registry string
		repo     string
		tag      string
		digest   string
	}{
		{"nginx", "", "nginx", "", ""},
		{"nginx:1.25", "", "nginx", "1.25", ""},
		{"library/nginx:1.25", "", "library/nginx", "1.25", ""},
		{"docker.io/library/nginx:1.25", "docker.io", "library/nginx", "1.25", ""},
		{"ghcr.io/org/app:v1.2.3", "ghcr.io", "org/app", "v1.2.3", ""},
		{"registry:5000/team/app:dev", "registry:5000", "team/app", "dev", ""},
		{"localhost/app", "localhost", "app", "", ""},
		{"org/app@sha256:abc", "", "org/app", "", "sha256:abc"},
		{"ghcr.io/org/app:1.0@sha256:deadbeef", "ghcr.io", "org/app", "1.0", "sha256:deadbeef"},
		{"", "", "", "", ""},
	}
	for _, c := range cases {
		got := ParseImageRef(c.in)
		if got.Registry != c.registry || got.Repository != c.repo || got.Tag != c.tag || got.Digest != c.digest {
			t.Errorf("ParseImageRef(%q) = {reg:%q repo:%q tag:%q digest:%q}, want {reg:%q repo:%q tag:%q digest:%q}",
				c.in, got.Registry, got.Repository, got.Tag, got.Digest, c.registry, c.repo, c.tag, c.digest)
		}
	}
}

func TestImageRefCoordinate(t *testing.T) {
	ref := ParseImageRef("ghcr.io/org/app:1.2.3")
	if name, ver := ref.Coordinate(true); name != "org/app" || ver != "1.2.3" {
		t.Errorf("Coordinate(strip) = %q@%q, want org/app@1.2.3", name, ver)
	}
	if name, ver := ref.Coordinate(false); name != "ghcr.io/org/app" || ver != "1.2.3" {
		t.Errorf("Coordinate(nostrip) = %q@%q, want ghcr.io/org/app@1.2.3", name, ver)
	}
	// Digest wins over tag for the version.
	d := ParseImageRef("org/app:1.0@sha256:abc")
	if _, ver := d.Coordinate(true); ver != "sha256:abc" {
		t.Errorf("Coordinate version = %q, want sha256:abc", ver)
	}
}

func TestImageRefMatchesPrefix(t *testing.T) {
	ref := ParseImageRef("registry.k8s.io/pause:3.9")
	if !ref.matchesPrefix([]string{"registry.k8s.io/"}) {
		t.Error("expected registry.k8s.io/pause to match the allowlist prefix")
	}
	if ref.matchesPrefix([]string{"ghcr.io/"}) {
		t.Error("did not expect a match against an unrelated prefix")
	}
}
