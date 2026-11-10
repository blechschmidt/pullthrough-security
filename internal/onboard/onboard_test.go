package onboard

import (
	"strings"
	"testing"
)

func ctx(token string) Context {
	return Context{ProxyBase: "https://proxy.example.com", Host: "proxy.example.com", Tenant: "acme", Token: token}
}

func TestForKnownTypesEmbedMountAndToken(t *testing.T) {
	c := ctx("secret-tok")
	cases := []struct {
		typ      string
		mustHave []string
	}{
		{"npm", []string{"registry=https://proxy.example.com/v1/x/", "_authToken=secret-tok"}},
		{"pip", []string{"index-url = https://secret-tok@proxy.example.com/v1/x/simple/"}},
		{"go", []string{"GOPROXY=https://proxy.example.com/v1/x,direct", "password secret-tok"}},
		{"docker", []string{"docker login proxy.example.com", "secret-tok"}},
	}
	for _, tc := range cases {
		t.Run(tc.typ, func(t *testing.T) {
			snips := For(c, Backend{Name: "x", Type: tc.typ})
			if len(snips) == 0 {
				t.Fatalf("no snippets for %s", tc.typ)
			}
			blob := snips[0].Body + strings.Join(snips[0].Notes, "\n")
			for _, want := range tc.mustHave {
				if !strings.Contains(blob, want) {
					t.Errorf("%s snippet missing %q\n%s", tc.typ, want, blob)
				}
			}
		})
	}
}

func TestForPlaceholderWithoutToken(t *testing.T) {
	snips := For(ctx(""), Backend{Name: "npm", Type: "npm"})
	if !strings.Contains(snips[0].Body, "${PULLTHROUGH_TOKEN}") {
		t.Errorf("expected token placeholder, got:\n%s", snips[0].Body)
	}
}

func TestForUnknownTypeIsAdvisory(t *testing.T) {
	snips := For(ctx(""), Backend{Name: "weird", Type: "quux"})
	if len(snips) != 1 || len(snips[0].Notes) == 0 {
		t.Fatalf("unknown type should yield an advisory snippet, got %+v", snips)
	}
	if !strings.Contains(snips[0].Notes[0], "/v1/weird") {
		t.Errorf("advisory should mention the mount, got %q", snips[0].Notes[0])
	}
}

func TestForAllCoversEveryBackend(t *testing.T) {
	snips := ForAll(ctx(""), []Backend{{Name: "npm", Type: "npm"}, {Name: "pypi", Type: "pip"}})
	if len(snips) != 2 {
		t.Fatalf("ForAll = %d snippets, want 2", len(snips))
	}
}

func TestWithUserinfoEncodesToken(t *testing.T) {
	got := WithUserinfo("https://proxy.example.com/v1/npm", "abc/123")
	want := "https://abc%2F123@proxy.example.com/v1/npm"
	if got != want {
		t.Errorf("WithUserinfo = %q, want %q", got, want)
	}
	if WithUserinfo("https://x/y", "") != "https://x/y" {
		t.Error("empty token should not alter the URL")
	}
}

// TestDockerSnippetMatchesWhatTheEngineAccepts pins the two facts a real Docker
// Engine enforces (verified by the ecosystem test suite): a registry mirror URL
// must not carry a path, and an explicit reference addresses the upstream as the
// repository's first path component (served at the proxy's host-root /v2/).
func TestDockerSnippetMatchesWhatTheEngineAccepts(t *testing.T) {
	snip := For(ctx(""), Backend{Name: "dockerhub", Type: "docker"})[0]
	for _, want := range []string{
		"docker pull proxy.example.com/dockerhub/library/alpine:latest",
		`"registry-mirrors": ["https://proxy.example.com"]`,
	} {
		if !strings.Contains(snip.Body, want) {
			t.Errorf("docker snippet missing %q\n%s", want, snip.Body)
		}
	}
	if strings.Contains(snip.Body, `["https://proxy.example.com/v1/`) {
		t.Errorf("the mirror URL carries a path, which the Docker Engine rejects:\n%s", snip.Body)
	}
	notes := strings.Join(snip.Notes, "\n")
	for _, want := range []string{"server.registry.defaultUpstream: dockerhub", "falls back to Docker Hub"} {
		if !strings.Contains(notes, want) {
			t.Errorf("docker notes missing %q\n%s", want, notes)
		}
	}
}

// TestTerraformSnippetServesTheRegistryHost checks the CLI-config host override:
// the block is keyed by the UPSTREAM registry's hostname (so .tf source
// addresses stay unchanged) and points both protocols at the proxy mount.
func TestTerraformSnippetServesTheRegistryHost(t *testing.T) {
	cases := []struct {
		url, wantHost string
	}{
		{"https://registry.terraform.io", "registry.terraform.io"},
		{"https://registry.opentofu.org/", "registry.opentofu.org"},
		{"", "registry.terraform.io"}, // unknown upstream: the public default
		{"::not a url::", "registry.terraform.io"},
	}
	for _, tc := range cases {
		snip := For(ctx("tok"), Backend{Name: "tf", Type: "terraform", URL: tc.url})[0]
		for _, want := range []string{
			`host "` + tc.wantHost + `" {`,
			`"providers.v1" = "https://proxy.example.com/v1/tf/v1/providers/"`,
			`"modules.v1"   = "https://proxy.example.com/v1/tf/v1/modules/"`,
			// Terraform sends the credentials of the registry hostname to the
			// overridden service URLs, i.e. to the proxy.
			`credentials "` + tc.wantHost + `" {`,
			`token = "tok"`,
		} {
			if !strings.Contains(snip.Body, want) {
				t.Errorf("terraform snippet (upstream %q) missing %q\n%s", tc.url, want, snip.Body)
			}
		}
	}

	anon := For(ctx(""), Backend{Name: "tf", Type: "terraform", URL: "https://registry.terraform.io"})[0]
	if strings.Contains(anon.Body, "credentials") {
		t.Errorf("no token was supplied but the snippet emits a credentials block:\n%s", anon.Body)
	}
	if !strings.Contains(strings.Join(anon.Notes, "\n"), `credentials "registry.terraform.io"`) {
		t.Errorf("without a token the notes should explain how to add credentials:\n%v", anon.Notes)
	}
}

func TestGitSnippetOffersInsteadOf(t *testing.T) {
	snip := For(ctx(""), Backend{Name: "github", Type: "git", URL: "https://github.com"})[0]
	want := `git config --global url."https://proxy.example.com/v1/github/".insteadOf "https://github.com/"`
	if !strings.Contains(snip.Body, want) {
		t.Errorf("git snippet missing the insteadOf rewrite %q\n%s", want, snip.Body)
	}
	// An SSH upstream has no HTTPS base URL to rewrite.
	ssh := For(ctx(""), Backend{Name: "gh-ssh", Type: "git", URL: "ssh://git@github.com/"})[0]
	if strings.Contains(ssh.Body, "insteadOf") {
		t.Errorf("an ssh upstream must not get an https insteadOf rewrite:\n%s", ssh.Body)
	}
	// Without the upstream URL the plain clone command is still produced.
	bare := For(ctx(""), Backend{Name: "github", Type: "git"})[0]
	if !strings.Contains(bare.Body, "git clone https://proxy.example.com/v1/github/<owner>/<repo>.git") {
		t.Errorf("git snippet missing the clone command:\n%s", bare.Body)
	}
}
