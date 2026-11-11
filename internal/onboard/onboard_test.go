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
		{"go", []string{"go env -w GOPROXY=https://proxy.example.com/v1/x\n", "password secret-tok"}},
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

// The snippets below pin what the real clients were verified to need (the
// client lab, scripts/client-lab): forms that look right and do not work are
// kept out of the generator.

// TestSnippetsCarryNoTokenTheClientCannotSend: cargo, NuGet and mix cannot
// present a proxy token, so a supplied token must not be written into their
// snippets, and the notes say what to do instead.
func TestSnippetsCarryNoTokenTheClientCannotSend(t *testing.T) {
	for _, typ := range []string{"cargo", "nuget", "hex", "conan"} {
		snip := For(ctx("secret-tok"), Backend{Name: "x", Type: typ})[0]
		if strings.Contains(snip.Body, "secret-tok") {
			t.Errorf("%s: the snippet carries a token the client cannot send:\n%s", typ, snip.Body)
		}
		if notes := strings.Join(snip.Notes, "\n"); !strings.Contains(notes, "anonymous") {
			t.Errorf("%s: the notes do not say how the operator admits the client:\n%s", typ, notes)
		}
	}
}

func TestCargoSnippetIsSourceReplacement(t *testing.T) {
	snip := For(ctx(""), Backend{Name: "crates", Type: "cargo"})[0]
	for _, want := range []string{
		"[source.crates-io]\nreplace-with = \"proxy\"",
		"registry = \"sparse+https://proxy.example.com/v1/crates/\"",
	} {
		if !strings.Contains(snip.Body, want) {
			t.Errorf("cargo snippet missing %q\n%s", want, snip.Body)
		}
	}
	notes := strings.Join(snip.Notes, "\n")
	// The environment form looks plausible and is ignored by cargo.
	if !strings.Contains(notes, "CARGO_SOURCE_* environment variables do not work") {
		t.Errorf("cargo notes should warn about CARGO_SOURCE_* variables:\n%s", notes)
	}
	if !strings.Contains(notes, "--config 'source.crates-io.replace-with=") {
		t.Errorf("cargo notes should give the --config form:\n%s", notes)
	}
}

// TestMavenSnippetSendsTheTokenAsAHeader: a <username>/<password> server is
// only presented in answer to a Basic challenge, which the proxy does not send.
func TestMavenSnippetSendsTheTokenAsAHeader(t *testing.T) {
	snip := For(ctx("tok<&>"), Backend{Name: "maven", Type: "maven"})[0]
	for _, want := range []string{
		"<mirrorOf>*</mirrorOf>",
		"<url>https://proxy.example.com/v1/maven</url>",
		"<name>Authorization</name>",
		"<value>Bearer tok&lt;&amp;&gt;</value>", // escaped: the file stays well-formed
	} {
		if !strings.Contains(snip.Body, want) {
			t.Errorf("maven snippet missing %q\n%s", want, snip.Body)
		}
	}
	if strings.Contains(snip.Body, "<password>") {
		t.Errorf("maven snippet uses <password>, which Maven does not send to the proxy:\n%s", snip.Body)
	}
	anon := For(ctx(""), Backend{Name: "maven", Type: "maven"})[0]
	if strings.Contains(anon.Body, "<servers>") {
		t.Errorf("no token was supplied but the snippet has a <servers> block:\n%s", anon.Body)
	}
}

func TestComposerSnippetSwitchesPackagistOff(t *testing.T) {
	snip := For(ctx(""), Backend{Name: "packagist", Type: "composer"})[0]
	if !strings.Contains(snip.Body, `{ "packagist.org": false }`) {
		t.Errorf("composer snippet does not switch packagist.org off:\n%s", snip.Body)
	}
	notes := strings.Join(snip.Notes, "\n")
	if !strings.Contains(notes, "composer config --global repositories.packagist.org false") {
		t.Errorf("the global form must switch packagist.org off too:\n%s", notes)
	}
	// Redefining "packagist" leaves packagist.org in use (Composer 2.11).
	if strings.Contains(notes, "repos.packagist composer") {
		t.Errorf("the notes recommend redefining packagist, which is not enough:\n%s", notes)
	}
}

func TestCondaSnippetUsesAChannelAlias(t *testing.T) {
	snip := For(ctx("tok"), Backend{Name: "conda-forge", Type: "conda"})[0]
	for _, want := range []string{
		// The token as a password: conda sends nothing for a user name alone.
		"channel_alias: https://pullthrough:tok@proxy.example.com/v1\n",
		"channels:\n  - conda-forge\n",
		"default_channels: []",
	} {
		if !strings.Contains(snip.Body, want) {
			t.Errorf("conda snippet missing %q\n%s", want, snip.Body)
		}
	}
}

func TestHexSnippetMirrorsHexpm(t *testing.T) {
	snip := For(ctx(""), Backend{Name: "hex", Type: "hex"})[0]
	if !strings.Contains(snip.Body, "export HEX_MIRROR=https://proxy.example.com/v1/hex\n") {
		t.Errorf("hex snippet missing HEX_MIRROR:\n%s", snip.Body)
	}
	// A separately named repository is rejected by Hex: the registry is signed
	// for the name hexpm.
	if strings.Contains(snip.Body, "hex.repo add") {
		t.Errorf("hex snippet registers the proxy as a named repository:\n%s", snip.Body)
	}
}

func TestHackageSnippetKeepsTheSecureRepository(t *testing.T) {
	snip := For(ctx(""), Backend{Name: "hackage", Type: "hackage"})[0]
	want := "repository hackage.haskell.org\n  url: https://proxy.example.com/v1/hackage/\n  secure: True\n"
	if !strings.Contains(snip.Body, want) {
		t.Errorf("hackage snippet missing the stanza\n%q\ngot\n%s", want, snip.Body)
	}
}
