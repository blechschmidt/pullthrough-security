package onboard

import (
	"strings"
	"testing"
)

// body returns the single snippet a backend type generates.
func single(t *testing.T, c Context, b Backend) Snippet {
	t.Helper()
	snips := For(c, b)
	if len(snips) != 1 {
		t.Fatalf("%s: got %d snippets, want 1", b.Type, len(snips))
	}
	return snips[0]
}

func TestEnvironmentConfiguredEcosystems(t *testing.T) {
	for _, tc := range []struct {
		typ, url     string
		open         []string // lines without a token
		withToken    []string // lines a token adds
		tokenInNotes bool     // the token is only described, never printed
	}{
		{
			typ:       "julia",
			open:      []string{"export JULIA_PKG_SERVER=https://proxy.example.com/v1/x\n"},
			withToken: []string{"# ~/.julia/servers/proxy.example.com/auth.toml\n", "access_token = \"tok\"\n"},
		},
		{
			typ:       "cpan",
			open:      []string{"export PERL_CPANM_OPT=\"--mirror https://proxy.example.com/v1/x --mirror-only\"\n"},
			withToken: []string{"export PERL_CPANM_OPT=\"--mirror https://pullthrough:tok@proxy.example.com/v1/x --mirror-only\"\n"},
		},
		{
			typ: "nix",
			url: "https://cache.nixos.org",
			open: []string{
				"substituters = https://proxy.example.com/v1/x\n",
				"trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=\n",
				"require-sigs = true\n",
			},
			withToken: []string{"netrc-file = /etc/nix/netrc\n", "machine proxy.example.com\n  login pullthrough\n  password tok\n"},
		},
		{
			typ: "homebrew",
			open: []string{
				"export HOMEBREW_API_DOMAIN=https://proxy.example.com/v1/x/api\n",
				"export HOMEBREW_ARTIFACT_DOMAIN=https://proxy.example.com/v1/x\n",
				"export HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=1\n",
			},
			withToken: []string{
				"export HOMEBREW_DOCKER_REGISTRY_TOKEN=\"tok\"\n",
				"export HOMEBREW_CURLRC=1\n",
				"# ~/.curlrc\nnetrc\n",
				"machine proxy.example.com\n  login pullthrough\n  password tok\n",
			},
		},
		{
			typ:       "huggingface",
			open:      []string{"export HF_ENDPOINT=https://proxy.example.com/v1/x\n"},
			withToken: []string{"export HF_TOKEN=\"tok\"\n"},
		},
	} {
		t.Run(tc.typ, func(t *testing.T) {
			b := Backend{Name: "x", Type: tc.typ, URL: tc.url}

			open := single(t, ctx(""), b)
			for _, want := range tc.open {
				if !strings.Contains(open.Body, want) {
					t.Errorf("without a token: missing %q\n%s", want, open.Body)
				}
			}
			if strings.Contains(open.Body, "tok") || strings.Contains(open.Body, "pullthrough:") {
				t.Errorf("without a token the snippet has credential lines:\n%s", open.Body)
			}
			// What to do with a token is said, not left out.
			if !strings.Contains(strings.Join(open.Notes, "\n"), "requires a token") {
				t.Errorf("without a token: no note says how to present one:\n%s", strings.Join(open.Notes, "\n"))
			}

			auth := single(t, ctx("tok"), b)
			for _, want := range tc.withToken {
				if !strings.Contains(auth.Body, want) {
					t.Errorf("with a token: missing %q\n%s", want, auth.Body)
				}
			}
			if auth.Title == "" || auth.File == "" || auth.Lang == "" {
				t.Errorf("incomplete snippet: %+v", auth)
			}
		})
	}
}

// A Nix cache other than the public one is signed with a key this generator
// cannot know: it must not print cache.nixos.org's.
func TestNixSnippetDoesNotGuessAKey(t *testing.T) {
	snip := single(t, ctx(""), Backend{Name: "x", Type: "nix", URL: "https://cache.internal.example"})
	if strings.Contains(snip.Body, "cache.nixos.org-1:") {
		t.Errorf("the snippet names cache.nixos.org's key for another cache:\n%s", snip.Body)
	}
	if !strings.Contains(snip.Body, "trusted-public-keys = <the upstream cache's public key>") {
		t.Errorf("the snippet has no placeholder for the key:\n%s", snip.Body)
	}
}

// ovsx cannot present a token for downloads: none is printed, and the note says
// what the operator has to do instead.
func TestOpenVSXSnippetCarriesNoToken(t *testing.T) {
	snip := single(t, ctx("tok"), Backend{Name: "x", Type: "openvsx"})
	if !strings.Contains(snip.Body, "--registryUrl https://proxy.example.com/v1/x ") {
		t.Errorf("missing the registry option:\n%s", snip.Body)
	}
	if strings.Contains(snip.Body, "tok") {
		t.Errorf("the snippet carries a token ovsx never sends:\n%s", snip.Body)
	}
	if notes := strings.Join(snip.Notes, "\n"); !strings.Contains(notes, "cannot present a proxy token") || !strings.Contains(notes, "auth.anonymousRoles") {
		t.Errorf("the notes do not say that ovsx cannot present a token:\n%s", notes)
	}
}

// ",direct" lets the go command fetch from the version-control host whatever
// the proxy answers 404 or 410 for — around the proxy.
func TestGoSnippetHasNoDirectFallback(t *testing.T) {
	for _, token := range []string{"", "tok"} {
		snip := single(t, ctx(token), Backend{Name: "x", Type: "go"})
		for _, line := range strings.Split(snip.Body, "\n") {
			if strings.HasPrefix(line, "#") {
				continue
			}
			if strings.Contains(line, "direct") {
				t.Errorf("the GOPROXY setting has a direct fallback: %q", line)
			}
		}
	}
}

// Git sends a token in the URL only in answer to a Basic challenge, which the
// proxy does not send: the token is a request header instead, and no URL the
// snippet prints carries it.
func TestGitSnippetSendsTheTokenAsAHeader(t *testing.T) {
	snip := single(t, ctx("tok"), Backend{Name: "x", Type: "git", URL: "https://github.com"})
	want := "git config --global http.https://proxy.example.com/.extraHeader \"Authorization: Bearer tok\"\n"
	if !strings.Contains(snip.Body, want) {
		t.Errorf("missing %q\n%s", want, snip.Body)
	}
	if strings.Contains(snip.Body, "tok@") {
		t.Errorf("a URL carries the token:\n%s", snip.Body)
	}
	for _, want := range []string{
		"git clone https://proxy.example.com/v1/x/<owner>/<repo>.git\n",
		"git config --global url.\"https://proxy.example.com/v1/x/\".insteadOf \"https://github.com/\"\n",
	} {
		if !strings.Contains(snip.Body, want) {
			t.Errorf("missing %q\n%s", want, snip.Body)
		}
	}

	open := single(t, ctx(""), Backend{Name: "x", Type: "git", URL: "https://github.com"})
	if strings.Contains(open.Body, "extraHeader") {
		t.Errorf("without a token the snippet sets a header:\n%s", open.Body)
	}
}

// The cabal stanza carries no credential, so its notes must not say it does —
// nor ask for a placeholder to be replaced that is not there.
func TestHackageNotesDescribeTheSnippet(t *testing.T) {
	for _, token := range []string{"", "tok"} {
		snip := single(t, ctx(token), Backend{Name: "x", Type: "hackage"})
		notes := strings.Join(snip.Notes, "\n")
		for _, wrong := range []string{"Credentials below", "replace the placeholder"} {
			if strings.Contains(notes, wrong) {
				t.Errorf("token=%q: the notes say %q about a snippet without credentials:\n%s", token, wrong, notes)
			}
		}
		if strings.Contains(snip.Body, "tok") {
			t.Errorf("the stanza carries the token:\n%s", snip.Body)
		}
		if !strings.Contains(notes, "~/.netrc") {
			t.Errorf("the notes do not say where the token goes:\n%s", notes)
		}
	}
}

func TestWithLogin(t *testing.T) {
	for _, tc := range []struct{ raw, token, want string }{
		{"https://proxy.example.com/v1", "tok", "https://pullthrough:tok@proxy.example.com/v1"},
		{"https://proxy.example.com/v1", "", "https://proxy.example.com/v1"},
		{"https://proxy.example.com/v1", "a/b@c:d e", "https://pullthrough:a%2Fb%40c%3Ad%20e@proxy.example.com/v1"},
		{"not a url", "tok", "not a url"},
	} {
		if got := withLogin(tc.raw, tc.token); got != tc.want {
			t.Errorf("withLogin(%q, %q) = %q, want %q", tc.raw, tc.token, got, tc.want)
		}
	}
}
