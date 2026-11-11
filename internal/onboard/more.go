package onboard

import (
	"fmt"
	"net/url"
	"strings"
)

// The generators in this file print, for their ecosystems, exactly the lines
// the client guide documents (docs/clients/<type>.md) and the client lab
// executes with the real client — a test in internal/clientguide holds them to
// the lab's scripts, so a line that no client has run cannot be printed here.

// anonymousNote is what a client that cannot present a proxy token is told.
const anonymousNote = "If the proxy enforces authentication, ask the operator to admit anonymous reads for this upstream " +
	"(auth.allowAnonymous with an auth.anonymousRoles role scoped to it)."

// withLogin embeds a token in a URL as the password of HTTP Basic
// authentication, under the user name the guide uses (the proxy accepts any).
// Unlike a token alone before the "@" (WithUserinfo), this is a form every
// client sends: conda, for one, drops credentials that have no password.
func withLogin(raw, token string) string {
	if token == "" {
		return raw
	}
	i := strings.Index(raw, "://")
	if i < 0 {
		return raw
	}
	return raw[:i+3] + url.UserPassword("pullthrough", token).String() + "@" + raw[i+3:]
}

// netrcEntry is a ~/.netrc entry that hands a host's requests the token.
func netrcEntry(host, token string) string {
	return "machine " + host + "\n  login pullthrough\n  password " + token + "\n"
}

func juliaSnippet(ctx Context, b Backend) Snippet {
	mount := ctx.mount(b)
	body := "export JULIA_PKG_SERVER=" + mount + "\n"
	notes := []string{
		"Set it in the shell profile, or in ~/.julia/config/startup.jl: ENV[\"JULIA_PKG_SERVER\"] = \"" + mount + "\".",
		"A package the Pkg server does not serve is cloned from its Git repository, not fetched through this upstream.",
	}
	if ctx.Token != "" {
		// Pkg keeps a server's token in a file named after the server's host and
		// sends it as a bearer token.
		body += "\n# ~/.julia/servers/" + ctx.Host + "/auth.toml\naccess_token = \"" + ctx.Token + "\"\n"
		notes = append(notes, "auth.toml holds your proxy token; keep it private.")
	} else {
		notes = append(notes, "If the proxy requires a token, put it into ~/.julia/servers/"+ctx.Host+"/auth.toml: access_token = \"<your proxy token>\".")
	}
	return Snippet{
		Title: fmt.Sprintf("Julia — %s (Pkg server)", b.Name),
		File:  "julia-pkg-server.sh",
		Lang:  "bash",
		Body:  body,
		Notes: notes,
	}
}

func cpanSnippet(ctx Context, b Backend) Snippet {
	mount := ctx.mount(b)
	body := "export PERL_CPANM_OPT=\"--mirror " + withLogin(mount, ctx.Token) + " --mirror-only\"\n"
	notes := []string{
		"--mirror-only is what keeps cpanm on the proxy: without it, cpanm resolves modules through cpanmetadb and falls back to other mirrors.",
	}
	if ctx.Token != "" {
		notes = append(notes, "The mirror URL carries your proxy token as the password (any user name); cpanm masks it in its output.")
	} else {
		notes = append(notes, "If the proxy requires a token: --mirror "+withLogin(mount, "<your proxy token>")+" (the token as the password, any user name).")
	}
	return Snippet{
		Title: fmt.Sprintf("CPAN — %s (cpanm)", b.Name),
		File:  "cpanm.env.sh",
		Lang:  "bash",
		Body:  body,
		Notes: notes,
	}
}

func openvsxSnippet(ctx Context, b Backend) Snippet {
	mount := ctx.mount(b)
	return Snippet{
		Title: fmt.Sprintf("Open VSX — %s (ovsx)", b.Name),
		File:  "ovsx-get.sh",
		Lang:  "bash",
		Body:  "npx --yes ovsx get <namespace>.<extension> --registryUrl " + mount + " -o extension.vsix\n",
		Notes: []string{
			"ovsx is itself an npm package: npx fetches it through the proxy's npm upstream when npm is configured for it.",
			"ovsx cannot present a proxy token for downloads (its token options are for publishing). " + anonymousNote,
			"An editor's extension gallery is not served: its search is a POST request, and the proxy serves GET and HEAD.",
		},
	}
}

// nixosCacheKey is the public key cache.nixos.org signs its store paths with.
const nixosCacheKey = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="

func nixSnippet(ctx Context, b Backend) Snippet {
	mount := ctx.mount(b)
	// The proxy serves each signed narinfo as the cache sent it, so the key Nix
	// trusts stays the upstream cache's own — which is known here only for the
	// public cache.
	key := "<the upstream cache's public key>"
	if registryHost(b.URL, "") == "cache.nixos.org" {
		key = nixosCacheKey
	}
	var sb strings.Builder
	sb.WriteString("# /etc/nix/nix.conf (or ~/.config/nix/nix.conf for a trusted user)\n")
	fmt.Fprintf(&sb, "substituters = %s\n", mount)
	fmt.Fprintf(&sb, "trusted-public-keys = %s\n", key)
	sb.WriteString("require-sigs = true\n")
	notes := []string{
		"trusted-public-keys stays the key of the cache behind the proxy: Nix keeps verifying every store path against that cache's signature.",
		"substituters replaces cache.nixos.org; use extra-substituters to add the proxy instead.",
	}
	if ctx.Token != "" {
		sb.WriteString("netrc-file = /etc/nix/netrc\n")
		sb.WriteString("\n# /etc/nix/netrc (mode 600; with a Nix daemon, readable by the daemon)\n")
		sb.WriteString(netrcEntry(ctx.Host, ctx.Token))
		notes = append(notes, "The netrc file holds your proxy token; keep it private.")
	} else {
		notes = append(notes, "If the proxy requires a token: netrc-file = /etc/nix/netrc, and in that file 'machine "+ctx.Host+" login pullthrough password <your proxy token>'.")
	}
	return Snippet{
		Title: fmt.Sprintf("Nix — %s (binary cache)", b.Name),
		File:  "nix.conf",
		Lang:  "ini",
		Body:  sb.String(),
		Notes: notes,
	}
}

func homebrewSnippet(ctx Context, b Backend) Snippet {
	mount := ctx.mount(b)
	var sb strings.Builder
	fmt.Fprintf(&sb, "export HOMEBREW_API_DOMAIN=%s/api\n", mount)
	fmt.Fprintf(&sb, "export HOMEBREW_ARTIFACT_DOMAIN=%s\n", mount)
	sb.WriteString("export HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=1\n")
	notes := []string{
		"Both domains are required: the formula index is signed and cannot be rewritten, so it is brew itself that sends bottle downloads to the artifact domain.",
		"brew updates itself from github.com before an install unless HOMEBREW_NO_AUTO_UPDATE=1 is set.",
	}
	if ctx.Token != "" {
		// Bottles and the formula API take the token by different routes.
		fmt.Fprintf(&sb, "export HOMEBREW_DOCKER_REGISTRY_TOKEN=\"%s\"\n", ctx.Token)
		sb.WriteString("export HOMEBREW_CURLRC=1\n")
		sb.WriteString("\n# ~/.curlrc\nnetrc\n")
		sb.WriteString("\n# ~/.netrc (mode 600)\n")
		sb.WriteString(netrcEntry(ctx.Host, ctx.Token))
		notes = append(notes, "brew sends the registry token to the artifact domain for bottles; for the formula API its curl takes the token from ~/.netrc, which HOMEBREW_CURLRC and the netrc line in ~/.curlrc switch on.")
	} else {
		notes = append(notes, "If the proxy requires a token, see docs/clients/homebrew.md: bottles and the formula API take it by different routes.")
	}
	return Snippet{
		Title: fmt.Sprintf("Homebrew — %s", b.Name),
		File:  "homebrew.env.sh",
		Lang:  "bash",
		Body:  sb.String(),
		Notes: notes,
	}
}

func huggingfaceSnippet(ctx Context, b Backend) Snippet {
	body := "export HF_ENDPOINT=" + ctx.mount(b) + "\n"
	notes := []string{
		"Read by every library built on huggingface_hub (transformers, datasets, the hf command).",
		"Pin a commit (--revision <40-character hash>): the proxy caches it and serves it without asking the Hub again.",
	}
	if ctx.Token != "" {
		body += "export HF_TOKEN=\"" + ctx.Token + "\"\n"
		notes = append(notes, "HF_TOKEN carries your proxy token, not a Hub token: the proxy holds the Hub's token itself and never forwards yours.")
	} else {
		notes = append(notes, "If the proxy requires a token: export HF_TOKEN=<your proxy token> (not a Hub token).")
	}
	return Snippet{
		Title: fmt.Sprintf("Hugging Face — %s", b.Name),
		File:  "huggingface.env.sh",
		Lang:  "bash",
		Body:  body,
		Notes: notes,
	}
}
