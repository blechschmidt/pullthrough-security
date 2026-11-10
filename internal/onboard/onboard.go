// Package onboard generates copy-paste client-configuration snippets that point
// a package manager (npm, pip, cargo, go, nuget, maven, docker, helm, ...) at
// the pull-through proxy. It is shared by the standalone client CLI (`ptctl
// config`, Task 55) and the tenant self-service portal (Task 71) so both surface
// identical, single-source-of-truth onboarding guidance.
//
// The generators are pure functions of a Context (proxy base URL, host, tenant,
// optional token) and a Backend (mount name + protocol type): no I/O, no global
// state, and deterministic output. An unknown backend type yields a single
// advisory snippet rather than failing, so a proxy running a newer backend than
// this code still gets useful output.
package onboard

import (
	"fmt"
	"net/url"
	"strings"
)

// Snippet is one generated client-configuration artifact: a titled, optionally
// file-named block of text plus human notes.
type Snippet struct {
	Title string   `json:"title"`           // human heading, e.g. "npm — npm (.npmrc)"
	File  string   `json:"file,omitempty"`  // conventional filename, e.g. ".npmrc"
	Lang  string   `json:"lang,omitempty"`  // fenced-code language, e.g. "ini"
	Body  string   `json:"body,omitempty"`  // the snippet text
	Notes []string `json:"notes,omitempty"` // human guidance
}

// Backend identifies one configured upstream the snippets target.
type Backend struct {
	Name string `json:"name"` // mount name, e.g. "npm"
	Type string `json:"type"` // protocol type, e.g. "npm", "pip", "cargo"
	URL  string `json:"url,omitempty"`
}

// Context carries the resolved inputs every generator needs.
type Context struct {
	ProxyBase string // e.g. https://proxy.example.com (no trailing slash)
	Host      string // e.g. proxy.example.com[:port]
	Tenant    string
	Token     string
}

// mount returns the public gateway base for a backend, e.g.
// https://proxy.example.com/v1/npm
func (c Context) mount(b Backend) string {
	return c.ProxyBase + "/v1/" + b.Name
}

// tokenOr returns the configured token, or the given placeholder when no token
// was supplied, so generated snippets are copy-paste complete either way.
func (c Context) tokenOr(placeholder string) string {
	if c.Token != "" {
		return c.Token
	}
	return placeholder
}

// authNote returns a leading note describing how the tenant/token is applied,
// shared across generators.
func (c Context) authNote() []string {
	if c.Token != "" {
		return []string{"Credentials below carry your proxy token; treat the file as a secret."}
	}
	return []string{"No token was supplied; replace the placeholder with your proxy access token (its team determines the tenant)."}
}

// For produces the client-config snippets for one backend. An unknown type
// yields a single advisory snippet rather than failing.
func For(ctx Context, b Backend) []Snippet {
	switch b.Type {
	case "npm":
		return []Snippet{npmSnippet(ctx, b)}
	case "pip", "pypi":
		return []Snippet{pipSnippet(ctx, b)}
	case "cargo":
		return []Snippet{cargoSnippet(ctx, b)}
	case "go":
		return []Snippet{goSnippet(ctx, b)}
	case "nuget":
		return []Snippet{nugetSnippet(ctx, b)}
	case "maven":
		return []Snippet{mavenSnippet(ctx, b)}
	case "docker", "oci":
		return []Snippet{dockerSnippet(ctx, b)}
	case "helm":
		return []Snippet{helmSnippet(ctx, b)}
	case "rubygems":
		return []Snippet{rubygemsSnippet(ctx, b)}
	case "composer":
		return []Snippet{composerSnippet(ctx, b)}
	case "apt", "deb":
		return []Snippet{aptSnippet(ctx, b)}
	case "yum", "rpm":
		return []Snippet{yumSnippet(ctx, b)}
	case "terraform":
		return []Snippet{terraformSnippet(ctx, b)}
	case "conan":
		return []Snippet{conanSnippet(ctx, b)}
	case "conda":
		return []Snippet{condaSnippet(ctx, b)}
	case "cran":
		return []Snippet{cranSnippet(ctx, b)}
	case "hex":
		return []Snippet{hexSnippet(ctx, b)}
	case "bazel":
		return []Snippet{bazelSnippet(ctx, b)}
	case "jsr":
		return []Snippet{jsrSnippet(ctx, b)}
	case "hackage":
		return []Snippet{hackageSnippet(ctx, b)}
	case "ansible":
		return []Snippet{ansibleSnippet(ctx, b)}
	case "puppet":
		return []Snippet{puppetSnippet(ctx, b)}
	case "swift":
		return []Snippet{swiftSnippet(ctx, b)}
	case "dart", "pub":
		return []Snippet{dartSnippet(ctx, b)}
	case "git":
		return []Snippet{gitSnippet(ctx, b)}
	default:
		return []Snippet{{
			Title: fmt.Sprintf("%s (%s)", b.Name, orUnknown(b.Type)),
			Notes: []string{fmt.Sprintf("No generator for backend type %q; point your client at %s and supply your proxy token.", orUnknown(b.Type), ctx.mount(b))},
		}}
	}
}

// ForAll generates the snippets for every backend, in order.
func ForAll(ctx Context, backends []Backend) []Snippet {
	var out []Snippet
	for _, b := range backends {
		out = append(out, For(ctx, b)...)
	}
	return out
}

func orUnknown(t string) string {
	if t == "" {
		return "unknown"
	}
	return t
}

func npmSnippet(ctx Context, b Backend) Snippet {
	mount := ctx.mount(b) + "/"
	var sb strings.Builder
	fmt.Fprintf(&sb, "registry=%s\n", mount)
	// npm attaches credentials to the registry host+path via :_authToken; emit it
	// always (with a placeholder when no token is set) so the file is complete.
	ref := strings.TrimPrefix(strings.TrimPrefix(mount, "https:"), "http:")
	fmt.Fprintf(&sb, "%s:_authToken=%s\n", ref, ctx.tokenOr("${PULLTHROUGH_TOKEN}"))
	return Snippet{
		Title: fmt.Sprintf("npm — %s (.npmrc)", b.Name),
		File:  ".npmrc",
		Lang:  "ini",
		Body:  sb.String(),
		Notes: append(ctx.authNote(),
			"Project-local or user-level (~/.npmrc). For a scope only, use '@scope:registry=' instead of 'registry='."),
	}
}

func pipSnippet(ctx Context, b Backend) Snippet {
	index := ctx.mount(b) + "/simple/"
	body := "[global]\nindex-url = " + WithUserinfo(index, ctx.Token) + "\n"
	return Snippet{
		Title: fmt.Sprintf("pip — %s (pip.conf)", b.Name),
		File:  "pip.conf",
		Lang:  "ini",
		Body:  body,
		Notes: append(ctx.authNote(),
			"Linux: ~/.config/pip/pip.conf · macOS: ~/Library/Application Support/pip/pip.conf · Windows: %APPDATA%\\pip\\pip.ini.",
			"uv/poetry/pdm accept the same index URL."),
	}
}

func cargoSnippet(ctx Context, b Backend) Snippet {
	sparse := "sparse+" + ctx.mount(b) + "/"
	body := "[registries.crates-io]\nprotocol = \"sparse\"\n\n" +
		"[source.crates-io]\nreplace-with = \"proxy\"\n\n" +
		"[source.proxy]\nregistry = \"" + sparse + "\"\n"
	notes := append(ctx.authNote(),
		"~/.cargo/config.toml. The trailing slash on the sparse+ URL is required.")
	if ctx.Token != "" {
		body += "\n[registries.proxy]\ntoken = \"" + ctx.Token + "\"\n"
		notes = append(notes, "cargo sends the token as an Authorization header to the registry.")
	} else {
		notes = append(notes, "If the proxy requires auth, add a [registries.proxy] token = \"...\" entry or set CARGO_REGISTRIES_PROXY_TOKEN.")
	}
	return Snippet{
		Title: fmt.Sprintf("cargo — %s (config.toml)", b.Name),
		File:  "cargo-config.toml",
		Lang:  "toml",
		Body:  body,
		Notes: notes,
	}
}

func goSnippet(ctx Context, b Backend) Snippet {
	mount := ctx.mount(b)
	body := "go env -w GOPROXY=" + mount + ",direct\n"
	notes := append(ctx.authNote(),
		"The GOPROXY protocol is path-relative, so no URL rewriting is needed.")
	if ctx.Token != "" {
		body += "\n# ~/.netrc (Go reads it for module-proxy auth):\nmachine " + ctx.Host + " login pullthrough password " + ctx.Token + "\n"
	} else {
		notes = append(notes, "If the proxy requires auth, add a ~/.netrc entry: 'machine "+ctx.Host+" login <user> password <token>'.")
	}
	return Snippet{
		Title: fmt.Sprintf("go — %s (GOPROXY)", b.Name),
		File:  "goproxy.env.sh",
		Lang:  "bash",
		Body:  body,
		Notes: notes,
	}
}

func nugetSnippet(ctx Context, b Backend) Snippet {
	index := ctx.mount(b) + "/v3/index.json"
	var sb strings.Builder
	sb.WriteString("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n")
	sb.WriteString("  <packageSources>\n    <clear />\n")
	fmt.Fprintf(&sb, "    <add key=\"proxy\" value=\"%s\" />\n", index)
	sb.WriteString("  </packageSources>\n")
	if ctx.Token != "" {
		sb.WriteString("  <packageSourceCredentials>\n    <proxy>\n")
		sb.WriteString("      <add key=\"Username\" value=\"pullthrough\" />\n")
		fmt.Fprintf(&sb, "      <add key=\"ClearTextPassword\" value=\"%s\" />\n", ctx.Token)
		sb.WriteString("    </proxy>\n  </packageSourceCredentials>\n")
	}
	sb.WriteString("</configuration>\n")
	return Snippet{
		Title: fmt.Sprintf("NuGet — %s (NuGet.config)", b.Name),
		File:  "NuGet.config",
		Lang:  "xml",
		Body:  sb.String(),
		Notes: append(ctx.authNote(),
			"Or: dotnet nuget add source "+index+" --name proxy."),
	}
}

func mavenSnippet(ctx Context, b Backend) Snippet {
	mount := ctx.mount(b)
	var sb strings.Builder
	sb.WriteString("<settings>\n  <mirrors>\n    <mirror>\n")
	sb.WriteString("      <id>pullthrough</id>\n      <name>pull-through proxy</name>\n")
	fmt.Fprintf(&sb, "      <url>%s</url>\n", mount)
	sb.WriteString("      <mirrorOf>*</mirrorOf>\n    </mirror>\n  </mirrors>\n")
	if ctx.Token != "" {
		sb.WriteString("  <servers>\n    <server>\n      <id>pullthrough</id>\n")
		sb.WriteString("      <username>pullthrough</username>\n")
		fmt.Fprintf(&sb, "      <password>%s</password>\n", ctx.Token)
		sb.WriteString("    </server>\n  </servers>\n")
	}
	sb.WriteString("</settings>\n")
	return Snippet{
		Title: fmt.Sprintf("Maven — %s (settings.xml)", b.Name),
		File:  "settings.xml",
		Lang:  "xml",
		Body:  sb.String(),
		Notes: append(ctx.authNote(),
			"~/.m2/settings.xml. Gradle: repositories { maven { url = uri(\""+mount+"\") } }."),
	}
}

func dockerSnippet(ctx Context, b Backend) Snippet {
	// The Docker CLI always appends /v2/ after the host, so a path-prefixed mount
	// cannot be pulled directly: either use a registry mirror (Docker Hub) or an
	// ingress /v2/ rewrite (any registry). The login command targets the host.
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Daemon-wide mirror for Docker Hub (/etc/docker/daemon.json):\n")
	fmt.Fprintf(&sb, "#   { \"registry-mirrors\": [\"%s\"] }\n", ctx.mount(b))
	if ctx.Token != "" {
		fmt.Fprintf(&sb, "echo %q | docker login %s --username pullthrough --password-stdin\n", ctx.Token, ctx.Host)
	} else {
		fmt.Fprintf(&sb, "docker login %s --username pullthrough   # enter your proxy token as the password\n", ctx.Host)
	}
	return Snippet{
		Title: fmt.Sprintf("Docker — %s (login + mirror)", b.Name),
		File:  "docker-login.sh",
		Lang:  "bash",
		Body:  sb.String(),
		Notes: append(ctx.authNote(),
			"Pull by explicit reference needs an ingress that rewrites /v2/ to /v1/"+b.Name+"/v2/ (see docs/clients.md)."),
	}
}

func helmSnippet(ctx Context, b Backend) Snippet {
	mount := ctx.mount(b)
	var sb strings.Builder
	if ctx.Token != "" {
		fmt.Fprintf(&sb, "helm repo add pullthrough %s --username pullthrough --password %q\n", mount, ctx.Token)
	} else {
		fmt.Fprintf(&sb, "helm repo add pullthrough %s   # add --username/--password if the proxy requires auth\n", mount)
	}
	sb.WriteString("helm repo update\n")
	return Snippet{
		Title: fmt.Sprintf("Helm — %s (repo add)", b.Name),
		File:  "helm-repo.sh",
		Lang:  "bash",
		Body:  sb.String(),
		Notes: append(ctx.authNote(),
			"OCI-hosted charts (settings.oci=true) use 'helm registry login "+ctx.Host+"' + 'helm pull oci://...'."),
	}
}

func rubygemsSnippet(ctx Context, b Backend) Snippet {
	mount := WithUserinfo(ctx.mount(b), ctx.Token)
	body := "bundle config mirror.https://rubygems.org " + mount + "\n"
	return Snippet{
		Title: fmt.Sprintf("RubyGems — %s (bundler)", b.Name),
		File:  "bundle-config.sh",
		Lang:  "bash",
		Body:  body,
		Notes: append(ctx.authNote(),
			"Or set the Gemfile source: source \""+ctx.mount(b)+"\"."),
	}
}

func composerSnippet(ctx Context, b Backend) Snippet {
	mount := ctx.mount(b)
	body := "{\n  \"repositories\": [\n    { \"type\": \"composer\", \"url\": \"" + mount + "\" }\n  ]\n}\n"
	notes := append(ctx.authNote(),
		"Add to composer.json. To route all Packagist traffic through the proxy, also add \"packagist.org\": false.")
	if ctx.Token != "" {
		notes = append(notes, "Auth: composer config --global --auth http-basic."+ctx.Host+" pullthrough "+ctx.Token)
	}
	return Snippet{
		Title: fmt.Sprintf("Composer — %s (composer.json)", b.Name),
		File:  "composer-repositories.json",
		Lang:  "json",
		Body:  body,
		Notes: notes,
	}
}

func aptSnippet(ctx Context, b Backend) Snippet {
	mount := ctx.mount(b)
	body := "# /etc/apt/sources.list.d/pullthrough.list\ndeb " + mount + " <suite> <components>\n# e.g.: deb " + mount + " bookworm main\n"
	return Snippet{
		Title: fmt.Sprintf("APT — %s (sources.list)", b.Name),
		File:  "pullthrough.list",
		Lang:  "text",
		Body:  body,
		Notes: append(ctx.authNote(),
			"For auth, add /etc/apt/auth.conf.d/pullthrough.conf: 'machine "+ctx.Host+" login pullthrough password <token>'."),
	}
}

func yumSnippet(ctx Context, b Backend) Snippet {
	mount := ctx.mount(b)
	body := "# /etc/yum.repos.d/pullthrough.repo\n[pullthrough]\nname=Pull-through proxy (" + b.Name + ")\nbaseurl=" + mount + "\nenabled=1\ngpgcheck=1\n"
	return Snippet{
		Title: fmt.Sprintf("YUM/DNF — %s (.repo)", b.Name),
		File:  "pullthrough.repo",
		Lang:  "ini",
		Body:  body,
		Notes: append(ctx.authNote(),
			"For auth, add 'username=' and 'password=' lines to the repo stanza."),
	}
}

func conanSnippet(ctx Context, b Backend) Snippet {
	mount := ctx.mount(b)
	var sb strings.Builder
	fmt.Fprintf(&sb, "conan remote add %s %s\n", b.Name, mount)
	if ctx.Token != "" {
		fmt.Fprintf(&sb, "conan remote login %s pullthrough -p %s\n", b.Name, ctx.Token)
	}
	return Snippet{
		Title: fmt.Sprintf("Conan — %s", b.Name),
		File:  "conan-remote.sh",
		Lang:  "bash",
		Body:  sb.String(),
		Notes: append(ctx.authNote(),
			"Conan 2.x only (the revisions API). The proxy serves the /v2/... endpoints under "+mount+"."),
	}
}

func condaSnippet(ctx Context, b Backend) Snippet {
	mount := ctx.mount(b)
	var sb strings.Builder
	sb.WriteString("# Add the proxied channel to ~/.condarc (or pass -c <url>).\n")
	fmt.Fprintf(&sb, "conda config --add channels %s\n", mount)
	fmt.Fprintf(&sb, "conda config --set custom_channels.%s %s\n", b.Name, mount)
	fmt.Fprintf(&sb, "# e.g. install a package through the proxy:\n# conda install -c %s numpy\n", mount)
	return Snippet{
		Title: fmt.Sprintf("Conda — %s", b.Name),
		File:  "conda-channel.sh",
		Lang:  "bash",
		Body:  sb.String(),
		Notes: append(ctx.authNote(),
			"The proxy serves the channel's per-subdir repodata.json indices and .conda/.tar.bz2 packages under "+mount+". Packages are verified against the SHA-256 their subdir's repodata.json declares."),
	}
}

func cranSnippet(ctx Context, b Backend) Snippet {
	mount := ctx.mount(b)
	var sb strings.Builder
	sb.WriteString("# Point R's package repository at the proxy (interactively or in ~/.Rprofile).\n")
	fmt.Fprintf(&sb, "options(repos = c(PROXY = %q))\n", mount)
	sb.WriteString("install.packages(\"jsonlite\")\n")
	return Snippet{
		Title: fmt.Sprintf("CRAN (R) — %s", b.Name),
		File:  "cran-repos.R",
		Lang:  "r",
		Body:  sb.String(),
		Notes: append(ctx.authNote(),
			"The proxy serves the PACKAGES indices and src/contrib (+ binary) tarballs under "+mount+". Tarballs are verified against the MD5sum their PACKAGES index declares."),
	}
}

func hexSnippet(ctx Context, b Backend) Snippet {
	mount := ctx.mount(b)
	var sb strings.Builder
	sb.WriteString("# Register the proxied repository with mix/hex, then fetch through it.\n")
	fmt.Fprintf(&sb, "mix hex.repo add %s %s\n", b.Name, mount)
	sb.WriteString("# Or point the default repo at the proxy for a project:\n")
	fmt.Fprintf(&sb, "#   export HEX_MIRROR=%s   # (or set :hex_mirror in config)\n", mount)
	fmt.Fprintf(&sb, "# e.g. fetch deps through the proxy:\n# HEX_MIRROR=%s mix deps.get\n", mount)
	return Snippet{
		Title: fmt.Sprintf("Hex (Elixir) — %s", b.Name),
		File:  "hex-repo.sh",
		Lang:  "bash",
		Body:  sb.String(),
		Notes: append(ctx.authNote(),
			"The proxy serves the signed /names, /versions and /packages registry resources and the /tarballs/<name>-<version>.tar artifacts under "+mount+". Tarballs are verified against the outer_checksum their /packages resource declares."),
	}
}

func bazelSnippet(ctx Context, b Backend) Snippet {
	mount := ctx.mount(b)
	var sb strings.Builder
	sb.WriteString("# Point Bazel's module resolution at the proxied registry (in .bazelrc\n")
	sb.WriteString("# or on the command line). Bzlmod resolves modules through it.\n")
	fmt.Fprintf(&sb, "common --registry=%s\n", mount)
	fmt.Fprintf(&sb, "# e.g. resolve the module graph through the proxy:\n# bazel mod deps --registry=%s\n", mount)
	return Snippet{
		Title: fmt.Sprintf("Bazel (Bzlmod) — %s", b.Name),
		File:  ".bazelrc",
		Lang:  "ini",
		Body:  sb.String(),
		Notes: append(ctx.authNote(),
			"The proxy serves the registry's modules/<name>/<version>/MODULE.bazel and source.json descriptors under "+mount+" and rewrites each source.json so its archive URL flows through the proxy, where the fetched archive is verified against the SRI integrity source.json declares."),
	}
}

func jsrSnippet(ctx Context, b Backend) Snippet {
	mount := ctx.mount(b)
	var sb strings.Builder
	sb.WriteString("# Point the JSR client at the proxied registry (Deno honors JSR_URL).\n")
	fmt.Fprintf(&sb, "export JSR_URL=%s\n", mount)
	sb.WriteString("deno add @std/encoding   # resolves modules through the proxy\n")
	return Snippet{
		Title: fmt.Sprintf("JSR (JavaScript Registry) — %s", b.Name),
		File:  "jsr-config.sh",
		Lang:  "bash",
		Body:  sb.String(),
		Notes: append(ctx.authNote(),
			"Setting JSR_URL routes JSR module resolution through the proxy at "+mount+". The proxy serves the package meta.json and <version>_meta.json documents (rewriting any absolute links back through the proxy) and the content-addressable module files, each verified against the SHA-256 the version manifest declares."),
	}
}

func hackageSnippet(ctx Context, b Backend) Snippet {
	mount := ctx.mount(b)
	var sb strings.Builder
	sb.WriteString("# Add the proxied repository to ~/.cabal/config (legacy remote-repo form).\n")
	fmt.Fprintf(&sb, "repository %s\n  url: %s\n", b.Name, mount)
	sb.WriteString("# Then refresh the index and build through the proxy:\n")
	sb.WriteString("cabal update\ncabal build\n")
	return Snippet{
		Title: fmt.Sprintf("Hackage (Haskell) — %s", b.Name),
		File:  "cabal-config",
		Lang:  "ini",
		Body:  sb.String(),
		Notes: append(ctx.authNote(),
			"The proxy serves the 01-index package index, TUF metadata, .cabal descriptions and the /package/<name>-<version>/<name>-<version>.tar.gz sdists under "+mount+". Sdists are verified against the SHA-256 the sibling package.json TUF target metadata declares, where available."),
	}
}

func ansibleSnippet(ctx Context, b Backend) Snippet {
	mount := ctx.mount(b)
	var sb strings.Builder
	sb.WriteString("# Point ansible-galaxy at the proxied registry (ansible.cfg).\n")
	fmt.Fprintf(&sb, "[galaxy]\nserver_list = pullthrough\n\n[galaxy_server.pullthrough]\nurl = %s/\n", mount)
	if ctx.Token != "" {
		fmt.Fprintf(&sb, "token = %s\n", ctx.Token)
	}
	sb.WriteString("# Then install a collection through the proxy:\n")
	sb.WriteString("# ansible-galaxy collection install community.general\n")
	return Snippet{
		Title: fmt.Sprintf("Ansible Galaxy — %s", b.Name),
		File:  "ansible.cfg",
		Lang:  "ini",
		Body:  sb.String(),
		Notes: append(ctx.authNote(),
			"The proxy serves the Galaxy v3 collection index, versions, and version-detail documents (rewriting each version detail's absolute download_url back through the proxy) and the content-addressable collection artifact tarballs under "+mount+". Artifacts are verified against the SHA-256 the version-detail document publishes."),
	}
}

func puppetSnippet(ctx Context, b Backend) Snippet {
	mount := ctx.mount(b)
	var sb strings.Builder
	sb.WriteString("# Point the Puppet module tool at the proxied Forge (puppet.conf / CLI).\n")
	fmt.Fprintf(&sb, "puppet module install puppetlabs-stdlib --module_repository %s\n", mount)
	sb.WriteString("# or persist it in puppet.conf:\n")
	fmt.Fprintf(&sb, "#   [main]\n#   module_repository = %s\n", mount)
	return Snippet{
		Title: fmt.Sprintf("Puppet Forge — %s", b.Name),
		File:  "puppet-forge.sh",
		Lang:  "bash",
		Body:  sb.String(),
		Notes: append(ctx.authNote(),
			"The proxy serves the Forge v3 module and release metadata documents (rewriting any absolute self-reference back through the proxy) and the /v3/files/<owner>-<name>-<version>.tar.gz release tarballs under "+mount+". Tarballs are verified against the file_sha256 (or legacy file_md5) the release metadata declares."),
	}
}

func swiftSnippet(ctx Context, b Backend) Snippet {
	mount := ctx.mount(b)
	var sb strings.Builder
	fmt.Fprintf(&sb, "swift package-registry set %s\n", mount)
	if ctx.Token != "" {
		fmt.Fprintf(&sb, "swift package-registry login %s --token %s\n", mount, ctx.Token)
	}
	sb.WriteString("# Opt a package in: add it as a registry dependency, then\n")
	sb.WriteString("swift package-registry resolve\n")
	return Snippet{
		Title: fmt.Sprintf("Swift Package Manager — %s", b.Name),
		File:  "swift-registry.sh",
		Lang:  "bash",
		Body:  sb.String(),
		Notes: append(ctx.authNote(),
			"The proxy serves the Swift Package Registry API (scope/name/version, Package.swift, source archives) under "+mount+". Source archives are verified against the release metadata's SHA-256 checksum."),
	}
}

func dartSnippet(ctx Context, b Backend) Snippet {
	mount := ctx.mount(b)
	var sb strings.Builder
	fmt.Fprintf(&sb, "export PUB_HOSTED_URL=%s\n", mount)
	sb.WriteString("dart pub get   # or: flutter pub get\n")
	if ctx.Token != "" {
		fmt.Fprintf(&sb, "# Or persist a token:\n# dart pub token add %s\n", mount)
	}
	return Snippet{
		Title: fmt.Sprintf("Dart / Flutter pub — %s", b.Name),
		File:  "pub-config.sh",
		Lang:  "bash",
		Body:  sb.String(),
		Notes: append(ctx.authNote(),
			"Setting PUB_HOSTED_URL routes `dart pub` / `flutter pub` through the proxy at "+mount+". Package archives are downloaded via the proxy and verified against each release's archive_sha256."),
	}
}

func terraformSnippet(ctx Context, b Backend) Snippet {
	mount := ctx.mount(b)
	host := ctx.Host + "/v1/" + b.Name
	var sb strings.Builder
	sb.WriteString("# Use the proxy as a provider/module registry host.\n")
	if ctx.Token != "" {
		sb.WriteString("# ~/.terraformrc:\n")
		fmt.Fprintf(&sb, "credentials \"%s\" {\n  token = %q\n}\n", ctx.Host, ctx.Token)
	}
	sb.WriteString("# Reference providers as " + host + "/<namespace>/<type>.\n")
	return Snippet{
		Title: fmt.Sprintf("Terraform — %s", b.Name),
		File:  "terraformrc",
		Lang:  "hcl",
		Body:  sb.String(),
		Notes: append(ctx.authNote(),
			"Discovery is served at "+mount+"/.well-known/terraform.json."),
	}
}

func gitSnippet(ctx Context, b Backend) Snippet {
	mount := WithUserinfo(ctx.mount(b), ctx.Token)
	body := "git clone " + mount + "/<owner>/<repo>.git\n"
	return Snippet{
		Title: fmt.Sprintf("Git over HTTPS — %s", b.Name),
		File:  "git-clone.sh",
		Lang:  "bash",
		Body:  body,
		Notes: append(ctx.authNote(),
			"Read-only (fetch/clone). Set an existing checkout with: git remote set-url origin "+ctx.mount(b)+"/<owner>/<repo>.git."),
	}
}

// WithUserinfo embeds a token as the userinfo of a URL (https://<token>@host/...)
// when a token is set. Many CLIs accept this inline-credential form. The token
// is percent-encoded so tokens containing reserved characters remain valid.
func WithUserinfo(raw, token string) string {
	if token == "" {
		return raw
	}
	i := strings.Index(raw, "://")
	if i < 0 {
		return raw
	}
	return raw[:i+3] + url.QueryEscape(token) + "@" + raw[i+3:]
}
