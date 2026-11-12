package ecotest

import "time"

// catalog is the ecosystem test set: for each supported ecosystem, the real
// client, the real upstream, a small real package that must install through the
// proxy (Good) and a second small real package that must be refused (Bad).
//
// Choosing packages:
//
//   - Good is the dependency the ecosystem's internal/testset fixture declares
//     wherever that is practical, so the two suites describe the same builds.
//   - Bad is an unrelated, equally small package that is NOT pulled in by the
//     good install (directly, transitively, or by the client's own tooling), so
//     its pin cannot break the good path. Nothing is wrong with these packages:
//     they are "bad" only because the test pins them to the fixture commit the
//     mock LLM flags malicious.
//   - Coordinate / CoordinateVersion spell the package the way the proxy backend
//     reports it to the admission gates, which is what an operator pins. It
//     differs from the client-facing name where the ecosystem's protocol does
//     (a CPAN module vs. its distribution, a Julia package vs. its UUID).
var catalog = []Ecosystem{
	{
		ID:       "npm",
		Client:   "npm",
		Image:    "node:22-slim",
		Upstream: Upstream{Name: "npm", Type: "npm", URL: "https://registry.npmjs.org"},
		Good:     Package{Name: "is-number", Version: "7.0.0", CoordinateVersion: "7.0.0"},
		Bad:      &Package{Name: "left-pad", Version: "1.3.0", CoordinateVersion: "1.3.0"},
		Artifact: `^npm:is-number/-/is-number-7\.0\.0\.tgz$`,
	},
	{
		ID:       "pip",
		Client:   "pip",
		Image:    "python:3.12-slim",
		Upstream: Upstream{Name: "pip", Type: "pip", URL: "https://pypi.org"},
		Good:     Package{Name: "six", Version: "1.16.0", CoordinateVersion: "1.16.0"},
		Bad:      &Package{Name: "toml", Version: "0.10.2", CoordinateVersion: "0.10.2"},
		Artifact: `^pip:files\.pythonhosted\.org/packages/.+/six-1\.16\.0-py2\.py3-none-any\.whl$`,
	},
	{
		ID:       "cargo",
		Client:   "cargo",
		Image:    "rust:1-slim",
		Upstream: Upstream{Name: "cargo", Type: "cargo", URL: "https://index.crates.io"},
		Good:     Package{Name: "cfg-if", Version: "1.0.0", CoordinateVersion: "1.0.0"},
		Bad:      &Package{Name: "itoa", Version: "1.0.11", CoordinateVersion: "1.0.11"},
		Artifact: `^cargo:crates\.io/api/v1/crates/cfg-if/1\.0\.0/download$`,
		// The download log is asserted with the real cargo: which crate went to
		// which client address, and which was refused.
		DownloadLog: true,
	},
	{
		ID:       "go",
		Client:   "go",
		Image:    "golang:1.24-alpine",
		Upstream: Upstream{Name: "go", Type: "go", URL: "https://proxy.golang.org"},
		Good:     Package{Name: "rsc.io/quote", Version: "v1.5.2", CoordinateVersion: "v1.5.2"},
		// Not rsc.io/sampler or golang.org/x/text: rsc.io/quote depends on both.
		Bad:      &Package{Name: "github.com/pkg/errors", Version: "v0.9.1", CoordinateVersion: "v0.9.1"},
		Artifact: `^go:rsc\.io/quote/@v/v1\.5\.2\.zip$`,
		// The download log is asserted with the real go command. Its refused
		// module is refused at the version's .info — the first request that names
		// it — which the log records although it is a metadata request.
		DownloadLog: true,
	},
	{
		ID:     "nuget",
		Client: "dotnet restore",
		Image:  "mcr.microsoft.com/dotnet/sdk:8.0",
		// The NuGet client refuses a repository-signature resource over plain HTTP.
		TLS:      true,
		Upstream: Upstream{Name: "nuget", Type: "nuget", URL: "https://api.nuget.org"},
		Good:     Package{Name: "Newtonsoft.Json", Version: "13.0.3", Coordinate: "newtonsoft.json", CoordinateVersion: "13.0.3"},
		Bad:      &Package{Name: "Humanizer.Core", Version: "2.14.1", Coordinate: "humanizer.core", CoordinateVersion: "2.14.1"},
		Artifact: `^nuget:.*newtonsoft\.json\.13\.0\.3\.nupkg$`,
		Notes:    "Served over HTTPS with a test CA: NuGet requires an HTTPS repository-signature resource.",
	},
	{
		ID:       "maven",
		Client:   "mvn",
		Image:    "maven:3.9-eclipse-temurin-17",
		Upstream: Upstream{Name: "maven", Type: "maven", URL: "https://repo1.maven.org/maven2"},
		Good:     Package{Name: "org.apache.commons:commons-lang3", Version: "3.14.0", CoordinateVersion: "3.14.0"},
		// Not a commons-* or plexus-* artifact: Maven's own plugins depend on those,
		// and they are downloaded through the proxy during the good install too.
		Bad:      &Package{Name: "org.json:json", Version: "20240303", CoordinateVersion: "20240303"},
		Artifact: `^maven:org/apache/commons/commons-lang3/3\.14\.0/commons-lang3-3\.14\.0\.jar$`,
		Timeout:  15 * time.Minute,
	},
	{
		ID:              "docker",
		Client:          "docker",
		Image:           "docker:27-dind",
		Runner:          RunnerDind,
		Upstream:        Upstream{Name: "docker", Type: "docker", URL: "https://registry-1.docker.io"},
		RegistryDefault: "docker",
		Good: Package{Name: "library/alpine", Version: "3.19", CoordinateVersion: "3.19",
			Env: map[string]string{"PKG_UPSTREAM": "docker"}},
		Bad: &Package{Name: "library/busybox", Version: "1.36", CoordinateVersion: "1.36",
			Env: map[string]string{"PKG_UPSTREAM": "docker"}},
		Artifact: `^docker:blobs:sha256:[0-9a-f]{64}$`,
		// The un-prefixed manifest request is what a registry mirror receives; it
		// proves the daemon's mirror-mode pull (not only the explicit reference)
		// was served by the proxy.
		Requests: []string{`^/v2/library/alpine/manifests/`, `^/v2/docker/library/alpine/manifests/`},
		Notes: "Exercises both the explicit `<proxy>/<upstream>/<repository>` reference and registry-mirror mode. " +
			"The daemon has no network, so a refused image cannot be fetched from Docker Hub instead.",
		// The script pulls twice, and the second pull is the registry mirror: a
		// mirror is configured as a host, a host has no path, and so a mirrored
		// pull cannot carry a link. The explicit reference can
		// ("<proxy>/u/<link>/<upstream>/<repository>"), and that is asserted with
		// the real Docker Engine — as is `docker login` with the link as the
		// password — by the hermetic suite in internal/e2e/userlinks.
		NoPersonalLink: "this script's second pull uses the registry mirror, which is configured as a bare host and cannot carry a link; " +
			"the personal image reference (`<proxy>/u/<link>/<upstream>/<repository>`) and `docker login` with the link are asserted " +
			"with the real Docker Engine by the personal-links suite ([user-links.md](user-links.md#tests))",
	},
	{
		ID:         "helm",
		Client:     "helm",
		Image:      "alpine/helm:3.16.3",
		Entrypoint: "sh",
		// A small public repository that publishes ABSOLUTE chart URLs, the case the
		// proxy has to rewrite for the archive download to flow through it.
		Upstream: Upstream{Name: "helm", Type: "helm", URL: "https://stefanprodan.github.io/podinfo"},
		Good:     Package{Name: "podinfo", Version: "6.7.1", CoordinateVersion: "6.7.1"},
		// The repository publishes a single chart, so the bad package is another
		// version of it; both pins are version-exact.
		Bad:      &Package{Name: "podinfo", Version: "6.7.0", CoordinateVersion: "6.7.0"},
		Artifact: `podinfo-6\.7\.1\.tgz$`,
	},
	{
		ID:       "rubygems",
		Client:   "bundler",
		Image:    "ruby:3.3-slim",
		Upstream: Upstream{Name: "rubygems", Type: "rubygems", URL: "https://rubygems.org"},
		Good:     Package{Name: "rake", Version: "13.1.0", CoordinateVersion: "13.1.0"},
		Bad:      &Package{Name: "rainbow", Version: "3.1.1", CoordinateVersion: "3.1.1"},
		Artifact: `^rubygems:gems/rake-13\.1\.0\.gem$`,
	},
	{
		ID:       "composer",
		Client:   "composer",
		Image:    "composer:2",
		Upstream: Upstream{Name: "composer", Type: "composer", URL: "https://repo.packagist.org"},
		Good:     Package{Name: "psr/log", Version: "3.0.0", CoordinateVersion: "3.0.0"},
		Bad:      &Package{Name: "psr/container", Version: "2.0.2", CoordinateVersion: "2.0.2"},
		Artifact: `^composer:.*psr/log/.*3\.0\.0`,
	},
	{
		ID:         "terraform",
		Client:     "terraform",
		Image:      "hashicorp/terraform:1.9",
		Entrypoint: "sh",
		Upstream:   Upstream{Name: "terraform", Type: "terraform", URL: "https://registry.terraform.io"},
		Good:       Package{Name: "hashicorp/null", Version: "3.2.2", CoordinateVersion: "3.2.2"},
		Bad:        &Package{Name: "hashicorp/random", Version: "3.6.0", CoordinateVersion: "3.6.0"},
		Artifact:   `^terraform:v1/providers/hashicorp/null/3\.2\.2/download/linux/[a-z0-9]+/zip$`,
	},
	{
		ID:       "conan",
		Client:   "conan",
		Image:    "python:3.12-slim",
		Upstream: Upstream{Name: "conan", Type: "conan", URL: "https://center2.conan.io"},
		// Conan itself is installed through the proxy's PyPI upstream.
		Extra:    []Upstream{{Name: "pip", Type: "pip", URL: "https://pypi.org"}},
		Good:     Package{Name: "zlib", Version: "1.3.1", CoordinateVersion: "1.3.1"},
		Bad:      &Package{Name: "bzip2", Version: "1.0.8", CoordinateVersion: "1.0.8"},
		Artifact: `^conan:.*zlib/1\.3\.1/.*conanfile\.py$`,
	},
	{
		ID:       "apt",
		Client:   "apt-get",
		Image:    "debian:bookworm-slim",
		Upstream: Upstream{Name: "apt", Type: "apt", URL: "https://deb.debian.org/debian"},
		// The image's own sources include the security archive. With an upstream
		// for it, the interception and NAT legs run APT with those sources
		// exactly as the image ships them.
		Extra: []Upstream{{Name: "apt-security", Type: "apt", URL: "https://deb.debian.org/debian-security"}},
		// APT picks the version the suite currently ships, so pin by name only.
		Good:     Package{Name: "hello"},
		Bad:      &Package{Name: "tree"},
		Artifact: `^apt:pool/main/h/hello/hello_[^/]+\.deb$`,
	},
	{
		ID:     "yum",
		Client: "dnf",
		Image:  "rockylinux:9",
		// BaseOS is small (a few MB of repodata), which keeps the run fast.
		Upstream: Upstream{Name: "yum", Type: "yum", URL: "https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os"},
		// DNF picks the version the repository currently ships: pin by name only.
		Good:     Package{Name: "tree"},
		Bad:      &Package{Name: "zip"},
		Artifact: `^yum:Packages/t/tree-[^/]+\.rpm$`,
	},
	{
		ID:         "git",
		Client:     "git",
		Image:      "alpine/git:2.49.1",
		Entrypoint: "sh",
		Upstream:   Upstream{Name: "git", Type: "git", URL: "https://github.com"},
		Good:       Package{Name: "octocat/Hello-World"},
		// A clone is a pack negotiation, not a versioned artifact: there is no
		// package coordinate for the admission policy to gate, and in pass-through
		// mode nothing immutable to cache. The check here is that a real git client
		// (wire protocol v2) can clone through the proxy at all.
		Bad:      nil,
		Artifact: "",
		Requests: []string{`^/v1/git/octocat/Hello-World\.git/info/refs$`, `^/v1/git/octocat/Hello-World\.git/git-upload-pack$`},
	},
	{
		ID:       "hex",
		Client:   "mix",
		Image:    "elixir:1.16-slim",
		Upstream: Upstream{Name: "hex", Type: "hex", URL: "https://repo.hex.pm"},
		// `mix local.hex` gets Hex itself from builds.hex.pm. repo.hex.pm serves
		// the same installs/ tree, so the hex upstream serves that host too.
		InterceptHosts: map[string]string{"builds.hex.pm": "hex"},
		Good:           Package{Name: "jason", Version: "1.4.1", CoordinateVersion: "1.4.1"},
		// Not decimal: it is an optional dependency of jason.
		Bad:      &Package{Name: "telemetry", Version: "1.2.1", CoordinateVersion: "1.2.1"},
		Artifact: `^hex:tarballs/jason-1\.4\.1\.tar$`,
	},
	{
		ID:         "bazel",
		Client:     "bazel",
		Image:      "gcr.io/bazel-public/bazel:7.4.1",
		Entrypoint: "sh",
		Upstream:   Upstream{Name: "bazel", Type: "bazel", URL: "https://bcr.bazel.build"},
		Good:       Package{Name: "platforms", Version: "0.0.10", CoordinateVersion: "0.0.10"},
		Bad:        &Package{Name: "rules_license", Version: "1.0.0", CoordinateVersion: "1.0.0"},
		Artifact:   `^bazel:modules/platforms/0\.0\.10/archive`,
		Timeout:    15 * time.Minute,
	},
	{
		ID:       "julia",
		Client:   "julia Pkg",
		Image:    "julia:1.10",
		Upstream: Upstream{Name: "julia", Type: "julia", URL: "https://pkg.julialang.org"},
		// The Pkg server protocol addresses a package by UUID and git-tree-sha1, so
		// that is the coordinate the proxy sees: pin the UUID (every tree hash).
		Good:     Package{Name: "Example", Version: "0.5.3", Coordinate: "7876af07-990d-54b4-ab0e-23690620f79a"},
		Bad:      &Package{Name: "IteratorInterfaceExtensions", Version: "1.0.0", Coordinate: "82899510-4779-5014-852e-03e436cf321d"},
		Artifact: `^julia:package/7876af07-990d-54b4-ab0e-23690620f79a/[0-9a-f]{40}$`,
		Timeout:  15 * time.Minute,
	},
	{
		ID:       "cpan",
		Client:   "cpanm",
		Image:    "perl:5.38-slim",
		Upstream: Upstream{Name: "cpan", Type: "cpan", URL: "https://www.cpan.org"},
		// cpanm installs a MODULE; the proxy sees the DISTRIBUTION that provides it.
		// --mirror-only resolves to the newest distribution, so pin by name only.
		Good:     Package{Name: "Try::Tiny", Coordinate: "Try-Tiny"},
		Bad:      &Package{Name: "Text::Glob", Coordinate: "Text-Glob"},
		Artifact: `^cpan:authors/id/.+/Try-Tiny-[0-9.]+\.tar\.gz$`,
	},
	{
		ID:       "openvsx",
		Client:   "ovsx",
		Image:    "node:22-slim",
		Upstream: Upstream{Name: "openvsx", Type: "openvsx", URL: "https://open-vsx.org"},
		// The ovsx CLI is fetched with npx through the proxy's npm upstream.
		Extra:    []Upstream{{Name: "npm", Type: "npm", URL: "https://registry.npmjs.org"}},
		Good:     Package{Name: "dracula-theme.theme-dracula", Version: "2.25.1", CoordinateVersion: "2.25.1"},
		Bad:      &Package{Name: "esbenp.prettier-vscode", Version: "11.0.0", CoordinateVersion: "11.0.0"},
		Artifact: `^openvsx:api/dracula-theme/theme-dracula/2\.25\.1/file/dracula-theme\.theme-dracula-2\.25\.1\.vsix$`,
	},
	{
		ID:     "nix",
		Client: "nix",
		Image:  "nixos/nix:2.35.6",
		Upstream: Upstream{Name: "nix", Type: "nix", URL: "https://cache.nixos.org", Settings: map[string]string{
			"trustedPublicKeys": "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=",
		}},
		// A binary cache addresses a store path by its hash, so the hash is the
		// coordinate. Both paths are GNU hello builds from pinned nixpkgs releases.
		Good: Package{Name: "hello", Version: "2.12.1 (nixos-23.11)", Coordinate: "n5glp21rsz314qssw9fbvfswgy3kc68f",
			Env: map[string]string{"PKG_STORE_PATH": "/nix/store/n5glp21rsz314qssw9fbvfswgy3kc68f-hello-2.12.1"}},
		Bad: &Package{Name: "cowsay", Version: "3.7.0 (nixos-24.05)", Coordinate: "64hd3cmf7cs2aq5wvjk7xz72z83l1i2v",
			Env: map[string]string{"PKG_STORE_PATH": "/nix/store/64hd3cmf7cs2aq5wvjk7xz72z83l1i2v-cowsay-3.7.0"}},
		Artifact: `^nix:nar/[0-9a-z]+\.nar\.xz$`,
	},
	{
		ID:       "jsr",
		Client:   "deno",
		Image:    "denoland/deno:debian-2.9.8",
		Upstream: Upstream{Name: "jsr", Type: "jsr", URL: "https://jsr.io"},
		Good:     Package{Name: "@luca/flag", Version: "1.0.1", CoordinateVersion: "1.0.1"},
		Bad:      &Package{Name: "@std/bytes", Version: "1.0.2", CoordinateVersion: "1.0.2"},
		Artifact: `^jsr:@luca/flag/1\.0\.1/`,
	},
	{
		ID:       "hackage",
		Client:   "cabal",
		Image:    "haskell:9-slim",
		Upstream: Upstream{Name: "hackage", Type: "hackage", URL: "https://hackage.haskell.org"},
		Good:     Package{Name: "text", Version: "2.1", CoordinateVersion: "2.1"},
		Bad:      &Package{Name: "split", Version: "0.2.5", CoordinateVersion: "0.2.5"},
		Artifact: `^hackage:package/text-2\.1`,
		Timeout:  15 * time.Minute,
	},
	{
		ID:       "homebrew",
		Client:   "brew",
		Image:    "homebrew/brew:4.6.20",
		Upstream: Upstream{Name: "homebrew", Type: "homebrew", URL: "https://formulae.brew.sh"},
		// brew installs whatever version the formula index currently lists: pin by
		// name only.
		Good: Package{Name: "hello"},
		Bad:  &Package{Name: "cowsay"},
		// A bottle is cached under its content address (the OCI blob digest).
		Artifact: `^homebrew:bottle:sha256:[0-9a-f]{64}$`,
		Timeout:  15 * time.Minute,
	},
	{
		ID:       "ansible",
		Client:   "ansible-galaxy",
		Image:    "python:3.12-slim",
		Upstream: Upstream{Name: "ansible", Type: "ansible", URL: "https://galaxy.ansible.com"},
		// ansible-core is installed through the proxy's PyPI upstream.
		Extra:    []Upstream{{Name: "pip", Type: "pip", URL: "https://pypi.org"}},
		Good:     Package{Name: "community.general", Version: "8.0.0", CoordinateVersion: "8.0.0"},
		Bad:      &Package{Name: "ansible.posix", Version: "1.5.4", CoordinateVersion: "1.5.4"},
		Artifact: `^ansible:.*community-general-8\.0\.0\.tar\.gz$`,
	},
	{
		ID:       "conda",
		Client:   "conda",
		Image:    "condaforge/miniforge3:24.9.2-0",
		Upstream: Upstream{Name: "conda", Type: "conda", URL: "https://conda.anaconda.org/conda-forge"},
		// Two data-only noarch packages without dependencies.
		Good:     Package{Name: "tzdata", Version: "2024a", CoordinateVersion: "2024a"},
		Bad:      &Package{Name: "font-ttf-ubuntu", Version: "0.83", CoordinateVersion: "0.83"},
		Artifact: `^conda:noarch/tzdata-2024a-[^/]+\.(conda|tar\.bz2)$`,
		Timeout:  20 * time.Minute,
	},
	{
		ID:       "huggingface",
		Client:   "huggingface_hub",
		Image:    "python:3.12-slim",
		Upstream: Upstream{Name: "huggingface", Type: "huggingface", URL: "https://huggingface.co"},
		// huggingface_hub is installed through the proxy's PyPI upstream.
		Extra: []Upstream{{Name: "pip", Type: "pip", URL: "https://pypi.org"}},
		// A commit-pinned revision is immutable, so the file is cached.
		Good: Package{Name: "hf-internal-testing/tiny-random-bert", Version: "f171d7baecaf37b5da5a3616d8833b9969753535",
			Env: map[string]string{"PKG_FILE": "config.json"}},
		Bad: &Package{Name: "hf-internal-testing/tiny-random-gpt2", Version: "71034c5d8bde858ff824298bdedc65515b97d2b9",
			Env: map[string]string{"PKG_FILE": "config.json"}},
		Artifact: `^huggingface:.*tiny-random-bert/resolve/f171d7baecaf37b5da5a3616d8833b9969753535/config\.json$`,
	},
	{
		ID:       "dart",
		Client:   "dart pub",
		Image:    "dart:3.5",
		Upstream: Upstream{Name: "dart", Type: "dart", URL: "https://pub.dev"},
		Good:     Package{Name: "path", Version: "1.9.0", CoordinateVersion: "1.9.0"},
		Bad:      &Package{Name: "collection", Version: "1.18.0", CoordinateVersion: "1.18.0"},
		Artifact: `^dart:.*path-1\.9\.0\.tar\.gz$`,
	},
	{
		ID:       "cran",
		Client:   "R install.packages",
		Image:    "r-base:4.4.1",
		Upstream: Upstream{Name: "cran", Type: "cran", URL: "https://cloud.r-project.org"},
		// install.packages() installs the version CRAN currently serves: pin by
		// name only. Both packages are pure R with no dependencies.
		Good:     Package{Name: "R6"},
		Bad:      &Package{Name: "praise"},
		Artifact: `^cran:src/contrib/R6_[0-9.]+\.tar\.gz$`,
	},
	{
		ID:       "puppet",
		Client:   "r10k",
		Image:    "ruby:3.3-slim",
		Upstream: Upstream{Name: "puppet", Type: "puppet", URL: "https://forgeapi.puppet.com"},
		// r10k is installed through the proxy's RubyGems upstream.
		Extra:    []Upstream{{Name: "rubygems", Type: "rubygems", URL: "https://rubygems.org"}},
		Good:     Package{Name: "puppetlabs-stdlib", Version: "9.4.1", CoordinateVersion: "9.4.1"},
		Bad:      &Package{Name: "puppetlabs-concat", Version: "9.0.2", CoordinateVersion: "9.0.2"},
		Artifact: `^puppet:v3/files/puppetlabs-stdlib-9\.4\.1\.tar\.gz$`,
	},
}
