package ecotest

import (
	"embed"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// clientScripts embeds the per-ecosystem client scripts. Each script configures
// one real package manager to use the pull-through proxy and installs the
// package named by $PKG_NAME / $PKG_VERSION. See clients/README.md for the
// environment contract.
//
//go:embed clients
var clientScripts embed.FS

// RunnerKind selects how an ecosystem's client is executed.
type RunnerKind string

const (
	// RunnerContainer runs the client script in a throwaway container of the
	// ecosystem's image on the host network, so the proxy is reachable at
	// 127.0.0.1 exactly as it would be for a developer on the same machine.
	RunnerContainer RunnerKind = "container"
	// RunnerDind runs the client script inside a private Docker-in-Docker
	// daemon whose registry mirror is the proxy. It is used for the Docker
	// ecosystem: the client under test IS a Docker daemon, and the host's own
	// daemon must not be reconfigured by a test.
	RunnerDind RunnerKind = "dind"
)

// Upstream is one upstream the proxy is configured with for a run.
type Upstream struct {
	// Name is the upstream's mount name ("/v1/<name>/").
	Name string
	// Type is the backend type (the ecosystem the admission gates see).
	Type string
	// URL is the real upstream registry.
	URL string
	// Settings are backend-specific settings.
	Settings map[string]string
}

// Package is a package the client is asked to install, together with the
// coordinate the proxy derives for it.
type Package struct {
	// Name and Version are what the client installs, in the ecosystem's own
	// notation. They are passed to the client script as $PKG_NAME/$PKG_VERSION.
	Name    string
	Version string
	// Env carries ecosystem-specific extras for the client script (for example a
	// Julia package UUID or a Nix store path), exported verbatim.
	Env map[string]string
	// Coordinate is the package name exactly as the proxy backend reports it to
	// the admission gates — the name an operator pins. Defaults to Name.
	Coordinate string
	// CoordinateVersion is the version the proxy reports, when the pin should be
	// version-exact. Empty pins every version of the coordinate, which is what a
	// test wants when the ecosystem's client decides the concrete version (apt,
	// dnf, brew) or when the "version" is an opaque content hash.
	CoordinateVersion string
}

// pinName is the coordinate name to pin for the package.
func (p Package) pinName() string {
	if p.Coordinate != "" {
		return p.Coordinate
	}
	return p.Name
}

// Ecosystem describes one real-package-manager test: which client runs, where,
// against which upstream, and which packages exercise the admit and block paths.
type Ecosystem struct {
	// ID is the ecosystem identifier. It matches the fixture ID in
	// internal/testset and names the upstream mount ("/v1/<ID>/").
	ID string
	// Client is the human name of the package manager under test.
	Client string
	// Image is the container image the client runs in.
	Image string
	// Runner selects the execution strategy (default RunnerContainer).
	Runner RunnerKind
	// Entrypoint overrides the image entrypoint for images whose entrypoint is
	// the tool itself; the script is then run as "<Entrypoint> /work/client.sh".
	// Empty runs "sh /work/client.sh" with the image's default entrypoint.
	Entrypoint string
	// User overrides the container user ("0" for images that default to an
	// unprivileged user but whose client needs root). Empty keeps the default.
	User string
	// TLS serves the proxy over HTTPS with a test CA, for clients that refuse a
	// plain-HTTP package source. The CA is handed to the script as $PT_CA_CERT.
	TLS bool
	// Upstream is the upstream under test. Its Name must equal ID.
	Upstream Upstream
	// Extra are auxiliary upstreams the client run needs (e.g. npm, to fetch a
	// CLI with npx).
	Extra []Upstream
	// RegistryDefault, when set, becomes server.registry.defaultUpstream so the
	// proxy serves registry-mirror requests at the host root (Docker).
	RegistryDefault string
	// Good is installed successfully through the proxy. Its source commit is the
	// benign fixture commit.
	Good Package
	// Bad must be refused: its source commit is the fixture commit the mock LLM
	// flags malicious. Nil when the ecosystem has no package coordinate to gate
	// (Git: a clone is a pack negotiation, not a versioned artifact).
	Bad *Package
	// Artifact is a regular expression matching the cache key of the good
	// package's artifact, proving it was stored by the proxy. Empty when the
	// ecosystem's pull is not cacheable in this configuration (Git pass-through).
	Artifact string
	// Requests are regular expressions over request paths; each must match at
	// least one request the proxy answered successfully during the good install.
	// They pin down a client behaviour the cache contents alone cannot prove
	// (e.g. that the Docker Engine really used the proxy as its registry mirror).
	Requests []string
	// Timeout bounds one client run (default 10 minutes).
	Timeout time.Duration
	// DownloadLog additionally asserts the proxy's download log (Task 176): the
	// good package must be logged as served to the address of each client
	// machine that installed it, and the bad package as refused for the machine
	// that tried — read through the admin API, as the console's Downloads tab
	// reads it. Every client step reaches the proxy from a source address of its
	// own, so "which address" is something the proxy observed. It needs a bad
	// package (the refused attempt is half of the assertion).
	DownloadLog bool
	// NoPersonalLink, when set, says why the personal-link check (Task 177) is
	// not run for the ecosystem. Everywhere else the good package is installed
	// once more with the client pointed at a user's personal address of the
	// package source — "<proxy>/u/<link>/v1/<upstream>" in place of
	// "<proxy>/v1/<upstream>" — and the proxy must record the install under
	// that user.
	NoPersonalLink string
	// Notes documents anything a reader needs to know about the choices above.
	Notes string
}

// timeout returns the per-run timeout.
func (e Ecosystem) timeout() time.Duration {
	if e.Timeout > 0 {
		return e.Timeout
	}
	return 10 * time.Minute
}

// runner returns the effective runner kind.
func (e Ecosystem) runner() RunnerKind {
	if e.Runner == "" {
		return RunnerContainer
	}
	return e.Runner
}

// upstreams returns every upstream of the run, the one under test first.
func (e Ecosystem) upstreams() []Upstream {
	return append([]Upstream{e.Upstream}, e.Extra...)
}

// Script returns the embedded client script for the ecosystem.
func (e Ecosystem) Script() ([]byte, error) {
	return clientScripts.ReadFile("clients/" + e.ID + ".sh")
}

// Catalog returns every ecosystem test, sorted by ID. The slice is freshly built
// on each call.
func Catalog() []Ecosystem {
	out := make([]Ecosystem, len(catalog))
	copy(out, catalog)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// IDs returns the sorted ecosystem identifiers in the catalog.
func IDs() []string {
	ids := make([]string, 0, len(catalog))
	for _, e := range catalog {
		ids = append(ids, e.ID)
	}
	sort.Strings(ids)
	return ids
}

// Lookup returns the ecosystem with the given ID.
func Lookup(id string) (Ecosystem, bool) {
	for _, e := range catalog {
		if e.ID == id {
			return e, true
		}
	}
	return Ecosystem{}, false
}

// Validate checks the catalog for internal consistency: unique IDs, a client
// script for every ecosystem (and no stray scripts), well-formed upstreams, a
// good package everywhere, a compilable artifact pattern, and a bad package that
// is distinguishable from the good one by the coordinate the pins key on.
func Validate() error {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	seen := map[string]bool{}
	for _, e := range catalog {
		if e.ID == "" {
			add("ecosystem with empty ID (client %q)", e.Client)
			continue
		}
		if seen[e.ID] {
			add("duplicate ecosystem ID %q", e.ID)
			continue
		}
		seen[e.ID] = true

		if e.Client == "" {
			add("%s: Client is empty", e.ID)
		}
		if e.Image == "" {
			add("%s: Image is empty", e.ID)
		} else if !strings.Contains(e.Image, ":") || strings.HasSuffix(e.Image, ":latest") {
			// A floating tag makes a red build irreproducible: the client that
			// failed yesterday is no longer the client that runs today.
			add("%s: Image %q must be pinned to an explicit, non-latest tag", e.ID, e.Image)
		}
		switch e.runner() {
		case RunnerContainer, RunnerDind:
		default:
			add("%s: unknown Runner %q", e.ID, e.Runner)
		}

		if e.Upstream.Name != e.ID {
			add("%s: Upstream.Name is %q, must equal the ecosystem ID", e.ID, e.Upstream.Name)
		}
		names := map[string]bool{}
		for _, u := range e.upstreams() {
			if u.Name == "" || u.Type == "" || u.URL == "" {
				add("%s: upstream %+v is missing a name, type or url", e.ID, u)
			}
			if names[u.Name] {
				add("%s: duplicate upstream name %q", e.ID, u.Name)
			}
			names[u.Name] = true
		}
		if e.RegistryDefault != "" && !names[e.RegistryDefault] {
			add("%s: RegistryDefault %q is not one of the run's upstreams", e.ID, e.RegistryDefault)
		}

		if e.Good.Name == "" {
			add("%s: Good.Name is empty", e.ID)
		}
		if e.Artifact != "" {
			if _, err := regexp.Compile(e.Artifact); err != nil {
				add("%s: Artifact pattern does not compile: %v", e.ID, err)
			}
		}
		for _, pattern := range e.Requests {
			if _, err := regexp.Compile(pattern); err != nil {
				add("%s: Requests pattern %q does not compile: %v", e.ID, pattern, err)
			}
		}
		if e.Bad != nil {
			if e.Bad.Name == "" {
				add("%s: Bad.Name is empty", e.ID)
			}
			// The bad pin must not also match the good package, or the good install
			// would be refused: either the coordinates differ, or both pins are
			// version-exact with different versions.
			sameName := strings.EqualFold(e.Bad.pinName(), e.Good.pinName())
			versionExact := e.Bad.CoordinateVersion != "" && e.Good.CoordinateVersion != "" &&
				e.Bad.CoordinateVersion != e.Good.CoordinateVersion
			if sameName && !versionExact {
				add("%s: the bad package's pin (%s) would also match the good package", e.ID, e.Bad.pinName())
			}
		}

		if e.DownloadLog && e.Bad == nil {
			add("%s: DownloadLog needs a bad package (the refused attempt is half of what it asserts)", e.ID)
		}

		if _, err := e.Script(); err != nil {
			add("%s: no client script clients/%s.sh (%v)", e.ID, e.ID, err)
		}
	}

	entries, err := clientScripts.ReadDir("clients")
	if err != nil {
		add("reading embedded client scripts: %v", err)
	}
	for _, ent := range entries {
		name := ent.Name()
		if !strings.HasSuffix(name, ".sh") {
			continue
		}
		if id := strings.TrimSuffix(name, ".sh"); !seen[id] {
			add("client script clients/%s has no catalog entry", name)
		}
	}

	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("ecotest catalog invalid:\n  - %s", strings.Join(problems, "\n  - "))
}
