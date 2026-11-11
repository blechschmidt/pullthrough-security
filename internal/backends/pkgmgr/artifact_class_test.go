package pkgmgr

import (
	"context"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// These tests pin what every ecosystem's Resolve says a path is, for the content
// gates (backends.ArtifactClass). The asymmetry they guard: a payload must never
// be called metadata, because metadata is served unexamined. An unnamed path is
// "unclassified", never "metadata".

const (
	payload      = backends.ArtifactPayload
	metadata     = backends.ArtifactMetadata
	unclassified = backends.ArtifactUnclassified
)

// classCase is one request path and the classification Resolve must give it.
type classCase struct {
	path string
	want backends.ArtifactClass
	// filename is the expected Artifact.Filename: set only for a payload whose
	// upstream URL does not end in the artifact's file name.
	filename string
}

func classOf(t *testing.T, b backends.Backend, path string) backends.Artifact {
	t.Helper()
	res, err := b.Resolve(context.Background(), &backends.Request{Method: "GET", Path: path})
	if err != nil {
		t.Fatalf("Resolve(%q): %v", path, err)
	}
	return res.Artifact
}

func checkClasses(t *testing.T, b backends.Backend, cases []classCase) {
	t.Helper()
	for _, c := range cases {
		got := classOf(t, b, c.path)
		if got.Class != c.want {
			t.Errorf("%q: class = %s, want %s", c.path, got.Class, c.want)
		}
		if got.Filename != c.filename {
			t.Errorf("%q: filename = %q, want %q", c.path, got.Filename, c.filename)
		}
		// The one single-file payload here is a legacy Windows installer on PyPI.
		wantKind := backends.ArtifactKind("")
		if lower := strings.ToLower(c.path); got.Class == backends.ArtifactPayload && strings.HasPrefix(c.path, "/files/") && (strings.HasSuffix(lower, ".exe") || strings.HasSuffix(lower, ".msi")) {
			wantKind = backends.KindFile
		}
		if got.Kind != wantKind {
			t.Errorf("%q: kind = %q, want %q", c.path, got.Kind, wantKind)
		}
	}
}

// hostileSpellings returns variants of a path that an upstream server may
// resolve to a different resource than the one the path appears to name: dot
// segments, doubled slashes, a backslash, a ";" path parameter, a second layer
// of percent-encoding, a control character.
func hostileSpellings(p string) []string {
	last := strings.LastIndex(p, "/")
	return []string{
		"/.." + p,
		"/x/.." + p,
		"/." + p,
		"/" + p,
		p[:last] + "//" + p[last+1:],
		p[:last] + "/./" + p[last+1:],
		p + "/..",
		p + ";x=1",
		p + "%2f..",
		p + "\x00",
		p + " ",
		p + "?x",
		p + "#x",
		strings.ReplaceAll(p, "/", `\`),
		p[:last] + `\..\` + p[last+1:],
	}
}

// checkHostileSpellings asserts that no hostile spelling of a metadata path is
// itself classified as metadata. (A spelling Resolve refuses outright — a
// control character in an absolutely routed URL — is never served at all.)
func checkHostileSpellings(t *testing.T, b backends.Backend, cases []classCase) {
	t.Helper()
	for _, c := range cases {
		if c.want != metadata {
			continue
		}
		for _, p := range hostileSpellings(c.path) {
			res, err := b.Resolve(context.Background(), &backends.Request{Method: "GET", Path: p})
			if err != nil {
				continue
			}
			if res.Artifact.Class == metadata {
				t.Errorf("%q (a spelling of %q) is classified as metadata", p, c.path)
			}
		}
	}
}

func TestNPMArtifactClass(t *testing.T) {
	b, err := NewNPM(Options{Name: "npm", UpstreamURL: "https://registry.npmjs.org", Client: testClient()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []classCase{
		// Tarballs.
		{path: "/lodash/-/lodash-4.17.21.tgz", want: payload},
		{path: "/@babel/core/-/core-7.0.0.tgz", want: payload},

		// Packuments and version manifests.
		{path: "/lodash", want: metadata},
		{path: "/lodash/", want: metadata},
		{path: "/@babel/core", want: metadata},
		{path: "/lodash/4.17.21", want: metadata},
		{path: "/lodash/latest", want: metadata},
		{path: "/@babel/core/7.0.0", want: metadata},

		// The registry's own API lives under "/-/": not a tarball, not a packument.
		{path: "/-/v1/search", want: unclassified},
		{path: "/-/ping", want: unclassified},
		{path: "/-/npm/v1/keys", want: unclassified},
		{path: "/-/package/lodash/dist-tags", want: unclassified},
		// A tarball marker without a tarball.
		{path: "/lodash/-/lodash-4.17.21.tar.gz", want: unclassified},
		{path: "/lodash/-/", want: unclassified},
		// Shapes the registry protocol does not define — where other registries
		// keep their tarballs (GitHub Packages serves them from "/download/…").
		{path: "/download/@scope/pkg/1.0.0/abcdef", want: unclassified},
		{path: "/some/deep/path/x.tgz", want: unclassified},
		{path: "/@scope/pkg/1.0.0/extra", want: unclassified},
		{path: "/a/b/c", want: unclassified},  // three segments need a scope
		{path: "/@scope", want: unclassified}, // a scope alone names no package
		{path: "/lodash/-", want: unclassified},
		{path: "/-", want: unclassified},
		// A short path that ends like an archive is not called a document.
		{path: "/lodash/4.17.21.tgz", want: unclassified},
		{path: "/pkg.zip", want: unclassified},
		{path: "/pkg.TAR.GZ", want: unclassified},
		{path: "/@scope/pkg.tar", want: unclassified},
		{path: "/", want: unclassified},
		{path: "", want: unclassified},
	}
	checkClasses(t, b, cases)
	checkHostileSpellings(t, b, cases)
}

func TestPyPIArtifactClass(t *testing.T) {
	b, err := NewPyPI(Options{
		Name: "pip", UpstreamURL: "https://pypi.org", Client: testClient(),
		Settings: map[string]string{"fileHosts": "files.corp.example:8443"},
	})
	if err != nil {
		t.Fatal(err)
	}
	const files = "/files/https/files.pythonhosted.org/packages/ab/cd/0123abcd/"
	cases := []classCase{
		// Distributions on the files route, by file name.
		{path: files + "requests-2.31.0-py3-none-any.whl", want: payload},
		{path: files + "Flask-3.0.0.tar.gz", want: payload},
		{path: files + "pkg-1.0.tgz", want: payload},
		{path: files + "pkg-1.0.zip", want: payload},
		{path: files + "pkg-1.0.tar.bz2", want: payload},
		{path: files + "pkg-1.0.tar.xz", want: payload},
		{path: files + "pkg-1.0.tar", want: payload},
		{path: files + "pkg-1.0-py3.11.egg", want: payload},
		{path: files + "pkg-1.0.win32.exe", want: payload},
		{path: files + "pkg-1.0.win32.msi", want: payload},
		{path: files + "PKG-1.0-PY3-NONE-ANY.WHL", want: payload},
		// The name decides even where the host is not on the allowlist (the
		// request then falls through to the index host).
		{path: "/files/https/evil.example.com/pkg-1.0-py3-none-any.whl", want: payload},

		// Sidecars of a distribution on an allowlisted host.
		{path: files + "requests-2.31.0-py3-none-any.whl.metadata", want: metadata},
		{path: files + "Flask-3.0.0.tar.gz.asc", want: metadata},
		{path: files + "Flask-3.0.0.tar.gz.sig", want: metadata},
		{path: files + "Flask-3.0.0.tar.gz.provenance", want: metadata},
		{path: files + "Flask-3.0.0.tar.gz.attestation", want: metadata},
		{path: "/files/https/files.corp.example:8443/pkgs/pkg-1.0-py3-none-any.whl.metadata", want: metadata},

		// The index host's APIs.
		{path: "/simple", want: metadata},
		{path: "/simple/", want: metadata},
		{path: "/simple/requests/", want: metadata},
		{path: "/simple/requests", want: metadata},
		{path: "/simple/typing-extensions/", want: metadata},
		{path: "/pypi/requests/json", want: metadata},
		{path: "/pypi/requests/2.31.0/json", want: metadata},
		{path: "/integrity/requests/2.31.0/requests-2.31.0-py3-none-any.whl/provenance", want: metadata},

		// Other files on the files route.
		{path: files + "README.txt", want: unclassified},
		{path: files, want: unclassified},
		// A sidecar name on a host the allowlist does not vouch for.
		{path: "/files/https/evil.example.com/pkg-1.0-py3-none-any.whl.metadata", want: unclassified},
		{path: "/files/ftp/files.pythonhosted.org/pkg-1.0.tar.gz.asc", want: unclassified},
		// A file an index links relatively is fetched from below the page that
		// links it. It is not a Simple page, whatever its prefix.
		{path: "/simple/requests/requests-2.31.0.tar.gz", want: unclassified},
		{path: "/simple/requests/requests-2.31.0-py3-none-any.whl", want: unclassified},
		{path: "/simple/requests/installer", want: unclassified},
		{path: "/simple/requests-2.31.0.tar.gz", want: unclassified},
		{path: "/simple/requests-2.31.0.tbz", want: unclassified},
		{path: "/simple/zope.interface/", want: unclassified}, // not a normalized name
		{path: "/packages/ab/cd/requests-2.31.0.tar.gz", want: unclassified},
		// Near misses of the JSON and Integrity APIs.
		{path: "/pypi/requests", want: unclassified},
		{path: "/pypi/requests/2.31.0/extra/json", want: unclassified},
		{path: "/pypi/json", want: unclassified},
		{path: "/integrity/requests/2.31.0/provenance", want: unclassified},
		{path: "/integrity/requests/2.31.0/requests-2.31.0.tar.gz", want: unclassified},
		{path: "/integrity/requests/2.31.0/requests-2.31.0.tar.gz/other", want: unclassified},
		{path: "/rss/updates.xml", want: unclassified},
		{path: "/", want: unclassified},
		{path: "", want: unclassified},
	}
	checkClasses(t, b, cases)
	checkHostileSpellings(t, b, cases)

	// A path parameter after a distribution's name makes the path end like a
	// sidecar while a servlet container still serves the distribution.
	for _, p := range []string{
		files + "evil-1.0.tar.gz;x=.metadata",
		files + "evil-1.0.tar.gz;.asc",
		"/files/https/files.pythonhosted.org/packages/..;/evil-1.0.tar.gz.metadata",
		"/simple/../packages/source/e/evil/evil-1.0.tar.gz",
		"/simple/..;/packages/evil",
	} {
		if got := classOf(t, b, p); got.Class == metadata {
			t.Errorf("%q is classified as metadata", p)
		}
	}
}

func TestCargoArtifactClass(t *testing.T) {
	b, err := NewCargo(Options{Name: "cargo", UpstreamURL: "https://index.crates.io", Client: testClient()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []classCase{
		// The download: its URL ends in "download", so the file name is stated.
		{path: "/api/v1/crates/serde/1.0.193/download", want: payload, filename: "serde-1.0.193.crate"},
		{path: "/api/v1/crates/tokio-util/0.7.10+build.1/download", want: payload, filename: "tokio-util-0.7.10+build.1.crate"},
		// Still the payload when the name or version does not read as one; it is
		// then not offered to the gates as a file name.
		{path: "/api/v1/crates/../1.0.0/download", want: payload},
		{path: `/api/v1/crates/a\b/1.0.0/download`, want: payload},
		{path: "/api/v1/crates/serde/1.0 .0/download", want: payload},

		// The registry configuration and the sparse index.
		{path: "/config.json", want: metadata},
		{path: "/1/a", want: metadata},
		{path: "/2/ab", want: metadata},
		{path: "/3/a/abc", want: metadata},
		{path: "/ab/cd/abcd", want: metadata},
		{path: "/se/rd/serde", want: metadata},
		{path: "/to/ki/tokio-util", want: metadata},
		{path: "/a_/b-/a_b-c", want: metadata},
		// The rest of the web API.
		{path: "/api/v1/crates", want: metadata},
		{path: "/api/v1/crates/serde", want: metadata},
		{path: "/api/v1/crates/serde/versions", want: metadata},
		{path: "/api/v1/crates/serde/1.0.193", want: metadata},
		{path: "/api/v1/crates/serde/1.0.193/dependencies", want: metadata},
		{path: "/api/v1/crates/serde/1.0.193/readme", want: metadata},

		// An API path that ends in "download" but is not the download path: an
		// upstream may still answer it with a crate.
		{path: "/api/v1/crates/serde/download", want: unclassified},
		{path: "/api/v1/crates/serde/1.0.193/download/", want: unclassified},
		{path: "/api/v1/crates/serde/1.0.193/DOWNLOAD", want: unclassified},
		{path: "/api/v1/crates/serde//1.0.193/download", want: unclassified},
		{path: "/api/v1/crates/a/b/c/download", want: unclassified},
		{path: "/api/v1/crates/download", want: unclassified},
		// Outside the API tree and the index layout.
		{path: "/api/v1/crates/a/b/c/d", want: unclassified},
		{path: "/api/v1/cratesx/serde", want: unclassified},
		{path: "/api/v2/crates/serde", want: unclassified},
		{path: "/api/v1/users/1", want: unclassified},
		{path: "/ab/cd/evil", want: unclassified}, // not below its own prefix directories
		{path: "/3/b/abc", want: unclassified},
		{path: "/1/ab", want: unclassified},
		{path: "/2/a", want: unclassified},
		{path: "/4/ab/cd/abcd", want: unclassified},
		{path: "/se/rd/serde/extra", want: unclassified},
		{path: "/SE/RD/SERDE", want: unclassified},
		{path: "/se/rd/serde.crate", want: unclassified},
		{path: "/config.json/", want: unclassified},
		{path: "/index.html", want: unclassified},
		{path: "/", want: unclassified},
		{path: "", want: unclassified},
	}
	checkClasses(t, b, cases)
	checkHostileSpellings(t, b, cases)

	// A traversal out of the API tree is not an API document.
	if got := classOf(t, b, "/api/v1/crates/../../../static/evil"); got.Class == metadata {
		t.Errorf("traversal classified as %s", got.Class)
	}
}

func TestGoArtifactClass(t *testing.T) {
	cases := []classCase{
		// The module zip.
		{path: "/golang.org/x/mod/@v/v0.1.0.zip", want: payload},
		{path: "/github.com/!burnt!sushi/toml/@v/v1.3.2.zip", want: payload},
		{path: "/example.com/m/@v/v2.0.0+incompatible.zip", want: payload},
		// However it is spelled, a zip path is a payload — never a checksum
		// database document.
		{path: "/sumdb/sum.golang.org/../../example.com/m/@v/v1.0.0.zip", want: payload},
		{path: "/sumdb/sum.golang.org/lookup/example.com/m/@v/v1.0.0.zip", want: payload},

		// The documents of the module protocol.
		{path: "/golang.org/x/mod/@v/list", want: metadata},
		{path: "/golang.org/x/mod/@latest", want: metadata},
		{path: "/golang.org/x/mod/@v/v0.1.0.info", want: metadata},
		{path: "/golang.org/x/mod/@v/v0.1.0.mod", want: metadata},
		{path: "/github.com/!burnt!sushi/toml/@v/v1.3.2.mod", want: metadata},
		{path: "/example.com/m/@v/v2.0.0+incompatible.info", want: metadata},
		{path: "/example.com/m/@v/v0.0.0-20240101000000-abcdef123456.info", want: metadata},
		// The checksum database, proxied by this backend …
		{path: "/sumdb/sum.golang.org/supported", want: metadata},
		{path: "/sumdb/sum.golang.org/latest", want: metadata},
		{path: "/sumdb/sum.golang.org/lookup/rsc.io/quote@v1.5.2", want: metadata},
		{path: "/sumdb/sum.golang.org/lookup/github.com/!burnt!sushi/toml@v1.3.2", want: metadata},
		{path: "/sumdb/sum.golang.org/tile/8/0/x277/878", want: metadata},
		{path: "/sumdb/sum.golang.org/tile/8/1/x001/085.p/119", want: metadata},
		{path: "/sumdb/sum.golang.org/tile/8/data/x277/878", want: metadata},
		// … or left to the upstream proxy.
		{path: "/sumdb/sum.golang.google.cn/supported", want: metadata},
		{path: "/sumdb/sum.golang.google.cn/latest", want: metadata},

		{path: "/golang.org/x/mod", want: unclassified},
		{path: "/golang.org/x/mod/@v/", want: unclassified},
		{path: "/golang.org/x/mod/@v/v0.1.0.ziphash", want: unclassified},
		{path: "/golang.org/x/mod/@v/v0.1.0", want: unclassified},
		{path: "/golang.org/x/mod/@v/.info", want: unclassified},
		{path: "/golang.org/x/mod/@v/v0.1.0.info/extra", want: unclassified},
		{path: "/golang.org/x/mod/@v/list/extra", want: unclassified},
		{path: "/golang.org/x/mod/@latest/extra", want: unclassified},
		{path: "/@v/list", want: unclassified},
		{path: "/@latest", want: unclassified},
		// A module path has no protocol element inside it.
		{path: "/example.com/m/@v/x/@v/v1.0.0.info", want: unclassified},
		{path: "/example.com/m/@v/x/@latest", want: unclassified},
		{path: "/example.com/m/@latest/@v/list", want: unclassified},
		{path: "/sumdb", want: unclassified},
		{path: "/sumdb/sum.golang.org", want: unclassified},
		{path: "/sumdb/sum.golang.org/", want: unclassified},
		{path: "/sumdb/sum.golang.org/unknown", want: unclassified},
		{path: "/sumdb/sum.golang.org/latest/extra", want: unclassified},
		{path: "/sumdb/sum.golang.org/supported/extra", want: unclassified},
		{path: "/sumdb/sum.golang.org/lookup", want: unclassified},
		{path: "/sumdb/sum.golang.org/tile", want: unclassified},
		{path: "/sumdb/sum.golang.org/../../example.com/m/@v/v1.0.0.info", want: unclassified},
		{path: "/", want: unclassified},
		{path: "", want: unclassified},
	}

	// With the checksum-database proxy on (the default) the backend is wrapped,
	// and the wrapper answers the "supported" probe itself; with it off every
	// path goes to the upstream proxy. The classification is the same.
	for name, settings := range map[string]map[string]string{
		"sumdb proxied": nil,
		"sumdb off":     {"sumdb": "off"},
	} {
		t.Run(name, func(t *testing.T) {
			b, err := NewGoProxy(Options{Name: "go", UpstreamURL: "https://proxy.golang.org", Client: testClient(), Settings: settings})
			if err != nil {
				t.Fatal(err)
			}
			if _, wrapped := b.(*goBackend); wrapped != (settings == nil) {
				t.Fatalf("backend wrapped = %v, want %v", wrapped, settings == nil)
			}
			checkClasses(t, b, cases)
			checkHostileSpellings(t, b, cases)
		})
	}
}

// The wrapper's synthetic "supported" answer carries the classification on the
// Resolved it builds itself, not only on those the generic engine builds.
func TestGoSumDBSupportedProbeIsMetadata(t *testing.T) {
	b, err := NewGoProxy(Options{Name: "go", UpstreamURL: "https://proxy.golang.org", Client: testClient()})
	if err != nil {
		t.Fatal(err)
	}
	res, err := b.Resolve(context.Background(), req("/sumdb/sum.golang.org/supported"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Metadata[metaGoSumDBSupported] != "1" {
		t.Fatal("the probe was not answered by the wrapper")
	}
	if res.Artifact != backends.Metadata() {
		t.Errorf("probe artifact = %+v, want metadata", res.Artifact)
	}
}

func TestNuGetArtifactClass(t *testing.T) {
	b, err := NewNuGet(Options{Name: "nuget", UpstreamURL: "https://api.nuget.org", Client: testClient()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []classCase{
		// Packages.
		{path: "/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg", want: payload},
		{path: "/v3-flatcontainer/Newtonsoft.Json/13.0.3/Newtonsoft.Json.13.0.3.NUPKG", want: payload},
		{path: "/packages/newtonsoft.json.13.0.3.nupkg", want: payload},

		// The documents of the v3 layout.
		{path: "/v3/index.json", want: metadata},
		{path: "/index.json", want: metadata},
		{path: "/v3-flatcontainer/newtonsoft.json/index.json", want: metadata},
		{path: "/v3/registration5-gz-semver2/newtonsoft.json/index.json", want: metadata},
		{path: "/v3/registration5-semver1/newtonsoft.json/page/1.0.0/13.0.3.json", want: metadata},
		{path: "/v3/registration5-semver1/ravendb.client/page/1.0.531/1.0.729-unstable.json", want: metadata},
		{path: "/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.nuspec", want: metadata},
		{path: "/v3-flatcontainer/Newtonsoft.Json/13.0.3/Newtonsoft.Json.nuspec", want: metadata},

		// A symbol package is neither.
		{path: "/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.snupkg", want: unclassified},
		// A download URL that ends in the package's id or version ends in whatever
		// the publisher chose: ".json" and ".nuspec" there do not make a document.
		{path: "/api/v2/package/Newtonsoft.Json", want: unclassified},
		{path: "/api/v2/package/Newtonsoft.Json/13.0.3", want: unclassified},
		{path: "/api/v2/package/Evil/1.0.0-rc.json", want: unclassified},
		{path: "/registration-semver2/Download/evil/1.0.0-rc.json", want: unclassified},
		{path: "/api/v2/package/Evil/1.0.0-rc.nuspec", want: unclassified},
		{path: "/api/v2/package/Evil.Nuspec", want: unclassified},
		// A registration leaf has that same shape, so it is not claimed either.
		{path: "/v3/registration5-semver1/newtonsoft.json/13.0.3.json", want: unclassified},
		{path: "/v3/catalog0/data/2024.01.01.00.00.00/newtonsoft.json.13.0.3.json", want: unclassified},
		{path: "/v3/vulnerabilities/vulnerability.base.json", want: unclassified},
		// A manifest that is not the package's own, or not below a version.
		{path: "/v3-flatcontainer/newtonsoft.json/13.0.3/other.nuspec", want: unclassified},
		{path: "/v3-flatcontainer/newtonsoft.json/latest/newtonsoft.json.nuspec", want: unclassified},
		{path: "/newtonsoft.json.nuspec", want: unclassified},
		// A page whose bounds are not versions.
		{path: "/v3/registration5-semver1/newtonsoft.json/page/a/b.json", want: unclassified},
		{path: "/v3-flatcontainer/newtonsoft.json/13.0.3/readme", want: unclassified},
		{path: "/query", want: unclassified},
		{path: "/", want: unclassified},
		{path: "", want: unclassified},
	}
	checkClasses(t, b, cases)
	checkHostileSpellings(t, b, cases)

	// A path parameter after a package's name makes the path end like a document
	// while a servlet container still serves the package.
	for _, p := range []string{
		"/v3-flatcontainer/evil/1.0.0/evil.1.0.0.nupkg;x/index.json",
		"/v3-flatcontainer/evil/1.0.0/evil.1.0.0.nupkg;index.json",
		"/v3-flatcontainer/evil/1.0.0/..;/..;/index.json",
	} {
		if got := classOf(t, b, p); got.Class == metadata {
			t.Errorf("%q is classified as metadata", p)
		}
	}
}

func TestPlainSegments(t *testing.T) {
	plain := map[string][]string{
		"/lodash":                          {"lodash"},
		"/@babel/core":                     {"@babel", "core"},
		"/github.com/!burnt!sushi/toml":    {"github.com", "!burnt!sushi", "toml"},
		"/m/@v/v2.0.0+incompatible.info":   {"m", "@v", "v2.0.0+incompatible.info"},
		"/simple/typing_extensions":        {"simple", "typing_extensions"},
		"/a~b/c-d/e.f":                     {"a~b", "c-d", "e.f"},
		"/sumdb/sum.golang.org/lookup/m@v": {"sumdb", "sum.golang.org", "lookup", "m@v"},
	}
	for p, want := range plain {
		got, ok := plainSegments(p)
		if !ok || strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("plainSegments(%q) = %q, %v; want %q, true", p, got, ok, want)
		}
	}
	for _, p := range []string{
		"", "/", "lodash", "//lodash", "/lodash/", "/a//b",
		"/.", "/..", "/a/./b", "/a/../b", "/../a",
		`/a\b`, "/a;b", "/a%2fb", "/a b", "/a\x00b", "/a\tb", "/a?b", "/a#b",
		"/a:b", "/a,b", "/a=b", "/a&b", "/a$b", "/a*b", "/a'b", `/a"b`, "/a(b)", "/a[b]", "/a{b}", "/a|b", "/a<b>", "/a^b", "/a`b",
		"/café", "/‮gpj.exe",
	} {
		if segs, ok := plainSegments(p); ok {
			t.Errorf("plainSegments(%q) = %q, true; want not plain", p, segs)
		}
	}
}
