package locate

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

func check(t *testing.T, a Artifact, body []byte) CheckResult {
	t.Helper()
	c, err := NewChecker(a, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(body); err != nil {
		t.Fatal(err)
	}
	return c.Result()
}

func hexOf(sum []byte) string { return hex.EncodeToString(sum) }

func TestCheckerVerifiesAndRejects(t *testing.T) {
	body := []byte("the tarball")
	s512 := sha512.Sum512(body)
	s1 := sha1.Sum(body)
	s256 := sha256.Sum256(body)

	res := check(t, Artifact{Role: "package", Expect: []lockfiles.Digest{
		{Algorithm: "sha512", Value: hexOf(s512[:])}, {Algorithm: "sha1", Value: hexOf(s1[:])},
	}}, body)
	if res.Status != CheckVerified || len(res.Checked) != 2 {
		t.Fatalf("both digests of the bytes should verify: %+v", res)
	}
	if res.SHA256 != "sha256:"+hexOf(s256[:]) || res.Size != int64(len(body)) {
		t.Fatalf("sha256/size of the bytes not reported: %+v", res)
	}

	// One algorithm wrong is a mismatch, whatever the other says.
	res = check(t, Artifact{Role: "package", Expect: []lockfiles.Digest{
		{Algorithm: "sha512", Value: hexOf(s512[:])}, {Algorithm: "sha1", Value: strings.Repeat("0", 40)},
	}}, body)
	if res.Status != CheckMismatch || !strings.Contains(res.Detail, "sha1") {
		t.Fatalf("a wrong sha1 must be a mismatch: %+v", res)
	}

	// pip --hash lists every file's hash: any one of them matching is enough.
	res = check(t, Artifact{Role: "file", File: "x-1.0.tar.gz", Expect: []lockfiles.Digest{
		{Algorithm: "sha256", Value: strings.Repeat("a", 64)}, {Algorithm: "sha256", Value: hexOf(s256[:])},
	}}, body)
	if res.Status != CheckVerified {
		t.Fatalf("any-of sha256 should verify: %+v", res)
	}

	// A digest of another file (a pip wheel next to this sdist) is not this
	// artifact's.
	res = check(t, Artifact{Role: "file", File: "x-1.0.tar.gz", Expect: []lockfiles.Digest{
		{Algorithm: "sha256", Value: strings.Repeat("b", 64), Of: "x-1.0-py3-none-any.whl"},
	}}, body)
	if res.Status != CheckUnchecked {
		t.Fatalf("another file's digest is not checked against this one: %+v", res)
	}

	// Kinds the proxy cannot compute are reported, never "verified".
	res = check(t, Artifact{Role: "package", Expect: []lockfiles.Digest{
		{Algorithm: "sha512", Value: hexOf(s512[:]), Of: "nuget-content"},
	}}, body)
	if res.Status != CheckUnchecked || res.Unchecked[0] != "nuget-content" {
		t.Fatalf("nuget-content is not computable: %+v", res)
	}

	if res := check(t, Artifact{Role: "package"}, body); res.Status != CheckUnverified {
		t.Fatalf("no expectation is unverified (TOFU): %+v", res)
	}
}

// The Go module hash is checked against what the go command itself recorded
// for a real module: the module cache keeps the zip, the .mod, and go.sum
// lines for golang.org/x/sync are in this repository's go.sum.
func TestCheckerGoModuleHashMatchesTheGoCommand(t *testing.T) {
	out, err := exec.Command("go", "env", "GOMODCACHE").Output()
	if err != nil {
		t.Skip("go env GOMODCACHE: ", err)
	}
	dir := filepath.Join(strings.TrimSpace(string(out)), "cache", "download", "golang.org", "x", "sync", "@v")
	zipData, err := os.ReadFile(filepath.Join(dir, "v0.16.0.zip"))
	if err != nil {
		t.Skip("golang.org/x/sync v0.16.0 is not in the module cache")
	}
	modData, err := os.ReadFile(filepath.Join(dir, "v0.16.0.mod"))
	if err != nil {
		t.Skip("golang.org/x/sync v0.16.0.mod is not in the module cache")
	}
	// From this repository's go.sum.
	const zipH1 = "ycBJEhp9p4vXvUZNszeOq0kGTPghopOL8q0fq3vstxw="
	const modH1 = "1dzgHSNfp02xaA81J2MS99Qcpr2w7fw1gpm99rleRqA="

	res := check(t, Artifact{Role: "package", Path: "/golang.org/x/sync/@v/v0.16.0.zip",
		Expect: []lockfiles.Digest{{Algorithm: "h1", Value: zipH1}}}, zipData)
	if res.Status != CheckVerified {
		t.Fatalf("module zip hash: %+v", res)
	}
	res = check(t, Artifact{Role: "go.mod", Path: "/golang.org/x/sync/@v/v0.16.0.mod",
		Expect: []lockfiles.Digest{{Algorithm: "h1", Value: modH1, Of: "go.mod"}}}, modData)
	if res.Status != CheckVerified {
		t.Fatalf("go.mod hash: %+v", res)
	}
	// A zip with one byte of a file changed no longer matches.
	tampered := tamperZip(t, zipData)
	res = check(t, Artifact{Role: "package", Path: "/golang.org/x/sync/@v/v0.16.0.zip",
		Expect: []lockfiles.Digest{{Algorithm: "h1", Value: zipH1}}}, tampered)
	if res.Status != CheckMismatch {
		t.Fatalf("a tampered module must not verify: %+v", res)
	}
}

func tamperZip(t *testing.T, data []byte) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		var content bytes.Buffer
		_, _ = content.ReadFrom(rc)
		rc.Close()
		b := content.Bytes()
		if i == 0 && len(b) > 0 {
			b[0] ^= 1
		}
		w, err := zw.Create(f.Name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(b)
	}
	_ = zw.Close()
	return buf.Bytes()
}

func ups(list ...Upstream) Env { return Env{Upstreams: list} }

func TestSelectUpstreamByRegistry(t *testing.T) {
	npmPublic := Upstream{Name: "npm", Type: "npm", URLs: []string{"https://registry.npmjs.org"}}
	npmCorp := Upstream{Name: "npm-corp", Type: "npm", URLs: []string{"https://npm.corp.example/api/npm/npm-a"}}
	cargo := Upstream{Name: "crates", Type: "cargo", URLs: []string{"https://index.crates.io"}}
	pypi := Upstream{Name: "pypi", Type: "pip", URLs: []string{"https://pypi.org"}}
	env := ups(npmPublic, npmCorp, cargo, pypi)

	cases := []struct {
		dep  lockfiles.Dependency
		want string
		err  string
	}{
		{lockfiles.Dependency{Type: "npm", Registry: "https://registry.yarnpkg.com"}, "npm", ""},
		{lockfiles.Dependency{Type: "npm", Registry: "https://npm.corp.example/api/npm/npm-a"}, "npm-corp", ""},
		// Another repository on the same host is another registry.
		{lockfiles.Dependency{Type: "npm", Registry: "https://npm.corp.example/api/npm/npm-b"}, "", "no configured npm upstream"},
		{lockfiles.Dependency{Type: "npm", Registry: "https://evil.example"}, "", "no configured npm upstream"},
		{lockfiles.Dependency{Type: "cargo", Registry: "https://github.com/rust-lang/crates.io-index"}, "crates", ""},
		{lockfiles.Dependency{Type: "pip", Registry: "https://pypi.org/simple"}, "pypi", ""},
		{lockfiles.Dependency{Type: "nuget"}, "", "no nuget upstream"},
		{lockfiles.Dependency{Type: "npm", Upstream: "npm-corp", Registry: "https://npm.corp.example/api/npm/npm-a"}, "npm-corp", ""},
		{lockfiles.Dependency{Type: "npm", Upstream: "gone"}, "", "not a configured npm upstream"},
	}
	for i, c := range cases {
		up, _, err := SelectUpstream(env, c.dep)
		switch {
		case c.err != "":
			if err == nil || !strings.Contains(err.Error(), c.err) || !IsUnsupported(err) {
				t.Errorf("case %d: want unsupported %q, got %v (%s)", i, c.err, err, up.Name)
			}
		case err != nil:
			t.Errorf("case %d: %v", i, err)
		case up.Name != c.want:
			t.Errorf("case %d: chose %q, want %q", i, up.Name, c.want)
		}
	}

	// Without a registry, two upstreams of the type: no guess — a private
	// package's name looked up in the public registry is dependency
	// confusion. With one upstream of the type, it is the answer.
	if up, _, err := SelectUpstream(env, lockfiles.Dependency{Type: "npm"}); !IsUnsupported(err) || !strings.Contains(err.Error(), "upstreams.npm") {
		t.Fatalf("ambiguous: %v %q", err, up.Name)
	}
	if up, notes, err := SelectUpstream(env, lockfiles.Dependency{Type: "cargo"}); err != nil || up.Name != "crates" || len(notes) != 0 {
		t.Fatalf("the only cargo upstream: %v %q %v", err, up.Name, notes)
	}
	// Two upstreams fronting the registry the lock file names: either, with
	// a note.
	mirror := Upstream{Name: "npm-mirror", Type: "npm", URLs: []string{"https://registry.npmjs.org"}}
	up, notes, err := SelectUpstream(ups(npmPublic, mirror), lockfiles.Dependency{Type: "npm", Registry: "https://registry.npmjs.org"})
	if err != nil || up.Name != "npm" || len(notes) == 0 {
		t.Fatalf("two fronting the same registry: %v %q %v", err, up.Name, notes)
	}
	// The repository's preference wins, with a note when the registry differs.
	env.Prefer = map[string]string{"npm": "npm-corp"}
	up, notes, err = SelectUpstream(env, lockfiles.Dependency{Type: "npm", Registry: "https://registry.npmjs.org"})
	if err != nil || up.Name != "npm-corp" || len(notes) == 0 {
		t.Fatalf("preferred: %v %q %v", err, up.Name, notes)
	}
	if up, _, err := SelectUpstream(env, lockfiles.Dependency{Type: "npm"}); err != nil || up.Name != "npm-corp" {
		t.Fatalf("preferred, no registry: %v %q", err, up.Name)
	}
}

func TestRegistryLabelHidesCredentials(t *testing.T) {
	if got := registryLabel("https://user:s3cret@npm.example/x?token=t"); strings.Contains(got, "s3cret") || strings.Contains(got, "token") {
		t.Fatalf("label leaks: %q", got)
	}
}

func TestDeterministicPaths(t *testing.T) {
	npm := Upstream{Name: "npm", Type: "npm", URLs: []string{"https://registry.npmjs.org"}}
	env := Env{Upstreams: []Upstream{
		npm,
		{Name: "crates", Type: "cargo", URLs: []string{"https://index.crates.io"}},
		{Name: "gomod", Type: "go", URLs: []string{"https://proxy.golang.org"}},
		{Name: "gems", Type: "rubygems", URLs: []string{"https://rubygems.org"}},
	}}
	cases := []struct {
		dep   lockfiles.Dependency
		paths []string
	}{
		{lockfiles.Dependency{Type: "npm", Name: "@types/node", Version: "20.14.10"}, []string{"/@types/node/-/node-20.14.10.tgz"}},
		{lockfiles.Dependency{Type: "npm", Name: "left-pad", Version: "1.3.0", URL: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0-custom.tgz"},
			[]string{"/left-pad/-/left-pad-1.3.0-custom.tgz"}},
		{lockfiles.Dependency{Type: "cargo", Name: "itoa", Version: "1.0.11"}, []string{"/api/v1/crates/itoa/1.0.11/download"}},
		{lockfiles.Dependency{Type: "go", Name: "github.com/Azure/go-x", Version: "v1.2.0", Digests: []lockfiles.Digest{{Algorithm: "h1", Value: "x"}}},
			[]string{"/github.com/!azure/go-x/@v/v1.2.0.info", "/github.com/!azure/go-x/@v/v1.2.0.mod", "/github.com/!azure/go-x/@v/v1.2.0.zip"}},
		// Only the go.mod is hashed: only the go.mod is pinned.
		{lockfiles.Dependency{Type: "go", Name: "rsc.io/quote", Version: "v1.5.2", Digests: []lockfiles.Digest{{Algorithm: "h1", Value: "x", Of: "go.mod"}}},
			[]string{"/rsc.io/quote/@v/v1.5.2.info", "/rsc.io/quote/@v/v1.5.2.mod"}},
		{lockfiles.Dependency{Type: "rubygems", Name: "nokogiri", Version: "1.16.7-aarch64-linux"}, []string{"/gems/nokogiri-1.16.7-aarch64-linux.gem"}},
	}
	for _, c := range cases {
		plan, err := Locate(context.Background(), env, c.dep)
		if err != nil {
			t.Errorf("%s %s: %v", c.dep.Type, c.dep.Name, err)
			continue
		}
		var got []string
		for _, a := range plan.Artifacts {
			got = append(got, a.Path)
		}
		if strings.Join(got, " ") != strings.Join(c.paths, " ") {
			t.Errorf("%s %s: paths %v, want %v", c.dep.Type, c.dep.Name, got, c.paths)
		}
	}
}

func TestLocateRefusesHostileCoordinates(t *testing.T) {
	env := ups(Upstream{Name: "npm", Type: "npm", URLs: []string{"https://registry.npmjs.org"}})
	for _, d := range []lockfiles.Dependency{
		{Type: "npm", Name: "../../admin", Version: "1.0.0"},
		{Type: "npm", Name: "x", Version: "1.0.0/../../y"},
		{Type: "npm", Name: "x", Version: "1.0.0?token=1"},
		{Type: "npm", Name: "", Version: "1.0.0"},
	} {
		if _, err := Locate(context.Background(), env, d); err == nil {
			t.Errorf("%q@%q was located", d.Name, d.Version)
		}
	}
}

func TestUnsupportedAndGitDependencies(t *testing.T) {
	env := ups(Upstream{Name: "c", Type: "composer", URLs: []string{"https://repo.packagist.org"}})
	if _, err := Locate(context.Background(), env, lockfiles.Dependency{Type: "composer", Name: "a/b", Version: "1"}); !IsUnsupported(err) {
		t.Fatalf("composer: %v", err)
	}
	if _, err := Locate(context.Background(), env, lockfiles.Dependency{Type: "npm", Name: "a", Version: "1", Source: lockfiles.SourceGit}); !IsUnsupported(err) {
		t.Fatalf("git source: %v", err)
	}
}

// Every lock-file type has a locator or a stated reason.
func TestEveryLockfileTypeIsCovered(t *testing.T) {
	for _, typ := range lockfiles.DefaultRegistry().Types() {
		ok, why := Supported(typ)
		if !ok && why == "" {
			t.Errorf("type %q: neither a locator nor a reason", typ)
		}
		if !ok {
			if _, listed := unsupportedTypes[lockfiles.CanonicalType(typ)]; !listed {
				t.Errorf("type %q has a lock-file parser but no locator and no entry in unsupportedTypes", typ)
			}
		}
	}
}

// fakeDocs serves index documents by path.
type fakeDocs map[string]Document

func (f fakeDocs) FetchDocument(_ context.Context, upstream, path, accept string) (Document, error) {
	d, ok := f[upstream+path]
	if !ok {
		return Document{Status: 404}, nil
	}
	return d, nil
}

func TestPipSelectsTheHashedFiles(t *testing.T) {
	page := map[string]any{"files": []map[string]any{
		{"filename": "certifi-2026.10.23-py3-none-any.whl", "url": "https://proxy.example/v1/pypi/files/https/files.pythonhosted.org/packages/aa/certifi-2026.10.23-py3-none-any.whl#sha256=e9", "hashes": map[string]string{"sha256": "e9"}},
		{"filename": "certifi-2026.10.23.tar.gz", "url": "/v1/pypi/files/https/files.pythonhosted.org/packages/bb/certifi-2026.10.23.tar.gz", "hashes": map[string]string{"sha256": "a9"}},
		{"filename": "certifi-2025.1.1.tar.gz", "url": "/v1/pypi/files/https/files.pythonhosted.org/packages/cc/certifi-2025.1.1.tar.gz", "hashes": map[string]string{"sha256": "c1"}},
	}}
	body, _ := json.Marshal(page)
	env := Env{
		Upstreams: []Upstream{{Name: "pypi", Type: "pip", URLs: []string{"https://pypi.org"}}},
		Fetch:     fakeDocs{"pypi/simple/certifi/": {Status: 200, ContentType: "application/vnd.pypi.simple.v1+json", Body: body}},
	}
	// poetry: digests by file name.
	plan, err := Locate(context.Background(), env, lockfiles.Dependency{Type: "pip", Name: "certifi", Version: "2026.10.23",
		Digests: []lockfiles.Digest{{Algorithm: "sha256", Value: "e9", Of: "certifi-2026.10.23-py3-none-any.whl"}, {Algorithm: "sha256", Value: "zz", Of: "certifi-2026.10.23-missing.whl"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Artifacts) != 2 || plan.Artifacts[1].Path != "/files/https/files.pythonhosted.org/packages/aa/certifi-2026.10.23-py3-none-any.whl" ||
		plan.Artifacts[0].Error == "" {
		t.Fatalf("by name: %+v", plan.Artifacts)
	}
	// requirements --hash: by digest.
	plan, err = Locate(context.Background(), env, lockfiles.Dependency{Type: "pip", Name: "certifi", Version: "2026.10.23",
		Digests: []lockfiles.Digest{{Algorithm: "sha256", Value: "a9"}}})
	if err != nil || len(plan.Artifacts) != 1 || plan.Artifacts[0].File != "certifi-2026.10.23.tar.gz" {
		t.Fatalf("by digest: %v %+v", err, plan)
	}
	// No digests: every file of the version.
	plan, err = Locate(context.Background(), env, lockfiles.Dependency{Type: "pip", Name: "certifi", Version: "2026.10.23"})
	if err != nil || len(plan.Artifacts) != 2 {
		t.Fatalf("tofu: %v %+v", err, plan)
	}
	// The HTML form of the page.
	html := `<html><body><a href="/v1/pypi/files/https/files.pythonhosted.org/packages/bb/certifi-2026.10.23.tar.gz#sha256=a9">certifi-2026.10.23.tar.gz</a></body></html>`
	env.Fetch = fakeDocs{"pypi/simple/certifi/": {Status: 200, ContentType: "text/html", Body: []byte(html)}}
	plan, err = Locate(context.Background(), env, lockfiles.Dependency{Type: "pip", Name: "certifi", Version: "2026.10.23",
		Digests: []lockfiles.Digest{{Algorithm: "sha256", Value: "a9"}}})
	if err != nil || len(plan.Artifacts) != 1 || !strings.HasSuffix(plan.Artifacts[0].Path, "certifi-2026.10.23.tar.gz") {
		t.Fatalf("html: %v %+v", err, plan)
	}
}

func TestMavenFollowsPackaging(t *testing.T) {
	pom := func(packaging string) Document {
		p := `<project><parent><packaging>pom</packaging></parent>`
		if packaging != "" {
			p += `<packaging>` + packaging + `</packaging>`
		}
		return Document{Status: 200, Body: []byte(p + `</project>`)}
	}
	up := Upstream{Name: "central", Type: "maven", URLs: []string{"https://repo.maven.apache.org/maven2"}}
	for packaging, want := range map[string]string{"": "guava-31.1-jre.jar", "war": "guava-31.1-jre.war", "pom": ""} {
		env := Env{Upstreams: []Upstream{up}, Fetch: fakeDocs{"central/com/google/guava/guava/31.1-jre/guava-31.1-jre.pom": pom(packaging)}}
		plan, err := Locate(context.Background(), env, lockfiles.Dependency{Type: "maven", Name: "com.google.guava:guava", Version: "31.1-jre"})
		if err != nil {
			t.Fatalf("%q: %v", packaging, err)
		}
		if plan.Artifacts[0].Role != "pom" {
			t.Fatalf("%q: the POM comes first: %+v", packaging, plan.Artifacts)
		}
		switch {
		case want == "" && len(plan.Artifacts) != 1:
			t.Fatalf("pom packaging has no main artifact: %+v", plan.Artifacts)
		case want != "" && (len(plan.Artifacts) != 2 || plan.Artifacts[1].File != want):
			t.Fatalf("%q: %+v", packaging, plan.Artifacts)
		}
	}
}

func TestNuGetUsesTheServiceIndex(t *testing.T) {
	index := `{"resources":[{"@id":"https://proxy.example/v1/nuget/v3-flatcontainer/","@type":"PackageBaseAddress/3.0.0"}]}`
	env := Env{
		Upstreams: []Upstream{{Name: "nuget", Type: "nuget", URLs: []string{"https://api.nuget.org/v3/index.json"}}},
		Fetch:     fakeDocs{"nuget/v3/index.json": {Status: 200, Body: []byte(index)}},
	}
	plan, err := Locate(context.Background(), env, lockfiles.Dependency{Type: "nuget", Name: "newtonsoft.json", Version: "13.0.3"})
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.Artifacts[0].Path; got != "/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg" {
		t.Fatalf("path %q", got)
	}
}

func TestDockerWalksTheIndex(t *testing.T) {
	d := func(s string) string { return "sha256:" + strings.Repeat(s, 64) }
	index := fmt.Sprintf(`{"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[
		{"digest":%q,"platform":{"os":"linux","architecture":"amd64"}},
		{"digest":%q,"platform":{"os":"linux","architecture":"arm64","variant":"v8"}},
		{"digest":%q,"platform":{"os":"unknown","architecture":"unknown"}}]}`, d("a"), d("b"), d("c"))
	image := func(cfg, layer string) Document {
		return Document{Status: 200, Body: []byte(fmt.Sprintf(`{"config":{"digest":%q},"layers":[{"digest":%q},{"digest":%q,"urls":["https://x"]}]}`, cfg, layer, d("f")))}
	}
	top := d("0")
	docs := fakeDocs{
		"hub/v2/library/alpine/manifests/" + top:    {Status: 200, Body: []byte(index)},
		"hub/v2/library/alpine/manifests/" + d("a"): image(d("1"), d("2")),
		"hub/v2/library/alpine/manifests/" + d("b"): image(d("3"), d("2")),
	}
	env := Env{Upstreams: []Upstream{{Name: "hub", Type: "docker", URLs: []string{"https://registry-1.docker.io"}}}, Fetch: docs}
	dep := lockfiles.Dependency{Type: "docker", Name: "library/alpine", Version: top, Registry: "https://registry-1.docker.io"}
	plan, err := Locate(context.Background(), env, dep)
	if err != nil {
		t.Fatal(err)
	}
	var roles []string
	for _, a := range plan.Artifacts {
		roles = append(roles, a.Role)
		if len(a.Expect) != 1 || !strings.HasSuffix(a.Path, a.Expect[0].Value) {
			t.Errorf("%s is not checked against its own digest: %+v", a.Path, a.Expect)
		}
	}
	// index, then per platform: manifest, config, layer (the shared layer once);
	// the attestation manifest and the foreign layer are not fetched.
	if got := strings.Join(roles, ","); got != "index,manifest,config,layer,manifest,config" {
		t.Fatalf("roles %s", got)
	}
	env.Platforms = []Platform{{OS: "linux", Arch: "arm64"}}
	plan, err = Locate(context.Background(), env, dep)
	if err != nil || len(plan.Artifacts) != 4 {
		t.Fatalf("one platform: %v %+v", err, plan)
	}
	// A tag is not a version.
	if _, err := Locate(context.Background(), env, lockfiles.Dependency{Type: "docker", Name: "library/alpine", Version: "3.19"}); !IsUnsupported(err) {
		t.Fatalf("tag: %v", err)
	}
}

func TestIndexFetchFailures(t *testing.T) {
	env := Env{Upstreams: []Upstream{{Name: "pypi", Type: "pip", URLs: []string{"https://pypi.org"}}}}
	if _, err := Locate(context.Background(), env, lockfiles.Dependency{Type: "pip", Name: "x", Version: "1"}); !IsUnsupported(err) {
		t.Fatalf("without a fetcher: %v", err)
	}
	env.Fetch = fakeDocs{}
	_, err := Locate(context.Background(), env, lockfiles.Dependency{Type: "pip", Name: "x", Version: "1"})
	if err == nil || IsUnsupported(err) || !strings.Contains(err.Error(), "404") {
		t.Fatalf("missing page: %v", err)
	}
	var u *UnsupportedError
	if errors.As(err, &u) {
		t.Fatal("a failed fetch is a failure, not unsupported")
	}
}

func TestPipVersionsFromFileNames(t *testing.T) {
	cases := map[string]string{
		"charset_normalizer-3.5.2-cp310-cp310-manylinux_2_17_x86_64.whl": "3.5.2",
		"charset-normalizer-3.5.2.tar.gz":                                "3.5.2",
		"Charset.Normalizer-3.5.2.zip":                                   "3.5.2",
	}
	for file, want := range cases {
		v, ok := pipFileVersion("charset-normalizer", file)
		if !ok || v != want {
			t.Errorf("%s: %q %v", file, v, ok)
		}
	}
	if !pipSameVersion("1.0", "1.0.0") || pipSameVersion("1.0", "1.0.1") {
		t.Fatal("version canonicalisation")
	}
}

// URLs from the lock file are untrusted: an encoded query, fragment or dot
// segment never reaches the backend as part of the path.
func TestLocatedPathsStayPlain(t *testing.T) {
	env := ups(Upstream{Name: "conda", Type: "conda", URLs: []string{"https://conda.anaconda.org/c"}})
	for _, u := range []string{
		"https://conda.anaconda.org/c/linux-64/x-1.0-0.conda%3Ftoken=1",
		"https://conda.anaconda.org/c/linux-64/%2e%2e/%2e%2e/admin",
		"https://conda.anaconda.org/c/linux-64/x%0d%0aHost:evil",
		"https://conda.anaconda.org/c/linux-64/x%23frag",
	} {
		plan, err := Locate(context.Background(), env, lockfiles.Dependency{Type: "conda", Name: "x", Version: "1.0", URL: u})
		if err == nil && plan.Artifacts[0].Error == "" {
			t.Errorf("%s located as %q", u, plan.Artifacts[0].Path)
		}
	}
	plan, err := Locate(context.Background(), env, lockfiles.Dependency{Type: "conda", Name: "x", Version: "1.0", URL: "https://conda.anaconda.org/c/linux-64/x-1.0-0.conda"})
	if err != nil || plan.Artifacts[0].Error != "" || plan.Artifacts[0].Path != "/linux-64/x-1.0-0.conda" {
		t.Fatalf("a plain URL: %v %+v", err, plan)
	}
}

// A Go module hash that cannot be computed over the bytes served fails
// closed: not a zip is not the module go.sum pins.
func TestCheckerModuleHashFailsClosed(t *testing.T) {
	res := check(t, Artifact{Role: "package", Path: "/m/@v/v1.0.0.zip",
		Expect: []lockfiles.Digest{{Algorithm: "h1", Value: "x"}}}, []byte("not a zip"))
	if res.Status != CheckMismatch || !strings.Contains(res.Detail, "could not be computed") {
		t.Fatalf("%+v", res)
	}
}
