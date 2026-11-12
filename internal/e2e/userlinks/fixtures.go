//go:build integration
// +build integration

package userlinks

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// pkg is one package of a stub registry: what a client asks for, and what the
// download log must say about it.
type pkg struct {
	// Name and Version are the coordinate in the ecosystem's own notation, as
	// the download log reports it.
	Name    string
	Version string
	// Body is the artifact as the upstream serves it.
	Body []byte
	// upstreamPath is the stub path of the artifact.
	upstreamPath string
	// names are the spellings under which upstream requests for the package can
	// be recognised (a wheel is "ptul-good" on the index and "ptul_good" as a
	// file).
	names []string
	// digest is the artifact's digest where the ecosystem addresses it by one (a
	// container image layer).
	digest string
}

func (p pkg) String() string {
	if p.Version == "" {
		return p.Name
	}
	return p.Name + "@" + p.Version
}

// The stub's mount points, one per ecosystem.
const (
	npmPrefix     = "/npm"
	pypiPrefix    = "/pypi"
	cratesPrefix  = "/crates"
	goproxyPrefix = "/goproxy"
)

// stub is the upstream side of the suite: an npm registry, a PyPI index with
// its file host, a crates.io and a GOPROXY on one loopback server, a container
// registry on a second (a registry lives at the root of its host), and a Git
// server — the real `git http-backend` — on a third. It records every request
// with its headers: the suite holds the proxy to never sending a link's token
// upstream.
type stub struct {
	srv *httptest.Server
	// registry is the container registry; registryFiles what it serves.
	registry *httptest.Server
	// gitSrv is the Git server, nil when gitErr says why there is none; gitRoot
	// the directory its repositories live in.
	gitSrv  *httptest.Server
	gitRoot string
	gitErr  error

	mu    sync.Mutex
	files map[string]stubFile
	seen  []string
	hits  map[string]int

	// One package per ecosystem. image is a container image (its artifact is the
	// layer), repo a Git repository.
	npm, pypi, crate, module, image, repo pkg
}

type stubFile struct {
	contentType string
	body        []byte
}

func newStub() (*stub, error) {
	s := &stub{files: map[string]stubFile{}, hits: map[string]int{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	base := s.srv.URL
	if err := s.addRegistry("ptul/good", "1.0.0"); err != nil {
		s.close()
		return nil, err
	}
	// The Git server needs git itself. Without it there is none, and the suite
	// says so in the Git row instead of failing here.
	s.gitErr = s.addGit("ptul/good")

	// npm: a packument that names the tarball by absolute URL — which the proxy
	// rewrites to its own mount — and the tarball.
	npmPkg, err := buildNpmPackage("ptul-good", "1.0.0")
	if err != nil {
		return nil, err
	}
	npmPkg.upstreamPath = npmPrefix + "/" + npmPkg.Name + "/-/" + npmPkg.Name + "-" + npmPkg.Version + ".tgz"
	sum1 := sha1.Sum(npmPkg.Body)
	sum512 := sha512.Sum512(npmPkg.Body)
	s.add(npmPrefix+"/"+npmPkg.Name, "application/json", mustJSON(map[string]any{
		"name":      npmPkg.Name,
		"dist-tags": map[string]string{"latest": npmPkg.Version},
		"versions": map[string]any{npmPkg.Version: map[string]any{
			"name": npmPkg.Name, "version": npmPkg.Version,
			"dist": map[string]string{
				"tarball":   base + npmPkg.upstreamPath,
				"shasum":    hex.EncodeToString(sum1[:]),
				"integrity": "sha512-" + base64.StdEncoding.EncodeToString(sum512[:]),
			},
		}},
		// Text that only looks like a link to the proxy's mount: a README has
		// every right to mention "/v1/npm".
		"readme": "Install from /v1/npm or see https://example.org/v1/npm/ptul-good.",
	}))
	s.add(npmPkg.upstreamPath, "application/octet-stream", npmPkg.Body)
	npmPkg.names = []string{npmPkg.Name}
	s.npm = npmPkg

	// PyPI: a Simple page linking to the wheel on the file host, with its hash.
	wheel, err := buildWheel("ptul-good", "1.0.0")
	if err != nil {
		return nil, err
	}
	wheelFile := "ptul_good-1.0.0-py3-none-any.whl"
	wheel.upstreamPath = pypiPrefix + "/files/" + wheelFile
	s.add(pypiPrefix+"/simple/ptul-good/", "text/html", []byte(
		"<!DOCTYPE html>\n<html><head><meta name=\"pypi:repository-version\" content=\"1.0\"><title>Links for ptul-good</title></head><body>\n"+
			"<a href=\""+base+wheel.upstreamPath+"#sha256="+sha256Hex(wheel.Body)+"\">"+wheelFile+"</a><br/>\n</body></html>\n"))
	s.add(wheel.upstreamPath, "application/octet-stream", wheel.Body)
	wheel.names = []string{"ptul-good", "ptul_good"}
	s.pypi = wheel

	// cargo: config.json names where crates are downloaded from; the proxy
	// rewrites it to point back at itself.
	crate, err := buildCrate("ptul-good", "1.0.0")
	if err != nil {
		return nil, err
	}
	crate.upstreamPath = cratesPrefix + "/api/v1/crates/" + crate.Name + "/" + crate.Version + "/download"
	s.add(cratesPrefix+"/config.json", "application/json",
		mustJSON(map[string]string{"dl": base + cratesPrefix + "/api/v1/crates", "api": base + cratesPrefix}))
	s.add(crate.upstreamPath, "application/gzip", crate.Body)
	s.add(cratesPrefix+"/"+crateIndexPath(crate.Name), "text/plain", append(mustJSON(map[string]any{
		"name": crate.Name, "vers": crate.Version, "deps": []any{},
		"cksum": sha256Hex(crate.Body), "features": map[string]any{}, "yanked": false,
	}), '\n'))
	crate.names = []string{crate.Name}
	s.crate = crate

	// Go: the module proxy protocol is relative; nothing in it names a URL.
	module, gomod, err := buildModule("ptul.test/good", "v1.0.0")
	if err != nil {
		return nil, err
	}
	modBase := goproxyPrefix + "/" + module.Name + "/@v/"
	module.upstreamPath = modBase + module.Version + ".zip"
	s.add(modBase+"list", "text/plain", []byte(module.Version+"\n"))
	s.add(modBase+module.Version+".info", "application/json",
		mustJSON(map[string]string{"Version": module.Version, "Time": "2024-01-02T03:04:05Z"}))
	s.add(modBase+module.Version+".mod", "text/plain", gomod)
	s.add(module.upstreamPath, "application/zip", module.Body)
	module.names = []string{module.Name}
	s.module = module
	return s, nil
}

func (s *stub) close() {
	s.srv.Close()
	if s.registry != nil {
		s.registry.Close()
	}
	if s.gitSrv != nil {
		s.gitSrv.Close()
	}
	if s.gitRoot != "" {
		_ = os.RemoveAll(s.gitRoot)
	}
}

func (s *stub) url(prefix string) string { return s.srv.URL + prefix }

// host is the stub's host:port, which is what the PyPI adapter is told is the
// index's file host.
func (s *stub) host() string { return strings.TrimPrefix(s.srv.URL, "http://") }

func (s *stub) add(path, contentType string, body []byte) {
	s.files[path] = stubFile{contentType: contentType, body: body}
}

// record notes a request an upstream received: its request line and headers.
func (s *stub) record(r *http.Request) {
	var hdr strings.Builder
	_ = r.Header.Write(&hdr)
	s.mu.Lock()
	s.seen = append(s.seen, r.Method+" "+r.URL.RequestURI()+"\n"+hdr.String())
	s.mu.Unlock()
}

func (s *stub) serve(w http.ResponseWriter, r *http.Request) {
	s.record(r)
	s.mu.Lock()
	file, ok := s.files[r.URL.Path]
	if ok {
		s.hits[r.URL.Path]++
	}
	s.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", file.contentType)
	_, _ = w.Write(file.body)
}

// requests returns everything the stub was sent, request lines and headers.
func (s *stub) requests() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.seen, "\n")
}

// fetches reports how often the artifact of p was fetched from the stub.
func (s *stub) fetches(p pkg) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[p.upstreamPath]
}

// requestsNaming counts the requests the upstreams received that name p.
func (s *stub) requestsNaming(p pkg) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, req := range s.seen {
		line, _, _ := strings.Cut(req, "\n")
		for _, name := range p.names {
			if strings.Contains(line, name) {
				n++
				break
			}
		}
	}
	return n
}

// --- the container registry -------------------------------------------------------

// Media types of a Docker image, schema 2.
const (
	mediaManifest = "application/vnd.docker.distribution.manifest.v2+json"
	mediaConfig   = "application/vnd.docker.container.image.v1+json"
	mediaLayer    = "application/vnd.docker.image.rootfs.diff.tar.gzip"
)

// addRegistry starts the container registry with one image: a single layer
// holding one file, built for the platform the suite runs on.
func (s *stub) addRegistry(repository, tag string) error {
	layerTar, err := tarOf([]member{{"answer.txt", "42\n"}})
	if err != nil {
		return err
	}
	layer, err := gzipOf(layerTar)
	if err != nil {
		return err
	}
	config := mustJSON(map[string]any{
		"architecture": runtime.GOARCH,
		"os":           "linux",
		"created":      "2024-01-02T03:04:05Z",
		"config":       map[string]any{"Labels": map[string]string{"org.opencontainers.image.title": "ptul-good"}},
		"rootfs":       map[string]any{"type": "layers", "diff_ids": []string{"sha256:" + sha256Hex(layerTar)}},
		"history":      []any{map[string]string{"created": "2024-01-02T03:04:05Z", "created_by": "the personal-links integration suite"}},
	})
	layerDigest, configDigest := "sha256:"+sha256Hex(layer), "sha256:"+sha256Hex(config)
	manifest := mustJSON(map[string]any{
		"schemaVersion": 2,
		"mediaType":     mediaManifest,
		"config":        map[string]any{"mediaType": mediaConfig, "size": len(config), "digest": configDigest},
		"layers":        []any{map[string]any{"mediaType": mediaLayer, "size": len(layer), "digest": layerDigest}},
	})
	manifestDigest := "sha256:" + sha256Hex(manifest)

	root := "/v2/" + repository
	s.add(root+"/manifests/"+tag, mediaManifest, manifest)
	s.add(root+"/manifests/"+manifestDigest, mediaManifest, manifest)
	s.add(root+"/blobs/"+configDigest, "application/octet-stream", config)
	s.add(root+"/blobs/"+layerDigest, "application/octet-stream", layer)
	s.image = pkg{
		Name: repository, Version: tag, Body: layer, upstreamPath: root + "/blobs/" + layerDigest,
		names: []string{"/" + repository + "/"}, digest: layerDigest,
	}
	s.registry = httptest.NewServer(http.HandlerFunc(s.serveRegistry))
	return nil
}

// serveRegistry speaks as much of the Registry v2 API as a pull needs.
func (s *stub) serveRegistry(w http.ResponseWriter, r *http.Request) {
	s.record(r)
	w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
	if r.URL.Path == "/v2/" || r.URL.Path == "/v2" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
		return
	}
	s.mu.Lock()
	file, ok := s.files[r.URL.Path]
	if ok && r.Method == http.MethodGet {
		s.hits[r.URL.Path]++
	}
	s.mu.Unlock()
	if !ok || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[{"code":"MANIFEST_UNKNOWN","message":"the stub registry has no such object"}]}`))
		return
	}
	w.Header().Set("Content-Type", file.contentType)
	w.Header().Set("Docker-Content-Digest", "sha256:"+sha256Hex(file.body))
	w.Header().Set("Content-Length", fmt.Sprint(len(file.body)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(file.body)
}

// --- the Git server ---------------------------------------------------------------

// addGit creates a repository with one commit and serves it with Git's own
// smart-HTTP server, `git http-backend`.
func (s *stub) addGit(repository string) error {
	gitBin, err := exec.LookPath("git")
	if err != nil {
		return err
	}
	out, err := exec.Command(gitBin, "--exec-path").Output()
	if err != nil {
		return fmt.Errorf("git --exec-path: %w", err)
	}
	backend := filepath.Join(strings.TrimSpace(string(out)), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		return fmt.Errorf("git's smart-HTTP server is not installed: %w", err)
	}
	root, err := os.MkdirTemp("", "userlinks-git-upstream-")
	if err != nil {
		return err
	}
	s.gitRoot = root

	// A work tree with one commit, pushed into the bare repository the server
	// exports. Nothing of the machine's own Git configuration is read.
	env := append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "HOME="+root,
		"GIT_AUTHOR_NAME=Fixture", "GIT_AUTHOR_EMAIL=fixture@example.com", "GIT_AUTHOR_DATE=2024-01-02T03:04:05Z",
		"GIT_COMMITTER_NAME=Fixture", "GIT_COMMITTER_EMAIL=fixture@example.com", "GIT_COMMITTER_DATE=2024-01-02T03:04:05Z",
	)
	work, bare := filepath.Join(root, "work"), filepath.Join(root, "repos", repository+".git")
	if err := writeFiles(map[string]string{filepath.Join(work, "README.md"): "# ptul/good\n\nFixture repository of the personal-links integration suite.\n"}); err != nil {
		return err
	}
	for _, args := range [][]string{
		{"init", "--quiet", "--bare", "--initial-branch=main", bare},
		{"-C", work, "init", "--quiet", "--initial-branch=main"},
		{"-C", work, "add", "README.md"},
		{"-C", work, "commit", "--quiet", "-m", "Initial commit"},
		{"-C", work, "push", "--quiet", bare, "main"},
	} {
		cmd := exec.Command(gitBin, args...)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}

	handler := &cgi.Handler{
		Path: backend,
		Env:  []string{"GIT_PROJECT_ROOT=" + filepath.Join(root, "repos"), "GIT_HTTP_EXPORT_ALL=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1"},
	}
	s.gitSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.record(r)
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git-upload-pack") {
			s.mu.Lock()
			s.hits[r.URL.Path]++
			s.mu.Unlock()
		}
		// The proxy streams a fetch request on without knowing its length, as a
		// web server in front of Git would receive it from any client with a
		// large one. CGI has no notion of a chunked body: a web server reads it
		// in and tells the program its length, and so does this one.
		if len(r.TransferEncoding) > 0 {
			body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
			r.TransferEncoding = nil
		}
		handler.ServeHTTP(w, r)
	}))
	// The download log calls a repository by its path on the forge.
	s.repo = pkg{
		Name: repository + ".git", upstreamPath: "/" + repository + ".git/git-upload-pack",
		names: []string{"/" + repository + ".git"},
	}
	return nil
}

// crateIndexPath is where the sparse index keeps a crate's version list.
func crateIndexPath(name string) string {
	switch len(name) {
	case 1:
		return "1/" + name
	case 2:
		return "2/" + name
	case 3:
		return "3/" + name[:1] + "/" + name
	default:
		return name[:2] + "/" + name[2:4] + "/" + name
	}
}

type member struct{ name, body string }

func tarGz(files []member) ([]byte, error) {
	raw, err := tarOf(files)
	if err != nil {
		return nil, err
	}
	return gzipOf(raw)
}

func gzipOf(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func tarOf(files []member) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		hdr := &tar.Header{
			Name: f.name, Mode: 0o644, Size: int64(len(f.body)),
			ModTime: time.Unix(1700000000, 0), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write([]byte(f.body)); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func zipOf(files []member) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range files {
		w, err := zw.Create(f.name)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(f.body)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// buildNpmPackage builds an npm tarball: a gzip-compressed tar whose members
// sit under "package/".
func buildNpmPackage(name, version string) (pkg, error) {
	body, err := tarGz([]member{
		{"package/package.json", string(mustJSON(map[string]string{
			"name": name, "version": version, "main": "index.js", "license": "MIT",
			"description": "Fixture package of the personal-links integration suite.",
		})) + "\n"},
		{"package/index.js", "'use strict';\nmodule.exports = function answer() { return 42; };\n"},
	})
	return pkg{Name: name, Version: version, Body: body}, err
}

// buildWheel builds a pure-Python wheel with the metadata pip reads.
func buildWheel(name, version string) (pkg, error) {
	module := strings.ReplaceAll(name, "-", "_")
	distInfo := module + "-" + version + ".dist-info/"
	files := []member{
		{module + "/__init__.py", "\"\"\"Fixture package of the personal-links integration suite.\"\"\"\n\n\ndef answer():\n    return 42\n"},
		{distInfo + "METADATA", "Metadata-Version: 2.1\nName: " + name + "\nVersion: " + version + "\nSummary: Fixture package of the personal-links integration suite.\n"},
		{distInfo + "WHEEL", "Wheel-Version: 1.0\nGenerator: pullthrough-userlinks-suite\nRoot-Is-Purelib: true\nTag: py3-none-any\n"},
	}
	// RECORD lists every file with its hash, and itself without one.
	var record strings.Builder
	for _, f := range files {
		sum := sha256.Sum256([]byte(f.body))
		fmt.Fprintf(&record, "%s,sha256=%s,%d\n", f.name, base64.RawURLEncoding.EncodeToString(sum[:]), len(f.body))
	}
	record.WriteString(distInfo + "RECORD,,\n")
	files = append(files, member{distInfo + "RECORD", record.String()})
	body, err := zipOf(files)
	return pkg{Name: name, Version: version, Body: body}, err
}

// buildCrate builds a .crate: a gzip-compressed tar whose members sit under
// "<name>-<version>/", with a manifest cargo accepts.
func buildCrate(name, version string) (pkg, error) {
	root := name + "-" + version + "/"
	body, err := tarGz([]member{
		{root + "Cargo.toml", "[package]\nname = \"" + name + "\"\nversion = \"" + version + "\"\nedition = \"2021\"\n" +
			"description = \"Fixture crate of the personal-links integration suite.\"\nlicense = \"MIT\"\n"},
		{root + "src/lib.rs", "//! Fixture crate of the personal-links integration suite.\n\n/// Returns the answer.\npub fn answer() -> u32 {\n    42\n}\n"},
	})
	return pkg{Name: name, Version: version, Body: body}, err
}

// buildModule builds a Go module zip, whose members sit under
// "<module>@<version>/", and returns it with its go.mod.
func buildModule(path, version string) (pkg, []byte, error) {
	root := path + "@" + version + "/"
	name := path[strings.LastIndex(path, "/")+1:]
	gomod := "module " + path + "\n\ngo 1.21\n"
	body, err := zipOf([]member{
		{root + "go.mod", gomod},
		{root + "lib.go", "// Package " + name + " is a fixture module of the personal-links integration suite.\npackage " + name +
			"\n\n// Answer returns the answer.\nfunc Answer() int { return 42 }\n"},
	})
	return pkg{Name: path, Version: version, Body: body}, []byte(gomod), err
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("marshalling a fixture document: %v", err))
	}
	return b
}
