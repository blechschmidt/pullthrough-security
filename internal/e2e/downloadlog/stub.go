//go:build integration
// +build integration

package downloadlog

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// pkg is one package of the stub registries: what a client asks for, and what
// the download log must say about it.
type pkg struct {
	// Name and Version are the coordinate, in the ecosystem's own notation.
	Name    string
	Version string
	// Artifact is the file name the log reports for the package's artifact.
	Artifact string
	// Body is the artifact as the upstream serves it.
	Body []byte
	// upstreamPath is the stub path the artifact is fetched from, for counting
	// how often the proxy went upstream for it.
	upstreamPath string
}

func (p pkg) String() string { return p.Name + "@" + p.Version }

// The packages every ecosystem's stub offers.
const (
	roleGood   = "good"   // installed by the first two client machines
	roleExtra  = "extra"  // installed by the machines behind the forwarders
	roleDenied = "denied" // on the dependency firewall's denylist
)

var roles = []string{roleGood, roleExtra, roleDenied}

// stub is the upstream side of the suite: a crates.io (sparse index plus crate
// downloads) and a GOPROXY on one loopback server, with request counting.
type stub struct {
	srv *httptest.Server

	mu    sync.Mutex
	hits  map[string]int
	files map[string]stubFile

	crates  map[string]pkg // by role
	modules map[string]pkg // by role
}

type stubFile struct {
	contentType string
	body        []byte
}

const (
	cratesPrefix  = "/crates"
	goproxyPrefix = "/goproxy"
)

func newStub() (*stub, error) {
	s := &stub{
		hits:    map[string]int{},
		files:   map[string]stubFile{},
		crates:  map[string]pkg{},
		modules: map[string]pkg{},
	}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))

	// config.json names where crates are downloaded from; the proxy rewrites it
	// to point back at itself.
	s.add(cratesPrefix+"/config.json", "application/json",
		mustJSON(map[string]string{"dl": s.cratesURL() + "/api/v1/crates", "api": s.cratesURL()}))

	for _, role := range roles {
		crate, err := buildCrate("ptdl-"+role, "1.0.0")
		if err != nil {
			return nil, err
		}
		crate.upstreamPath = cratesPrefix + "/api/v1/crates/" + crate.Name + "/" + crate.Version + "/download"
		s.add(crate.upstreamPath, "application/gzip", crate.Body)
		line := mustJSON(map[string]any{
			"name": crate.Name, "vers": crate.Version, "deps": []any{},
			"cksum": sha256Hex(crate.Body), "features": map[string]any{}, "yanked": false,
		})
		s.add(cratesPrefix+"/"+crateIndexPath(crate.Name), "text/plain", append(line, '\n'))
		s.crates[role] = crate

		module, gomod, err := buildModule("ptdl.test/"+role, "v1.0.0")
		if err != nil {
			return nil, err
		}
		base := goproxyPrefix + "/" + module.Name + "/@v/"
		module.upstreamPath = base + module.Version + ".zip"
		s.add(base+"list", "text/plain", []byte(module.Version+"\n"))
		s.add(base+module.Version+".info", "application/json",
			mustJSON(map[string]string{"Version": module.Version, "Time": "2024-01-02T03:04:05Z"}))
		s.add(base+module.Version+".mod", "text/plain", gomod)
		s.add(module.upstreamPath, "application/zip", module.Body)
		s.modules[role] = module
	}
	return s, nil
}

func (s *stub) close() { s.srv.Close() }

func (s *stub) cratesURL() string  { return s.srv.URL + cratesPrefix }
func (s *stub) goproxyURL() string { return s.srv.URL + goproxyPrefix }

func (s *stub) add(path, contentType string, body []byte) {
	s.files[path] = stubFile{contentType: contentType, body: body}
}

func (s *stub) serve(w http.ResponseWriter, r *http.Request) {
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

// fetches reports how many times the artifact of p was fetched from the stub.
func (s *stub) fetches(p pkg) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[p.upstreamPath]
}

// crateIndexPath is where the sparse index keeps a crate's version list: names
// of four or more characters fan out as "<first two>/<next two>/<name>".
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

// buildCrate builds a .crate: a gzip-compressed tar whose members sit under
// "<name>-<version>/", with a manifest cargo accepts.
func buildCrate(name, version string) (pkg, error) {
	root := name + "-" + version + "/"
	files := []struct{ name, body string }{
		{root + "Cargo.toml", "[package]\nname = \"" + name + "\"\nversion = \"" + version + "\"\nedition = \"2021\"\n" +
			"description = \"Fixture crate of the download-log integration suite.\"\nlicense = \"MIT\"\n"},
		{root + "src/lib.rs", "//! Fixture crate of the download-log integration suite.\n\n/// Returns the answer.\npub fn answer() -> u32 {\n    42\n}\n"},
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, f := range files {
		hdr := &tar.Header{
			Name: f.name, Mode: 0o644, Size: int64(len(f.body)),
			ModTime: time.Unix(1700000000, 0), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return pkg{}, err
		}
		if _, err := tw.Write([]byte(f.body)); err != nil {
			return pkg{}, err
		}
	}
	if err := tw.Close(); err != nil {
		return pkg{}, err
	}
	if err := zw.Close(); err != nil {
		return pkg{}, err
	}
	return pkg{Name: name, Version: version, Artifact: name + "-" + version + ".crate", Body: buf.Bytes()}, nil
}

// buildModule builds a Go module zip, whose members sit under
// "<module>@<version>/", and returns it with its go.mod.
func buildModule(path, version string) (pkg, []byte, error) {
	root := path + "@" + version + "/"
	name := path[strings.LastIndex(path, "/")+1:]
	gomod := "module " + path + "\n\ngo 1.21\n"
	files := []struct{ name, body string }{
		{root + "go.mod", gomod},
		{root + "lib.go", "// Package " + name + " is a fixture module of the download-log integration suite.\npackage " + name +
			"\n\n// Answer returns the answer.\nfunc Answer() int { return 42 }\n"},
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range files {
		w, err := zw.Create(f.name)
		if err != nil {
			return pkg{}, nil, err
		}
		if _, err := w.Write([]byte(f.body)); err != nil {
			return pkg{}, nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return pkg{}, nil, err
	}
	return pkg{Name: path, Version: version, Artifact: version + ".zip", Body: buf.Bytes()}, []byte(gomod), nil
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
