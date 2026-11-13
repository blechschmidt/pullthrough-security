//go:build integration || livellm

package livescan

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
)

// Stub registries: one per ecosystem the corpus needs, each serving both
// variants of every sample of its kind in the ecosystem's own protocol, the
// way the real registry serves them — so the proxy's real backends, metadata
// rewriting and verify-on-fetch run before the gate sees the bytes.

// stubServer is a registry: fixed documents by path, plus handlers.
type stubServer struct {
	srv *httptest.Server

	mu     sync.Mutex
	files  map[string]stubFile
	routes map[string]http.HandlerFunc
	hits   map[string]int
}

type stubFile struct {
	body        []byte
	contentType string
}

func newStubServer() *stubServer {
	s := &stubServer{files: map[string]stubFile{}, routes: map[string]http.HandlerFunc{}, hits: map[string]int{}}
	s.srv = httptest.NewServer(s)
	return s
}

func (s *stubServer) URL() string { return s.srv.URL }
func (s *stubServer) Close()      { s.srv.Close() }

// File serves body at path.
func (s *stubServer) File(path string, body []byte, contentType string) {
	s.mu.Lock()
	s.files[path] = stubFile{body: body, contentType: contentType}
	s.mu.Unlock()
}

// Handle serves path with h.
func (s *stubServer) Handle(path string, h http.HandlerFunc) {
	s.mu.Lock()
	s.routes[path] = h
	s.mu.Unlock()
}

// Hits counts the requests for path.
func (s *stubServer) Hits(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[path]
}

func (s *stubServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.hits[r.URL.Path]++
	f, okFile := s.files[r.URL.Path]
	h, okRoute := s.routes[r.URL.Path]
	s.mu.Unlock()
	switch {
	case okRoute:
		h(w, r)
	case okFile:
		w.Header().Set("Content-Type", f.contentType)
		w.Header().Set("Content-Length", fmt.Sprint(len(f.body)))
		if r.Method != http.MethodHead {
			_, _ = w.Write(f.body)
		}
	default:
		http.NotFound(w, r)
	}
}

// step is one client request below an upstream's mount.
type step struct {
	Path   string
	Header http.Header
	// Contains are strings the response must contain (with "{mount}" standing
	// for the upstream's mount on the proxy): the proof that a client reading
	// the document is sent to the proxy, not around it.
	Contains []string
}

const mountPlaceholder = "{mount}"

// pull is how a client fetches one variant of a sample through the proxy.
type pull struct {
	Sample  *Sample
	Variant Variant
	// Upstream is the name of the upstream (and of its mount) the pull goes to.
	Upstream string
	// Name and Version are the coordinate the proxy's verdict is recorded under.
	Name, Version string
	// Preamble are the metadata requests before the payload.
	Preamble []step
	// Payload is the artifact request the gate decides on.
	Payload step
	// Body is the artifact as the registry serves it; Digest its sha256.
	Body   []byte
	Digest string
	// Followers are fetched after the payload (an image's blobs).
	Followers []step
}

// registries builds the stub registries for the package samples: one per
// ecosystem, keyed by upstream name, and the pulls of every variant.
func registries(samples []*Sample) (map[string]*stubServer, []*pull, error) {
	stubs := map[string]*stubServer{}
	get := func(name string) *stubServer {
		if s, ok := stubs[name]; ok {
			return s
		}
		s := newStubServer()
		stubs[name] = s
		return s
	}
	var pulls []*pull
	npmDocs := map[string]map[string]any{} // packuments, filled per version
	pypiPages := map[string][]string{}     // simple pages: links, per project
	for _, s := range samples {
		for _, v := range []Variant{Benign, Malicious} {
			version := s.VersionOf(v)
			tree := s.Files(v)
			var p *pull
			switch s.Kind {
			case KindNPM:
				st := get("npm")
				body := NPMTarball(tree)
				file := "/" + s.Name + "/-/" + NPMTarballName(s.Name, version)
				st.File(file, body, "application/octet-stream")
				doc := npmDocs[s.Name]
				if doc == nil {
					doc = map[string]any{"name": s.Name, "dist-tags": map[string]string{}, "versions": map[string]any{}}
					npmDocs[s.Name] = doc
				}
				doc["versions"].(map[string]any)[version] = map[string]any{
					"name": s.Name, "version": version,
					"dist": map[string]any{"tarball": st.URL() + file, "shasum": sha1Hex(body), "integrity": npmIntegrity(body)},
				}
				if v == Malicious {
					doc["dist-tags"].(map[string]string)["latest"] = version
				}
				p = &pull{
					Upstream: "npm", Name: s.Name, Version: version,
					Preamble: []step{{Path: "/" + s.Name, Contains: []string{mountPlaceholder + file}}},
					Payload:  step{Path: file}, Body: body,
				}
			case KindWheel, KindSdist:
				st := get("pypi")
				project := normalizePyPI(s.Name)
				var body []byte
				var file string
				if s.Kind == KindWheel {
					body, file = Wheel(s.Name, version, tree), WheelFileName(s.Name, version)
				} else {
					body, file = Sdist(s.Name, version, tree), SdistFileName(s.Name, version)
				}
				path := "/packages/" + file
				st.File(path, body, "application/octet-stream")
				pypiPages[project] = append(pypiPages[project], fmt.Sprintf(`<a href="%s%s#sha256=%s">%s</a><br/>`, st.URL(), path, hexDigest(body), file))
				scheme, host, _ := strings.Cut(st.URL(), "://")
				proxied := "/files/" + scheme + "/" + host + path
				p = &pull{
					Upstream: "pypi", Name: project, Version: version,
					Preamble: []step{{Path: "/simple/" + project + "/", Contains: []string{mountPlaceholder + proxied}}},
					Payload:  step{Path: proxied}, Body: body,
				}
			case KindOCIImage:
				st := get("docker")
				img := BuildImage(tree, s.Image)
				base := "/v2/" + s.Name
				manifestDigest := Digest(img.Manifest)
				serve := func(manifest []byte, digest string) http.HandlerFunc {
					return func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Content-Type", MediaDockerManifest)
						w.Header().Set("Docker-Content-Digest", digest)
						if r.Method != http.MethodHead {
							_, _ = w.Write(manifest)
						}
					}
				}
				st.Handle(base+"/manifests/"+version, serve(img.Manifest, manifestDigest))
				st.Handle(base+"/manifests/"+manifestDigest, serve(img.Manifest, manifestDigest))
				st.File(base+"/blobs/"+Digest(img.Config), img.Config, "application/octet-stream")
				st.File(base+"/blobs/"+Digest(img.Layer), img.Layer, "application/octet-stream")
				st.Handle("/v2/", func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte("{}"))
				})
				accept := http.Header{"Accept": {MediaDockerManifest, "application/vnd.oci.image.manifest.v1+json", "application/vnd.oci.image.index.v1+json"}}
				p = &pull{
					Upstream: "docker", Name: s.Name, Version: version,
					Preamble: []step{{Path: "/v2/"}},
					Payload:  step{Path: base + "/manifests/" + version, Header: accept}, Body: img.Manifest,
					Followers: []step{{Path: base + "/blobs/" + Digest(img.Config)}, {Path: base + "/blobs/" + Digest(img.Layer)}},
				}
			case KindVSIX:
				st := get("openvsx")
				ns, ext := s.Extension.Publisher, s.Extension.Name
				body := VSIX(ns, ext, version, tree)
				meta := "/api/" + ns + "/" + ext + "/" + version
				files := meta + "/file/"
				archive := files + ns + "." + ext + "-" + version + ".vsix"
				sidecar := files + ns + "." + ext + "-" + version + ".sha256"
				st.File(archive, body, "application/octet-stream")
				st.File(sidecar, []byte(hexDigest(body)), "text/plain")
				st.File(meta, mustJSON(map[string]any{
					"namespaceUrl": st.URL() + "/api/" + ns,
					"files": map[string]string{
						"download": st.URL() + archive, "sha256": st.URL() + sidecar, "manifest": st.URL() + files + "package.json",
					},
					"name": ext, "namespace": ns, "version": version, "targetPlatform": "universal",
					"timestamp": s.Date + "T00:00:00.000000Z", "displayName": s.Title,
					"engines": map[string]string{"vscode": "^1.80.0"}, "verified": false,
				}), "application/json")
				p = &pull{
					Upstream: "openvsx", Name: ns + "." + ext, Version: version,
					Preamble: []step{{Path: meta, Contains: []string{mountPlaceholder + archive}}},
					Payload:  step{Path: archive}, Body: body,
				}
			case KindTarball:
				st := get("generic")
				dir := tarballDir(s.Name) + "-" + version
				file := dir + ".tar.gz"
				body := Tarball(dir, tree)
				release := "/releases/" + version + "/" + file
				st.File(release, body, "application/gzip")
				st.File(release+".sha256", []byte(hexDigest(body)+"  "+file+"\n"), "text/plain")
				p = &pull{
					Upstream: "generic", Name: file, Version: version,
					Payload: step{Path: release}, Body: body,
				}
			default:
				continue // git-commit samples are not pulled
			}
			p.Sample, p.Variant, p.Digest = s, v, Digest(p.Body)
			pulls = append(pulls, p)
		}
	}
	for name, doc := range npmDocs {
		get("npm").File("/"+name, mustJSON(doc), "application/json")
	}
	for project, links := range pypiPages {
		sort.Strings(links)
		get("pypi").File("/simple/"+project+"/", []byte(fmt.Sprintf(
			"<!DOCTYPE html>\n<html><head><meta name=\"pypi:repository-version\" content=\"1.0\"><title>Links for %s</title></head>\n<body><h1>Links for %s</h1>\n%s\n</body></html>\n",
			project, project, strings.Join(links, "\n"))), "text/html")
	}
	return stubs, pulls, nil
}

// normalizePyPI is a project's PEP 503 normalized name.
func normalizePyPI(name string) string {
	return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(WheelDist(name), "_", "-"), ".", "-"))
}

// tarballDir is the directory name of a release tarball: the last path
// segment of the sample's name.
func tarballDir(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}

func hexDigest(b []byte) string { return strings.TrimPrefix(Digest(b), "sha256:") }

// genericRoutes is the generic upstream's declaration: release archives on a
// cacheable route that lists the package scan, verified against the sibling
// ".sha256" file the release server publishes.
func genericRoutes() map[string]any {
	return map[string]any{"routes": []any{map[string]any{
		"name":      "releases",
		"match":     `^/releases/[^/]+/[^/]+\.tar\.gz$`,
		"cacheable": true,
		"mediaType": "application/gzip",
		"gates":     []any{"llmPackageScan"},
		"verify":    map[string]any{"algorithm": "sha256", "source": "sidecar", "sidecarSuffix": ".sha256"},
	}}}
}
