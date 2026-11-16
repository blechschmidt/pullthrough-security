//go:build integration
// +build integration

package pkgscan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// This file is the kit's part for the full-mirror suite (internal/e2e/fullmirror,
// Task 194). That suite does not pull packages: it publishes them on a stub
// registry and watches the proxy's full mirror find and fetch them by itself.
// So it needs a registry whose packages appear over time — the same registry
// this suite builds for an ecosystem, built again with every package published
// so far — and room for the endpoints a registry's change feed adds (npm's
// _changes, a Git index, an Atom feed), which that suite serves in front of the
// registry.

// MirrorStub is a stub registry of one ecosystem whose packages are published
// one after another. It serves the registry built from the packages published
// so far, behind the routes added with Handle and Fallback.
//
// A package is one of this suite's fixtures, named by its variant: "benign" and
// "malicious" are what the names say; any other lower-case word ("seed",
// "late") is a benign package of that name. The registry is rebuilt on every
// Publish: its index documents (an APT Packages file, a Helm index.yaml, a
// conda repodata.json) list exactly the packages published, are served with a
// Last-Modified that advances with every build and an ETag of their content,
// and the packages themselves keep their bytes from build to build.
type MirrorStub struct {
	e       eco
	srv     *httptest.Server
	overlay *stubMux

	mu        sync.Mutex
	published []variant
	when      map[variant]time.Time
	reg       *registry
	builds    int
	bodies    map[variant][]byte
	requests  []Request
}

// Request is one request the stub received, and how it was answered.
type Request struct {
	Method string
	// URI is the request URI, query included.
	URI string
	// Status is the answer's status code.
	Status int
	// Header holds the request headers that make a request conditional or
	// partial (Range, If-Range, If-None-Match, If-Modified-Since) and its
	// Accept: what a client that keeps a copy sends.
	Header http.Header
	// Digest is the sha256 of the answer's body ("sha256:<hex>"), and Bytes
	// its length.
	Digest string
	Bytes  int64
}

// String renders a request the way Requests lists it.
func (r Request) String() string { return fmt.Sprintf("%s %s -> %d", r.Method, r.URI, r.Status) }

// recordedHeaders are the request headers Request keeps.
var recordedHeaders = []string{"Range", "If-Range", "If-None-Match", "If-Modified-Since", "Accept"}

// bodyRecorder notes the status a handler wrote and hashes the body.
type bodyRecorder struct {
	http.ResponseWriter
	status int
	h      hash.Hash
	n      int64
}

func (b *bodyRecorder) WriteHeader(code int) {
	if b.status == 0 {
		b.status = code
	}
	b.ResponseWriter.WriteHeader(code)
}

func (b *bodyRecorder) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	b.h.Write(p)
	b.n += int64(len(p))
	return b.ResponseWriter.Write(p)
}

// StartMirrorStub starts the stub registry of the ecosystem id with the given
// packages published.
func StartMirrorStub(id string, variants ...string) (*MirrorStub, error) {
	var e eco
	found := false
	for _, c := range ecosystems() {
		if c.ID == id {
			e, found = c, true
			break
		}
	}
	switch {
	case !found:
		return nil, fmt.Errorf("pkgscan: no ecosystem %q (have %s)", id, strings.Join(StubIDs(), " "))
	case e.Registry == nil:
		return nil, fmt.Errorf("pkgscan: ecosystem %s has no stub registry", id)
	}
	s := &MirrorStub{e: e, overlay: newStubMux(), when: map[variant]time.Time{}, bodies: map[variant][]byte{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	if err := s.Publish(variants...); err != nil {
		s.srv.Close()
		return nil, err
	}
	return s, nil
}

// serve answers a request with the suite's routes first, then the registry.
func (s *MirrorStub) serve(w http.ResponseWriter, r *http.Request) {
	rec := &bodyRecorder{ResponseWriter: w, h: sha256.New()}
	if !s.overlay.dispatch(rec, r) {
		s.mu.Lock()
		reg := s.reg
		s.mu.Unlock()
		if reg == nil || !reg.mux.dispatch(rec, r) {
			http.Error(rec, "the stub registry serves no such path", http.StatusNotFound)
		}
	}
	if rec.status == 0 {
		rec.status = http.StatusOK
	}
	req := Request{Method: r.Method, URI: r.URL.RequestURI(), Status: rec.status, Header: http.Header{},
		Digest: "sha256:" + hex.EncodeToString(rec.h.Sum(nil)), Bytes: rec.n}
	for _, k := range recordedHeaders {
		if v := r.Header.Values(k); len(v) > 0 {
			req.Header[k] = append([]string(nil), v...)
		}
	}
	s.mu.Lock()
	s.requests = append(s.requests, req)
	s.mu.Unlock()
}

// Publish adds packages to the registry. It returns once the registry that
// lists them is being served. Publishing a package twice is an error.
func (s *MirrorStub) Publish(variants ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := append([]variant(nil), s.published...)
	for _, v := range variants {
		if v == "" || strings.Trim(v, "abcdefghijklmnopqrstuvwxyz") != "" {
			return fmt.Errorf("pkgscan: %q is not a package variant (lower-case letters only)", v)
		}
		for _, p := range next {
			if p == variant(v) {
				return fmt.Errorf("pkgscan: the %s stub registry has published %q already", s.e.ID, v)
			}
		}
		next = append(next, variant(v))
	}
	specs := make([]pkgSpec, 0, len(next))
	for _, v := range next {
		specs = append(specs, newSpec(s.e.ID, v))
	}
	reg, err := s.e.Registry(stubEnv{URL: s.srv.URL, Specs: specs})
	if err != nil {
		return fmt.Errorf("building the %s stub registry: %w", s.e.ID, err)
	}
	for _, v := range next {
		p := reg.pulls[v]
		switch {
		case p == nil:
			return fmt.Errorf("the %s stub registry serves no %q package", s.e.ID, v)
		case p.Payload.Path == "" || len(p.Body) == 0 || p.Marker == "":
			return fmt.Errorf("the %s stub registry's %q package lacks a payload path, a body or a marker path", s.e.ID, v)
		}
		// A package keeps its bytes: the mirror cached them under their digest.
		if old, ok := s.bodies[v]; ok && !bytes.Equal(old, p.Body) {
			return fmt.Errorf("the %s stub registry built the %q package with other bytes than before: its builder is not deterministic", s.e.ID, v)
		}
	}
	s.builds++
	reg.mux.modTime = stubModTime.Add(time.Duration(s.builds) * time.Minute)
	reg.mux.etags = true
	now := time.Now().UTC()
	for _, v := range next[len(s.published):] {
		s.when[v] = now
		s.bodies[v] = append([]byte(nil), reg.pulls[v].Body...)
	}
	s.reg, s.published = reg, next
	return nil
}

// Published lists the packages published so far, in the order they were.
func (s *MirrorStub) Published() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.published))
	for _, v := range s.published {
		out = append(out, string(v))
	}
	return out
}

// PublishedAt is when a package was published (zero: it was not).
func (s *MirrorStub) PublishedAt(v string) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.when[variant(v)]
}

// Package returns a published package.
func (s *MirrorStub) Package(v string) (StubPackage, bool) {
	s.mu.Lock()
	reg := s.reg
	s.mu.Unlock()
	if reg == nil {
		return StubPackage{}, false
	}
	p := reg.pulls[variant(v)]
	if p == nil {
		return StubPackage{}, false
	}
	out := StubPackage{
		Name: p.Name, Version: p.Version, Path: p.Payload.Path, Header: p.Payload.Header.Clone(),
		Body: append([]byte(nil), p.Body...), Token: newSpec(s.e.ID, variant(v)).Token, Marker: p.Marker,
	}
	for _, f := range p.Followers {
		out.Followers = append(out.Followers, f.Path)
	}
	return out, true
}

// Fetch answers a GET of path (with its query) from the current registry,
// in process and unrecorded: how a feed built beside the registry reads the
// documents the registry serves (a crate's index line, a module's source.json).
func (s *MirrorStub) Fetch(path string) (int, []byte, http.Header) {
	s.mu.Lock()
	reg := s.reg
	s.mu.Unlock()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if reg == nil || !reg.mux.dispatch(rec, req) {
		return http.StatusNotFound, nil, nil
	}
	return rec.Code, rec.Body.Bytes(), rec.Header()
}

// Handle serves path (the decoded request path, without the query) with h,
// in front of the registry.
func (s *MirrorStub) Handle(path string, h http.HandlerFunc) { s.overlay.Handle(path, h) }

// File serves body at path in front of the registry, the way the registry
// serves its own files (Range, HEAD and conditional requests, an ETag of the
// content, a Last-Modified that is when File was last called for the path).
func (s *MirrorStub) File(path string, body []byte, contentType string) {
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	modTime := time.Now().UTC().Truncate(time.Second)
	body = append([]byte(nil), body...)
	s.overlay.Handle(path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("ETag", etagOf(body))
		http.ServeContent(w, r, "", modTime, bytes.NewReader(body))
	})
}

// Fallback adds a handler consulted, in the order added and in front of the
// registry, for a path no route of the suite serves. It returns false to pass
// the request on.
func (s *MirrorStub) Fallback(h func(w http.ResponseWriter, r *http.Request) bool) {
	s.overlay.Fallback(h)
}

// Requests returns every request received, "<method> <uri> -> <status>".
func (s *MirrorStub) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.requests))
	for _, r := range s.requests {
		out = append(out, r.String())
	}
	return out
}

// Log returns every request received, with its conditional headers and a
// digest of the answer's body.
func (s *MirrorStub) Log() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Request, len(s.requests))
	for i, r := range s.requests {
		r.Header = r.Header.Clone()
		out[i] = r
	}
	return out
}

// Served counts the answers that sent body — a whole 2xx body with the given
// digest ("sha256:<hex>") — whatever path they were for: how often the stub
// handed out a package's bytes.
func (s *MirrorStub) Served(digest string) int {
	n := 0
	for _, r := range s.Log() {
		if r.Status >= 200 && r.Status < 300 && r.Digest == digest {
			n++
		}
	}
	return n
}

// Hits counts the 2xx answers to requests for path (query string ignored).
func (s *MirrorStub) Hits(path string) int {
	n := 0
	for _, line := range s.Requests() {
		fields := strings.Fields(line)
		if len(fields) != 4 {
			continue
		}
		uri, _, _ := strings.Cut(fields[1], "?")
		if uri == path && strings.HasPrefix(fields[3], "2") {
			n++
		}
	}
	return n
}

// URL is the stub's base URL ("http://127.0.0.1:<port>").
func (s *MirrorStub) URL() string { return s.srv.URL }

// Close stops the stub.
func (s *MirrorStub) Close() { s.srv.Close() }

// Type is the upstream type the stub plays.
func (s *MirrorStub) Type() string { return s.e.Type }

// Title is the ecosystem's display name.
func (s *MirrorStub) Title() string { return s.e.Title }

// Format says what artifact the registry serves.
func (s *MirrorStub) Format() string { return s.e.Format }

// UpstreamURL is the `url:` of an upstream fronting the stub.
func (s *MirrorStub) UpstreamURL() string { return s.srv.URL + s.e.UpstreamPath }

// Settings is the `settings:` block of an upstream fronting the stub (nil for
// none).
func (s *MirrorStub) Settings() map[string]string {
	if s.e.Settings == nil {
		return nil
	}
	return s.e.Settings(s.srv.URL)
}

// etagOf is a strong ETag of body.
func etagOf(body []byte) string { return `"` + hexOf(body)[:24] + `"` }

// Digest is the sha256 digest of b as the proxy writes digests,
// "sha256:<hex>".
func Digest(b []byte) string { return digestOf(b) }
