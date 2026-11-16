//go:build integration
// +build integration

package fullmirror

import (
	"fmt"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/e2e/pkgscan"
)

// A row is one upstream type the full mirror follows. Its file, row_<type>.go,
// registers it from init with register: the feed its adapter follows, served
// in front of the LLM package-scan suite's stub registry for the type, and the
// adapter's options pointing at it. Everything else — the proxy, the packages,
// the scenario, the assertions — is the suite's.
//
// The packages, in the order they are published (see runner.go):
//
//	seed       before the proxy starts: found by the enumeration (Bootstrap)
//	benign     after the enumeration: found by a poll of the feed (Changes)
//	malicious  together with benign; the mock LLM judges it malicious
//	late       while the proxy is stopped: found after the restart, from the
//	           cursor the mirror stored
//
// Each is the stub registry's fixture of that name ("pte2e-seed", …, in the
// ecosystem's own spelling), version 1.0.0 unless the ecosystem spells it
// otherwise.
type row struct {
	// Type is the upstream type, as the catalog lists it.
	Type string
	// Stub is the LLM package-scan suite's ecosystem whose registry serves the
	// packages (default: Type).
	Stub string
	// Feed says, for the matrix, what the stub serves as the registry's feed
	// ("_changes and _all_docs", "a Git index (git http-backend)").
	Feed string

	// Start installs the feed in front of the stub registry: routes added with
	// env.Stub.Handle, File and Fallback, a Git repository made with
	// newGitRepo. It is called once, before the proxy starts, with the seed
	// published (env.Publications()).
	Start func(env *feedEnv) error
	// Publish updates the feed for packages just published: the stub registry
	// lists them already (and so does everything Start's routes compute from
	// env.Publications() at request time). Nil when there is nothing to update.
	Publish func(env *feedEnv, added []publication) error
	// Options are the adapter's options, fullMirror.feed: its feed's URL on
	// the stub, a settle time of zero, the choices the stub serves.
	Options func(env *feedEnv) map[string]string
	// Settings, when set, returns the upstream's settings; base is the stub's
	// own (from the LLM package-scan suite).
	Settings func(env *feedEnv, base map[string]string) map[string]string
	// UpstreamURL, when set, returns the upstream's url (default: the stub's).
	UpstreamURL func(env *feedEnv) string

	// Files lists the files the adapter has the mirror fetch for a package,
	// as request paths below the upstream's mount, the payload — the archive
	// the LLM package scan reads — first. Nil: the payload alone.
	Files func(env *feedEnv, p publication) []file
	// Refused lists, of the malicious package's files, those the gate refuses.
	// Nil: the payload.
	Refused func(env *feedEnv, p publication) []string
	// Rereported lists the packages the adapter reports again, by design,
	// after its enumeration: it follows its feed from a margin before the
	// point the enumeration was taken (Composer's CDN-lagged package list,
	// CPAN's unindexed uploads), and the package published before the proxy
	// started lies within it. The mirror finds their files cached: exactly
	// they are counted skipped (cached).
	Rereported []string
	// Resumed, when set, checks the requests the stub received from the
	// restarted proxy: that its first read of the feed continued from the
	// stored cursor (npm's _changes?since=<the stored sequence>), in the feed's
	// own terms. The suite checks the rest itself (no new enumeration, nothing
	// fetched twice).
	Resumed func(env *feedEnv, requests []string) error

	// Notes are remarks for the matrix (what the row does not cover).
	Notes []string
}

// file is one file the mirror fetches: its request path below the mount, and
// the Accept header the request carries (an OCI manifest), if any.
type file struct {
	Path   string
	Accept string
	// Metadata marks a file the backend classifies as metadata (a Go
	// module's .info and .mod, a Conan manifest): the download log leaves a
	// served one out (downloadLog.includeMetadata is off by default), so the
	// suite expects no entry of it.
	Metadata bool
}

// stubID is the ecosystem of the LLM package-scan suite whose registry the row
// uses.
func (r row) stubID() string {
	if r.Stub != "" {
		return r.Stub
	}
	return r.Type
}

var (
	rowsMu     sync.Mutex
	registered = map[string]row{}
)

// register adds a row. Each row file calls it from init.
func register(r row) {
	rowsMu.Lock()
	defer rowsMu.Unlock()
	if r.Type == "" || r.Start == nil || r.Options == nil {
		panic("fullmirror e2e: a row needs a type, a Start and Options")
	}
	if _, dup := registered[r.Type]; dup {
		panic("fullmirror e2e: upstream type " + r.Type + " registered twice")
	}
	registered[r.Type] = r
}

// rows returns the registered rows, sorted by type.
func rows() []row {
	rowsMu.Lock()
	defer rowsMu.Unlock()
	out := make([]row, 0, len(registered))
	for _, r := range registered {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

// The packages a row publishes.
const (
	pkgSeed      = "seed"
	pkgBenign    = "benign"
	pkgMalicious = "malicious"
	pkgLate      = "late"
)

// publication is one package as the stub registry published it.
type publication struct {
	// Variant names the package: seed, benign, malicious or late.
	Variant string
	// Pkg is the package as the stub registry serves it: name, version,
	// payload path and bytes, the content token the mock LLM records.
	Pkg pkgscan.StubPackage
	// Seq is the package's place in the order of publication (from 1).
	Seq int
	// Time is when it was published.
	Time time.Time
}

// feedEnv is what a row's feed is built with.
type feedEnv struct {
	// Stub is the stub registry: the routes of the feed go in front of it.
	Stub *pkgscan.MirrorStub
	// Dir is a directory of the row's own (a Git repository's home).
	Dir string

	mu    sync.Mutex
	pubs  []publication
	state map[string]any
}

// set keeps a value of the row's own with the feed (its Git repository, its
// sequence counter), for its handlers and its Publish to find.
func (e *feedEnv) set(key string, v any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state == nil {
		e.state = map[string]any{}
	}
	e.state[key] = v
}

// get returns a value kept with set (nil when there is none).
func (e *feedEnv) get(key string) any {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.state[key]
}

// URL is the stub's base URL ("http://127.0.0.1:<port>").
func (e *feedEnv) URL() string { return e.Stub.URL() }

// Publications lists the packages published so far, in order.
func (e *feedEnv) Publications() []publication {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]publication(nil), e.pubs...)
}

// Publication returns the publication of a package, if it was published.
func (e *feedEnv) Publication(variant string) (publication, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, p := range e.pubs {
		if p.Variant == variant {
			return p, true
		}
	}
	return publication{}, false
}

// publish publishes packages on the stub registry and returns their
// publications. The registry lists them before the row's feed does (Publish
// is called after): a feed that names a package the registry cannot serve yet
// would cost the mirror the version.
func (e *feedEnv) publish(variants ...string) ([]publication, error) {
	if err := e.Stub.Publish(variants...); err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	var added []publication
	for _, v := range variants {
		pkg, ok := e.Stub.Package(v)
		if !ok {
			return nil, fmt.Errorf("the stub registry does not serve the %s package it published", v)
		}
		p := publication{Variant: v, Pkg: pkg, Seq: len(e.pubs) + 1, Time: e.Stub.PublishedAt(v)}
		e.pubs = append(e.pubs, p)
		added = append(added, p)
	}
	return added, nil
}

// fetch reads a document the stub registry serves (path with its query), in
// process: the bytes a feed built beside the registry must agree with.
func (e *feedEnv) fetch(path string) ([]byte, error) {
	status, body, _ := e.Stub.Fetch(path)
	if status != http.StatusOK {
		return nil, fmt.Errorf("the stub registry answers %s with %d", path, status)
	}
	return body, nil
}

// files returns the files a row's adapter fetches for a package.
func (r row) files(env *feedEnv, p publication) []file {
	if r.Files != nil {
		return r.Files(env, p)
	}
	return []file{{Path: p.Pkg.Path}}
}

// refused returns the files of a package the gate refuses: the malicious
// package's payload (or what the row says), nothing of another.
func (r row) refused(env *feedEnv, p publication) map[string]bool {
	out := map[string]bool{}
	if p.Variant != pkgMalicious {
		return out
	}
	if r.Refused != nil {
		for _, path := range r.Refused(env, p) {
			out[path] = true
		}
		return out
	}
	out[p.Pkg.Path] = true
	return out
}

// mkdir creates a directory below the row's own.
func (e *feedEnv) mkdir(name string) (string, error) {
	dir := e.Dir + "/" + name
	return dir, os.MkdirAll(dir, 0o755)
}
