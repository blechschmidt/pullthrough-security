package fullmirror

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// The feed adapters' tests run against recorded registry responses: the files
// under testdata/feeds/<type>/ were fetched from the live registries (see
// testdata/feeds/README.md) and trimmed to a few entries, keeping their exact
// format. A fixtureServer stands in for the registry, a fakeReads for the
// proxy's gated pipeline (Env.Read), and the adapters' answers are compared
// with golden files under testdata/feeds/<type>/golden/ — regenerate them
// with `go test ./internal/fullmirror -run <Test> -update-feed-golden` and
// review the diff.

var updateFeedGolden = flag.Bool("update-feed-golden", false, "rewrite the feed adapters' golden files under testdata/feeds/*/golden")

// fixture reads a recorded response.
func fixture(t testing.TB, typ, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "feeds", typ, name))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return data
}

// route is one answer of a fixtureServer.
type route struct {
	method string
	path   string
	query  url.Values
	header map[string]string
	status int
	body   []byte
	resp   http.Header
	// times limits how often the route answers (0: always).
	times int
	hits  int
}

// fixtureServer serves recorded responses and fails the test on a request no
// route expects.
type fixtureServer struct {
	t      *testing.T
	srv    *httptest.Server
	mu     sync.Mutex
	routes []*route
	log    []string
}

func newFixtureServer(t *testing.T) *fixtureServer {
	t.Helper()
	s := &fixtureServer{t: t}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

// URL is the server's base URL.
func (s *fixtureServer) URL() string { return s.srv.URL }

// on adds a route for "METHOD /path?query" (the query lists parameters that
// must match exactly; others are ignored). A later route wins over an
// earlier one.
func (s *fixtureServer) on(method, target string) *route {
	u, err := url.Parse(target)
	if err != nil {
		s.t.Fatalf("route %q: %v", target, err)
	}
	r := &route{method: method, path: u.EscapedPath(), query: u.Query(), status: http.StatusOK, resp: http.Header{}}
	s.mu.Lock()
	s.routes = append(s.routes, r)
	s.mu.Unlock()
	return r
}

func (r *route) reply(status int, body []byte) *route { r.status, r.body = status, body; return r }
func (r *route) json(body string) *route              { r.body = []byte(body); return r }
func (r *route) withHeader(k, v string) *route        { r.resp.Set(k, v); return r }
func (r *route) once() *route                         { r.times = 1; return r }
func (r *route) requireHeader(k, v string) *route {
	if r.header == nil {
		r.header = map[string]string{}
	}
	r.header[k] = v
	return r
}

func (s *fixtureServer) serve(w http.ResponseWriter, req *http.Request) {
	s.mu.Lock()
	s.log = append(s.log, req.Method+" "+req.URL.RequestURI())
	var hit *route
	for i := len(s.routes) - 1; i >= 0; i-- {
		r := s.routes[i]
		if r.method != req.Method || r.path != req.URL.EscapedPath() || (r.times > 0 && r.hits >= r.times) {
			continue
		}
		ok := true
		for k, vs := range r.query {
			if strings.Join(req.URL.Query()[k], ",") != strings.Join(vs, ",") {
				ok = false
			}
		}
		for k, v := range r.header {
			if req.Header.Get(k) != v {
				ok = false
			}
		}
		if ok {
			hit = r
			break
		}
	}
	if hit != nil {
		hit.hits++
	}
	s.mu.Unlock()
	if hit == nil {
		s.t.Errorf("unexpected request %s %s", req.Method, req.URL.RequestURI())
		http.Error(w, "no fixture", 599)
		return
	}
	for k, vs := range hit.resp {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(hit.status)
	_, _ = w.Write(hit.body)
}

// requests returns the requests served so far.
func (s *fixtureServer) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.log...)
}

// fakeDoc is one document the fake gated pipeline serves.
type fakeDoc struct {
	status int
	body   []byte
	gate   string
	code   string
	retry  time.Duration
}

// fakeReads stands in for Env.Read: the gated pipeline as the mirror's system
// principal sees it.
type fakeReads struct {
	mu    sync.Mutex
	docs  map[string]fakeDoc
	reads map[string]int
}

func newFakeReads() *fakeReads {
	return &fakeReads{docs: map[string]fakeDoc{}, reads: map[string]int{}}
}

func (f *fakeReads) set(path string, body []byte) { f.setDoc(path, fakeDoc{status: 200, body: body}) }

func (f *fakeReads) setDoc(path string, d fakeDoc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.docs[path] = d
}

func (f *fakeReads) read(ctx context.Context, path, _ string, w io.Writer) (FetchResult, error) {
	if err := ctx.Err(); err != nil {
		return FetchResult{}, err
	}
	f.mu.Lock()
	d, ok := f.docs[path]
	f.reads[path]++
	f.mu.Unlock()
	if !ok {
		return FetchResult{Status: http.StatusNotFound, Reason: "no such document"}, nil
	}
	if d.status == http.StatusOK {
		if _, err := w.Write(d.body); err != nil {
			return FetchResult{Status: http.StatusOK}, err
		}
	}
	return FetchResult{Status: d.status, Gate: d.gate, Code: d.code, RetryAfter: d.retry}, nil
}

func (f *fakeReads) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads[path]
}

// testEnv is the environment an adapter is built with in a test: the fixture
// server as the upstream, the fake pipeline as Env.Read, a fresh directory.
func testEnv(t *testing.T, typ, upstreamURL string, reads *fakeReads, opts map[string]string) Env {
	t.Helper()
	env := Env{
		Upstream: typ + "-test", Type: typ, URL: upstreamURL, Options: opts,
		HTTP: &http.Client{Timeout: 30 * time.Second}, UserAgent: "pullthrough-feed-test", Dir: t.TempDir(),
	}
	if reads != nil {
		env.Read = reads.read
	}
	return env
}

// mustFeed builds the registered adapter for env.
func mustFeed(t *testing.T, env Env) Feed {
	t.Helper()
	feed, err := NewFeed(env)
	if err != nil {
		t.Fatalf("NewFeed(%s): %v", env.Type, err)
	}
	return feed
}

// checkGolden compares got, rendered as indented JSON, with a golden file.
func checkGolden(t *testing.T, typ, name string, got any) {
	t.Helper()
	data, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	p := filepath.Join("testdata", "feeds", typ, "golden", name+".json")
	if *updateFeedGolden {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("golden file: %v (run with -update-feed-golden to create it)", err)
	}
	if !bytes.Equal(want, data) {
		t.Errorf("%s differs from the golden file (run with -update-feed-golden and review the diff):\n--- got\n%s\n--- want\n%s", p, data, want)
	}
}

// batchView is a Batch as the golden files show it: the cursor decoded.
type batchView struct {
	Items    []Coordinate    `json:"items"`
	Next     json.RawMessage `json:"next"`
	More     bool            `json:"more"`
	Head     string          `json:"head,omitempty"`
	Lag      int64           `json:"lag,omitempty"`
	LagKnown bool            `json:"lagKnown,omitempty"`
	HeadTime string          `json:"headTime,omitempty"`
	CurTime  string          `json:"cursorTime,omitempty"`
}

func viewBatch(t *testing.T, b Batch) batchView {
	t.Helper()
	if err := validateBatch(b); err != nil {
		t.Fatalf("the engine would refuse the batch: %v", err)
	}
	v := batchView{Items: b.Items, More: b.More, Head: b.Head, Lag: b.Lag, LagKnown: b.LagKnown}
	if v.Items == nil {
		v.Items = []Coordinate{}
	}
	if json.Valid([]byte(b.Next)) {
		v.Next = json.RawMessage(b.Next)
	} else {
		v.Next, _ = json.Marshal(b.Next)
	}
	if !b.HeadTime.IsZero() {
		v.HeadTime = b.HeadTime.UTC().Format(time.RFC3339Nano)
	}
	if !b.CursorTime.IsZero() {
		v.CurTime = b.CursorTime.UTC().Format(time.RFC3339Nano)
	}
	return v
}

// releaseView is a Release as the golden files show it.
type releaseView struct {
	Version   string     `json:"version"`
	Published string     `json:"published,omitempty"`
	Yanked    bool       `json:"yanked,omitempty"`
	Artifacts []Artifact `json:"artifacts"`
}

func viewReleases(rels []Release) []releaseView {
	out := make([]releaseView, 0, len(rels))
	for _, r := range rels {
		v := releaseView{Version: r.Version, Yanked: r.Yanked, Artifacts: r.Artifacts}
		if !r.Published.IsZero() {
			v.Published = r.Published.UTC().Format(time.RFC3339Nano)
		}
		if v.Artifacts == nil {
			v.Artifacts = []Artifact{}
		}
		out = append(out, v)
	}
	return out
}

// mustErr checks that err is an error of the given kind.
func mustErr(t *testing.T, err error, permanent, cursorInvalid bool, contains string) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error, want one containing %q", contains)
	}
	if IsPermanent(err) != permanent {
		t.Errorf("IsPermanent(%v) = %v, want %v", err, !permanent, permanent)
	}
	if errors.Is(err, ErrCursorInvalid) != cursorInvalid {
		t.Errorf("errors.Is(%v, ErrCursorInvalid) = %v, want %v", err, !cursorInvalid, cursorInvalid)
	}
	if contains != "" && !strings.Contains(err.Error(), contains) {
		t.Errorf("error %q does not say %q", err, contains)
	}
}

// names lists the coordinates' names.
func names(items []Coordinate) []string {
	out := make([]string, 0, len(items))
	for _, c := range items {
		out = append(out, c.String())
	}
	return out
}

// expectServed checks that every artifact path resolves, through the
// backend's own Resolve, to a cacheable object of the package and version it
// was listed for: the engine fetches exactly what the backend serves, and
// what a client requesting the version would be served. coordinate maps a
// release to the coordinate name the backend should derive ("" skips the
// check, for a backend whose path carries no name).
func expectServed(t *testing.T, b backends.Backend, rels []Release, coordinate func(r Release, a Artifact) (name, version string)) {
	t.Helper()
	n := 0
	for _, r := range rels {
		for _, a := range r.Artifacts {
			n++
			if !validArtifactPath(a.Path) {
				t.Errorf("%s: invalid path %q", r.Version, a.Path)
				continue
			}
			dec, err := url.PathUnescape(a.Path)
			if err != nil {
				t.Errorf("%s: %q does not decode: %v", r.Version, a.Path, err)
				continue
			}
			hdr := http.Header{}
			if a.Accept != "" {
				hdr.Set("Accept", a.Accept)
			}
			res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: dec, Query: url.Values{}, Header: hdr})
			if err != nil {
				t.Errorf("%s: the backend does not resolve %s: %v", r.Version, a.Path, err)
				continue
			}
			if !res.Cacheable {
				t.Errorf("%s: the backend does not cache %s", r.Version, a.Path)
			}
			if coordinate != nil {
				name, version := coordinate(r, a)
				if name != "" && res.Coordinate.Name != name {
					t.Errorf("%s: %s resolves to package %q, want %q", r.Version, a.Path, res.Coordinate.Name, name)
				}
				if version != "" && res.Coordinate.Version != version {
					t.Errorf("%s: %s resolves to version %q, want %q", r.Version, a.Path, res.Coordinate.Version, version)
				}
			}
		}
	}
	if n == 0 {
		t.Errorf("no artifact to check")
	}
}

// errorf is fmt.Errorf (keeps the import used by helpers that build errors).
var errorf = fmt.Errorf
