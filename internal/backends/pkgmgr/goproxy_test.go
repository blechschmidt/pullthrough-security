package pkgmgr

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

func TestParseGoSumDBs(t *testing.T) {
	cases := []struct {
		setting string
		want    []string
		wantErr bool
	}{
		{"sum.golang.org", []string{"sum.golang.org"}, false},
		{"sum.golang.org, sum.golang.google.cn", []string{"sum.golang.org", "sum.golang.google.cn"}, false},
		{"sum.golang.org\tsumdb.corp.example", []string{"sum.golang.org", "sumdb.corp.example"}, false},
		{"off", nil, false},
		{"OFF", nil, false},
		{"none", nil, false},
		{"sum.golang.org off", nil, false}, // "off" anywhere disables
		{"", nil, false},
		// A name becomes the host of a URL the proxy fetches: anything that could
		// redirect that fetch is rejected.
		{"sum.golang.org/evil", nil, true},
		{"sum.golang.org:8443", nil, true},
		{"user@sum.golang.org", nil, true},
		{"https://sum.golang.org", nil, true},
		{"localhost", nil, true},
		{".sum.golang.org", nil, true},
		{"-sum.golang.org", nil, true},
		{"169.254.169.254?x", nil, true},
	}
	for _, tc := range cases {
		got, err := parseGoSumDBs(tc.setting)
		if (err != nil) != tc.wantErr {
			t.Errorf("parseGoSumDBs(%q): err = %v, wantErr %v", tc.setting, err, tc.wantErr)
			continue
		}
		if tc.wantErr {
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("parseGoSumDBs(%q) = %v, want %v", tc.setting, got, tc.want)
			continue
		}
		for _, name := range tc.want {
			if !got[name] {
				t.Errorf("parseGoSumDBs(%q) lacks %q (got %v)", tc.setting, name, got)
			}
		}
	}
}

func TestGoSumDBURL(t *testing.T) {
	sumdbs := map[string]bool{"sum.golang.org": true}
	cases := []struct {
		path string
		want string
		ok   bool
	}{
		{"/sumdb/sum.golang.org/latest", "https://sum.golang.org/latest", true},
		{"/sumdb/sum.golang.org/lookup/rsc.io/quote@v1.5.2", "https://sum.golang.org/lookup/rsc.io/quote@v1.5.2", true},
		{"/sumdb/sum.golang.org/tile/8/0/x277/878", "https://sum.golang.org/tile/8/0/x277/878", true},
		{"/sumdb/sum.golang.org/tile/8/1/x001/085.p/119", "https://sum.golang.org/tile/8/1/x001/085.p/119", true},
		// Not on the allowlist: never fetched, falls through to the upstream proxy.
		{"/sumdb/sum.evil.example/latest", "", false},
		{"/sumdb/169.254.169.254/latest", "", false},
		// Not a database request at all.
		{"/sumdb/sum.golang.org", "", false},
		{"/sumdb/sum.golang.org/", "", false},
		{"/sumdb//latest", "", false},
		{"/rsc.io/quote/@v/v1.5.2.zip", "", false},
		// Traversal is rejected, not normalized.
		{"/sumdb/sum.golang.org/../../etc/passwd", "", false},
		{"/sumdb/sum.golang.org/tile/./x", "", false},
	}
	for _, tc := range cases {
		got, ok := goSumDBURL(tc.path, sumdbs)
		if ok != tc.ok || got != tc.want {
			t.Errorf("goSumDBURL(%q) = (%q, %v), want (%q, %v)", tc.path, got, ok, tc.want, tc.ok)
		}
	}
	if _, ok := goSumDBURL("/sumdb/sum.golang.org/latest", nil); ok {
		t.Error("goSumDBURL must refuse every database when none is configured")
	}
}

// recordingUpstream is a fake GOPROXY upstream that records requested paths.
type recordingUpstream struct {
	*httptest.Server
	mu   sync.Mutex
	seen []string
}

func newRecordingUpstream(t *testing.T) *recordingUpstream {
	t.Helper()
	u := &recordingUpstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.seen = append(u.seen, r.URL.Path)
		u.mu.Unlock()
		if strings.HasPrefix(r.URL.Path, "/sumdb/") {
			// proxy.golang.org does not proxy the checksum database.
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "upstream:"+r.URL.Path)
	}))
	t.Cleanup(u.Close)
	return u
}

func (u *recordingUpstream) paths() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.seen...)
}

func TestGoProxySumDBSupportedProbe(t *testing.T) {
	up := newRecordingUpstream(t)
	b, err := NewGoProxy(Options{Name: "go", UpstreamURL: up.URL, Client: testClient()})
	if err != nil {
		t.Fatalf("NewGoProxy: %v", err)
	}

	// The probe is answered by the proxy itself: 200 with no upstream request.
	res, err := b.Resolve(context.Background(), &backends.Request{Method: "GET", Path: "/sumdb/sum.golang.org/supported"})
	if err != nil {
		t.Fatalf("Resolve(supported): %v", err)
	}
	if res.Cacheable {
		t.Error("the supported probe must not be cached")
	}
	if res.Coordinate != (backends.Coordinate{}) {
		t.Errorf("the supported probe must carry no coordinate (it is not an artifact), got %+v", res.Coordinate)
	}
	fr, err := b.Fetch(context.Background(), res)
	if err != nil {
		t.Fatalf("Fetch(supported): %v", err)
	}
	body, _ := io.ReadAll(fr.Content)
	_ = fr.Content.Close()
	if fr.Status != http.StatusOK || len(body) != 0 {
		t.Errorf("supported probe = status %d body %q, want 200 with an empty body", fr.Status, body)
	}
	if got := up.paths(); len(got) != 0 {
		t.Errorf("the supported probe reached the upstream: %v", got)
	}

	// The database's real paths are routed to the database, not to the upstream
	// proxy (which does not serve them).
	for path, want := range map[string]string{
		"/sumdb/sum.golang.org/latest":                     "https://sum.golang.org/latest",
		"/sumdb/sum.golang.org/lookup/rsc.io/quote@v1.5.2": "https://sum.golang.org/lookup/rsc.io/quote@v1.5.2",
		"/sumdb/sum.golang.org/tile/8/0/x277/878":          "https://sum.golang.org/tile/8/0/x277/878",
	} {
		res, err := b.Resolve(context.Background(), &backends.Request{Method: "GET", Path: path})
		if err != nil {
			t.Fatalf("Resolve(%s): %v", path, err)
		}
		if res.UpstreamURL != want {
			t.Errorf("Resolve(%s).UpstreamURL = %q, want %q", path, res.UpstreamURL, want)
		}
		if res.Cacheable {
			t.Errorf("%s must not be cached (the tree head advances)", path)
		}
		if res.Coordinate != (backends.Coordinate{}) {
			t.Errorf("%s must carry no coordinate, got %+v", path, res.Coordinate)
		}
	}

	// A database that is not configured is NOT answered as supported: the
	// request falls through to the upstream proxy, whose 404 tells the go
	// command to contact that database directly.
	res, err = b.Resolve(context.Background(), &backends.Request{Method: "GET", Path: "/sumdb/sum.evil.example/supported"})
	if err != nil {
		t.Fatalf("Resolve(unconfigured db): %v", err)
	}
	if !strings.HasPrefix(res.UpstreamURL, up.URL) {
		t.Errorf("an unconfigured database resolved to %q, want the upstream proxy", res.UpstreamURL)
	}

	// Module requests are unaffected.
	if res, body := fetch(t, b, "/rsc.io/quote/@v/v1.5.2.zip"); body != "upstream:/rsc.io/quote/@v/v1.5.2.zip" || !res.Cacheable {
		t.Errorf("module zip: body %q cacheable %v", body, res.Cacheable)
	}
}

func TestGoProxySumDBDisabled(t *testing.T) {
	up := newRecordingUpstream(t)
	b, err := NewGoProxy(Options{Name: "go", UpstreamURL: up.URL, Client: testClient(),
		Settings: map[string]string{"sumdb": "off"}})
	if err != nil {
		t.Fatalf("NewGoProxy: %v", err)
	}
	// With the database proxy off, the probe is forwarded like any other path
	// and the upstream's answer (404) is what the client sees.
	res, err := b.Resolve(context.Background(), &backends.Request{Method: "GET", Path: "/sumdb/sum.golang.org/supported"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !strings.HasPrefix(res.UpstreamURL, up.URL) {
		t.Errorf("UpstreamURL = %q, want the upstream proxy", res.UpstreamURL)
	}
	if _, err := b.Fetch(context.Background(), res); err == nil {
		t.Error("expected the upstream's 404 to surface")
	} else if se, ok := backends.AsStatusError(err); !ok || se.Status != http.StatusNotFound {
		t.Errorf("error = %v, want a 404 StatusError", err)
	}
}

func TestGoProxySumDBCustomDatabases(t *testing.T) {
	up := newRecordingUpstream(t)
	b, err := NewGoProxy(Options{Name: "go", UpstreamURL: up.URL, Client: testClient(),
		Settings: map[string]string{"sumdb": "sum.golang.org sumdb.corp.example"}})
	if err != nil {
		t.Fatalf("NewGoProxy: %v", err)
	}
	for _, db := range []string{"sum.golang.org", "sumdb.corp.example"} {
		res, err := b.Resolve(context.Background(), &backends.Request{Method: "GET", Path: "/sumdb/" + db + "/latest"})
		if err != nil {
			t.Fatalf("Resolve(%s): %v", db, err)
		}
		if want := "https://" + db + "/latest"; res.UpstreamURL != want {
			t.Errorf("UpstreamURL = %q, want %q", res.UpstreamURL, want)
		}
	}

	if _, err := NewGoProxy(Options{Name: "go", UpstreamURL: up.URL, Client: testClient(),
		Settings: map[string]string{"sumdb": "sum.golang.org/path"}}); err == nil {
		t.Error("expected an invalid sumdb setting to be rejected")
	}
}

func TestGoCacheableNeverCachesSumDB(t *testing.T) {
	for _, path := range []string{
		"/sumdb/sum.golang.org/latest",
		"/sumdb/sum.golang.org/lookup/rsc.io/quote@v1.5.2",
		"/sumdb/sum.golang.org/tile/8/0/x277/878",
		"/sumdb/sum.golang.org/supported",
	} {
		if goCacheable(&backends.Request{Method: "GET", Path: path}) {
			t.Errorf("goCacheable(%s) = true, want false", path)
		}
	}
}
