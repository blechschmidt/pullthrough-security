package fullmirror

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

func TestStatusClassification(t *testing.T) {
	base := errors.New("x")
	for _, tc := range []struct {
		status    int
		permanent bool
		hold      bool
	}{
		{404, true, false}, {410, true, false},
		{401, false, true}, {403, false, true}, {407, false, true},
		{408, false, false}, {500, false, false}, {502, false, false}, {0, false, false},
		{400, true, false}, {422, true, false},
	} {
		err := classifyStatus(base, tc.status, 0, false)
		d, held := RetryAfterOf(err)
		if IsPermanent(err) != tc.permanent || (held && d == holdAfterRefusal) != tc.hold {
			t.Errorf("%d: permanent=%v hold=%v (%v)", tc.status, IsPermanent(err), held, err)
		}
	}
	if d, ok := RetryAfterOf(classifyStatus(base, 429, 90*time.Second, true)); !ok || d != 90*time.Second {
		t.Errorf("429 with a wait: %v", d)
	}
	// The pipeline's answers: a refused authorization upstream holds too.
	if d, ok := RetryAfterOf(readError("/x", FetchResult{Status: 401})); !ok || d != holdAfterRefusal {
		t.Errorf("a relayed 401 is not a hold")
	}
	for v, want := range map[string]time.Duration{"120": 2 * time.Minute, "0": 0, "-5": 0, "soon": 0, "999999999": maxRetryAfter} {
		got, _ := retryAfter(v, time.Now())
		if got != want {
			t.Errorf("Retry-After %q: %v, want %v", v, got, want)
		}
	}
	at := time.Now().Add(time.Hour).UTC().Format(http.TimeFormat)
	if got, ok := retryAfter(at, time.Now()); !ok || got < 59*time.Minute {
		t.Errorf("an HTTP-date Retry-After: %v", got)
	}
}

func TestCredentialsStayOnTheUpstreamsOrigin(t *testing.T) {
	// The upstream's own host on another port: net/http would forward the
	// Authorization header on the redirect.
	var leaked, sent string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization")
		w.Write([]byte("{}"))
	}))
	defer other.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent = r.Header.Get("Authorization")
		http.Redirect(w, r, other.URL+"/elsewhere", http.StatusFound)
	}))
	defer up.Close()
	k, err := newKit(Env{URL: up.URL, HTTP: http.DefaultClient, Authorize: func(r *http.Request) { r.Header.Set("Authorization", "Bearer secret") }})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := k.get(context.Background(), up.URL+"/feed", nil, 1<<10); err != nil {
		t.Fatal(err)
	}
	if sent != "Bearer secret" || leaked != "" {
		t.Errorf("sent %q to the upstream, %q to the other origin", sent, leaked)
	}
	// A feed on another host never gets them.
	sent, leaked = "", ""
	if _, _, err := k.get(context.Background(), other.URL+"/feed", nil, 1<<10); err != nil {
		t.Fatal(err)
	}
	if leaked != "" {
		t.Errorf("credentials sent to another origin: %q", leaked)
	}
}

func TestOptionsAndBaseURLs(t *testing.T) {
	env := Env{Type: "npm", Options: map[string]string{"url": " https://x ", "Mode": "a"}}
	if _, err := parseOptions(env, "url"); err == nil || !strings.Contains(err.Error(), `no option "Mode"`) {
		t.Errorf("an unknown option: %v", err)
	}
	if _, err := parseOptions(Env{Type: "npm", Options: map[string]string{"url": "a\nb"}}, "url"); err == nil {
		t.Errorf("a control character accepted")
	}
	o, err := parseOptions(Env{Type: "pip", Options: map[string]string{"mode": "XMLRPC"}}, "mode")
	if err != nil {
		t.Fatal(err)
	}
	if v, err := o.oneOf("mode", "auto", "xmlrpc", "simple"); err != nil || v != "xmlrpc" {
		t.Errorf("oneOf: %q %v", v, err)
	}
	if _, err := o.oneOf("other", "a"); err != nil {
		t.Errorf("a default: %v", err)
	}
	for _, bad := range []string{"", "ftp://x", "https://", "https://u:p@x", "https://x/?q=1", "https://x/#f", "::"} {
		if _, err := parseBaseURL("u", bad); err == nil {
			t.Errorf("base URL %q accepted", bad)
		}
	}
	u, err := parseBaseURL("u", "https://registry.example/path/")
	if err != nil || u.Path != "/path" || join(u, "a b/c") != "https://registry.example/path/a%20b/c" {
		t.Errorf("base URL %v %v %s", u, err, join(u, "a b/c"))
	}
}

func TestArtifactPathValidation(t *testing.T) {
	for p, ok := range map[string]bool{
		"/a/-/a-1.0.0.tgz": true, "/@s/n/-/n-1.tgz": true, "/files/https/h/p%20q.whl": true,
		"a": false, "/a?b": false, "/a#b": false, "/a/%2e%2e/b": false, "/a/../b": false, "/a/%00": false,
		"/a\\b": false, "/%zz": false, "/" + strings.Repeat("x", 5000): false,
	} {
		if validArtifactPath(p) != ok {
			t.Errorf("%q: %v, want %v", p, !ok, ok)
		}
	}
}

func TestLocateErrorsWithoutAFetcherArePermanent(t *testing.T) {
	k, _ := newKit(Env{Upstream: "n", Type: "npm", URL: "https://registry.npmjs.org"})
	_, err := k.locate(context.Background(), lockfiles.Dependency{Name: "a", Version: "1?x"}, nil)
	if !IsPermanent(err) {
		t.Errorf("a coordinate no path can carry: %v", err)
	}
}

func TestPruneKeepsTheNewestAndSweepsTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	fs := files{dir: dir}
	old := time.Now().Add(-2 * time.Hour)
	for i, n := range []string{"trees-a.gz", "trees-b.gz", "trees-c.gz", "trees-d.gz"} {
		p := filepath.Join(dir, n)
		os.WriteFile(p, []byte(n), 0o600)
		ts := old.Add(time.Duration(i) * time.Minute)
		os.Chtimes(p, ts, ts)
	}
	tmp := filepath.Join(dir, ".trees-x.gz.123.tmp")
	os.WriteFile(tmp, nil, 0o600)
	os.Chtimes(tmp, old, old)
	fresh := filepath.Join(dir, ".trees-y.gz.456.tmp")
	os.WriteFile(fresh, nil, 0o600)
	fs.pruneKeepingNewest("trees-", 1, "trees-a.gz")
	var left []string
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		left = append(left, e.Name())
	}
	if strings.Join(left, " ") != ".trees-y.gz.456.tmp trees-a.gz trees-d.gz" {
		t.Errorf("left %v", left)
	}
}

func TestOrderReleasesByVersion(t *testing.T) {
	rels := []Release{{Version: "1.10.0"}, {Version: "not-a-version"}, {Version: "1.2.0"}, {Version: "1.9.0-rc.1"}, {Version: "1.9.0"}}
	orderReleases("npm", rels)
	var got []string
	for _, r := range rels {
		got = append(got, r.Version)
	}
	if strings.Join(got, " ") != "not-a-version 1.2.0 1.9.0-rc.1 1.9.0 1.10.0" {
		t.Errorf("order %v", got)
	}
	unknown := []Release{{Version: "b"}, {Version: "a"}}
	orderReleases("no-such-type", unknown)
	if unknown[0].Version != "b" {
		t.Errorf("a type without a scheme keeps the registry's order")
	}
}

func TestDecodeCursorRefusesWhatItDoesNotKnow(t *testing.T) {
	var c npmCursor
	for _, bad := range []string{"", "x", `{"format":"npm/1"} {}`, `{"format":"npm/2","since":"1"}`, `{"format":"npm/1","bogus":1}`} {
		if err := decodeCursor(bad, "npm/1", &c); !errors.Is(err, ErrCursorInvalid) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}
