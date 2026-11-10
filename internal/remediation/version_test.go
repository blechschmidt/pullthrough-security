package remediation

import (
	"context"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"1.0.0", "1.0.1", -1, true},
		{"1.2.0", "1.1.9", 1, true},
		{"1.0.0", "1.0.0", 0, true},
		{"v2.0.0", "1.9.9", 1, true},
		{"1.0", "1.0.0", 0, true},
		{"1.0.0-rc1", "1.0.0", -1, true},     // prerelease < release
		{"1.0.0-rc1", "1.0.0-rc2", -1, true}, // numeric prerelease ordering
		{"1.0.0-alpha", "1.0.0-beta", -1, true},
		{"1.0.0-rc.1", "1.0.0-rc.1.1", -1, true},  // longer tail wins
		{"1.0.0+build1", "1.0.0+build2", 0, true}, // build metadata ignored
		{"not-a-version", "1.0.0", 0, false},
		{"1.2.3", "", 0, false},
	}
	for _, c := range cases {
		got, ok := compareVersions(c.a, c.b)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("compareVersions(%q,%q) = (%d,%v), want (%d,%v)", c.a, c.b, got, ok, c.want, c.ok)
		}
	}
}

func TestNewerVersions(t *testing.T) {
	all := []string{"0.9.0", "1.0.0", "1.0.1", "2.0.0-rc1", "2.0.0", "garbage", "1.0.1"}
	// Stable releases newer than 1.0.0, ascending, deduped, prerelease excluded.
	got := newerVersions(all, "1.0.0", false)
	want := []string{"1.0.1", "2.0.0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("newerVersions (stable) = %v, want %v", got, want)
	}
	// With prerelease included, 2.0.0-rc1 appears before 2.0.0.
	got = newerVersions(all, "1.0.0", true)
	want = []string{"1.0.1", "2.0.0-rc1", "2.0.0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("newerVersions (prerelease) = %v, want %v", got, want)
	}
}

func TestIsPrerelease(t *testing.T) {
	for _, tc := range []struct {
		v    string
		want bool
	}{
		{"1.0.0", false},
		{"1.0.0-rc1", true},
		{"1.0.0+build", false},
		{"garbage", false},
	} {
		if got := isPrerelease(tc.v); got != tc.want {
			t.Errorf("isPrerelease(%q) = %v, want %v", tc.v, got, tc.want)
		}
	}
}

// stubDoer serves canned responses keyed by URL substring.
type stubDoer struct {
	routes map[string]string
}

func (s stubDoer) Do(req *http.Request) (*http.Response, error) {
	for substr, body := range s.routes {
		if strings.Contains(req.URL.String(), substr) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		}
	}
	return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(""))}, nil
}

func TestHTTPVersionLister(t *testing.T) {
	doer := stubDoer{routes: map[string]string{
		"registry.npmjs.org/lodash":          `{"versions":{"4.17.20":{},"4.17.21":{}}}`,
		"pypi.org/pypi/requests/json":        `{"releases":{"2.31.0":[],"2.32.0":[]}}`,
		"crates.io/api/v1/crates/serde":      `{"versions":[{"num":"1.0.0"},{"num":"1.0.1","yanked":true}]}`,
		"proxy.golang.org":                   "v1.0.0\nv1.1.0\n",
		"v3-flatcontainer/newtonsoft.json":   `{"versions":["13.0.0","13.0.1"]}`,
		"rubygems.org/api/v1/versions/rails": `[{"number":"7.0.0"},{"number":"7.1.0"}]`,
	}}
	l := NewHTTPVersionLister(doer, "test")

	check := func(eco, name string, want []string) {
		t.Helper()
		got, err := l.Versions(context.Background(), eco, name)
		if err != nil {
			t.Fatalf("%s/%s: %v", eco, name, err)
		}
		// order-insensitive compare (maps have no order)
		if !sameSet(got, want) {
			t.Fatalf("%s/%s versions = %v, want %v", eco, name, got, want)
		}
	}
	check("npm", "lodash", []string{"4.17.20", "4.17.21"})
	check("pip", "requests", []string{"2.31.0", "2.32.0"})
	check("cargo", "serde", []string{"1.0.0"}) // yanked 1.0.1 excluded
	check("go", "example.com/mod", []string{"v1.0.0", "v1.1.0"})
	check("nuget", "Newtonsoft.Json", []string{"13.0.0", "13.0.1"})
	check("rubygems", "rails", []string{"7.0.0", "7.1.0"})

	// Unknown ecosystem → no error, no versions.
	if got, err := l.Versions(context.Background(), "unknowneco", "x"); err != nil || len(got) != 0 {
		t.Fatalf("unknown ecosystem = (%v,%v), want (nil,nil)", got, err)
	}
	// A 404 yields no versions, not an error.
	if got, err := l.Versions(context.Background(), "npm", "does-not-exist"); err != nil || len(got) != 0 {
		t.Fatalf("missing package = (%v,%v), want (nil,nil)", got, err)
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, s := range a {
		m[s]++
	}
	for _, s := range b {
		m[s]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}
