package maturity

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func newBody(s string) io.ReadCloser { return io.NopCloser(strings.NewReader(s)) }

func mustParse(t *testing.T, layout, v string) time.Time {
	t.Helper()
	tm, err := time.Parse(layout, v)
	if err != nil {
		t.Fatalf("parse %q: %v", v, err)
	}
	return tm.UTC()
}

func TestParseNpmTime(t *testing.T) {
	data := []byte(`{"name":"left-pad","time":{"created":"2014-01-01T00:00:00.000Z","1.0.0":"2020-05-01T10:00:00.000Z","1.1.0":"2021-06-02T11:30:00.000Z"}}`)
	ts, ok, err := parseNpmTime(data, "1.1.0")
	if err != nil || !ok {
		t.Fatalf("parseNpmTime: ok=%v err=%v", ok, err)
	}
	want := mustParse(t, time.RFC3339, "2021-06-02T11:30:00Z")
	if !ts.Equal(want) {
		t.Fatalf("got %s want %s", ts, want)
	}
	if _, ok, _ := parseNpmTime(data, "9.9.9"); ok {
		t.Fatalf("missing version should be not-found")
	}
}

func TestParsePyPITime(t *testing.T) {
	data := []byte(`{"urls":[
		{"upload_time":"2022-03-10T08:00:00","upload_time_iso_8601":"2022-03-10T08:00:00.123456Z"},
		{"upload_time":"2022-03-10T07:00:00","upload_time_iso_8601":"2022-03-10T07:00:00.000000Z"}
	]}`)
	ts, ok, err := parsePyPITime(data)
	if err != nil || !ok {
		t.Fatalf("parsePyPITime: ok=%v err=%v", ok, err)
	}
	// Earliest of the two upload times.
	want := mustParse(t, time.RFC3339Nano, "2022-03-10T07:00:00Z")
	if !ts.Equal(want) {
		t.Fatalf("got %s want %s", ts, want)
	}
}

func TestParseCargoTime(t *testing.T) {
	data := []byte(`{"version":{"num":"1.2.3","created_at":"2023-07-01T12:00:00.000000+00:00"}}`)
	ts, ok, err := parseCargoTime(data)
	if err != nil || !ok {
		t.Fatalf("parseCargoTime: ok=%v err=%v", ok, err)
	}
	if ts.Year() != 2023 || ts.Month() != time.July {
		t.Fatalf("unexpected %s", ts)
	}
}

func TestParseGoInfoTime(t *testing.T) {
	data := []byte(`{"Version":"v1.5.0","Time":"2021-02-03T04:05:06Z"}`)
	ts, ok, err := parseGoInfoTime(data)
	if err != nil || !ok {
		t.Fatalf("parseGoInfoTime: ok=%v err=%v", ok, err)
	}
	if !ts.Equal(mustParse(t, time.RFC3339, "2021-02-03T04:05:06Z")) {
		t.Fatalf("unexpected %s", ts)
	}
}

func TestParseNuGetTime(t *testing.T) {
	leaf := []byte(`{"catalogEntry":{"published":"2020-08-08T08:08:08+00:00"}}`)
	ts, ok, err := parseNuGetTime(leaf)
	if err != nil || !ok {
		t.Fatalf("parseNuGetTime: ok=%v err=%v", ok, err)
	}
	if ts.Year() != 2020 {
		t.Fatalf("unexpected %s", ts)
	}
	// Sentinel year for unlisted packages → not-found.
	if _, ok, _ := parseNuGetTime([]byte(`{"published":"1900-01-01T00:00:00+00:00"}`)); ok {
		t.Fatalf("1900 sentinel must be treated as unknown")
	}
}

func TestParseRubyGemsTime(t *testing.T) {
	data := []byte(`[{"number":"2.0.0","created_at":"2022-01-01T00:00:00.000Z"},{"number":"1.0.0","created_at":"2021-01-01T00:00:00.000Z"}]`)
	ts, ok, err := parseRubyGemsTime(data, "1.0.0")
	if err != nil || !ok {
		t.Fatalf("parseRubyGemsTime: ok=%v err=%v", ok, err)
	}
	if ts.Year() != 2021 {
		t.Fatalf("unexpected %s", ts)
	}
	if _, ok, _ := parseRubyGemsTime(data, "9.9.9"); ok {
		t.Fatalf("missing version must be not-found")
	}
}

func TestParseComposerTime(t *testing.T) {
	data := []byte(`{"packages":{"acme/widget":[{"version":"v1.2.0","time":"2022-09-09T09:09:09+00:00"},{"version":"1.1.0","time":"2022-08-08T08:08:08+00:00"}]}}`)
	ts, ok, err := parseComposerTime(data, "acme/widget", "1.2.0")
	if err != nil || !ok {
		t.Fatalf("parseComposerTime: ok=%v err=%v", ok, err)
	}
	if ts.Month() != time.September {
		t.Fatalf("unexpected %s", ts)
	}
}

func TestParseMavenTime(t *testing.T) {
	// solrsearch timestamp is epoch milliseconds.
	ms := time.Date(2021, 4, 5, 6, 7, 8, 0, time.UTC).UnixMilli()
	data := []byte(`{"response":{"docs":[{"timestamp":` + itoa(ms) + `}]}}`)
	ts, ok, err := parseMavenTime(data)
	if err != nil || !ok {
		t.Fatalf("parseMavenTime: ok=%v err=%v", ok, err)
	}
	if !ts.Equal(time.Date(2021, 4, 5, 6, 7, 8, 0, time.UTC)) {
		t.Fatalf("unexpected %s", ts)
	}
	if _, ok, _ := parseMavenTime([]byte(`{"response":{"docs":[]}}`)); ok {
		t.Fatalf("empty docs must be not-found")
	}
}

func TestSplitMavenCoordinate(t *testing.T) {
	g, a, ok := splitMavenCoordinate("com.google.guava:guava")
	if !ok || g != "com.google.guava" || a != "guava" {
		t.Fatalf("colon form: %q %q %v", g, a, ok)
	}
	g, a, ok = splitMavenCoordinate("com/google/guava/guava")
	if !ok || g != "com.google.guava" || a != "guava" {
		t.Fatalf("slash form: %q %q %v", g, a, ok)
	}
	if _, _, ok := splitMavenCoordinate("nocoordinate"); ok {
		t.Fatalf("single token must not split")
	}
}

func TestGoModuleEscape(t *testing.T) {
	got, err := goModuleEscape("github.com/BurntSushi/toml")
	if err != nil {
		t.Fatal(err)
	}
	if got != "github.com/!burnt!sushi/toml" {
		t.Fatalf("unexpected escape %q", got)
	}
}

func TestParseTimestampForms(t *testing.T) {
	cases := []string{
		"2020-01-02T03:04:05Z",
		"2020-01-02T03:04:05.123456Z",
		"2020-01-02T03:04:05",
		"2020-01-02 03:04:05 -0700",
		"1577934245", // epoch seconds
	}
	for _, raw := range cases {
		if _, ok, err := parseTimestamp(raw); err != nil || !ok {
			t.Fatalf("parseTimestamp(%q): ok=%v err=%v", raw, ok, err)
		}
	}
	if _, ok, _ := parseTimestamp(""); ok {
		t.Fatalf("empty must be not-found")
	}
	if _, _, err := parseTimestamp("not-a-time"); err == nil {
		t.Fatalf("garbage must error")
	}
}

// roundTripFunc adapts a function to the Doer interface for the dispatch test.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

func TestHTTPResolver_DispatchAndURL(t *testing.T) {
	var gotURL string
	client := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotURL = r.URL.String()
		body := `{"time":{"1.0.0":"2020-05-01T10:00:00.000Z"}}`
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       newBody(body),
			Header:     make(http.Header),
		}, nil
	})
	r := NewHTTPResolver(client, "test-agent")
	ts, ok, err := r.PublishedAt(context.Background(), Coordinate{Ecosystem: "npm", Name: "@scope/pkg", Version: "1.0.0"})
	if err != nil || !ok {
		t.Fatalf("PublishedAt: ok=%v err=%v", ok, err)
	}
	if ts.Year() != 2020 {
		t.Fatalf("unexpected %s", ts)
	}
	if !strings.Contains(gotURL, "registry.npmjs.org/@scope/pkg") {
		t.Fatalf("unexpected URL %q", gotURL)
	}

	// Unsupported ecosystem → unknown, no error.
	if _, ok, err := r.PublishedAt(context.Background(), Coordinate{Ecosystem: "cocoapods", Name: "x", Version: "1"}); ok || err != nil {
		t.Fatalf("unsupported ecosystem should be unknown: ok=%v err=%v", ok, err)
	}
}

func TestHTTPResolver_NotFoundIsUnknown(t *testing.T) {
	client := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusNotFound, Body: newBody(""), Header: make(http.Header)}, nil
	})
	r := NewHTTPResolver(client, "test")
	ts, ok, err := r.PublishedAt(context.Background(), Coordinate{Ecosystem: "pip", Name: "x", Version: "1.0.0"})
	if ok || err != nil || !ts.IsZero() {
		t.Fatalf("404 should be unknown without error, got ok=%v err=%v ts=%s", ok, err, ts)
	}
}
