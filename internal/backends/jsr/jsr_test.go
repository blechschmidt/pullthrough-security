package jsr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// --- path classification ----------------------------------------------------

func TestClassify(t *testing.T) {
	cases := []struct {
		path string
		want resourceKind
	}{
		{"/@luca/flag/meta.json", kindPackageMeta},
		{"/@luca/flag/1.0.1_meta.json", kindVersionMeta},
		{"/@luca/flag/1.0.1/main.ts", kindModuleFile},
		{"/@std/encoding/1.0.0/src/base64.ts", kindModuleFile},
		{"/@scope-with-hyphen/pkg0/2.3.4-beta.1/mod.ts", kindModuleFile},
	}
	for _, c := range cases {
		res, ok := classify(c.path)
		if !ok {
			t.Errorf("classify(%q) returned ok=false", c.path)
			continue
		}
		if res.kind != c.want {
			t.Errorf("classify(%q).kind = %v, want %v", c.path, res.kind, c.want)
		}
	}

	for _, bad := range []string{
		"", "/", "////",
		"/luca/flag/meta.json",       // scope not @-prefixed
		"/@luca",                     // missing name+tail
		"/@luca/flag",                // missing tail
		"/@Luca/flag/meta.json",      // uppercase scope
		"/@luca/Flag/meta.json",      // uppercase name
		"/@luca/flag/1.0.1/../x",     // traversal
		"/@luca/flag/_meta.json",     // empty version in version-meta
		"/@luca/flag/bad ver/mod.ts", // space in version
	} {
		if _, ok := classify(bad); ok {
			t.Errorf("classify(%q) unexpectedly ok", bad)
		}
	}
}

func TestClassifyCoordinate(t *testing.T) {
	res, ok := classify("/@luca/flag/1.0.1/main.ts")
	if !ok {
		t.Fatal("classify failed")
	}
	if res.coordinateName() != "@luca/flag" || res.version != "1.0.1" {
		t.Errorf("coordinate = %q/%q", res.coordinateName(), res.version)
	}
	if res.filePath != "/main.ts" {
		t.Errorf("filePath = %q", res.filePath)
	}
	if !res.cacheable() {
		t.Error("a module file should be cacheable")
	}

	meta, _ := classify("/@luca/flag/meta.json")
	if meta.cacheable() {
		t.Error("package meta.json must not be cacheable")
	}
	if meta.coordinateName() != "@luca/flag" {
		t.Errorf("meta coordinate = %q", meta.coordinateName())
	}
}

// --- checksum parsing -------------------------------------------------------

func TestParseSRIChecksum(t *testing.T) {
	good := "sha256-" + fmt.Sprintf("%064x", 1)
	if h, ok := parseSRIChecksum(good); !ok || len(h) != 64 {
		t.Errorf("parseSRIChecksum(%q) = %q ok=%v", good, h, ok)
	}
	if _, ok := parseSRIChecksum("sha512-" + fmt.Sprintf("%0128x", 1)); ok {
		t.Error("sha512 must be rejected")
	}
	if _, ok := parseSRIChecksum("sha256-xyz"); ok {
		t.Error("non-hex must be rejected")
	}
	if _, ok := parseSRIChecksum(""); ok {
		t.Error("empty must be rejected")
	}
}

// --- metadata rewriting -----------------------------------------------------

func TestRewriteMetadata(t *testing.T) {
	origin := "https://jsr.io"
	public := "https://proxy.example.com/v1/jsr"
	body := []byte(`{"name":"@luca/flag","self":"https://jsr.io/@luca/flag/meta.json","rel":"./main.ts","nested":{"link":"https://jsr.io/x"}}`)
	out, changed := rewriteMetadata(body, origin, public)
	if !changed {
		t.Fatal("expected rewrite to change the body")
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("rewritten body is not valid JSON: %v", err)
	}
	if m["self"] != public+"/@luca/flag/meta.json" {
		t.Errorf("self = %v", m["self"])
	}
	if m["rel"] != "./main.ts" {
		t.Errorf("relative link must be untouched, got %v", m["rel"])
	}
	nested := m["nested"].(map[string]any)
	if nested["link"] != public+"/x" {
		t.Errorf("nested link = %v", nested["link"])
	}

	// No upstream URL present -> unchanged.
	if _, changed := rewriteMetadata([]byte(`{"a":"./b"}`), origin, public); changed {
		t.Error("body without an upstream URL must not be marked changed")
	}
	// Non-JSON -> served unchanged.
	if _, changed := rewriteMetadata([]byte("not json"), origin, public); changed {
		t.Error("non-JSON body must not be marked changed")
	}
}

// --- verifying reader -------------------------------------------------------

func TestVerifyingReaderMismatch(t *testing.T) {
	served := []byte("POISONED")
	real := sha256.Sum256([]byte("the real bytes"))
	exp := expectedChecksum{filePath: "/main.ts", hex: fmt.Sprintf("%x", real)}
	result := true
	vr := newVerifyingReader(io.NopCloser(bytes.NewReader(served)), exp, "http://x", func(ok bool) { result = ok })
	_, err := io.ReadAll(vr)
	var mm *ChecksumMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("expected ChecksumMismatchError, got %v", err)
	}
	if result {
		t.Error("onResult should report failure")
	}
}

// --- integration: fake registry + backend -----------------------------------

type fakeRemote struct {
	srv   *httptest.Server
	files map[string][]byte
}

func newFakeRemote(t *testing.T) *fakeRemote {
	t.Helper()
	fr := &fakeRemote{files: map[string][]byte{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, ok := fr.files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	})
	fr.srv = httptest.NewServer(mux)
	t.Cleanup(fr.srv.Close)
	return fr
}

func newTestBackend(t *testing.T, fr *fakeRemote, m *Metrics) *Backend {
	t.Helper()
	b, err := New(Options{
		Name:          "jsr",
		UpstreamURL:   fr.srv.URL,
		PublicBaseURL: "https://proxy.example.com/v1/jsr",
		Client:        upstream.NewWithHTTPClient(fr.srv.Client(), "test/1"),
		Metrics:       m,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func resolveFetch(t *testing.T, b *Backend, path string) (*backends.FetchResult, []byte, error) {
	t.Helper()
	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: path, Query: url.Values{}})
	if err != nil {
		return nil, nil, err
	}
	fres, err := b.Fetch(context.Background(), res)
	if err != nil {
		return nil, nil, err
	}
	var body []byte
	var rerr error
	if fres.Content != nil {
		body, rerr = io.ReadAll(fres.Content)
		_ = fres.Content.Close()
	}
	fres.Resolved = res
	return fres, body, rerr
}

// seedModule registers a module file and the sibling <version>_meta.json. When
// tamper is true, the manifest declares a checksum that does not match the
// bytes.
func seedModule(t *testing.T, fr *fakeRemote, tamper bool) (content []byte, modPath string) {
	t.Helper()
	content = []byte("export const flag = true;\n")
	declared := content
	if tamper {
		declared = []byte("a completely different module body")
	}
	sum := sha256.Sum256(declared)
	manifest := map[string]any{
		"manifest": map[string]any{
			"/main.ts": map[string]any{"size": len(declared), "checksum": "sha256-" + fmt.Sprintf("%x", sum)},
		},
		"exports": map[string]any{".": "./main.ts"},
	}
	mb, _ := json.Marshal(manifest)
	fr.files["/@luca/flag/1.0.1_meta.json"] = mb
	modPath = "/@luca/flag/1.0.1/main.ts"
	fr.files[modPath] = content
	return content, modPath
}

func TestModuleVerifiesAndCacheable(t *testing.T) {
	fr := newFakeRemote(t)
	content, path := seedModule(t, fr, false)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, path)
	if err != nil {
		t.Fatalf("fetch module: %v", err)
	}
	if !bytes.Equal(body, content) {
		t.Fatal("module body mismatch")
	}
	if !fres.Resolved.Cacheable {
		t.Error("module file should be cacheable")
	}
	if fres.Resolved.Metadata[MetaChecksumVerified] != "sha256" {
		t.Errorf("checksum metadata = %q", fres.Resolved.Metadata[MetaChecksumVerified])
	}
	if fres.Header.Get("X-Checksum-Verified") != "sha256" {
		t.Errorf("X-Checksum-Verified = %q", fres.Header.Get("X-Checksum-Verified"))
	}
	if fres.Resolved.Coordinate.Name != "@luca/flag" || fres.Resolved.Coordinate.Version != "1.0.1" {
		t.Errorf("coordinate = %+v", fres.Resolved.Coordinate)
	}
	if st := m.Stats(); st.ModulesVerified != 1 || st.VersionMetaFetched != 1 {
		t.Errorf("metrics = %+v", st)
	}
}

func TestModuleChecksumMismatchRefused(t *testing.T) {
	fr := newFakeRemote(t)
	_, path := seedModule(t, fr, true)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	_, _, err := resolveFetch(t, b, path)
	if err == nil {
		t.Fatal("expected checksum mismatch error")
	}
	var cm *ChecksumMismatchError
	if !errors.As(err, &cm) {
		t.Fatalf("error = %v, want ChecksumMismatchError", err)
	}
	if m.Stats().ChecksumMismatch != 1 {
		t.Errorf("mismatch metric = %v", m.Stats().ChecksumMismatch)
	}
}

func TestModuleMissingManifestServesUnverified(t *testing.T) {
	fr := newFakeRemote(t)
	// Module present but no sibling version meta (so no manifest entry).
	path := "/@luca/flag/9.9.9/orphan.ts"
	fr.files[path] = []byte("orphan module, no manifest")
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, path)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("empty body")
	}
	if fres.Resolved.Metadata[MetaChecksumVerified] != "none" {
		t.Errorf("checksum metadata = %q, want none", fres.Resolved.Metadata[MetaChecksumVerified])
	}
	if m.Stats().ChecksumMissing != 1 {
		t.Errorf("checksum-missing metric = %v", m.Stats().ChecksumMissing)
	}
}

func TestMetadataServedAndRewritten(t *testing.T) {
	fr := newFakeRemote(t)
	// meta.json embeds an absolute upstream URL that must be rewritten.
	doc := fmt.Sprintf(`{"scope":"luca","name":"flag","link":"%s/@luca/flag/1.0.1_meta.json"}`, fr.srv.URL)
	fr.files["/@luca/flag/meta.json"] = []byte(doc)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, "/@luca/flag/meta.json")
	if err != nil {
		t.Fatalf("fetch meta.json: %v", err)
	}
	if fres.Resolved.Cacheable {
		t.Error("meta.json must not be cacheable")
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("served body not JSON: %v", err)
	}
	want := "https://proxy.example.com/v1/jsr/@luca/flag/1.0.1_meta.json"
	if got["link"] != want {
		t.Errorf("link = %v, want %v", got["link"], want)
	}
	if st := m.Stats(); st.MetadataServed != 1 || st.MetadataRewritten != 1 {
		t.Errorf("metrics = %+v", st)
	}
}

func TestResolveRejectsNonJSRPath(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), &Metrics{})
	_, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/not/a/jsr/file.txt", Query: url.Values{}})
	if !errors.Is(err, backends.ErrNotSupported) {
		t.Fatalf("error = %v, want ErrNotSupported", err)
	}
}

func TestFetchUpstreamErrorPropagated(t *testing.T) {
	fr := newFakeRemote(t)
	b := newTestBackend(t, fr, &Metrics{})
	// Version meta is absent (served unverified) and the module itself is 404.
	_, _, err := resolveFetch(t, b, "/@luca/flag/1.0.1/absent.ts")
	var se *backends.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error = %v, want StatusError", err)
	}
	if se.Status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", se.Status)
	}
}
