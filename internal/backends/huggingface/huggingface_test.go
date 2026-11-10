package huggingface

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

func sha256Hex(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }

const commitSHA = "0123456789abcdef0123456789abcdef01234567"

// --- path classification ----------------------------------------------------

// TestClassify is the backend-detection test: the Hub route table is recognized
// exactly and non-Hub paths are rejected (so the gateway reports them unsupported
// rather than blindly proxying them).
func TestClassify(t *testing.T) {
	cases := []struct {
		path     string
		wantKind resourceKind
		wantType repoType
		wantRepo string
		wantRev  string
		wantFile string
	}{
		{"/gpt2/resolve/main/config.json", kindResolve, repoModel, "gpt2", "main", "config.json"},
		{"/bigscience/bloom/resolve/main/pytorch_model.bin", kindResolve, repoModel, "bigscience/bloom", "main", "pytorch_model.bin"},
		{"/org/model/resolve/" + commitSHA + "/model.safetensors", kindResolve, repoModel, "org/model", commitSHA, "model.safetensors"},
		{"/datasets/squad/resolve/main/data/train.parquet", kindResolve, repoDataset, "squad", "main", "data/train.parquet"},
		{"/spaces/owner/app/resolve/main/app.py", kindResolve, repoSpace, "owner/app", "main", "app.py"},
		{"/api/models/gpt2", kindModelInfo, repoModel, "gpt2", "", ""},
		{"/api/models/bigscience/bloom/revision/" + commitSHA, kindModelInfo, repoModel, "bigscience/bloom", commitSHA, ""},
		{"/api/datasets/squad", kindDatasetInfo, repoDataset, "squad", "", ""},
	}
	for _, c := range cases {
		res, ok := classify(c.path)
		if !ok {
			t.Errorf("classify(%q) returned ok=false", c.path)
			continue
		}
		if res.kind != c.wantKind || res.repoType != c.wantType || res.repoID != c.wantRepo ||
			res.revision != c.wantRev || res.filepath != c.wantFile {
			t.Errorf("classify(%q) = %+v, want kind=%v type=%v repo=%q rev=%q file=%q",
				c.path, res, c.wantKind, c.wantType, c.wantRepo, c.wantRev, c.wantFile)
		}
	}

	for _, bad := range []string{
		"", "/", "////",
		"/gpt2/resolve/main",                       // missing filepath
		"/gpt2/resolve",                            // missing revision+file
		"/resolve/main/x",                          // missing repo
		"/api/models",                              // missing repo
		"/api/unknown/foo",                         // unknown api type
		"/gpt2/blob/main/config.json",              // not a resolve/api path
		"/org/model/resolve/main/../../etc/passwd", // traversal
	} {
		if _, ok := classify(bad); ok {
			t.Errorf("classify(%q) unexpectedly ok", bad)
		}
	}
}

func TestCoordinateAndCacheability(t *testing.T) {
	ds, _ := classify("/datasets/squad/resolve/main/x.json")
	if ds.coordinateName() != "datasets/squad" {
		t.Errorf("dataset coordinate = %q", ds.coordinateName())
	}
	branchCfg, _ := classify("/gpt2/resolve/main/config.json")
	if branchCfg.cacheable() {
		t.Error("a branch-pinned non-weight resolve must not be cacheable")
	}
	branchWeight, _ := classify("/gpt2/resolve/main/pytorch_model.bin")
	if !branchWeight.cacheable() {
		t.Error("a branch-pinned weight file must be cacheable so it is gated/verified")
	}
	pinned, _ := classify("/gpt2/resolve/" + commitSHA + "/config.json")
	if !pinned.cacheable() {
		t.Error("a commit-pinned resolve should be cacheable")
	}
	meta, _ := classify("/api/models/gpt2")
	if meta.cacheable() {
		t.Error("metadata must not be cacheable")
	}
}

func TestWeightFormat(t *testing.T) {
	cases := map[string]string{
		"model.safetensors": formatSafetensors,
		"pytorch_model.bin": formatPickle,
		"weights.pt":        formatPickle,
		"ckpt.ckpt":         formatPickle,
		"model.gguf":        formatGGUF,
		"model.onnx":        formatOtherWeight,
		"config.json":       formatOther,
		"tokenizer.json":    formatOther,
	}
	for name, want := range cases {
		if got := weightFormat(name); got != want {
			t.Errorf("weightFormat(%q) = %q, want %q", name, got, want)
		}
	}
}

// --- LFS pointer parsing ----------------------------------------------------

func TestParsePointer(t *testing.T) {
	oid := sha256Hex([]byte("real weights"))
	body := []byte(pointerPrefix + "\noid sha256:" + oid + "\nsize 4242\n")
	p, ok := parsePointer(body)
	if !ok || p.oid != oid || p.size != 4242 {
		t.Fatalf("parsePointer = %+v ok=%v", p, ok)
	}
	if _, ok := parsePointer([]byte("not a pointer at all")); ok {
		t.Error("non-pointer must not parse")
	}
	if _, ok := parsePointer([]byte(pointerPrefix + "\noid sha256:short\nsize 1\n")); ok {
		t.Error("pointer with a non-SHA-256 oid must not parse")
	}
}

func TestNormalizeLinkedETag(t *testing.T) {
	want := sha256Hex([]byte("x"))
	for _, in := range []string{want, `"` + want + `"`, "sha256:" + want, `W/"` + want + `"`} {
		got, ok := normalizeLinkedETag(in)
		if !ok || got != want {
			t.Errorf("normalizeLinkedETag(%q) = %q ok=%v", in, got, ok)
		}
	}
	// A Git blob SHA-1 (40 hex) is not a content SHA-256 and must be rejected.
	if _, ok := normalizeLinkedETag(`"` + commitSHA + `"`); ok {
		t.Error("a 40-hex ETag must not be treated as a SHA-256")
	}
}

// --- fake remote + integration ----------------------------------------------

type fakeRemote struct {
	srv   *httptest.Server
	files map[string][]byte
	hdrs  map[string]http.Header
}

func newFakeRemote(t *testing.T) *fakeRemote {
	t.Helper()
	fr := &fakeRemote{files: map[string][]byte{}, hdrs: map[string]http.Header{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if h, ok := fr.hdrs[r.URL.Path]; ok {
			for k, vs := range h {
				for _, v := range vs {
					w.Header().Add(k, v)
				}
			}
		}
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
		Name:        "huggingface",
		UpstreamURL: fr.srv.URL,
		Client:      upstream.NewWithHTTPClient(fr.srv.Client(), "test/1"),
		Metrics:     m,
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

func TestResolveBlobVerifiesSHA256(t *testing.T) {
	fr := newFakeRemote(t)
	weights := []byte("\x80\x02 fake safetensors payload")
	oid := sha256Hex(weights)
	p := "/org/model/resolve/" + commitSHA + "/model.safetensors"
	fr.files[p] = weights
	fr.hdrs[p] = http.Header{
		"X-Linked-Etag": {`"` + oid + `"`},
		"X-Repo-Commit": {commitSHA},
		"X-Linked-Size": {"27"},
	}
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, p)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !bytes.Equal(body, weights) {
		t.Fatal("body mismatch")
	}
	if fres.Resolved.Metadata[MetaChecksumVerified] != "sha256" {
		t.Errorf("checksum metadata = %q", fres.Resolved.Metadata[MetaChecksumVerified])
	}
	if fres.Resolved.Metadata[MetaCommit] != commitSHA {
		t.Errorf("commit metadata = %q", fres.Resolved.Metadata[MetaCommit])
	}
	if fres.Resolved.Metadata[MetaFormat] != formatSafetensors {
		t.Errorf("format metadata = %q", fres.Resolved.Metadata[MetaFormat])
	}
	if !fres.Resolved.Cacheable {
		t.Error("commit-pinned resolve should be cacheable")
	}
	if s := m.Stats(); s.FilesVerified != 1 || s.LFSResolved != 1 || s.SafetensorsServed != 1 {
		t.Errorf("metrics = %+v", s)
	}
}

func TestResolveBlobChecksumMismatchRefused(t *testing.T) {
	fr := newFakeRemote(t)
	p := "/org/model/resolve/" + commitSHA + "/pytorch_model.bin"
	fr.files[p] = []byte("POISONED WEIGHTS")
	fr.hdrs[p] = http.Header{"X-Linked-Etag": {sha256Hex([]byte("the real weights"))}}
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	_, _, err := resolveFetch(t, b, p)
	var cm *ChecksumMismatchError
	if !errors.As(err, &cm) {
		t.Fatalf("error = %v, want ChecksumMismatchError", err)
	}
	if m.Stats().ChecksumMismatch != 1 {
		t.Errorf("mismatch metric = %v", m.Stats().ChecksumMismatch)
	}
}

func TestResolveFollowsCDNRedirect(t *testing.T) {
	// Mirror the Hub's LFS behavior: the resolve endpoint 302-redirects to a CDN
	// that serves the bytes and carries the content SHA-256. The shared HTTP client
	// follows the redirect transparently; the backend verifies the final bytes.
	weights := []byte("\x80\x04 large LFS weight payload streamed from the CDN")
	oid := sha256Hex(weights)
	mux := http.NewServeMux()
	resolvePath := "/org/model/resolve/" + commitSHA + "/pytorch_model.bin"
	mux.HandleFunc("/cdn/blob", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Linked-Etag", `"`+oid+`"`)
		_, _ = w.Write(weights)
	})
	mux.HandleFunc(resolvePath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Repo-Commit", commitSHA)
		http.Redirect(w, r, "/cdn/blob", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	m := &Metrics{}
	b, err := New(Options{Name: "huggingface", UpstreamURL: srv.URL, Client: upstream.NewWithHTTPClient(srv.Client(), "test/1"), Metrics: m})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fres, body, err := resolveFetch(t, b, resolvePath)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !bytes.Equal(body, weights) {
		t.Fatal("CDN body mismatch")
	}
	if fres.Resolved.Metadata[MetaChecksumVerified] != "sha256" {
		t.Errorf("checksum metadata = %q", fres.Resolved.Metadata[MetaChecksumVerified])
	}
	if m.Stats().FilesVerified != 1 {
		t.Errorf("verified metric = %v", m.Stats().FilesVerified)
	}
}

func TestResolvePointerRecognized(t *testing.T) {
	fr := newFakeRemote(t)
	oid := sha256Hex([]byte("the real object"))
	p := "/org/model/resolve/main/pytorch_model.bin"
	fr.files[p] = []byte(pointerPrefix + "\noid sha256:" + oid + "\nsize 9001\n")
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, _, err := resolveFetch(t, b, p)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if fres.Resolved.Metadata[MetaPointer] != "1" {
		t.Error("pointer flag not set")
	}
	if fres.Resolved.Metadata[MetaOID] != oid {
		t.Errorf("oid metadata = %q", fres.Resolved.Metadata[MetaOID])
	}
	if m.Stats().PointersSeen != 1 {
		t.Errorf("pointer metric = %v", m.Stats().PointersSeen)
	}
}

func TestResolveUnverifiedWhenNoHash(t *testing.T) {
	fr := newFakeRemote(t)
	p := "/gpt2/resolve/main/config.json"
	fr.files[p] = []byte(`{"model_type":"gpt2"}`)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, p)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !strings.Contains(string(body), "gpt2") {
		t.Fatalf("body = %q", body)
	}
	if fres.Resolved.Metadata[MetaChecksumVerified] != "none" {
		t.Errorf("checksum metadata = %q, want none", fres.Resolved.Metadata[MetaChecksumVerified])
	}
	if fres.MediaType != "application/json" {
		t.Errorf("media type = %q", fres.MediaType)
	}
	if m.Stats().ChecksumMissing != 1 {
		t.Errorf("missing metric = %v", m.Stats().ChecksumMissing)
	}
}

func TestMetadataProxied(t *testing.T) {
	fr := newFakeRemote(t)
	fr.files["/api/models/gpt2"] = []byte(`{"id":"gpt2","sha":"` + commitSHA + `"}`)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/api/models/gpt2", Query: url.Values{}})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.Cacheable {
		t.Error("metadata must not be cacheable")
	}
	if _, _, err := resolveFetch(t, b, "/api/models/gpt2"); err != nil {
		t.Fatalf("fetch metadata: %v", err)
	}
	if m.Stats().MetadataServed != 1 {
		t.Errorf("metadata metric = %v", m.Stats().MetadataServed)
	}
}

func TestResolveRejectsNonHFPath(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), &Metrics{})
	_, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/not/a/hub/path/at", Query: url.Values{}})
	if !errors.Is(err, backends.ErrNotSupported) {
		t.Fatalf("error = %v, want ErrNotSupported", err)
	}
}

func TestFetchUpstreamErrorPropagated(t *testing.T) {
	fr := newFakeRemote(t)
	b := newTestBackend(t, fr, &Metrics{})
	_, _, err := resolveFetch(t, b, "/gpt2/resolve/main/missing.bin")
	var se *backends.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error = %v, want StatusError", err)
	}
	if se.Status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", se.Status)
	}
}
