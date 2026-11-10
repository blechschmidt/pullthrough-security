package openvsx

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		path      string
		ok        bool
		kind      resourceKind
		extID     string
		version   string
		cacheable bool
		rewrite   bool
	}{
		{"/api/dracula-theme/theme-dracula", true, kindMetadata, "", "", false, true},
		{"/api/dracula-theme/theme-dracula/2.25.1", true, kindMetadata, "", "", false, true},
		{"/api/-/query", true, kindMetadata, "", "", false, true},
		{
			"/api/dracula-theme/theme-dracula/2.25.1/file/dracula-theme.theme-dracula-2.25.1.vsix",
			true, kindVsix, "dracula-theme.theme-dracula", "2.25.1", true, false,
		},
		{
			// target-platform form: version is still the segment before "file".
			"/api/ms-vscode/cpptools/linux-x64/1.0.0/file/ms-vscode.cpptools-linux-x64-1.0.0.vsix",
			true, kindVsix, "ms-vscode.cpptools", "1.0.0", true, false,
		},
		{
			"/api/dracula-theme/theme-dracula/2.25.1/file/dracula-theme.theme-dracula-2.25.1.sha256",
			true, kindFile, "", "", false, false,
		},
		{"/vscode/gallery/extensionquery", true, kindGallery, "", "", false, true},
		{"/vscode/asset/dracula-theme/theme-dracula/2.25.1/Microsoft.VisualStudio.Services.VSIXPackage", true, kindGallery, "", "", false, true},
		// Unsupported / traversal.
		{"/", false, 0, "", "", false, false},
		{"/other/thing", false, 0, "", "", false, false},
		{"/api/../etc/passwd", false, 0, "", "", false, false},
		{"/api/ns/ext//file/x.vsix", false, 0, "", "", false, false},
	}
	for _, tc := range cases {
		res, ok := classify(tc.path)
		if ok != tc.ok {
			t.Errorf("classify(%q) ok=%v, want %v", tc.path, ok, tc.ok)
			continue
		}
		if !ok {
			continue
		}
		if res.kind != tc.kind {
			t.Errorf("classify(%q) kind=%v, want %v", tc.path, res.kind, tc.kind)
		}
		if res.extID != tc.extID {
			t.Errorf("classify(%q) extID=%q, want %q", tc.path, res.extID, tc.extID)
		}
		if res.version != tc.version {
			t.Errorf("classify(%q) version=%q, want %q", tc.path, res.version, tc.version)
		}
		if res.cacheable() != tc.cacheable {
			t.Errorf("classify(%q) cacheable=%v, want %v", tc.path, res.cacheable(), tc.cacheable)
		}
		if res.rewritable() != tc.rewrite {
			t.Errorf("classify(%q) rewritable=%v, want %v", tc.path, res.rewritable(), tc.rewrite)
		}
	}
}

func TestParseSHA256Sidecar(t *testing.T) {
	good := strings.Repeat("a", 64)
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{good, good, true},
		{good + "\n", good, true},
		{"  " + strings.ToUpper(good) + "  \n", good, true},
		{"sha256:" + good, good, true},
		{good + "  dracula-theme.theme-dracula-2.25.1.vsix\n", good, true}, // coreutils form
		{"", "", false},
		{"deadbeef", "", false},                    // too short
		{strings.Repeat("a", 63) + "z", "", false}, // non-hex char
		{strings.Repeat("a", 65), "", false},       // too long
	}
	for _, tc := range cases {
		got, ok := parseSHA256Sidecar([]byte(tc.in))
		if ok != tc.ok || got != tc.want {
			t.Errorf("parseSHA256Sidecar(%q) = (%q,%v), want (%q,%v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestSHA256SidecarURL(t *testing.T) {
	in := "https://open-vsx.org/api/ns/ext/1.0.0/file/ns.ext-1.0.0.vsix"
	want := "https://open-vsx.org/api/ns/ext/1.0.0/file/ns.ext-1.0.0.sha256"
	got, ok := sha256SidecarURL(in)
	if !ok || got != want {
		t.Errorf("sha256SidecarURL(%q) = (%q,%v), want (%q,true)", in, got, ok, want)
	}
	if _, ok := sha256SidecarURL("https://x/y/z.txt"); ok {
		t.Error("sha256SidecarURL should reject a non-.vsix URL")
	}
}

func TestVerifyingReaderMismatch(t *testing.T) {
	body := []byte("the real .vsix bytes")
	wrong := strings.Repeat("0", 64)
	var result *bool
	vr := newVerifyingReader(io.NopCloser(strings.NewReader(string(body))),
		expectedChecksum{filename: "x.vsix", sha256: wrong}, "u", func(ok bool) { result = &ok })
	_, err := io.ReadAll(vr)
	var mm *ChecksumMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("expected ChecksumMismatchError, got %v", err)
	}
	if result == nil || *result {
		t.Error("onResult should have reported failure")
	}
}

// --- fake remote integration -------------------------------------------------

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
		if strings.HasSuffix(r.URL.Path, ".vsix") {
			w.Header().Set("Content-Type", "application/octet-stream")
		} else {
			w.Header().Set("Content-Type", "application/json")
		}
		_, _ = w.Write(body)
	})
	fr.srv = httptest.NewServer(mux)
	t.Cleanup(fr.srv.Close)
	return fr
}

func newTestBackend(t *testing.T, fr *fakeRemote, public string, m *Metrics) *Backend {
	t.Helper()
	b, err := New(Options{
		Name:          "openvsx",
		UpstreamURL:   fr.srv.URL,
		PublicBaseURL: public,
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

func seedVsix(fr *fakeRemote, tamper bool) (vsix []byte, path string) {
	vsix = []byte("PK\x03\x04 pretend this is a zipped .vsix")
	sum := sha256.Sum256(vsix)
	declared := toHex(sum[:])
	if tamper {
		declared = strings.Repeat("f", 64)
	}
	path = "/api/dracula-theme/theme-dracula/2.25.1/file/dracula-theme.theme-dracula-2.25.1.vsix"
	fr.files[path] = vsix
	fr.files["/api/dracula-theme/theme-dracula/2.25.1/file/dracula-theme.theme-dracula-2.25.1.sha256"] = []byte(declared + "\n")
	return vsix, path
}

func TestVsixVerifiesAndCacheable(t *testing.T) {
	fr := newFakeRemote(t)
	vsix, path := seedVsix(fr, false)
	m := &Metrics{}
	b := newTestBackend(t, fr, "https://proxy.example/v1/openvsx", m)

	fres, body, rerr := resolveFetch(t, b, path)
	if rerr != nil {
		t.Fatalf("read vsix: %v", rerr)
	}
	if string(body) != string(vsix) {
		t.Errorf("body mismatch: got %q", body)
	}
	if !fres.Resolved.Cacheable {
		t.Error("a .vsix must be cacheable")
	}
	if fres.Resolved.Coordinate.Name != "dracula-theme.theme-dracula" || fres.Resolved.Coordinate.Version != "2.25.1" {
		t.Errorf("coordinate = %+v", fres.Resolved.Coordinate)
	}
	if fres.Resolved.Metadata[MetaChecksumVerified] != "sha256" {
		t.Errorf("not verified: %q", fres.Resolved.Metadata[MetaChecksumVerified])
	}
	if st := m.Stats(); st.VsixVerified != 1 || st.SHA256Fetched != 1 || st.VsixServed != 1 {
		t.Errorf("metrics: %+v", st)
	}
}

func TestVsixTamperRefused(t *testing.T) {
	fr := newFakeRemote(t)
	_, path := seedVsix(fr, true)
	m := &Metrics{}
	b := newTestBackend(t, fr, "", m)

	_, _, rerr := resolveFetch(t, b, path)
	var mm *ChecksumMismatchError
	if !errors.As(rerr, &mm) {
		t.Fatalf("expected checksum mismatch, got %v", rerr)
	}
	if st := m.Stats(); st.ChecksumMismatch != 1 {
		t.Errorf("mismatch metric not recorded: %+v", st)
	}
}

func TestVsixMissingSidecarServedUnverified(t *testing.T) {
	fr := newFakeRemote(t)
	vsix := []byte("some bytes")
	path := "/api/ns/ext/1.0.0/file/ns.ext-1.0.0.vsix"
	fr.files[path] = vsix // no sidecar
	m := &Metrics{}
	b := newTestBackend(t, fr, "", m)

	fres, body, rerr := resolveFetch(t, b, path)
	if rerr != nil {
		t.Fatalf("read: %v", rerr)
	}
	if string(body) != string(vsix) {
		t.Errorf("body mismatch")
	}
	if fres.Resolved.Metadata[MetaChecksumVerified] != "none" {
		t.Errorf("expected unverified, got %q", fres.Resolved.Metadata[MetaChecksumVerified])
	}
	if st := m.Stats(); st.ChecksumMissing != 1 {
		t.Errorf("missing metric not recorded: %+v", st)
	}
}

func TestMetadataRewritesUpstreamURLs(t *testing.T) {
	fr := newFakeRemote(t)
	// The metadata embeds absolute upstream URLs plus an unrelated external link.
	meta := `{"files":{"download":"` + fr.srv.URL + `/api/ns/ext/1.0.0/file/ns.ext-1.0.0.vsix",` +
		`"sha256":"` + fr.srv.URL + `/api/ns/ext/1.0.0/file/ns.ext-1.0.0.sha256"},` +
		`"repository":"https://github.com/ns/ext"}`
	fr.files["/api/ns/ext"] = []byte(meta)
	m := &Metrics{}
	b := newTestBackend(t, fr, "https://proxy.example/v1/openvsx", m)

	fres, body, rerr := resolveFetch(t, b, "/api/ns/ext")
	if rerr != nil {
		t.Fatalf("read metadata: %v", rerr)
	}
	s := string(body)
	if strings.Contains(s, fr.srv.URL) {
		t.Errorf("upstream origin not rewritten: %s", s)
	}
	if !strings.Contains(s, "https://proxy.example/v1/openvsx/api/ns/ext/1.0.0/file/ns.ext-1.0.0.vsix") {
		t.Errorf("download URL not rewritten through proxy: %s", s)
	}
	if !strings.Contains(s, "https://github.com/ns/ext") {
		t.Errorf("unrelated external URL must be left intact: %s", s)
	}
	if fres.Resolved.Cacheable {
		t.Error("metadata must not be cacheable")
	}
	if st := m.Stats(); st.MetadataServed != 1 || st.MetadataRewrite != 1 {
		t.Errorf("metadata metrics: %+v", st)
	}
}

func TestSidecarPassthroughNotRewritten(t *testing.T) {
	fr := newFakeRemote(t)
	digest := strings.Repeat("a", 64)
	fr.files["/api/ns/ext/1.0.0/file/ns.ext-1.0.0.sha256"] = []byte(digest)
	m := &Metrics{}
	b := newTestBackend(t, fr, "https://proxy.example/v1/openvsx", m)

	fres, body, rerr := resolveFetch(t, b, "/api/ns/ext/1.0.0/file/ns.ext-1.0.0.sha256")
	if rerr != nil {
		t.Fatalf("read sidecar: %v", rerr)
	}
	if string(body) != digest {
		t.Errorf("sidecar body mutated: %q", body)
	}
	if fres.Resolved.Cacheable {
		t.Error("sidecar must not be cacheable")
	}
	if st := m.Stats(); st.FileServed != 1 {
		t.Errorf("file metric not recorded: %+v", st)
	}
}

func TestUnsupportedPath(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), "", &Metrics{})
	_, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/nope", Query: url.Values{}})
	if !errors.Is(err, backends.ErrNotSupported) {
		t.Errorf("expected ErrNotSupported, got %v", err)
	}
}
