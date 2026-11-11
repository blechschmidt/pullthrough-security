package nix

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
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

// --- nix base-32 ------------------------------------------------------------

func TestNixBase32RoundTrip(t *testing.T) {
	// A fixed 32-byte digest encodes to a stable 52-character string and decodes
	// back to the same bytes.
	sum := sha256.Sum256([]byte("pullthrough nix test"))
	enc := nixBase32Encode(sum[:])
	if len(enc) != 52 {
		t.Fatalf("encoded length = %d, want 52", len(enc))
	}
	if !isNixBase32(enc) {
		t.Fatalf("encoded %q is not valid nix base-32", enc)
	}
	dec, err := nixBase32Decode(enc, sha256Bytes)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(dec) != string(sum[:]) {
		t.Fatalf("round-trip mismatch")
	}
}

func TestNixBase32KnownVector(t *testing.T) {
	// The empty-input SHA-256 digest, encoded in Nix base-32, is a well-known
	// value (verifiable with `nix hash to-base32 --type sha256`).
	sum := sha256.Sum256(nil)
	const want = "0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73"
	if got := nixBase32Encode(sum[:]); got != want {
		t.Fatalf("encode(sha256(\"\")) = %q, want %q", got, want)
	}
}

func TestNixBase32Rejects(t *testing.T) {
	// Length mismatch.
	if _, err := nixBase32Decode("abc", sha256Bytes); err == nil {
		t.Error("short string accepted")
	}
	// Illegal character ('e' is not in the alphabet) at the right length.
	bad := strings.Repeat("e", 52)
	if _, err := nixBase32Decode(bad, sha256Bytes); err == nil {
		t.Error("illegal character accepted")
	}
}

// --- path classification ----------------------------------------------------

func TestClassify(t *testing.T) {
	fh := strings.Repeat("a", 52) // valid-length nix base-32 (sha256)
	sh := strings.Repeat("a", 32) // valid store hash

	cases := []struct {
		path       string
		kind       resourceKind
		verifiable bool
		cacheable  bool
	}{
		{"/nix-cache-info", kindCacheInfo, false, false},
		{"/" + sh + ".narinfo", kindNarInfo, false, false},
		{"/nar/" + fh + ".nar.xz", kindNar, true, true},
		{"/nar/" + fh + ".nar", kindNar, true, true},
		{"/nar/" + fh + ".nar.zst", kindNar, true, true},
		// A 32-char (non-sha256) content address is still a valid address, but
		// unverifiable by this backend.
		{"/nar/" + sh + ".nar.xz", kindNar, false, true},
	}
	for _, c := range cases {
		res, ok := classify(c.path)
		if !ok {
			t.Errorf("classify(%q) ok=false", c.path)
			continue
		}
		if res.kind != c.kind {
			t.Errorf("classify(%q).kind = %v, want %v", c.path, res.kind, c.kind)
		}
		if res.verifiable() != c.verifiable {
			t.Errorf("classify(%q).verifiable = %v, want %v", c.path, res.verifiable(), c.verifiable)
		}
		if res.cacheable() != c.cacheable {
			t.Errorf("classify(%q).cacheable = %v, want %v", c.path, res.cacheable(), c.cacheable)
		}
	}

	for _, bad := range []string{
		"", "/", "////",
		"/foo.narinfo", // store hash wrong length
		"/" + strings.Repeat("e", 32) + ".narinfo", // illegal char
		"/nar/" + fh + ".tar.xz",                   // not a .nar
		"/nar/.nar.xz",                             // empty hash
		"/nar/" + fh,                               // missing .nar marker
		"/nar/../etc/passwd",                       // traversal
		"/other/thing",                             // unknown namespace
		"/nar/" + fh + ".nar.xz/extra",             // too many segments
	} {
		if _, ok := classify(bad); ok {
			t.Errorf("classify(%q) unexpectedly ok", bad)
		}
	}
}

// --- fake binary cache ------------------------------------------------------

type fakeCache struct {
	srv   *httptest.Server
	files map[string][]byte
}

func newFakeCache(t *testing.T) *fakeCache {
	t.Helper()
	fc := &fakeCache{files: map[string][]byte{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, ok := fc.files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	})
	fc.srv = httptest.NewServer(mux)
	t.Cleanup(fc.srv.Close)
	return fc
}

func newTestBackend(t *testing.T, fc *fakeCache, keys []string, m *Metrics) *Backend {
	t.Helper()
	b, err := New(Options{
		Name:              "nix",
		UpstreamURL:       fc.srv.URL,
		PublicBaseURL:     "https://proxy.example/v1/nix",
		TrustedPublicKeys: keys,
		Client:            upstream.NewWithHTTPClient(fc.srv.Client(), "test/1"),
		Metrics:           m,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func resolveFetch(t *testing.T, b *Backend, path string) (*backends.FetchResult, []byte, error) {
	t.Helper()
	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: path, Query: url.Values{}, Header: http.Header{}})
	if err != nil {
		return nil, nil, err
	}
	fres, err := b.Fetch(context.Background(), res)
	if err != nil {
		return nil, nil, err
	}
	fres.Resolved = res
	body, rerr := io.ReadAll(fres.Content)
	_ = fres.Content.Close()
	return fres, body, rerr
}

// --- NAR content-address verification ---------------------------------------

func TestNarContentAddressVerified(t *testing.T) {
	fc := newFakeCache(t)
	nar := []byte("this is pretend compressed NAR content")
	sum := sha256.Sum256(nar)
	fh := nixBase32Encode(sum[:])
	narPath := "/nar/" + fh + ".nar.xz"
	fc.files[narPath] = nar

	m := &Metrics{}
	b := newTestBackend(t, fc, nil, m)

	fres, body, rerr := resolveFetch(t, b, narPath)
	if rerr != nil {
		t.Fatalf("read NAR: %v", rerr)
	}
	if string(body) != string(nar) {
		t.Fatalf("body mismatch")
	}
	if fres.Resolved.Metadata[MetaFileHashVerified] != "sha256" {
		t.Errorf("not sha256-verified: %q", fres.Resolved.Metadata[MetaFileHashVerified])
	}
	if !fres.Resolved.Cacheable {
		t.Error("NAR must be cacheable")
	}
	if st := m.Stats(); st.NarsVerified != 1 || st.FileHashMismatch != 0 || st.NarsServed != 1 {
		t.Errorf("metrics = %+v", st)
	}
}

func TestNarContentAddressMismatch(t *testing.T) {
	fc := newFakeCache(t)
	// Serve different bytes than the hash in the URL names.
	realSum := sha256.Sum256([]byte("the real content"))
	fh := nixBase32Encode(realSum[:])
	narPath := "/nar/" + fh + ".nar.xz"
	fc.files[narPath] = []byte("tampered content")

	m := &Metrics{}
	b := newTestBackend(t, fc, nil, m)

	_, _, rerr := resolveFetch(t, b, narPath)
	if rerr == nil {
		t.Fatal("expected a verification error, got nil")
	}
	var mm *FileHashMismatchError
	if !errors.As(rerr, &mm) {
		t.Fatalf("error = %v, want *FileHashMismatchError", rerr)
	}
	if st := m.Stats(); st.FileHashMismatch != 1 || st.NarsVerified != 0 {
		t.Errorf("metrics = %+v", st)
	}
}

// --- narinfo signature + rewrite --------------------------------------------

// buildSignedNarInfo returns a narinfo document signed by key under keyName, plus
// the store hash, for a store path referencing one NAR.
func buildSignedNarInfo(t *testing.T, keyName string, priv ed25519.PrivateKey, narURL string) (doc string, storeHash string) {
	t.Helper()
	storeHash = strings.Repeat("b", storeHashLen)
	storePath := "/nix/store/" + storeHash + "-hello-2.12.1"
	narSum := sha256.Sum256([]byte("nar body"))
	narHash := "sha256:" + nixBase32Encode(narSum[:])
	ni := &narInfo{
		StorePath:  storePath,
		NarHash:    narHash,
		NarSize:    226552,
		References: []string{storeHash + "-hello-2.12.1"},
	}
	fp, err := ni.fingerprint()
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	sig := ed25519.Sign(priv, []byte(fp))
	sigField := keyName + ":" + base64.StdEncoding.EncodeToString(sig)

	doc = strings.Join([]string{
		"StorePath: " + storePath,
		"URL: " + narURL,
		"Compression: xz",
		"FileHash: sha256:" + strings.Repeat("a", 52),
		"FileSize: 50088",
		"NarHash: " + narHash,
		"NarSize: 226552",
		"References: " + storeHash + "-hello-2.12.1",
		"Deriver: " + strings.Repeat("c", storeHashLen) + "-hello-2.12.1.drv",
		"Sig: " + sigField,
		"",
	}, "\n")
	return doc, storeHash
}

func TestNarInfoSignedVerifiedAndRewritten(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	keyName := "test-cache-1"
	trusted := keyName + ":" + base64.StdEncoding.EncodeToString(pub)

	fc := newFakeCache(t)
	doc, storeHash := buildSignedNarInfo(t, keyName, priv, "nar/1abc.nar.xz")
	niPath := "/" + storeHash + ".narinfo"
	fc.files[niPath] = []byte(doc)

	m := &Metrics{}
	b := newTestBackend(t, fc, []string{trusted}, m)

	fres, body, rerr := resolveFetch(t, b, niPath)
	if rerr != nil {
		t.Fatalf("read narinfo: %v", rerr)
	}
	// Signature verified.
	if got := fres.Resolved.Metadata[MetaSignatureVerified]; got != "trusted:"+keyName {
		t.Errorf("signatureVerified = %q, want trusted:%s", got, keyName)
	}
	// URL rewritten through the proxy, everything else preserved.
	if !strings.Contains(string(body), "URL: https://proxy.example/v1/nix/nar/1abc.nar.xz") {
		t.Errorf("URL not rewritten through proxy:\n%s", body)
	}
	if !strings.Contains(string(body), "NarHash: ") || !strings.Contains(string(body), "Sig: "+keyName+":") {
		t.Errorf("signed fields not preserved:\n%s", body)
	}
	if fres.Resolved.Cacheable {
		t.Error("narinfo must not be cacheable")
	}
	if st := m.Stats(); st.NarInfoSigValid != 1 || st.NarInfoRewritten != 1 || st.NarInfoServed != 1 {
		t.Errorf("metrics = %+v", st)
	}
}

func TestNarInfoUntrustedSignatureRejected(t *testing.T) {
	// A narinfo signed by a different key than the one configured is rejected.
	pub, _, _ := ed25519.GenerateKey(nil)
	_, signer, _ := ed25519.GenerateKey(nil) // different private key
	keyName := "test-cache-1"
	trusted := keyName + ":" + base64.StdEncoding.EncodeToString(pub)

	fc := newFakeCache(t)
	doc, storeHash := buildSignedNarInfo(t, keyName, signer, "nar/1abc.nar.xz")
	niPath := "/" + storeHash + ".narinfo"
	fc.files[niPath] = []byte(doc)

	m := &Metrics{}
	b := newTestBackend(t, fc, []string{trusted}, m)

	_, _, rerr := resolveFetch(t, b, niPath)
	if rerr == nil {
		t.Fatal("expected a signature error, got nil")
	}
	var se *SignatureError
	if !errors.As(rerr, &se) {
		t.Fatalf("error = %v, want *SignatureError", rerr)
	}
	if st := m.Stats(); st.NarInfoSigInvalid != 1 || st.NarInfoSigValid != 0 {
		t.Errorf("metrics = %+v", st)
	}
}

func TestNarInfoNoKeysServedUnverified(t *testing.T) {
	// With no trusted keys configured, the narinfo is served (annotated) and its
	// URL rewritten, but not signature-verified.
	_, priv, _ := ed25519.GenerateKey(nil)
	fc := newFakeCache(t)
	doc, storeHash := buildSignedNarInfo(t, "whatever-1", priv, "https://cache.nixos.org/nar/1abc.nar.xz")
	niPath := "/" + storeHash + ".narinfo"
	fc.files[niPath] = []byte(doc)

	m := &Metrics{}
	b := newTestBackend(t, fc, nil, m)

	fres, body, rerr := resolveFetch(t, b, niPath)
	if rerr != nil {
		t.Fatalf("read narinfo: %v", rerr)
	}
	if got := fres.Resolved.Metadata[MetaSignatureVerified]; got != "unverified" {
		t.Errorf("signatureVerified = %q, want unverified", got)
	}
	// An absolute upstream NAR URL is rewritten to route through the proxy.
	if !strings.Contains(string(body), "URL: https://proxy.example/v1/nix/nar/1abc.nar.xz") {
		t.Errorf("absolute URL not rewritten:\n%s", body)
	}
	if st := m.Stats(); st.NarInfoUnverified != 1 || st.NarInfoServed != 1 {
		t.Errorf("metrics = %+v", st)
	}
}

// The URL is the one field of a narinfo its signature does not cover, and Nix
// fetches an absolute URL there as it stands. A cache — hostile, or compromised
// — can therefore sign a store path and locate its NAR anywhere, and the client
// would download it without the bytes ever passing through the proxy: no cache,
// no content verification, no gate. Such a narinfo is not served.
func TestNarInfoLocatingItsNarOffTheProxyIsNotServed(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	keyName := "test-cache-1"
	trusted := keyName + ":" + base64.StdEncoding.EncodeToString(pub)

	for _, tc := range []struct {
		name string
		url  string
	}{
		{"an absolute URL on another host, outside nar/", "https://attacker.example/store/1abc.nar.xz"},
		{"plain http", "http://attacker.example/x.nar.xz"},
		{"a file URL", "file:///tmp/1abc.nar.xz"},
		{"another host, with a traversal the rewrite will not touch", "https://attacker.example/nar/../1abc.nar.xz"},
		{"a scheme in upper case", "HTTPS://attacker.example/store/1abc.nar.xz"},
		{"a scheme-relative reference", "//attacker.example/store/1abc.nar.xz"},
		{"a scheme the proxy does not know", "s3://bucket/1abc.nar.xz"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, keys := range [][]string{{trusted}, nil} { // signed and trusted, or unverified: refused either way
				fc := newFakeCache(t)
				doc, storeHash := buildSignedNarInfo(t, keyName, priv, tc.url)
				niPath := "/" + storeHash + ".narinfo"
				fc.files[niPath] = []byte(doc)
				m := &Metrics{}
				b := newTestBackend(t, fc, keys, m)

				_, body, rerr := resolveFetch(t, b, niPath)
				var le *LocationError
				if !errors.As(rerr, &le) {
					t.Fatalf("trusted keys %v: error = %v (body %q), want *LocationError", keys != nil, rerr, body)
				}
				if st := m.Stats(); st.NarInfoLocationRefused != 1 || st.NarInfoServed != 0 || st.NarInfoRewritten != 0 {
					t.Errorf("metrics = %+v, want one refusal and nothing served", st)
				}
			}
		})
	}
}

// What is not refused: a location the proxy routes through itself, and a
// relative one outside nar/, which the client asks the proxy for — where the
// path is refused, because it is outside the layout.
func TestNarInfoLocationsThatStayOnTheProxy(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	for _, tc := range []struct {
		name, url, served string
	}{
		{"relative, under nar/", "nar/1abc.nar.xz", "URL: https://proxy.example/v1/nix/nar/1abc.nar.xz"},
		{"absolute, under /nar/: rewritten to the proxy's own upstream", "https://attacker.example/nar/1abc.nar.xz", "URL: https://proxy.example/v1/nix/nar/1abc.nar.xz"},
		{"relative, outside nar/: passed on, and refused when asked for", "store/1abc.nar.xz", "URL: store/1abc.nar.xz"},
		{"an absolute path: still relative to the cache the client talks to", "/store/1abc.nar.xz", "URL: /store/1abc.nar.xz"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fc := newFakeCache(t)
			doc, storeHash := buildSignedNarInfo(t, "whatever-1", priv, tc.url)
			niPath := "/" + storeHash + ".narinfo"
			fc.files[niPath] = []byte(doc)
			m := &Metrics{}
			b := newTestBackend(t, fc, nil, m)
			_, body, rerr := resolveFetch(t, b, niPath)
			if rerr != nil {
				t.Fatalf("read narinfo: %v", rerr)
			}
			if !strings.Contains(string(body), tc.served+"\n") {
				t.Errorf("served narinfo does not carry %q:\n%s", tc.served, body)
			}
			if st := m.Stats(); st.NarInfoLocationRefused != 0 {
				t.Errorf("refusals = %v, want none", st.NarInfoLocationRefused)
			}
		})
	}
	// The relative location outside nar/ is not a path this backend serves.
	if _, ok := classify("/store/1abc.nar.xz"); ok {
		t.Error("a NAR path outside nar/ is accepted by classify")
	}
}

func TestNarURLLeavesProxy(t *testing.T) {
	for raw, want := range map[string]bool{
		"":                                 false,
		"nar/1abc.nar.xz":                  false,
		"store/1abc.nar.xz":                false,
		"/store/1abc.nar.xz":               false,
		"  nar/1abc.nar.xz  ":              false,
		"https://cache.example/x.nar":      true,
		"http://cache.example/x.nar":       true,
		"file:///x.nar":                    true,
		"FTP://cache.example/x.nar":        true,
		"//cache.example/x.nar":            true,
		"javascript:alert(1)":              true,
		"nar/x.nar?next=https://elsewhere": true, // conservative: it names another location
		"http://[::1":                      true, // does not parse
	} {
		if got := narURLLeavesProxy(raw); got != want {
			t.Errorf("narURLLeavesProxy(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestNarInfoFingerprintMatchesNixFormat(t *testing.T) {
	ni := &narInfo{
		StorePath:  "/nix/store/" + strings.Repeat("b", storeHashLen) + "-hello",
		NarHash:    "sha256:1xyz",
		NarSize:    100,
		References: []string{"dep1-foo", "dep2-bar"},
	}
	fp, err := ni.fingerprint()
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	want := "1;/nix/store/" + strings.Repeat("b", storeHashLen) + "-hello;sha256:1xyz;100;/nix/store/dep1-foo,/nix/store/dep2-bar"
	if fp != want {
		t.Errorf("fingerprint =\n  %q\nwant\n  %q", fp, want)
	}
}

// TestCoordinatesAreConcrete pins the coordinate contract the admission gates
// rely on. The policy gate (and with it provenance pins, the dependency firewall
// and break-glass approvals) only evaluates a coordinate that has BOTH a name
// and a version; a store path used to be reported with a name only, so no such
// gate ever saw a Nix artifact. The content address is name and version alike.
func TestCoordinatesAreConcrete(t *testing.T) {
	b := newTestBackend(t, newFakeCache(t), nil, nil)
	resolve := func(path string) backends.Coordinate {
		t.Helper()
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: path, Query: url.Values{}, Header: http.Header{}})
		if err != nil {
			t.Fatalf("Resolve(%s): %v", path, err)
		}
		return res.Coordinate
	}

	const storeHash = "n5glp21rsz314qssw9fbvfswgy3kc68f"
	if got, want := resolve("/"+storeHash+".narinfo"), (backends.Coordinate{Name: storeHash, Version: storeHash}); got != want {
		t.Errorf("narinfo coordinate = %+v, want %+v", got, want)
	}

	const fileHash = "1qi9kgysh7rpfnj20zxiys6xg15265ws0sc5kybmw1zdj8asc37j"
	if got, want := resolve("/nar/"+fileHash+".nar.xz"), (backends.Coordinate{Name: fileHash, Version: fileHash}); got != want {
		t.Errorf("nar coordinate = %+v, want %+v", got, want)
	}

	// The cache descriptor is not an artifact and must stay ungated.
	if got := resolve("/nix-cache-info"); got != (backends.Coordinate{}) {
		t.Errorf("nix-cache-info coordinate = %+v, want none", got)
	}
}

func TestCacheInfoPassthrough(t *testing.T) {
	fc := newFakeCache(t)
	info := "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n"
	fc.files["/nix-cache-info"] = []byte(info)

	m := &Metrics{}
	b := newTestBackend(t, fc, nil, m)

	fres, body, rerr := resolveFetch(t, b, "/nix-cache-info")
	if rerr != nil {
		t.Fatalf("read cache-info: %v", rerr)
	}
	if string(body) != info {
		t.Errorf("cache-info altered:\n%s", body)
	}
	if fres.Resolved.Cacheable {
		t.Error("nix-cache-info must not be cacheable")
	}
	if st := m.Stats(); st.CacheInfoServed != 1 {
		t.Errorf("metrics = %+v", st)
	}
}

func TestParsePublicKeyErrors(t *testing.T) {
	for _, bad := range []string{"", "noseparator", "name:", ":base64", "name:not-base64!!", "name:" + base64.StdEncoding.EncodeToString([]byte("tooshort"))} {
		if _, err := parsePublicKey(bad); err == nil {
			t.Errorf("parsePublicKey(%q) unexpectedly ok", bad)
		}
	}
	pub, _, _ := ed25519.GenerateKey(nil)
	good := "cache.nixos.org-1:" + base64.StdEncoding.EncodeToString(pub)
	if _, err := parsePublicKey(good); err != nil {
		t.Errorf("parsePublicKey(good) failed: %v", err)
	}
}
