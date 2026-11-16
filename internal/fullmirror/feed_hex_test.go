package fullmirror

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	hexbackend "github.com/blechschmidt/pullthrough-security/internal/backends/hex"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// The hex fixtures are hex.pm's /names and /versions of 2026-11-16, trimmed to
// five packages by copying their entries byte for byte (names.pb and
// versions.pb are the payloads, decompressed and unwrapped), and a whole
// /packages/aatree resource as served, signed by hex.pm. Trimming a payload
// voids hex.pm's signature over it, so the tests sign the payloads with a key
// of their own and name it with the option publicKey; that hex.pm's key and
// the signature scheme fit hex.pm's own resources is checked on
// /packages/aatree.

var (
	hexTestKeyOnce sync.Once
	hexTestKeyPriv *rsa.PrivateKey
)

// hexTestKey is the repository key the tests sign with.
func hexTestKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	hexTestKeyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		hexTestKeyPriv = k
	})
	return hexTestKeyPriv
}

// hexKeyOption spells a public key as the option publicKey takes it.
func hexKeyOption(t testing.TB, pub any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func hexPBVarint(x uint64) []byte { return binary.AppendUvarint(nil, x) }

func hexPBLen(field int, val []byte) []byte {
	out := hexPBVarint(uint64(field<<3 | 2))
	out = append(out, hexPBVarint(uint64(len(val)))...)
	return append(out, val...)
}

// hexResource wraps a payload as a repository serves it: gzip(Signed{payload,
// signature}), signed with key (unsigned when key is nil).
func hexResource(t testing.TB, payload []byte, key *rsa.PrivateKey) []byte {
	t.Helper()
	signed := hexPBLen(1, payload)
	if key != nil {
		sum := sha512.Sum512(payload)
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA512, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		signed = append(signed, hexPBLen(2, sig)...)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(signed)
	_ = zw.Close()
	return buf.Bytes()
}

// hexEncodeVersions encodes a Versions payload.
func hexEncodeVersions(entries []hexbackend.VersionsEntry, repo string) []byte {
	var out []byte
	for _, e := range entries {
		msg := hexPBLen(1, []byte(e.Name))
		var retired []byte
		for i, v := range e.Versions {
			msg = append(msg, hexPBLen(2, []byte(v))...)
			if i < len(e.Retired) && e.Retired[i] {
				retired = append(retired, hexPBVarint(uint64(i))...)
			}
		}
		if retired != nil {
			msg = append(msg, hexPBLen(3, retired)...)
		}
		out = append(out, hexPBLen(1, msg)...)
	}
	return append(out, hexPBLen(2, []byte(repo))...)
}

// hexEncodeNames encodes a Names payload.
func hexEncodeNames(entries []hexbackend.NamesEntry, repo string) []byte {
	var out []byte
	for _, e := range entries {
		msg := hexPBLen(1, []byte(e.Name))
		if !e.Updated.IsZero() {
			ts := append(hexPBVarint(1<<3), hexPBVarint(uint64(e.Updated.Unix()))...)
			ts = append(ts, hexPBVarint(2<<3)...)
			ts = append(ts, hexPBVarint(uint64(e.Updated.Nanosecond()))...)
			msg = append(msg, hexPBLen(3, ts)...)
		}
		out = append(out, hexPBLen(1, msg)...)
	}
	return append(out, hexPBLen(2, []byte(repo))...)
}

// hexDecodeVersions reads a Versions payload into its entries.
func hexDecodeVersions(t *testing.T, payload []byte) ([]hexbackend.VersionsEntry, string) {
	t.Helper()
	var out []hexbackend.VersionsEntry
	repo, err := hexbackend.ParseVersions(payload, func(e hexbackend.VersionsEntry) error { out = append(out, e); return nil })
	if err != nil {
		t.Fatal(err)
	}
	return out, repo
}

// hexServe has the fixture server serve /names and /versions, signed with key
// and with an ETag; a request carrying it is answered 304.
func hexServe(t *testing.T, srv *fixtureServer, names, versions []byte, key *rsa.PrivateKey, etag string) {
	t.Helper()
	for path, payload := range map[string][]byte{"/names": names, "/versions": versions} {
		tag := `"` + strings.TrimPrefix(path, "/") + "-" + etag + `"`
		srv.on("GET", path).reply(http.StatusOK, hexResource(t, payload, key)).withHeader("ETag", tag).withHeader("Content-Type", "binary/octet-stream")
		srv.on("GET", path).requireHeader("If-None-Match", tag).reply(http.StatusNotModified, nil).withHeader("ETag", tag)
	}
}

// hexTestBackend is the backend the adapter's paths are checked against.
func hexTestBackend(t *testing.T, env Env) backends.Backend {
	t.Helper()
	b, err := hexbackend.New(hexbackend.Options{Name: env.Upstream, UpstreamURL: env.URL, Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestHexFeedLocation(t *testing.T) {
	src := func(env Env) *hexSource {
		t.Helper()
		f, err := newHexFeed(env)
		if err != nil {
			t.Fatal(err)
		}
		return f.(*hexFeed).src.(*hexSource)
	}
	def, err := hexParseKey("")
	if err != nil {
		t.Fatal(err)
	}
	// hex.pm: its key and repository name; an organisation's repository
	// (named after the organisation), a mini_repo and an Artifactory
	// repository serve the two resources beneath their URLs — the last two,
	// checked with hex.pm's key, are taken for mirrors of hex.pm ("hexpm").
	for _, tc := range []struct{ url, names, repo string }{
		{"https://repo.hex.pm", "https://repo.hex.pm/names", "hexpm"},
		{"https://repo.hex.pm/", "https://repo.hex.pm/names", "hexpm"},
		{"https://repo.hex.pm/repos/acme", "https://repo.hex.pm/repos/acme/names", "acme"},
		{"https://repo.hex.pm/other/path", "https://repo.hex.pm/other/path/names", ""},
		{"http://mini-repo.internal:4000/repos/hexpm", "http://mini-repo.internal:4000/repos/hexpm/names", "hexpm"},
		{"https://acme.jfrog.io/artifactory/api/hex/hex-remote", "https://acme.jfrog.io/artifactory/api/hex/hex-remote/names", "hexpm"},
	} {
		s := src(Env{Upstream: "hex", Type: "hex", URL: tc.url})
		if s.names != tc.names || s.versions != strings.TrimSuffix(tc.names, "names")+"versions" || s.repository != tc.repo || s.key == nil || !s.key.Equal(def) {
			t.Errorf("%s: names %s versions %s repository %q key %v", tc.url, s.names, s.versions, s.repository, s.key != nil)
		}
	}
	if def.N.BitLen() != 2048 {
		t.Errorf("hex.pm's key has %d bits", def.N.BitLen())
	}
	// The option url names another repository base; publicKey another key,
	// in any of its spellings, or none.
	pub := &hexTestKey(t).PublicKey
	b64 := hexKeyOption(t, pub)
	s := src(Env{Upstream: "hex", Type: "hex", URL: "https://repo.hex.pm", Options: map[string]string{"url": "https://hexpm.mirror.example/hex/", "publicKey": b64}})
	if s.names != "https://hexpm.mirror.example/hex/names" || s.repository != "hexpm" || !s.key.Equal(pub) {
		t.Errorf("options: %s %q", s.names, s.repository)
	}
	// The repository name a mirror read through the option url must state is
	// the upstream's; one checked with another key states its own, unknown
	// unless the option repository names it.
	for _, tc := range []struct {
		url  string
		opts map[string]string
		want string
	}{
		{"https://repo.hex.pm/repos/acme", map[string]string{"url": "https://hex-mirror.internal/repos/acme"}, "acme"},
		{"https://mini-repo.internal/repos/mine", map[string]string{"publicKey": b64}, ""},
		{"https://mini-repo.internal/repos/mine", map[string]string{"publicKey": b64, "repository": "mine"}, "mine"},
		{"https://repo.hex.pm", map[string]string{"repository": "none"}, ""},
		{"https://hexpm.mirror.example", map[string]string{"repository": "acme"}, "acme"},
	} {
		if got := src(Env{Upstream: "hex", Type: "hex", URL: tc.url, Options: tc.opts}).repository; got != tc.want {
			t.Errorf("%s %v: repository %q, want %q", tc.url, tc.opts, got, tc.want)
		}
	}
	pkcs1 := base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(pub))
	for _, v := range []string{"-----BEGIN PUBLIC KEY----- " + b64 + " -----END PUBLIC KEY-----", "-----BEGIN RSA PUBLIC KEY-----" + pkcs1 + "-----END RSA PUBLIC KEY-----", b64[:40] + " " + b64[40:]} {
		if k, err := hexParseKey(v); err != nil || !k.Equal(pub) {
			t.Errorf("%.60s…: %v", v, err)
		}
	}
	if s := src(Env{Upstream: "hex", Type: "hex", URL: "https://repo.hex.pm", Options: map[string]string{"publicKey": "None"}}); s.key != nil {
		t.Errorf("publicKey none checks signatures")
	}
	// Refused when the configuration is loaded.
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	for _, opts := range []map[string]string{{"since": "1"}, {"url": "ftp://repo.example"}, {"url": "https://repo.example/?q=1"},
		{"publicKey": "not a key!"}, {"publicKey": base64.StdEncoding.EncodeToString([]byte("not DER"))},
		{"publicKey": hexKeyOption(t, &ec.PublicKey)}, {"publicKey": hexKeyOption(t, &small.PublicKey)},
		{"repository": "a\x01b"}, {"repository": strings.Repeat("r", hexMaxRepository+1)}} {
		if err := Check(Env{Upstream: "hex", Type: "hex", URL: "https://repo.hex.pm", Options: opts}); err == nil {
			t.Errorf("options %v accepted", opts)
		}
	}
	if err := Check(Env{Upstream: "hex", Type: "hex", URL: "file:///srv/hex"}); err == nil {
		t.Errorf("a file URL accepted")
	}
}

// hex.pm's own key verifies hex.pm's signature on a resource as served.
func TestHexVerifiesHexpmSignatures(t *testing.T) {
	key, err := hexParseKey("")
	if err != nil {
		t.Fatal(err)
	}
	s := &hexSource{key: key}
	payload, err := s.open(fixture(t, "hex", "packages-aatree"), "/packages/aatree")
	if err != nil {
		t.Fatalf("hex.pm's resource: %v", err)
	}
	if !bytes.Contains(payload, []byte("aatree")) {
		t.Errorf("payload %q", payload)
	}
	// One flipped byte of the payload, inside the compressed resource.
	raw, sig, _ := hexbackend.OpenSignedResource(fixture(t, "hex", "packages-aatree"))
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)/2] ^= 0x20
	if err := hexbackend.VerifyResourceSignature(tampered, sig, key); err == nil {
		t.Errorf("a changed payload verified")
	}
}

func TestHexBootstrapChangesReleases(t *testing.T) {
	key := hexTestKey(t)
	srv := newFixtureServer(t)
	names, versions := fixture(t, "hex", "names.pb"), fixture(t, "hex", "versions.pb")
	hexServe(t, srv, names, versions, key, "1")
	env := testEnv(t, "hex", srv.URL(), nil, map[string]string{"publicKey": hexKeyOption(t, &key.PublicKey)})
	f := mustFeed(t, env).(*hexFeed)
	ctx := context.Background()

	b, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	// addressBook's name is outside the backend's rule: not followed.
	checkGolden(t, "hex", "bootstrap", viewBatch(t, b))
	backend := hexTestBackend(t, env)
	for _, name := range []string{"jason", "a2ui", "aatree", "altcha"} {
		rels, err := f.Releases(ctx, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if name == "jason" || name == "a2ui" {
			checkGolden(t, "hex", "releases-"+name, viewReleases(rels))
		}
		expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return name, r.Version })
	}
	if rels, _ := f.Releases(ctx, "altcha"); len(rels) != 10 || rels[3].Version != "2.0.0-beta.1" || rels[9].Version != "2.3.0" {
		t.Errorf("altcha in SemVer order: %+v", rels)
	}
	_, err = f.Releases(ctx, "addressBook")
	mustErr(t, err, true, false, "not a Hex package name")
	_, err = f.Releases(ctx, "nope")
	mustErr(t, err, true, false, "not in the hex index")

	// Nothing changed: two 304s, nothing reported, the cursor stays.
	before := len(srv.requests())
	ch, err := f.Changes(ctx, b.Next)
	if err != nil || len(ch.Items) != 0 || ch.Next != b.Next {
		t.Fatalf("unchanged: %+v %v", ch, err)
	}
	if got := srv.requests()[before:]; fmt.Sprint(got) != "[GET /versions GET /names]" {
		t.Errorf("requests %v", got)
	}

	// /names alone changed (a package's documentation): nothing to mirror,
	// a newer head time and the new validator in the cursor.
	nent := []hexbackend.NamesEntry{{Name: "jason", Updated: time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)}}
	hexServe(t, srv, hexEncodeNames(nent, "hexpm"), versions, key, "2")
	srv.on("GET", "/versions").requireHeader("If-None-Match", `"versions-1"`).reply(http.StatusNotModified, nil)
	ch, err = f.Changes(ctx, b.Next)
	if err != nil || len(ch.Items) != 0 || !ch.HeadTime.Equal(nent[0].Updated) {
		t.Fatalf("names changed: %+v %v", ch, err)
	}
	var c indexCursor
	var st hexState
	if err := json.Unmarshal([]byte(ch.Next), &c); err != nil || json.Unmarshal(c.State, &st) != nil || st.Names.ETag != `"names-2"` || st.Versions.ETag != `"versions-1"` {
		t.Errorf("cursor %s (%v)", ch.Next, err)
	}

	// /versions changed: jason published 1.5.0, a2ui retired 0.3.1, aatree
	// is gone and zzz_new is new.
	entries, repo := hexDecodeVersions(t, versions)
	var edited []hexbackend.VersionsEntry
	for _, e := range entries {
		switch e.Name {
		case "jason":
			e.Versions = append(e.Versions, "1.5.0")
			e.Retired = append(e.Retired, false)
		case "a2ui":
			e.Retired[3] = true
		case "aatree":
			continue
		}
		edited = append(edited, e)
	}
	edited = append(edited, hexbackend.VersionsEntry{Name: "zzz_new", Versions: []string{"0.1.0"}, Retired: []bool{false}})
	var nedited []hexbackend.NamesEntry
	if _, err := hexbackend.ParseNames(names, func(e hexbackend.NamesEntry) error {
		switch e.Name {
		case "jason", "a2ui":
			e.Updated = time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
		case "aatree":
			return nil
		}
		nedited = append(nedited, e)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	nedited = append(nedited, hexbackend.NamesEntry{Name: "zzz_new", Updated: time.Date(2026, 11, 16, 10, 0, 1, 0, time.UTC)})
	hexServe(t, srv, hexEncodeNames(nedited, "hexpm"), hexEncodeVersions(edited, repo), key, "3")
	ch, err = f.Changes(ctx, ch.Next)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "hex", "changes", viewBatch(t, ch))
	if rels, err := f.Releases(ctx, "jason"); err != nil || rels[len(rels)-1].Version != "1.5.0" {
		t.Errorf("Releases reads the newest copy: %+v %v", rels, err)
	}
	if _, err := f.Releases(ctx, "aatree"); !IsPermanent(err) {
		t.Errorf("a package gone: %v", err)
	}
}

func TestHexRefusesWhatDoesNotVerify(t *testing.T) {
	key := hexTestKey(t)
	names, versions := fixture(t, "hex", "names.pb"), fixture(t, "hex", "versions.pb")
	ctx := context.Background()
	for name, tc := range map[string]struct {
		opts  map[string]string
		serve func(srv *fixtureServer)
		want  string
	}{
		// hex.pm's key does not verify what another key signed.
		"default key": {nil, func(srv *fixtureServer) { hexServe(t, srv, names, versions, key, "1") }, "does not verify"},
		"unsigned": {map[string]string{"publicKey": hexKeyOption(t, &key.PublicKey)}, func(srv *fixtureServer) {
			hexServe(t, srv, names, versions, key, "1")
			srv.on("GET", "/versions").reply(http.StatusOK, hexResource(t, versions, nil))
		}, "not signed"},
		"tampered": {map[string]string{"publicKey": hexKeyOption(t, &key.PublicKey)}, func(srv *fixtureServer) {
			hexServe(t, srv, names, versions, key, "1")
			body := hexResource(t, versions, key)
			payload, sig, _ := hexbackend.OpenSignedResource(body)
			payload = bytes.Replace(payload, []byte("1.4.5"), []byte("6.6.6"), 1)
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			_, _ = zw.Write(append(hexPBLen(1, payload), hexPBLen(2, sig)...))
			_ = zw.Close()
			srv.on("GET", "/versions").reply(http.StatusOK, buf.Bytes())
		}, "does not verify"},
	} {
		t.Run(name, func(t *testing.T) {
			srv := newFixtureServer(t)
			tc.serve(srv)
			f := mustFeed(t, testEnv(t, "hex", srv.URL(), nil, tc.opts))
			_, err := f.Bootstrap(ctx, "")
			mustErr(t, err, true, false, tc.want)
		})
	}
	// Without the check, the same resources are followed.
	srv := newFixtureServer(t)
	hexServe(t, srv, names, versions, nil, "1")
	f := mustFeed(t, testEnv(t, "hex", srv.URL(), nil, map[string]string{"publicKey": "none"}))
	if b, err := f.Bootstrap(ctx, ""); err != nil || len(b.Items) != 4 {
		t.Errorf("publicKey none: %+v %v", b, err)
	}
}

func TestHexMalformedAndRefused(t *testing.T) {
	key := hexTestKey(t)
	opts := map[string]string{"publicKey": hexKeyOption(t, &key.PublicKey)}
	namesPB := fixture(t, "hex", "names.pb")
	ctx := context.Background()
	bootstrap := func(serve func(srv *fixtureServer)) (Batch, error) {
		srv := newFixtureServer(t)
		serve(srv)
		return mustFeed(t, testEnv(t, "hex", srv.URL(), nil, opts)).Bootstrap(ctx, "")
	}
	// A body that is not a registry resource, a payload that does not read.
	for name, body := range map[string][]byte{
		"html":      []byte("<html>rate limited</html>"),
		"truncated": hexResource(t, []byte{0x0a, 0x7f, 0x01}, key),
		"no payload": func() []byte {
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			_, _ = zw.Write(hexPBLen(2, []byte("signature only")))
			_ = zw.Close()
			return buf.Bytes()
		}(),
	} {
		_, err := bootstrap(func(srv *fixtureServer) {
			hexServe(t, srv, namesPB, fixture(t, "hex", "versions.pb"), key, "1")
			srv.on("GET", "/versions").reply(http.StatusOK, body)
		})
		mustErr(t, err, true, false, "/versions")
		if t.Failed() {
			t.Fatalf("%s", name)
		}
	}
	// Past the bound.
	_, err := bootstrap(func(srv *fixtureServer) {
		hexServe(t, srv, namesPB, fixture(t, "hex", "versions.pb"), key, "1")
		srv.on("GET", "/versions").reply(http.StatusOK, make([]byte, hexMaxResource+1))
	})
	mustErr(t, err, true, false, "larger than")

	// Bad names and versions are dropped, the rest followed.
	bad := hexEncodeVersions([]hexbackend.VersionsEntry{
		{Name: "Upper", Versions: []string{"1.0.0"}},
		{Name: "has-dash", Versions: []string{"1.0.0"}},
		{Name: "", Versions: []string{"1.0.0"}},
		{Name: "ok_pkg", Versions: []string{"1.0.0", "../1.0.0", "1.0.0/x", "", "1.0.0 x", "v1.0.0", "1.0.0\n", strings.Repeat("1", 300), "1.0.0-rc.1+b.2"}},
	}, "hexpm")
	srv := newFixtureServer(t)
	hexServe(t, srv, namesPB, bad, key, "1")
	f := mustFeed(t, testEnv(t, "hex", srv.URL(), nil, opts)).(*hexFeed)
	b, err := f.Bootstrap(ctx, "")
	if err != nil || fmt.Sprint(names(b.Items)) != "[ok_pkg]" {
		t.Fatalf("bad entries: %+v %v", b, err)
	}
	if rels, err := f.Releases(ctx, "ok_pkg"); err != nil || len(rels) != 2 || rels[0].Version != "1.0.0-rc.1+b.2" || rels[1].Version != "1.0.0" {
		t.Errorf("ok_pkg: %+v %v", rels, err)
	}

	// /names gives only the head time: a repository that does not serve it,
	// or not now, or one whose /names does not read, verify or name the
	// repository, is followed without one. One without /versions is not
	// followed.
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, names := range map[string]func(srv *fixtureServer){
		"404": func(srv *fixtureServer) { srv.on("GET", "/names").reply(http.StatusNotFound, nil) },
		"400": func(srv *fixtureServer) { srv.on("GET", "/names").reply(http.StatusBadRequest, nil) },
		"403": func(srv *fixtureServer) { srv.on("GET", "/names").reply(http.StatusForbidden, nil) },
		"500": func(srv *fixtureServer) { srv.on("GET", "/names").reply(http.StatusInternalServerError, nil) },
		"429": func(srv *fixtureServer) {
			srv.on("GET", "/names").reply(http.StatusTooManyRequests, nil).withHeader("Retry-After", "120")
		},
		"garbage":           func(srv *fixtureServer) { srv.on("GET", "/names").reply(http.StatusOK, []byte("<html>")) },
		"signed by another": func(srv *fixtureServer) { srv.on("GET", "/names").reply(http.StatusOK, hexResource(t, namesPB, other)) },
	} {
		b, err = bootstrap(func(srv *fixtureServer) {
			hexServe(t, srv, namesPB, fixture(t, "hex", "versions.pb"), key, "1")
			names(srv)
		})
		if err != nil || len(b.Items) != 4 || !b.HeadTime.IsZero() {
			t.Errorf("/names %s: %+v %v", name, b, err)
		}
	}
	_, err = bootstrap(func(srv *fixtureServer) {
		hexServe(t, srv, namesPB, fixture(t, "hex", "versions.pb"), key, "1")
		srv.on("GET", "/versions").reply(http.StatusNotFound, nil)
	})
	mustErr(t, err, true, false, "not found")
	_, err = bootstrap(func(srv *fixtureServer) {
		hexServe(t, srv, namesPB, fixture(t, "hex", "versions.pb"), key, "1")
		srv.on("GET", "/versions").reply(http.StatusTooManyRequests, nil).withHeader("Retry-After", "120")
	})
	if d, ok := RetryAfterOf(err); !ok || d != 2*time.Minute || IsPermanent(err) {
		t.Errorf("a 429 on /versions: %v", err)
	}
	// The option repository names what the index must state.
	srv = newFixtureServer(t)
	hexServe(t, srv, namesPB, fixture(t, "hex", "versions.pb"), key, "1")
	_, err = mustFeed(t, testEnv(t, "hex", srv.URL(), nil, map[string]string{"publicKey": opts["publicKey"], "repository": "acme"})).Bootstrap(ctx, "")
	mustErr(t, err, true, false, `repository "hexpm", not "acme"`)

	// On hex.pm the resources must be hexpm's index.
	srv = newFixtureServer(t)
	hexServe(t, srv, namesPB, hexEncodeVersions([]hexbackend.VersionsEntry{{Name: "x", Versions: []string{"1.0.0"}}}, "acme"), key, "1")
	env := testEnv(t, "hex", srv.URL(), nil, opts)
	k, err := newKit(env)
	if err != nil {
		t.Fatal(err)
	}
	src := &hexSource{k: k, names: srv.URL() + "/names", versions: srv.URL() + "/versions", key: &key.PublicKey, repository: "hexpm"}
	_, err = (&hexFeed{indexFeed: newIndexFeed("hex", env, src)}).Bootstrap(ctx, "")
	mustErr(t, err, true, false, `repository "acme", not "hexpm"`)

	// An organisation's repository read from a mirror (the option url): the
	// public index, validly signed by the same key, is not the
	// organisation's.
	mirror := newFixtureServer(t)
	hexServe(t, mirror, namesPB, fixture(t, "hex", "versions.pb"), key, "1")
	orgEnv := testEnv(t, "hex", "https://repo.hex.pm/repos/acme", nil, map[string]string{"url": mirror.URL(), "publicKey": opts["publicKey"]})
	_, err = mustFeed(t, orgEnv).Bootstrap(ctx, "")
	mustErr(t, err, true, false, `repository "hexpm", not "acme"`)
}

// A cursor's state the source cannot use — of another shape, not an object,
// with a validator that cannot go back into a request header — means both
// resources are read in full, as on the first read.
func TestHexStateItCannotUse(t *testing.T) {
	key := hexTestKey(t)
	srv := newFixtureServer(t)
	hexServe(t, srv, fixture(t, "hex", "names.pb"), fixture(t, "hex", "versions.pb"), key, "1")
	f := mustFeed(t, testEnv(t, "hex", srv.URL(), nil, map[string]string{"publicKey": hexKeyOption(t, &key.PublicKey)}))
	ctx := context.Background()
	b, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	var c indexCursor
	if err := json.Unmarshal([]byte(b.Next), &c); err != nil {
		t.Fatal(err)
	}
	for _, st := range []string{`{"names":{"etag":"\"names-1\"\r\nX-Injected: 1"},"versions":{"etag":"\"versions-1\""}}`,
		`{"names":{"etag":"\"names-1\""},"versions":{"lastModified":"` + strings.Repeat("x", 600) + `"}}`, `{"etag":"x"}`, `[1,2]`, `"text"`} {
		c.State = json.RawMessage(st)
		before := len(srv.requests())
		ch, err := f.Changes(ctx, encodeCursor(&c))
		if err != nil || len(ch.Items) != 0 {
			t.Errorf("state %.40s: %+v %v", st, ch, err)
			continue
		}
		var got hexState
		var next indexCursor
		if json.Unmarshal([]byte(ch.Next), &next) != nil || json.Unmarshal(next.State, &got) != nil || got.Names.ETag != `"names-1"` || got.Versions.ETag != `"versions-1"` {
			t.Errorf("state %.40s: the cursor goes on with %s", st, ch.Next)
		}
		if n := len(srv.requests()) - before; n != 2 {
			t.Errorf("state %.40s: %d requests", st, n)
		}
	}
}

// Bootstrap lists the copy page by page; its last cursor is the follow cursor,
// which a listing cursor, or another adapter's, is not.
func TestHexBootstrapPagesAndCursors(t *testing.T) {
	key := hexTestKey(t)
	srv := newFixtureServer(t)
	hexServe(t, srv, fixture(t, "hex", "names.pb"), fixture(t, "hex", "versions.pb"), key, "1")
	f := mustFeed(t, testEnv(t, "hex", srv.URL(), nil, map[string]string{"publicKey": hexKeyOption(t, &key.PublicKey)})).(*hexFeed)
	f.page = 3
	ctx := context.Background()
	b1, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	b2, err := f.Bootstrap(ctx, b1.Next)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(names(b1.Items), b1.More, b1.Lag, names(b2.Items), b2.More); got != "[a2ui aatree altcha] true 1 [jason] false" {
		t.Fatalf("bootstrap %s", got)
	}
	if len(srv.requests()) != 2 {
		t.Errorf("the second page read the repository: %v", srv.requests())
	}
	var c indexCursor
	if err := decodeCursor(b2.Next, "hex/1", &c); err != nil || c.Listing || c.After != "" {
		t.Errorf("final cursor %s (%v)", b2.Next, err)
	}
	for _, bad := range []string{b1.Next, `{"format":"openvsx/1","snap":"` + c.Snap + `"}`, `{"format":"hex/1","snap":"` + strings.Repeat("0", 64) + `"}`} {
		_, err := f.Changes(ctx, bad)
		mustErr(t, err, false, true, "")
	}
	if _, err := f.Bootstrap(ctx, b2.Next); err == nil {
		t.Errorf("Bootstrap continued from a follow cursor")
	}
}
