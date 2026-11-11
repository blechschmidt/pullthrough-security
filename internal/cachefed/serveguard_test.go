package cachefed

import (
	"bytes"
	"context"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// Tests for the serve guards of the peer endpoint: ServeGuard, the guards
// Federation.Handler takes, and the ServedRefused counter.
//
// The handler answers a sibling's HEAD/GET by cache key out of this proxy's
// cache. A guard is this proxy declining to hand out an entry it has itself
// refused. The handler is driven in-process, without a listener, except where
// what a sibling sees on the wire is the point.

// refusedArtifact stands for an artifact that has a verdict against it and is
// still in the cache. Not one of its bytes is ASCII, so a single byte of it in
// a refusal — which is text — cannot be mistaken for anything else.
var refusedArtifact = bytes.Repeat([]byte{0xde, 0xad, 0xbe, 0xef}, 256)

// entryHeaders are the protocol headers that describe a served entry.
var entryHeaders = []string{headerDigest, headerContentType, headerOrigin, headerPeerSize}

// guardFixture is the serving half of a federation: a Federation that serves,
// its cache, and the handler under test built over the given guards.
type guardFixture struct {
	fed     *Federation
	cache   cache.Cache
	handler http.Handler
}

func newGuardFixture(t *testing.T, guards ...ServeGuard) *guardFixture {
	t.Helper()
	fed, err := New(Config{Enabled: true, Serve: true, AuthToken: testToken}, NewMetrics())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c := cache.NewMemoryCache()
	return &guardFixture{fed: fed, cache: c, handler: fed.Handler(c, guards...)}
}

// put stores content in the serving proxy's cache under key.
func (f *guardFixture) put(t *testing.T, key string, content []byte, meta map[string]string) {
	t.Helper()
	if _, err := f.cache.Put(context.Background(), key, bytes.NewReader(content), meta); err != nil {
		t.Fatalf("cache put %q: %v", key, err)
	}
}

func (f *guardFixture) snapshot() Snapshot { return f.fed.Metrics().Snapshot() }

// listen mounts the handler at BasePath behind a real listener, the way the
// gateway does, for the tests that are about what a sibling sees on the wire.
func (f *guardFixture) listen(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(BasePath, f.handler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// siblingRequest is a sibling's request for key, carrying the shared token.
func siblingRequest(method, key string) *http.Request {
	req := httptest.NewRequest(method, BasePath+"?"+url.Values{"key": {key}}.Encode(), nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	return req
}

// servedResponse is what the handler sent: the status and headers as they stood
// when the response was committed, and every body byte written.
type servedResponse struct {
	status int
	header http.Header
	body   []byte
}

// serveOnce runs one request through the handler, in this goroutine.
func serveOnce(h http.Handler, req *http.Request) servedResponse {
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	res := rr.Result()
	return servedResponse{status: res.StatusCode, header: res.Header, body: rr.Body.Bytes()}
}

// countingGuard returns a guard that counts its consultations and answers err.
func countingGuard(calls *atomic.Int64, err error) ServeGuard {
	return func(context.Context, string, *cache.Stat) error {
		calls.Add(1)
		return err
	}
}

// assertNoArtifactBytes fails when body holds the artifact, or so much as one
// of the byte values the artifact is made of.
func assertNoArtifactBytes(t *testing.T, body, artifact []byte) {
	t.Helper()
	if bytes.Contains(body, artifact) {
		t.Errorf("the response body contains the whole artifact (%d bytes)", len(artifact))
		return
	}
	var ofArtifact [256]bool
	for _, b := range artifact {
		ofArtifact[b] = true
	}
	for i, b := range body {
		if ofArtifact[b] {
			t.Errorf("response body byte %d (%#02x) is a byte of the artifact; body = %q", i, b, body)
			return
		}
	}
}

// assertRefused checks the answer to a refused request: a 403 marked as a
// policy block, with none of the headers that describe the entry and none of
// the entry's bytes.
func assertRefused(t *testing.T, got servedResponse, artifact []byte) {
	t.Helper()
	if got.status != http.StatusForbidden {
		t.Errorf("status = %d, want 403", got.status)
	}
	if d := got.header.Get("X-Policy-Decision"); d != "block" {
		t.Errorf("X-Policy-Decision = %q, want %q", d, "block")
	}
	for _, name := range entryHeaders {
		if v := got.header.Values(name); len(v) != 0 {
			t.Errorf("%s = %q on a refusal, want the header absent", name, v)
		}
	}
	assertNoArtifactBytes(t, got.body, artifact)
}

// TestServeGuardRefusesHeadAndGet: an entry a guard objects to is refused for
// HEAD and GET alike, and each refused request is counted once — as a refusal,
// not as a served entry, a miss or an authentication failure.
func TestServeGuardRefusesHeadAndGet(t *testing.T) {
	var calls atomic.Int64
	f := newGuardFixture(t, countingGuard(&calls, errors.New("malicious verdict on file")))
	key := sha256Digest(refusedArtifact)
	f.put(t, key, refusedArtifact, map[string]string{
		cache.MetaContentType: "application/gzip",
		cache.MetaOrigin:      "https://registry.example/evil/-/evil-1.0.0.tgz",
	})

	for i, method := range []string{http.MethodHead, http.MethodGet} {
		t.Run(method, func(t *testing.T) {
			got := serveOnce(f.handler, siblingRequest(method, key))
			assertRefused(t, got, refusedArtifact)

			want := Snapshot{ServedRefused: uint64(i + 1)}
			if snap := f.snapshot(); snap != want {
				t.Errorf("metrics = %+v, want %+v", snap, want)
			}
			if n := calls.Load(); n != int64(i+1) {
				t.Errorf("guard consulted %d times over %d requests, want once per request", n, i+1)
			}
		})
	}
}

// TestServeGuardRefusalOnTheWire asks the way a sibling does, over HTTP: what
// arrives for a refused entry is the 403, without the entry's protocol headers
// and without a byte of its content.
func TestServeGuardRefusalOnTheWire(t *testing.T) {
	f := newGuardFixture(t, func(context.Context, string, *cache.Stat) error {
		return errors.New("malicious verdict on file")
	})
	key := sha256Digest(refusedArtifact)
	f.put(t, key, refusedArtifact, map[string]string{cache.MetaContentType: "application/gzip"})
	srv := f.listen(t)

	for _, method := range []string{http.MethodHead, http.MethodGet} {
		t.Run(method, func(t *testing.T) {
			req, err := http.NewRequest(method, srv.URL+BasePath+"?"+url.Values{"key": {key}}.Encode(), nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+testToken)
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatalf("reading the refusal: %v", err)
			}
			assertRefused(t, servedResponse{status: resp.StatusCode, header: resp.Header, body: body}, refusedArtifact)
		})
	}
	if snap, want := f.snapshot(), (Snapshot{ServedRefused: 2}); snap != want {
		t.Errorf("metrics = %+v, want %+v", snap, want)
	}
}

// TestServeGuardRefusedSiblingFallsBack is the refusal seen from the asking
// proxy: its read-through finds no peer for the key (the gateway then goes to
// the upstream) and it is handed no content. Once the guard relents the same
// sibling is served, so it was the guard that stood in the way and nothing else.
func TestServeGuardRefusedSiblingFallsBack(t *testing.T) {
	var refuse atomic.Bool
	refuse.Store(true)
	f := newGuardFixture(t, func(context.Context, string, *cache.Stat) error {
		if refuse.Load() {
			return errors.New("malicious verdict on file")
		}
		return nil
	})
	content := []byte("an artifact the serving proxy has a verdict against")
	key := sha256Digest(content)
	f.put(t, key, content, nil)
	// The generous header deadline keeps a stalled machine from turning the
	// fetch that must succeed into a timeout.
	sibling := newClient(t, Config{PeerTimeout: time.Minute}, Peer{Name: "guarded", URL: f.listen(t).URL})

	res, err := sibling.Fetch(context.Background(), key, key)
	if !errors.Is(err, ErrNoPeer) {
		if res != nil {
			res.Content.Close()
		}
		t.Fatalf("Fetch of a refused entry: err = %v, want ErrNoPeer", err)
	}
	if hits := sibling.Metrics().Snapshot().Hits; hits != 0 {
		t.Errorf("sibling counted %d peer hits for a refused entry, want 0", hits)
	}
	if snap, want := f.snapshot(), (Snapshot{ServedRefused: 1}); snap != want {
		t.Errorf("serving proxy metrics = %+v, want %+v", snap, want)
	}

	refuse.Store(false)
	res, err = sibling.Fetch(context.Background(), key, key)
	if err != nil {
		t.Fatalf("Fetch once the guard allows: %v", err)
	}
	got, err := readAll(t, res.Content)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("content once the guard allows = %q, %v; want %q", got, err, content)
	}
	if snap, want := f.snapshot(), (Snapshot{Served: 1, ServedRefused: 1}); snap != want {
		t.Errorf("serving proxy metrics = %+v, want %+v", snap, want)
	}
}

// TestServeGuardAllowServesNormally: a guard that returns nil changes nothing
// about the answer — status, protocol headers, body, the served counter.
func TestServeGuardAllowServesNormally(t *testing.T) {
	var calls atomic.Int64
	f := newGuardFixture(t, countingGuard(&calls, nil))
	content := []byte("a perfectly ordinary artifact")
	key := sha256Digest(content)
	const origin = "https://registry.example/good/-/good-1.0.0.tgz"
	f.put(t, key, content, map[string]string{
		cache.MetaContentType: "application/gzip",
		cache.MetaOrigin:      origin,
	})
	wantHeaders := map[string]string{
		headerDigest:      key,
		headerContentType: "application/gzip",
		headerOrigin:      origin,
		headerPeerSize:    strconv.Itoa(len(content)),
	}

	for i, method := range []string{http.MethodHead, http.MethodGet} {
		t.Run(method, func(t *testing.T) {
			got := serveOnce(f.handler, siblingRequest(method, key))
			if got.status != http.StatusOK {
				t.Fatalf("status = %d, want 200; body = %q", got.status, got.body)
			}
			for name, want := range wantHeaders {
				if v := got.header.Get(name); v != want {
					t.Errorf("%s = %q, want %q", name, v, want)
				}
			}
			if v := got.header.Values("X-Policy-Decision"); len(v) != 0 {
				t.Errorf("X-Policy-Decision = %q on a served entry, want the header absent", v)
			}
			wantBody := content
			if method == http.MethodHead {
				wantBody = nil
			}
			if !bytes.Equal(got.body, wantBody) {
				t.Errorf("body = %q, want %q", got.body, wantBody)
			}
			if snap, want := f.snapshot(), (Snapshot{Served: uint64(i + 1)}); snap != want {
				t.Errorf("metrics = %+v, want %+v", snap, want)
			}
			if n := calls.Load(); n != int64(i+1) {
				t.Errorf("guard consulted %d times over %d requests, want once per request", n, i+1)
			}
		})
	}
}

// TestServeGuardNilGuardIsSkipped: a nil guard in the list neither allows nor
// refuses anything, and does not end the list — the guards around it decide.
func TestServeGuardNilGuardIsSkipped(t *testing.T) {
	cases := []struct {
		name       string
		guards     string // one letter per guard: n = nil, a = allows, d = refuses
		wantStatus int
		wantCalls  int64 // consultations of the non-nil guards, per request
	}{
		{"nothing but a nil guard", "n", http.StatusOK, 0},
		{"nil guards around one that allows", "nan", http.StatusOK, 1},
		{"nil guard before one that refuses", "nd", http.StatusForbidden, 1},
		{"nil guard after one that refuses", "dn", http.StatusForbidden, 1},
	}
	for _, tc := range cases {
		for _, method := range []string{http.MethodHead, http.MethodGet} {
			t.Run(tc.name+"/"+method, func(t *testing.T) {
				var calls atomic.Int64
				var guards []ServeGuard
				for _, kind := range tc.guards {
					switch kind {
					case 'n':
						guards = append(guards, nil)
					case 'a':
						guards = append(guards, countingGuard(&calls, nil))
					case 'd':
						guards = append(guards, countingGuard(&calls, errors.New("refused")))
					}
				}
				f := newGuardFixture(t, guards...)
				key := sha256Digest(refusedArtifact)
				f.put(t, key, refusedArtifact, nil)

				got := serveOnce(f.handler, siblingRequest(method, key))
				if got.status != tc.wantStatus {
					t.Errorf("status = %d, want %d", got.status, tc.wantStatus)
				}
				if n := calls.Load(); n != tc.wantCalls {
					t.Errorf("non-nil guards consulted %d times, want %d", n, tc.wantCalls)
				}
			})
		}
	}
}

// TestServeGuardFirstErrorRefuses: with several guards the first one that
// objects refuses the entry, the guards after it are not consulted, and the
// request still counts as one refusal.
func TestServeGuardFirstErrorRefuses(t *testing.T) {
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		t.Run(method, func(t *testing.T) {
			var consulted []string
			guard := func(name string, err error) ServeGuard {
				return func(context.Context, string, *cache.Stat) error {
					consulted = append(consulted, name)
					return err
				}
			}
			f := newGuardFixture(t,
				guard("first", nil),
				guard("second", errors.New("verdict of the second guard")),
				guard("third", errors.New("verdict of the third guard")),
				guard("fourth", nil),
			)
			key := sha256Digest(refusedArtifact)
			f.put(t, key, refusedArtifact, nil)

			got := serveOnce(f.handler, siblingRequest(method, key))
			assertRefused(t, got, refusedArtifact)
			if want := "first,second"; strings.Join(consulted, ",") != want {
				t.Errorf("guards consulted = %q, want %q", consulted, want)
			}
			// The refusal names the reason of the guard that refused.
			if body := string(got.body); !strings.Contains(body, "verdict of the second guard") || strings.Contains(body, "third") {
				t.Errorf("refusal body = %q, want the second guard's reason and not the third's", body)
			}
			if snap, want := f.snapshot(), (Snapshot{ServedRefused: 1}); snap != want {
				t.Errorf("metrics = %+v, want %+v", snap, want)
			}
		})
	}
}

// TestServeGuardAllConsultedInOrder: an entry is served only once every guard
// has been asked, in the order the guards were given.
func TestServeGuardAllConsultedInOrder(t *testing.T) {
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		t.Run(method, func(t *testing.T) {
			var consulted []string
			guard := func(name string) ServeGuard {
				return func(context.Context, string, *cache.Stat) error {
					consulted = append(consulted, name)
					return nil
				}
			}
			f := newGuardFixture(t, guard("first"), guard("second"), guard("third"))
			content := []byte("an artifact nobody objects to")
			key := sha256Digest(content)
			f.put(t, key, content, nil)

			got := serveOnce(f.handler, siblingRequest(method, key))
			if got.status != http.StatusOK {
				t.Fatalf("status = %d, want 200; body = %q", got.status, got.body)
			}
			if want := "first,second,third"; strings.Join(consulted, ",") != want {
				t.Errorf("guards consulted = %q, want %q", consulted, want)
			}
		})
	}
}

// guardCtxKey marks the request context in TestServeGuardIsGivenKeyAndStat.
type guardCtxKey struct{}

// TestServeGuardIsGivenKeyAndStat pins what a guard has to decide on: the key
// the sibling asked for, the entry's Stat with its metadata (the content digest
// among it), and the request's context. The key here is a logical coordinate,
// not a content address, so the key and the digest cannot be confused.
func TestServeGuardIsGivenKeyAndStat(t *testing.T) {
	const key = "npm/@scope/pkg/-/pkg-1.0.0.tgz"
	content := []byte("the bytes a guard never needs to see")
	meta := map[string]string{
		cache.MetaContentType: "application/gzip",
		cache.MetaOrigin:      "https://registry.example/@scope/pkg/-/pkg-1.0.0.tgz",
		"note":                "kept verbatim",
	}

	for _, method := range []string{http.MethodHead, http.MethodGet} {
		t.Run(method, func(t *testing.T) {
			type consultation struct {
				ctxValue any
				key      string
				stat     *cache.Stat
			}
			var seen []consultation
			f := newGuardFixture(t, func(ctx context.Context, key string, stat *cache.Stat) error {
				c := consultation{ctxValue: ctx.Value(guardCtxKey{}), key: key}
				if stat != nil {
					cp := *stat
					cp.Metadata = maps.Clone(stat.Metadata)
					c.stat = &cp
				}
				seen = append(seen, c)
				return nil
			})
			f.put(t, key, content, meta)

			req := siblingRequest(method, key)
			req = req.WithContext(context.WithValue(req.Context(), guardCtxKey{}, "request-scoped"))
			if got := serveOnce(f.handler, req); got.status != http.StatusOK {
				t.Fatalf("status = %d, want 200; body = %q", got.status, got.body)
			}

			if len(seen) != 1 {
				t.Fatalf("guard consulted %d times, want 1", len(seen))
			}
			got := seen[0]
			if got.key != key {
				t.Errorf("guard was given key %q, want the requested key %q", got.key, key)
			}
			if got.ctxValue != "request-scoped" {
				t.Errorf("guard context value = %v, want the request's context", got.ctxValue)
			}
			if got.stat == nil {
				t.Fatal("guard was given a nil Stat")
			}
			if got.stat.Key != key {
				t.Errorf("stat.Key = %q, want %q", got.stat.Key, key)
			}
			if got.stat.Size != int64(len(content)) {
				t.Errorf("stat.Size = %d, want %d", got.stat.Size, len(content))
			}
			if d, want := got.stat.Metadata[cache.MetaDigest], sha256Digest(content); d != want {
				t.Errorf("stat.Metadata[%q] = %q, want %q", cache.MetaDigest, d, want)
			}
			for k, want := range meta {
				if v := got.stat.Metadata[k]; v != want {
					t.Errorf("stat.Metadata[%q] = %q, want %q", k, v, want)
				}
			}
		})
	}
}

// brokenCache fails every read with an error that is not ErrNotFound.
type brokenCache struct{ cache.Cache }

func (brokenCache) Get(context.Context, string) (*cache.Entry, error) {
	return nil, errors.New("disk on fire")
}

func (brokenCache) Stat(context.Context, string) (*cache.Stat, error) {
	return nil, errors.New("disk on fire")
}

// TestServeGuardNotConsultedWhenRequestFailsEarlier: a guard rules on an entry
// about to be handed out, and on nothing else. A request that is turned away
// before there is such an entry — serving disabled, wrong method, bad
// credentials, no key, key not held, cache failure — never reaches a guard and
// is not counted as a refusal. The entry is in the cache in every case that
// has one, so it is the earlier check and not a miss that keeps the guard out.
func TestServeGuardNotConsultedWhenRequestFailsEarlier(t *testing.T) {
	serving := Config{Enabled: true, Serve: true, AuthToken: testToken}
	with := func(method string, edit func(*http.Request)) func(string) *http.Request {
		return func(key string) *http.Request {
			req := siblingRequest(method, key)
			if edit != nil {
				edit(req)
			}
			return req
		}
	}
	absent := sha256Digest([]byte("not in the cache"))

	cases := []struct {
		name    string
		cfg     Config
		cache   func() cache.Cache // the cache the handler is given; nil: one holding the entry
		request func(key string) *http.Request
		want    int
	}{
		{name: "federation disabled", cfg: Config{Serve: true, AuthToken: testToken},
			request: with(http.MethodGet, nil), want: http.StatusServiceUnavailable},
		{name: "serving switched off", cfg: Config{Enabled: true, AuthToken: testToken},
			request: with(http.MethodGet, nil), want: http.StatusServiceUnavailable},
		{name: "no auth token configured", cfg: Config{Enabled: true, Serve: true},
			request: with(http.MethodHead, nil), want: http.StatusServiceUnavailable},
		{name: "no cache", cfg: serving, cache: func() cache.Cache { return nil },
			request: with(http.MethodGet, nil), want: http.StatusServiceUnavailable},

		{name: "POST", cfg: serving,
			request: with(http.MethodPost, nil), want: http.StatusMethodNotAllowed},
		{name: "DELETE", cfg: serving,
			request: with(http.MethodDelete, nil), want: http.StatusMethodNotAllowed},

		{name: "GET without credentials", cfg: serving,
			request: with(http.MethodGet, func(r *http.Request) { r.Header.Del("Authorization") }),
			want:    http.StatusUnauthorized},
		{name: "GET with the wrong token", cfg: serving,
			request: with(http.MethodGet, func(r *http.Request) { r.Header.Set("Authorization", "Bearer not-the-token") }),
			want:    http.StatusUnauthorized},
		{name: "HEAD with the wrong token", cfg: serving,
			request: with(http.MethodHead, func(r *http.Request) { r.Header.Set("Authorization", "Bearer not-the-token") }),
			want:    http.StatusUnauthorized},
		{name: "token without the Bearer scheme", cfg: serving,
			request: with(http.MethodGet, func(r *http.Request) { r.Header.Set("Authorization", testToken) }),
			want:    http.StatusUnauthorized},

		{name: "no key parameter", cfg: serving,
			request: with(http.MethodGet, func(r *http.Request) { r.URL.RawQuery = "" }),
			want:    http.StatusBadRequest},
		{name: "blank key", cfg: serving,
			request: func(string) *http.Request { return siblingRequest(http.MethodHead, "   ") },
			want:    http.StatusBadRequest},

		{name: "GET of a key not held", cfg: serving,
			request: func(string) *http.Request { return siblingRequest(http.MethodGet, absent) },
			want:    http.StatusNotFound},
		{name: "HEAD of a key not held", cfg: serving,
			request: func(string) *http.Request { return siblingRequest(http.MethodHead, absent) },
			want:    http.StatusNotFound},

		{name: "GET when the cache fails", cfg: serving, cache: func() cache.Cache { return brokenCache{} },
			request: with(http.MethodGet, nil), want: http.StatusInternalServerError},
		{name: "HEAD when the cache fails", cfg: serving, cache: func() cache.Cache { return brokenCache{} },
			request: with(http.MethodHead, nil), want: http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fed, err := New(tc.cfg, NewMetrics())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			key := sha256Digest(refusedArtifact)
			var c cache.Cache
			if tc.cache != nil {
				c = tc.cache()
			} else {
				held := cache.NewMemoryCache()
				if _, err := held.Put(context.Background(), key, bytes.NewReader(refusedArtifact), nil); err != nil {
					t.Fatalf("cache put: %v", err)
				}
				c = held
			}
			var calls atomic.Int64
			handler := fed.Handler(c, countingGuard(&calls, errors.New("the guard must not be consulted")))

			got := serveOnce(handler, tc.request(key))
			if got.status != tc.want {
				t.Errorf("status = %d, want %d; body = %q", got.status, tc.want, got.body)
			}
			if n := calls.Load(); n != 0 {
				t.Errorf("guard consulted %d times, want 0", n)
			}
			if snap := fed.Metrics().Snapshot(); snap.ServedRefused != 0 || snap.Served != 0 {
				t.Errorf("metrics = %+v, want neither a refusal nor a served entry", snap)
			}
			assertNoArtifactBytes(t, got.body, refusedArtifact)
		})
	}
}

// TestHandlerWithoutGuardsServesAsBefore: guards are optional. A handler built
// with none — or with an empty or nil list of them — serves what the cache
// holds and never counts a refusal.
func TestHandlerWithoutGuardsServesAsBefore(t *testing.T) {
	variants := []struct {
		name   string
		guards []ServeGuard
	}{
		{"no guard argument", nil},
		{"empty guard list", []ServeGuard{}},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			var f *guardFixture
			if v.guards == nil {
				f = newGuardFixture(t)
			} else {
				f = newGuardFixture(t, v.guards...)
			}
			content := []byte("served the way it always was")
			key := sha256Digest(content)
			f.put(t, key, content, map[string]string{cache.MetaContentType: "text/plain"})

			get := serveOnce(f.handler, siblingRequest(http.MethodGet, key))
			if get.status != http.StatusOK || !bytes.Equal(get.body, content) {
				t.Errorf("GET = %d %q, want 200 %q", get.status, get.body, content)
			}
			if d := get.header.Get(headerDigest); d != key {
				t.Errorf("GET %s = %q, want %q", headerDigest, d, key)
			}
			head := serveOnce(f.handler, siblingRequest(http.MethodHead, key))
			if head.status != http.StatusOK || len(head.body) != 0 {
				t.Errorf("HEAD = %d with a %d-byte body, want 200 and no body", head.status, len(head.body))
			}
			if d := head.header.Get(headerDigest); d != key {
				t.Errorf("HEAD %s = %q, want %q", headerDigest, d, key)
			}
			miss := serveOnce(f.handler, siblingRequest(http.MethodGet, sha256Digest([]byte("absent"))))
			if miss.status != http.StatusNotFound {
				t.Errorf("GET of a key not held = %d, want 404", miss.status)
			}
			if snap, want := f.snapshot(), (Snapshot{Served: 2, ServedMisses: 1}); snap != want {
				t.Errorf("metrics = %+v, want %+v", snap, want)
			}
		})
	}
}

// TestServeGuardConsultedOnEveryRequest: nothing about a guard's answer is
// remembered. A verdict that arrives after an entry was already handed out
// refuses the next request for it, and one that is lifted lets it through again.
func TestServeGuardConsultedOnEveryRequest(t *testing.T) {
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		t.Run(method, func(t *testing.T) {
			var refuse bool
			var calls atomic.Int64
			f := newGuardFixture(t, func(context.Context, string, *cache.Stat) error {
				calls.Add(1)
				if refuse {
					return errors.New("a verdict arrived")
				}
				return nil
			})
			key := sha256Digest(refusedArtifact)
			f.put(t, key, refusedArtifact, nil)

			steps := []struct {
				refuse bool
				want   int
			}{
				{false, http.StatusOK},
				{true, http.StatusForbidden},
				{true, http.StatusForbidden},
				{false, http.StatusOK},
			}
			for i, step := range steps {
				refuse = step.refuse
				if got := serveOnce(f.handler, siblingRequest(method, key)); got.status != step.want {
					t.Errorf("request %d (guard refuses: %v): status = %d, want %d", i+1, step.refuse, got.status, step.want)
				}
			}
			if n := calls.Load(); n != int64(len(steps)) {
				t.Errorf("guard consulted %d times over %d requests", n, len(steps))
			}
			if snap, want := f.snapshot(), (Snapshot{Served: 2, ServedRefused: 2}); snap != want {
				t.Errorf("metrics = %+v, want %+v", snap, want)
			}
		})
	}
}

// contentSpyCache wraps a cache and watches the content streams Get hands out:
// how many were opened, how many of those were closed again, and how many bytes
// were read from them.
type contentSpyCache struct {
	cache.Cache
	opened, closed, read atomic.Int64
}

func (c *contentSpyCache) Get(ctx context.Context, key string) (*cache.Entry, error) {
	entry, err := c.Cache.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	c.opened.Add(1)
	entry.Content = &spiedContent{ReadCloser: entry.Content, spy: c}
	return entry, nil
}

type spiedContent struct {
	io.ReadCloser
	spy    *contentSpyCache
	closed atomic.Bool
}

func (s *spiedContent) Read(p []byte) (int, error) {
	n, err := s.ReadCloser.Read(p)
	s.spy.read.Add(int64(n))
	return n, err
}

func (s *spiedContent) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		s.spy.closed.Add(1)
	}
	return s.ReadCloser.Close()
}

// TestServeGuardRefusalReleasesTheEntry: a refusal reads nothing of the entry's
// content and leaves no content stream open behind it. (A guard is given
// metadata, never content; a HEAD does not open the content at all.)
func TestServeGuardRefusalReleasesTheEntry(t *testing.T) {
	newSpied := func(t *testing.T, guard ServeGuard) (*contentSpyCache, http.Handler, string) {
		t.Helper()
		fed, err := New(Config{Enabled: true, Serve: true, AuthToken: testToken}, NewMetrics())
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		spy := &contentSpyCache{Cache: cache.NewMemoryCache()}
		key := sha256Digest(refusedArtifact)
		if _, err := spy.Put(context.Background(), key, bytes.NewReader(refusedArtifact), nil); err != nil {
			t.Fatalf("cache put: %v", err)
		}
		return spy, fed.Handler(spy, guard), key
	}
	refuse := func(context.Context, string, *cache.Stat) error { return errors.New("malicious verdict on file") }

	t.Run("GET", func(t *testing.T) {
		spy, handler, key := newSpied(t, refuse)
		got := serveOnce(handler, siblingRequest(http.MethodGet, key))
		assertRefused(t, got, refusedArtifact)
		if opened, closed := spy.opened.Load(), spy.closed.Load(); opened != closed {
			t.Errorf("%d content streams opened, %d closed: a refusal leaked the entry", opened, closed)
		}
		if n := spy.read.Load(); n != 0 {
			t.Errorf("%d content bytes were read for a refused entry, want 0", n)
		}
	})

	t.Run("HEAD", func(t *testing.T) {
		spy, handler, key := newSpied(t, refuse)
		got := serveOnce(handler, siblingRequest(http.MethodHead, key))
		assertRefused(t, got, refusedArtifact)
		if opened := spy.opened.Load(); opened != 0 {
			t.Errorf("a HEAD opened %d content streams, want 0", opened)
		}
	})

	// The spy itself: a served GET opens one stream, reads all of it, closes it.
	t.Run("served GET", func(t *testing.T) {
		spy, handler, key := newSpied(t, nil)
		got := serveOnce(handler, siblingRequest(http.MethodGet, key))
		if got.status != http.StatusOK || !bytes.Equal(got.body, refusedArtifact) {
			t.Fatalf("status = %d with a %d-byte body, want 200 and the entry", got.status, len(got.body))
		}
		if opened, closed, read := spy.opened.Load(), spy.closed.Load(), spy.read.Load(); opened != 1 || closed != 1 || read != int64(len(refusedArtifact)) {
			t.Errorf("opened/closed/read = %d/%d/%d, want 1/1/%d", opened, closed, read, len(refusedArtifact))
		}
	})
}

// TestServeGuardConcurrentRequests has siblings ask for a refused and an
// allowed entry at the same time, HEAD and GET mixed, with a guard that rules
// by content digest the way the gateway's does. Every answer is the right one
// for its entry and the counters add up. Run under -race this also covers the
// refused counter.
func TestServeGuardConcurrentRequests(t *testing.T) {
	good := []byte("an artifact nobody objects to")
	goodKey, badKey := sha256Digest(good), sha256Digest(refusedArtifact)
	f := newGuardFixture(t, func(_ context.Context, _ string, stat *cache.Stat) error {
		if stat.Metadata[cache.MetaDigest] == badKey {
			return errors.New("malicious verdict on file")
		}
		return nil
	})
	f.put(t, goodKey, good, nil)
	f.put(t, badKey, refusedArtifact, nil)

	const requests = 64 // a multiple of four: {refused, allowed} x {HEAD, GET}
	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			method := http.MethodGet
			if i%2 == 1 {
				method = http.MethodHead
			}
			if i%4 < 2 {
				got := serveOnce(f.handler, siblingRequest(method, badKey))
				assertRefused(t, got, refusedArtifact)
				return
			}
			got := serveOnce(f.handler, siblingRequest(method, goodKey))
			if got.status != http.StatusOK {
				t.Errorf("%s of the allowed entry: status = %d, want 200", method, got.status)
			}
			if method == http.MethodGet && !bytes.Equal(got.body, good) {
				t.Errorf("GET of the allowed entry: body = %q, want %q", got.body, good)
			}
		}(i)
	}
	wg.Wait()

	if snap, want := f.snapshot(), (Snapshot{Served: requests / 2, ServedRefused: requests / 2}); snap != want {
		t.Errorf("metrics = %+v, want %+v", snap, want)
	}
}

// TestMetricsServedRefused covers the counter on its own: it moves only for a
// refusal, it is reported in the snapshot's ServedRefused field and nowhere
// else, and a nil *Metrics stays a valid no-op.
func TestMetricsServedRefused(t *testing.T) {
	m := NewMetrics()
	if got := m.Snapshot(); got != (Snapshot{}) {
		t.Fatalf("fresh metrics = %+v, want zeros", got)
	}

	for i := 0; i < 3; i++ {
		m.recordServedRefused()
	}
	if got, want := m.Snapshot(), (Snapshot{ServedRefused: 3}); got != want {
		t.Errorf("after 3 refusals: %+v, want %+v", got, want)
	}

	m.recordServed()
	m.recordServedMiss()
	m.recordUnauthorized()
	if got, want := m.Snapshot(), (Snapshot{Served: 1, ServedMisses: 1, ServedRefused: 3, Unauthorized: 1}); got != want {
		t.Errorf("after the other server-path counters moved: %+v, want %+v", got, want)
	}

	var none *Metrics
	none.recordServedRefused() // must not panic
	if got := none.Snapshot(); got != (Snapshot{}) {
		t.Errorf("nil metrics snapshot = %+v, want zeros", got)
	}
}
