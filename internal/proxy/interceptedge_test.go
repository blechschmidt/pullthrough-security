package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/downloadlog"
	"github.com/blechschmidt/pullthrough-security/internal/intercept"
)

var natInfo = intercept.Info{Mode: intercept.ModeNAT, Host: "registry.npmjs.org", Origin: "https://registry.npmjs.org", Backend: "npm"}

func TestInterceptRewriter(t *testing.T) {
	cases := []struct {
		name, publicURL, in, want string
		info                      intercept.Info
	}{
		{
			name:      "an absolute link to the public URL",
			publicURL: "https://proxy.example.com",
			in:        `{"tarball":"https://proxy.example.com/v1/npm/a/-/a-1.0.0.tgz"}`,
			want:      `{"tarball":"https://registry.npmjs.org/_pullthrough/v1/npm/a/-/a-1.0.0.tgz"}`,
		},
		{
			name:      "a root-relative link",
			publicURL: "",
			in:        `<a href="/v1/npm/b.tgz">b</a>`,
			want:      `<a href="/_pullthrough/v1/npm/b.tgz">b</a>`,
		},
		{
			name:      "a link to the host the request was addressed to",
			publicURL: "https://proxy.example.com",
			in:        `{"href":"https://registry.npmjs.org/v1/npm/objects/x"}`,
			want:      `{"href":"https://registry.npmjs.org/_pullthrough/v1/npm/objects/x"}`,
		},
		{
			name:      "a public URL with a path",
			publicURL: "https://example.com/proxy/",
			in:        `["https://example.com/proxy/v1/npm/a","/proxy/v1/npm/b"]`,
			want:      `["https://registry.npmjs.org/_pullthrough/v1/npm/a","/_pullthrough/v1/npm/b"]`,
		},
		{
			name:      "an origin with a port",
			publicURL: "http://127.0.0.1:8080",
			in:        `{"u":"http://127.0.0.1:8080/v1/npm/a"}`,
			want:      `{"u":"https://registry.example:8443/_pullthrough/v1/npm/a"}`,
			info:      intercept.Info{Mode: intercept.ModeForward, Host: "registry.example", Origin: "https://registry.example:8443", Backend: "npm"},
		},
		{
			name:      "nothing that is not a link to the mount",
			publicURL: "https://proxy.example.com",
			in: `{"readme":"see https://proxy.example.com/v1/npm/x in prose",` +
				`"dep":"https://attacker.example/x?a=/v1/npm/",` +
				`"other":"https://proxy.example.com/v1/npm-internal/x",` +
				`"prefix":"https://proxy.example.com/v1/npmx",` +
				`"elsewhere":"https://example.org/v1/npm/y"}`,
		},
		{
			name:      "every link of a YAML index",
			publicURL: "https://proxy.example.com",
			in:        "entries:\n  a:\n  - urls:\n    - https://proxy.example.com/v1/npm/charts/a-1.tgz\n    home: /v1/npm/home\n",
			want:      "entries:\n  a:\n  - urls:\n    - https://registry.npmjs.org/_pullthrough/v1/npm/charts/a-1.tgz\n    home: /_pullthrough/v1/npm/home\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := tc.info
			if info.Host == "" {
				info = natInfo
			}
			want := tc.want
			if want == "" {
				want = tc.in
			}
			rw := newInterceptRewriter("npm", tc.publicURL, info.Host, info)
			if got := rw.rewriteAll(tc.in); got != want {
				t.Fatalf("rewriteAll:\n got  %s\n want %s", got, want)
			}
			// Streamed in random chunks the result is the same.
			rng := rand.New(rand.NewSource(int64(len(tc.in))))
			for round := 0; round < 200; round++ {
				rw.reset()
				var out strings.Builder
				rest := tc.in
				for len(rest) > 0 {
					n := 1 + rng.Intn(len(rest))
					out.Write(rw.feed([]byte(rest[:n]), false))
					rest = rest[n:]
				}
				out.Write(rw.feed(nil, true))
				if out.String() != want {
					t.Fatalf("streamed (round %d):\n got  %s\n want %s", round, out.String(), want)
				}
			}
		})
	}
}

// serveInterceptedThroughEdge sends one intercepted request through the
// interception edge to a handler standing in for the backend chain.
func serveInterceptedThroughEdge(t *testing.T, backend string, class backends.ArtifactClass, info *intercept.Info, respond http.HandlerFunc) (*httptest.ResponseRecorder, *Gateway) {
	t.Helper()
	gw, err := New(Dependencies{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Cache: cache.NewMemoryCache(),
		Backends: backends.NewRegistry(),
	}, Options{HTTPAddr: ":0", PublicURL: testPublicURL, LinkBackends: map[string]bool{"npm": true}})
	if err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		notePersonalBackend(r.Context(), backend)
		if class != backends.ArtifactUnclassified {
			notePersonalResolved(r.Context(), &backends.Resolved{Artifact: backends.Artifact{Class: class}})
		}
		respond(w, r)
	})
	req := httptest.NewRequest(http.MethodGet, "https://registry.npmjs.org/v1/"+backend+"/thing", nil)
	if info != nil {
		req = req.WithContext(intercept.WithInfo(req.Context(), *info))
	}
	rr := httptest.NewRecorder()
	gw.withInterceptEdge(next).ServeHTTP(rr, req)
	return rr, gw
}

func TestInterceptWriterDecidesByTheResponse(t *testing.T) {
	const canonical = `{"url":"https://proxy.example.com/v1/npm/a.tgz"}`
	const moved = `{"url":"https://registry.npmjs.org/_pullthrough/v1/npm/a.tgz"}`
	cases := []struct {
		name      string
		class     backends.ArtifactClass
		header    map[string]string
		info      *intercept.Info
		rewritten bool
	}{
		{name: "an index document", class: backends.ArtifactMetadata, header: map[string]string{"Content-Type": "application/json"}, info: &natInfo, rewritten: true},
		{name: "a payload", class: backends.ArtifactPayload, header: map[string]string{"Content-Type": "application/json"}, info: &natInfo},
		{name: "out of the cache", class: backends.ArtifactMetadata, header: map[string]string{"Content-Type": "application/json", "X-Cache": "HIT"}, info: &natInfo},
		{name: "a binary type", class: backends.ArtifactMetadata, header: map[string]string{"Content-Type": "application/gzip"}, info: &natInfo},
		{name: "not intercepted", class: backends.ArtifactMetadata, header: map[string]string{"Content-Type": "application/json"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr, gw := serveInterceptedThroughEdge(t, "npm", tc.class, tc.info, func(w http.ResponseWriter, r *http.Request) {
				for k, v := range tc.header {
					w.Header().Set(k, v)
				}
				w.Header().Set("Location", "https://proxy.example.com/v1/npm/elsewhere")
				w.Header().Set("Content-Length", fmt.Sprint(len(canonical)))
				w.Header().Set("Cache-Control", "public, max-age=300")
				half := len(canonical) / 2
				_, _ = io.WriteString(w, canonical[:half])
				_, _ = io.WriteString(w, canonical[half:])
			})
			want := canonical
			if tc.rewritten {
				want = moved
			}
			if rr.Body.String() != want {
				t.Fatalf("body = %s, want %s", rr.Body, want)
			}
			wantLocation := "https://proxy.example.com/v1/npm/elsewhere"
			if tc.info != nil {
				// A link in a header is a link whatever the body is.
				wantLocation = "https://registry.npmjs.org/_pullthrough/v1/npm/elsewhere"
			}
			if got := rr.Header().Get("Location"); got != wantLocation {
				t.Errorf("Location = %q, want %q", got, wantLocation)
			}
			if tc.rewritten && rr.Header().Get("Content-Length") != "" {
				t.Errorf("a rewritten body announces the original's length")
			}
			// An intercepted response is not made private: it was produced for
			// whoever asks, like any other.
			if got := rr.Header().Get("Cache-Control"); got != "public, max-age=300" {
				t.Errorf("Cache-Control = %q", got)
			}
			m := gw.InterceptLinkMetrics()
			if (tc.info != nil) != (m.Requests == 1) || tc.rewritten != (m.Rewritten == 1) {
				t.Errorf("interception edge metrics = %+v", m)
			}
			if p := gw.PersonalLinkMetrics(); p.Requests != 0 {
				t.Errorf("an intercepted request was counted as a personal one: %+v", p)
			}
		})
	}
}

// interceptedClient is an HTTP client whose connections to any host land on the
// interception listener: through the forward proxy at forward, or — when
// forward is empty — at the NAT listener natTLS (natHTTP for port 80), the way
// a NAT redirect lands them there.
func interceptedClient(t *testing.T, ca *intercept.CA, forward, natTLS, natHTTP string) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("cannot load the interception CA")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}, DisableKeepAlives: true}
	if forward != "" {
		u, _ := url.Parse("http://" + forward)
		tr.Proxy = http.ProxyURL(u)
	} else {
		d := &net.Dialer{Timeout: 5 * time.Second}
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if _, port, _ := net.SplitHostPort(addr); port == "80" {
				return d.DialContext(ctx, network, natHTTP)
			}
			return d.DialContext(ctx, network, natTLS)
		}
	}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

// TestInterceptedInstallsThroughRealAdapters drives the gateway with its real
// npm, PyPI and cargo adapters through the interception listeners — the forward
// proxy and the NAT listeners — the way an intercepted client does: it fetches
// the index from the registry's own host, follows the links in it, and must
// never be sent anywhere else.
func TestInterceptedInstallsThroughRealAdapters(t *testing.T) {
	g := newPersonalGateway(t, personalOptions{})
	dir := t.TempDir()
	ca, err := intercept.LoadOrGenerateCA(intercept.CAOptions{
		CertFile: dir + "/ca.crt", KeyFile: dir + "/ca.key", Generate: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	router := intercept.NewRouter(map[string]string{
		"registry.npmjs.org": "npm",
		"pypi.org":           "pypi",
		"index.crates.io":    "cargo",
	})
	p, err := intercept.New(intercept.Options{Router: router, CA: ca, AllowPlainHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	listen := func() net.Listener {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return ln
	}
	fwd, natTLS, natHTTP := listen(), listen(), listen()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for _, run := range []func() error{
		func() error { return p.Serve(ctx, fwd, g.handler) },
		func() error { return p.ServeNAT(ctx, natTLS, g.handler) },
		func() error { return p.ServeNATHTTP(ctx, natHTTP, g.handler) },
	} {
		wg.Add(1)
		go func(run func() error) { defer wg.Done(); _ = run() }(run)
	}
	t.Cleanup(func() { cancel(); wg.Wait() })

	clients := map[intercept.Mode]*http.Client{
		intercept.ModeForward: interceptedClient(t, ca, fwd.Addr().String(), "", ""),
		intercept.ModeNAT:     interceptedClient(t, ca, "", natTLS.Addr().String(), natHTTP.Addr().String()),
	}
	get := func(c *http.Client, target string, header ...string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, target, nil)
		for i := 0; i+1 < len(header); i += 2 {
			req.Header.Set(header[i], header[i+1])
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", target, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	linkRE := regexp.MustCompile(`https?://[^"'#<> ]+`)

	for _, mode := range []intercept.Mode{intercept.ModeForward, intercept.ModeNAT} {
		c := clients[mode]
		t.Run(string(mode), func(t *testing.T) {
			// npm: the packument's tarball URL leads back to registry.npmjs.org.
			status, packument := get(c, "https://registry.npmjs.org/left-pad")
			if status != http.StatusOK {
				t.Fatalf("packument: %d %s", status, packument)
			}
			tarball := "https://registry.npmjs.org/_pullthrough/v1/npm/left-pad/-/left-pad-1.3.0.tgz"
			if !strings.Contains(packument, `"tarball":"`+tarball+`"`) {
				t.Fatalf("the packument's tarball link was not moved onto the registry's host:\n%s", packument)
			}
			for _, link := range linkRE.FindAllString(packument, -1) {
				if strings.Contains(link, personalHost) {
					t.Errorf("the packument sends the client to the proxy's own address: %s", link)
				}
			}
			// What the client did not get from the proxy stays as it was.
			if !strings.Contains(packument, `"homepage":"https://example.org/v1/npm/left-pad"`) {
				t.Errorf("a homepage that is not a link to the mount was changed:\n%s", packument)
			}
			if status, body := get(c, tarball); status != http.StatusOK || body != npmTarball {
				t.Fatalf("tarball: %d %q", status, body)
			}

			// PyPI, in both of its index formats.
			for _, accept := range []string{"text/html", "application/vnd.pypi.simple.v1+json"} {
				status, page := get(c, "https://pypi.org/simple/requests/", "Accept", accept)
				if status != http.StatusOK {
					t.Fatalf("simple page (%s): %d", accept, status)
				}
				m := regexp.MustCompile(`https://pypi\.org/_pullthrough/v1/pypi/[^"#]+\.whl`).FindString(page)
				if m == "" {
					t.Fatalf("the simple page (%s) has no wheel link on pypi.org:\n%s", accept, page)
				}
				if status, body := get(c, m); status != http.StatusOK || body != wheelBody {
					t.Fatalf("wheel %s: %d %q", m, status, body)
				}
			}

			// cargo: config.json's dl leads back to the index host, over plain
			// HTTP as well as HTTPS.
			for _, scheme := range []string{"https", "http"} {
				status, cfgDoc := get(c, scheme+"://index.crates.io/config.json")
				if status != http.StatusOK || !strings.Contains(cfgDoc, scheme+"://index.crates.io/_pullthrough/v1/cargo") {
					t.Fatalf("config.json over %s: %d %s", scheme, status, cfgDoc)
				}
			}

			// A host the proxy does not intercept is not served.
			if _, err := c.Get("https://registry.yarnpkg.com/left-pad"); err == nil {
				t.Error("a host without a rule was served")
			}
		})
	}

	// The download log knows how each download got here.
	vias := map[string]int{}
	for _, e := range g.entries() {
		if e.Outcome == downloadlog.OutcomeServed {
			vias[e.Via]++
		}
	}
	if vias[downloadlog.ViaIntercept] == 0 || vias[downloadlog.ViaNAT] == 0 || vias[""] != 0 {
		t.Errorf("served downloads by via = %v, want intercept and nat only", vias)
	}
	// So does the request log.
	if !strings.Contains(g.logs.String(), "via=nat host=registry.npmjs.org") ||
		!strings.Contains(g.logs.String(), "via=intercept host=pypi.org") {
		t.Errorf("the request log does not say how requests got here:\n%s", tail(g.logs.String(), 2000))
	}
	if m := g.gw.InterceptLinkMetrics(); m.Rewritten == 0 || m.Links == 0 {
		t.Errorf("interception edge metrics = %+v", m)
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
