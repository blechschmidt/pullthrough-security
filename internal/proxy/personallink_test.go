package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
	"github.com/blechschmidt/pullthrough-security/internal/backends/pkgmgr"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/downloadlog"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
	"github.com/blechschmidt/pullthrough-security/internal/userlinks"
)

// --- the rewriter -----------------------------------------------------------

const (
	testPublicURL = "https://proxy.example.com"
	testPrefix    = "/u/ptl1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func rewriteOnce(mount, publicURL, host, in string) string {
	return newLinkRewriter(mount, testPrefix, publicURL, host).rewriteAll(in)
}

// rewriteMarkup rewrites an HTML or XML document.
func rewriteMarkup(mount, publicURL, host, in string) string {
	rw := newLinkRewriter(mount, testPrefix, publicURL, host)
	rw.markup = true
	return rw.rewriteAll(in)
}

func TestLinkRewriter(t *testing.T) {
	const P = testPrefix
	cases := []struct {
		name      string
		mount     string
		publicURL string
		host      string
		markup    bool // an HTML or XML body
		in, want  string
	}{
		{
			name: "the public URL", mount: "/v1/npm", publicURL: testPublicURL,
			in:   `{"dist":{"tarball":"https://proxy.example.com/v1/npm/lodash/-/lodash-4.17.21.tgz"}}`,
			want: `{"dist":{"tarball":"https://proxy.example.com` + P + `/v1/npm/lodash/-/lodash-4.17.21.tgz"}}`,
		},
		{
			name: "every occurrence", mount: "/v1/pypi", publicURL: testPublicURL, markup: true,
			in: `<a href="https://proxy.example.com/v1/pypi/files/https/files.pythonhosted.org/a.whl">a</a>` +
				`<a href='https://proxy.example.com/v1/pypi/files/https/files.pythonhosted.org/b.whl'>b</a>`,
			want: `<a href="https://proxy.example.com` + P + `/v1/pypi/files/https/files.pythonhosted.org/a.whl">a</a>` +
				`<a href='https://proxy.example.com` + P + `/v1/pypi/files/https/files.pythonhosted.org/b.whl'>b</a>`,
		},
		{
			name: "the mount itself, without a trailing slash", mount: "/v1/cargo", publicURL: testPublicURL,
			in:   `{"api":"https://proxy.example.com/v1/cargo","dl":"https://proxy.example.com/v1/cargo/api/v1/crates"}`,
			want: `{"api":"https://proxy.example.com` + P + `/v1/cargo","dl":"https://proxy.example.com` + P + `/v1/cargo/api/v1/crates"}`,
		},
		{
			name: "a root-relative link", mount: "/v1/terraform", publicURL: testPublicURL,
			in:   `{"modules.v1":"/v1/terraform/v1/modules/","providers.v1":"/v1/terraform/v1/providers/"}`,
			want: `{"modules.v1":"` + P + `/v1/terraform/v1/modules/","providers.v1":"` + P + `/v1/terraform/v1/providers/"}`,
		},
		{
			name: "root-relative, where a value starts", mount: "/v1/x", publicURL: "", markup: true,
			in:   `<a href="/v1/x/a" src = '/v1/x/b'> "url":"/v1/x/c"`,
			want: `<a href="` + P + `/v1/x/a" src = '` + P + `/v1/x/b'> "url":"` + P + `/v1/x/c"`,
		},
		{
			// An attribute written without quotes looks like a query parameter.
			// Neither is taken for a value start.
			name: "after an equals sign is not where a value starts", mount: "/v1/x", publicURL: testPublicURL, markup: true,
			in:   `<a href=/v1/x/a> <a href=https://proxy.example.com/v1/x/b>`,
			want: `<a href=/v1/x/a> <a href=https://proxy.example.com/v1/x/b>`,
		},
		{
			name: "a single quote opens no value in JSON", mount: "/v1/x", publicURL: testPublicURL,
			in:   `{"a":"'/v1/x/a","b":"x='https://proxy.example.com/v1/x/b"}`,
			want: `{"a":"'/v1/x/a","b":"x='https://proxy.example.com/v1/x/b"}`,
		},
		{
			// What a package's author writes into a document the proxy serves:
			// a URL dependency, a homepage. The link to the mount in it would
			// carry the user's link to another host (npm fetches URL
			// dependencies by itself).
			name: "a mount path inside someone else's URL", mount: "/v1/npm", publicURL: testPublicURL,
			in: `{"dependencies":{"helper":"https://attacker.example/h.tgz?a=/v1/npmjs/&b=/v1/npm/"},` +
				`"homepage":"https://attacker.example/c?x=/v1/npm/","bugs":{"url":"https://attacker.example/?u=https://proxy.example.com/v1/npm/"},` +
				`"repository":"https://attacker.example/https://proxy.example.com/v1/npm/x","readme":"#\"/v1/npm/ and \"https://proxy.example.com/v1/npm/y"}`,
			want: `{"dependencies":{"helper":"https://attacker.example/h.tgz?a=/v1/npmjs/&b=/v1/npm/"},` +
				`"homepage":"https://attacker.example/c?x=/v1/npm/","bugs":{"url":"https://attacker.example/?u=https://proxy.example.com/v1/npm/"},` +
				`"repository":"https://attacker.example/https://proxy.example.com/v1/npm/x","readme":"#\"/v1/npm/ and \"https://proxy.example.com/v1/npm/y"}`,
		},
		{
			name: "a quote after an escaped backslash opens a value", mount: "/v1/npm", publicURL: testPublicURL,
			in:   `["a\\","https://proxy.example.com/v1/npm/x"]`,
			want: `["a\\","https://proxy.example.com` + P + `/v1/npm/x"]`,
		},
		{
			// A Nix narinfo: "Field: value" lines. A field's value starts after
			// its name; "x: " inside a value does not start one.
			name: "a field at the start of a line", mount: "/v1/nix", publicURL: testPublicURL,
			in: "StorePath: /nix/store/abc-hello\nURL: https://proxy.example.com/v1/nix/nar/1abc.nar.xz\nCompression: xz\n" +
				"Description: see: https://proxy.example.com/v1/nix/x and https://attacker.example/?u=: https://proxy.example.com/v1/nix/y\n" +
				"  home: https://proxy.example.com/v1/nix/z\nkey : https://proxy.example.com/v1/nix/w\n",
			want: "StorePath: /nix/store/abc-hello\nURL: https://proxy.example.com" + P + "/v1/nix/nar/1abc.nar.xz\nCompression: xz\n" +
				"Description: see: https://proxy.example.com/v1/nix/x and https://attacker.example/?u=: https://proxy.example.com/v1/nix/y\n" +
				"  home: https://proxy.example.com" + P + "/v1/nix/z\nkey : https://proxy.example.com/v1/nix/w\n",
		},
		{
			// Helm's index.yaml: the archive URLs are sequence entries. Text
			// elsewhere in a value is left alone.
			name: "a YAML sequence entry", mount: "/v1/helm", publicURL: testPublicURL,
			in: "entries:\n  podinfo:\n  - home: https://attacker.example/?u=https://proxy.example.com/v1/helm/\n" +
				"    description: x - https://proxy.example.com/v1/helm/a.tgz\n    urls:\n    - https://proxy.example.com/v1/helm/podinfo-6.7.1.tgz\n" +
				"    - \"https://proxy.example.com/v1/helm/b.tgz\"\n",
			want: "entries:\n  podinfo:\n  - home: https://attacker.example/?u=https://proxy.example.com/v1/helm/\n" +
				"    description: x - https://proxy.example.com/v1/helm/a.tgz\n    urls:\n    - https://proxy.example.com" + P + "/v1/helm/podinfo-6.7.1.tgz\n" +
				"    - \"https://proxy.example.com" + P + "/v1/helm/b.tgz\"\n",
		},
		{
			name: "a path in prose is not a link", mount: "/v1/x", publicURL: "",
			in:   "see /v1/x/a, (/v1/x/b) [/v1/x/c] </v1/x/d>\n/v1/x/e\turl: /v1/x/f and x/v1/x/g",
			want: "see /v1/x/a, (/v1/x/b) [/v1/x/c] </v1/x/d>\n/v1/x/e\turl: /v1/x/f and x/v1/x/g",
		},
		{
			name: "the request's own host (how the Git LFS adapter names the proxy)", mount: "/v1/git", publicURL: testPublicURL, host: "internal-lb:8443",
			in:   `{"objects":[{"actions":{"download":{"href":"http://internal-lb:8443/v1/git/o/r/info/lfs/objects/abc?size=3"}}},{"actions":{"download":{"href":"https://internal-lb:8443/v1/git/x"}}}]}`,
			want: `{"objects":[{"actions":{"download":{"href":"http://internal-lb:8443` + P + `/v1/git/o/r/info/lfs/objects/abc?size=3"}}},{"actions":{"download":{"href":"https://internal-lb:8443` + P + `/v1/git/x"}}}]}`,
		},
		{
			name: "a public URL with a path", mount: "/v1/npm", publicURL: "https://example.com/proxy/",
			in:   `"https://example.com/proxy/v1/npm/a" "/proxy/v1/npm/b" "/v1/npm/c" "https://example.com/v1/npm/d" "https://example.com/other/v1/npm/e"`,
			want: `"https://example.com/proxy` + P + `/v1/npm/a" "/proxy` + P + `/v1/npm/b" "/v1/npm/c" "https://example.com/v1/npm/d" "https://example.com/other/v1/npm/e"`,
		},
		{
			name: "another mount whose name starts the same way", mount: "/v1/npm", publicURL: testPublicURL,
			in:   `"https://proxy.example.com/v1/npm-internal/a" "https://proxy.example.com/v1/npmjs/b" "https://proxy.example.com/v1/npm.x/c" "https://proxy.example.com/v1/npm/d"`,
			want: `"https://proxy.example.com/v1/npm-internal/a" "https://proxy.example.com/v1/npmjs/b" "https://proxy.example.com/v1/npm.x/c" "https://proxy.example.com` + P + `/v1/npm/d"`,
		},
		{
			name: "someone else's URL with the same path", mount: "/v1/npm", publicURL: testPublicURL,
			in:   `"homepage":"https://example.org/v1/npm/","repo":"http://proxy.example.com.evil.example/v1/npm/x","docs":"see api/v1/npm/ and x/v1/npm/y","cdn":"//cdn.example/v1/npm/z"`,
			want: `"homepage":"https://example.org/v1/npm/","repo":"http://proxy.example.com.evil.example/v1/npm/x","docs":"see api/v1/npm/ and x/v1/npm/y","cdn":"//cdn.example/v1/npm/z"`,
		},
		{
			name: "another scheme or port of the public host is not the proxy", mount: "/v1/npm", publicURL: testPublicURL,
			in:   `"http://proxy.example.com/v1/npm/a" "https://proxy.example.com:8443/v1/npm/b" "ftp://proxy.example.com/v1/npm/c"`,
			want: `"http://proxy.example.com/v1/npm/a" "https://proxy.example.com:8443/v1/npm/b" "ftp://proxy.example.com/v1/npm/c"`,
		},
		{
			name: "a link that is personal already", mount: "/v1/npm", publicURL: testPublicURL,
			in:   `"https://proxy.example.com` + P + `/v1/npm/a" "` + P + `/v1/npm/b"`,
			want: `"https://proxy.example.com` + P + `/v1/npm/a" "` + P + `/v1/npm/b"`,
		},
		{
			name: "another user's personal link is not touched either", mount: "/v1/npm", publicURL: testPublicURL,
			in:   `"https://proxy.example.com/u/ptl1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/v1/npm/a"`,
			want: `"https://proxy.example.com/u/ptl1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/v1/npm/a"`,
		},
		{
			name: "the mount at the very end", mount: "/v1/npm", publicURL: testPublicURL,
			in:   `https://proxy.example.com/v1/npm`,
			want: `https://proxy.example.com` + P + `/v1/npm`,
		},
		{
			name: "the whole text is a root-relative link (a Location header)", mount: "/v1/ansible", publicURL: testPublicURL,
			in:   `/v1/ansible/api/v3/collections/?page=2`,
			want: P + `/v1/ansible/api/v3/collections/?page=2`,
		},
		{
			name: "a mount named like the route prefix", mount: "/v1/v1", publicURL: testPublicURL,
			in:   `"https://proxy.example.com/v1/v1/v1/v1/x" "/v1/v1"`,
			want: `"https://proxy.example.com` + P + `/v1/v1/v1/v1/x" "` + P + `/v1/v1"`,
		},
		{
			name: "escaped slashes are another spelling, and left alone", mount: "/v1/npm", publicURL: testPublicURL,
			in:   `"https:\/\/proxy.example.com\/v1\/npm\/a"`,
			want: `"https:\/\/proxy.example.com\/v1\/npm\/a"`,
		},
		{name: "nothing to do", mount: "/v1/npm", publicURL: testPublicURL, in: "plain text, no links", want: "plain text, no links"},
		{name: "empty", mount: "/v1/npm", publicURL: testPublicURL, in: "", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rewrite := rewriteOnce
			if tc.markup {
				rewrite = rewriteMarkup
			}
			if got := rewrite(tc.mount, tc.publicURL, tc.host, tc.in); got != tc.want {
				t.Fatalf("rewritten\n %s\nwant\n %s", got, tc.want)
			}
			// However the text is cut into chunks, the result is the same.
			for size := 1; size <= len(tc.in)+1 && size <= 64; size++ {
				rw := newLinkRewriter(tc.mount, testPrefix, tc.publicURL, tc.host)
				rw.markup = tc.markup
				var out []byte
				for i := 0; i < len(tc.in); i += size {
					out = append(out, rw.feed([]byte(tc.in[i:min(i+size, len(tc.in))]), false)...)
				}
				out = append(out, rw.feed(nil, true)...)
				if string(out) != tc.want {
					t.Fatalf("in chunks of %d:\n %s\nwant\n %s", size, out, tc.want)
				}
			}
		})
	}
}

func TestLinkRewriterRandomChunks(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	doc := strings.Repeat(`{"v":"1.0.0","dist":{"tarball":"https://proxy.example.com/v1/npm/pkg/-/pkg-1.0.0.tgz"},"readme":"see /v1/npm and https://example.org/v1/npm/x"},`, 200)
	want := rewriteOnce("/v1/npm", testPublicURL, "", doc)
	if strings.Count(want, testPrefix) != 200 {
		t.Fatalf("%d links were rewritten, want 200", strings.Count(want, testPrefix))
	}
	for round := 0; round < 50; round++ {
		rw := newLinkRewriter("/v1/npm", testPrefix, testPublicURL, "")
		var out bytes.Buffer
		for rest := []byte(doc); len(rest) > 0; {
			n := 1 + rng.Intn(97)
			if n > len(rest) {
				n = len(rest)
			}
			out.Write(rw.feed(rest[:n], false))
			rest = rest[n:]
		}
		out.Write(rw.feed(nil, true))
		if out.String() != want {
			t.Fatalf("round %d: random chunking changed the result", round)
		}
		if rw.count != 200 {
			t.Fatalf("round %d: counted %d links, want 200", round, rw.count)
		}
	}
}

func TestRedactPersonalPath(t *testing.T) {
	const tok = "ptl1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for in, want := range map[string]string{
		"/u/" + tok + "/v1/npm/lodash":                    "/u/<link>/v1/npm/lodash",
		"/u/" + tok:                                       "/u/<link>/",
		"/u/" + tok + "/":                                 "/u/<link>/",
		"/u/not-even-a-token/v1/npm/x":                    "/u/<link>/v1/npm/x",
		"/v2/u/" + tok + "/dockerhub/alpine/manifests/1":  "/v2/u/<link>/dockerhub/alpine/manifests/1",
		"/v1/npm/lodash":                                  "/v1/npm/lodash",
		"/v2/u/ptl1cutshort/dockerhub/alpine/manifests/1": "/v2/u/<link>/dockerhub/alpine/manifests/1",
		"/v2/u/library/alpine/manifests/1":                "/v2/u/library/alpine/manifests/1", // a namespace called "u"
		// Not a personal path — but a link pasted anywhere is still a link.
		"/v1/npm/u/" + tok + "/x":                       "/v1/npm/u/<link>/x",
		"/u/" + tok + "/v2/u/" + tok + "/a/manifests/1": "/u/<link>/v2/u/<link>/a/manifests/1",
		"/u":      "/u",
		"/user/x": "/user/x",
		"":        "",
	} {
		if got := redactPersonalPath(in, "/u"); got != want {
			t.Errorf("redactPersonalPath(%q) = %q, want %q", in, got, want)
		}
		if strings.Contains(redactPersonalPath(in, "/u"), tok) {
			t.Errorf("the token survived redaction of %q", in)
		}
	}
	if got := redactPersonalPath("/u/"+tok+"/v1/x", ""); got != "/u/"+tok+"/v1/x" {
		t.Errorf("with the feature off, paths are left alone: %q", got)
	}
}

func TestMakePrivate(t *testing.T) {
	for in, want := range map[string]string{
		"":                                 "private",
		"public, max-age=300":              "private, max-age=300",
		"max-age=60, s-maxage=600, public": "private, max-age=60",
		"private":                          "private",
		"no-store":                         "private, no-store",
		"PUBLIC , Max-Age=5":               "private, Max-Age=5",
	} {
		h := http.Header{}
		if in != "" {
			h.Set("Cache-Control", in)
		}
		makePrivate(h)
		if got := h.Get("Cache-Control"); got != want {
			t.Errorf("makePrivate(%q) = %q, want %q", in, got, want)
		}
	}
	h := http.Header{"Cache-Control": {"public", "max-age=10"}}
	makePrivate(h)
	if got := h.Values("Cache-Control"); len(got) != 1 || got[0] != "private, max-age=10" {
		t.Errorf("several header lines = %q", got)
	}
}

// --- the edge, with real protocol adapters ------------------------------------

const (
	npmTarball   = "NPM-TARBALL-left-pad-1.3.0"
	wheelBody    = "WHEEL-BYTES-requests-2.32.3"
	personalHost = "proxy.test"
)

// personalStub plays an npm registry, a PyPI index with its file host, a
// crates.io and a GOPROXY. It records every request it receives, with headers:
// the tests hold it to never seeing a link's token.
type personalStub struct {
	*httptest.Server
	mu   sync.Mutex
	seen []string
}

func newPersonalStub(t *testing.T) *personalStub {
	t.Helper()
	s := &personalStub{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var hdr strings.Builder
		_ = r.Header.Write(&hdr)
		s.mu.Lock()
		s.seen = append(s.seen, r.Method+" "+r.URL.RequestURI()+"\n"+hdr.String())
		s.mu.Unlock()
		base := "http://" + r.Host
		switch r.URL.Path {
		case "/left-pad":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "public, max-age=300")
			w.Header().Set("ETag", `"packument-1"`)
			// The README mentions the proxy's public mount in prose and someone
			// else's URL with the same path; neither is a link the adapter wrote.
			fmt.Fprintf(w, `{"name":"left-pad","versions":{"1.3.0":{"name":"left-pad","version":"1.3.0","dist":{"tarball":"%s/left-pad/-/left-pad-1.3.0.tgz","shasum":"abc"}},"1.2.0":{"dist":{"tarball":"%s/left-pad/-/left-pad-1.2.0.tgz"}}},"homepage":"https://example.org/v1/npm/left-pad","readme":"mirror at api/v1/npm/ too"}`, base, base)
		case "/left-pad/-/left-pad-1.3.0.tgz":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = io.WriteString(w, npmTarball)
		case "/docs-pkg/-/docs-pkg-1.0.0.tgz":
			// A payload that is text and names the proxy's own mount. It is what
			// the client verifies against a checksum: not one byte may change.
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "set registry=http://"+personalHost+"/v1/npm/ in your .npmrc\n")
		case "/simple/requests/":
			if strings.Contains(r.Header.Get("Accept"), "application/vnd.pypi.simple.v1+json") {
				w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
				fmt.Fprintf(w, `{"name":"requests","files":[{"filename":"requests-2.32.3-py3-none-any.whl","url":"%s/packages/requests-2.32.3-py3-none-any.whl","hashes":{"sha256":"00"}}]}`, base)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<!DOCTYPE html><html><body><a href="%s/packages/requests-2.32.3-py3-none-any.whl#sha256=00">requests-2.32.3-py3-none-any.whl</a></body></html>`, base)
		case "/packages/requests-2.32.3-py3-none-any.whl":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = io.WriteString(w, wheelBody)
		case "/config.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"dl":"https://static.crates.io/crates","api":"https://crates.io"}`)
		case "/api/v1/crates/cfg-if/1.0.0/download":
			w.Header().Set("Content-Type", "application/gzip")
			_, _ = io.WriteString(w, crateBody)
		case "/rsc.io/quote/@v/v1.5.2.zip":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = io.WriteString(w, moduleBody)
		case "/rsc.io/quote/@v/list":
			_, _ = io.WriteString(w, "v1.5.2\n")
		case "/dists/stable/Release":
			// A byte-exact, signed index of an ecosystem whose adapter writes no
			// links — which happens to contain the proxy's address.
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "Origin: http://"+personalHost+"/v1/apt/\nSHA256:\n 00 12 main/binary-amd64/Packages\n")
		case "/v2/library/alpine/manifests/3.19":
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_, _ = io.WriteString(w, `{"schemaVersion":2}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *personalStub) requests() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.seen, "\n")
}

// memoryAudit reads the audit events a gateway wrote.
type memoryAudit struct{ sink *audit.MemorySink }

func (m *memoryAudit) all() []audit.Event {
	records := m.sink.Records()
	out := make([]audit.Event, len(records))
	for i, rec := range records {
		out[i] = rec.Event
	}
	return out
}

// personalGateway is a gateway with personal links enabled in front of the stub.
type personalGateway struct {
	t       *testing.T
	gw      *Gateway
	handler http.Handler
	links   *userlinks.Service
	log     *downloadlog.Log
	stub    *personalStub
	audit   *memoryAudit
	logs    *bytes.Buffer
}

type personalOptions struct {
	enforcer  *auth.Enforcer
	publicURL *string
	registry  *RegistryRoot
}

func newPersonalGateway(t *testing.T, o personalOptions) *personalGateway {
	t.Helper()
	stub := newPersonalStub(t)
	client := upstream.NewWithHTTPClient(http.DefaultClient, "test/1")
	publicURL := "http://" + personalHost
	if o.publicURL != nil {
		publicURL = *o.publicURL
	}

	registry := backends.NewRegistry()
	mount := func(name string) string { return pkgmgr.PublicBase(publicURL, name) }
	stubHost := strings.TrimPrefix(stub.URL, "http://")
	npm, err := pkgmgr.NewNPM(pkgmgr.Options{Name: "npm", UpstreamURL: stub.URL, Client: client, PublicBaseURL: mount("npm")})
	if err != nil {
		t.Fatal(err)
	}
	pypi, err := pkgmgr.NewPyPI(pkgmgr.Options{Name: "pypi", UpstreamURL: stub.URL, Client: client, PublicBaseURL: mount("pypi"),
		Settings: map[string]string{"filesUrl": stub.URL, "fileHosts": stubHost}})
	if err != nil {
		t.Fatal(err)
	}
	cargo, err := pkgmgr.NewCargo(pkgmgr.Options{Name: "cargo", UpstreamURL: stub.URL, Client: client, PublicBaseURL: mount("cargo"),
		Settings: map[string]string{"downloadUrl": stub.URL}})
	if err != nil {
		t.Fatal(err)
	}
	goproxy, err := pkgmgr.NewGoProxy(pkgmgr.Options{Name: "go", UpstreamURL: stub.URL, Client: client, Settings: map[string]string{"sumdb": "off"}})
	if err != nil {
		t.Fatal(err)
	}
	// Two pass-through backends: one standing in for an ecosystem whose adapter
	// writes no links (APT), one for a container registry.
	apt, err := httpbackend.New(httpbackend.Options{Name: "apt", BaseURL: stub.URL, Client: client,
		Cacheable: func(*backends.Request) bool { return false },
		Classify:  func(*backends.Request) backends.Artifact { return backends.Metadata() }})
	if err != nil {
		t.Fatal(err)
	}
	dockerhub, err := httpbackend.New(httpbackend.Options{Name: "dockerhub", BaseURL: stub.URL, Client: client})
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range []backends.Backend{npm, pypi, cargo, goproxy, apt, dockerhub} {
		if err := registry.Register(b); err != nil {
			t.Fatal(err)
		}
	}

	links, err := userlinks.New(userlinks.Config{PublicURL: publicURL, Store: userlinks.NewMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	log, err := downloadlog.New(downloadlog.Config{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	sink := &memoryAudit{sink: audit.NewMemorySink()}
	auditLog, err := audit.NewLogger(context.Background(), audit.Options{Key: []byte("test-key"), Sink: sink.sink})
	if err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	deps := Dependencies{
		Logger:      slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Cache:       cache.NewMemoryCache(),
		Backends:    registry,
		Ecosystems:  map[string]string{"npm": "npm", "pypi": "pip", "cargo": "cargo", "go": "go", "apt": "apt", "dockerhub": "docker"},
		DownloadLog: log,
		UserLinks:   links,
		Audit:       auditLog,
		Enforcer:    o.enforcer,
	}
	gw, err := New(deps, Options{
		HTTPAddr:     ":0",
		PublicURL:    publicURL,
		LinkBackends: map[string]bool{"npm": true, "pypi": true, "cargo": true},
		RegistryRoot: o.registry,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &personalGateway{t: t, gw: gw, handler: gw.Handler(), links: links, log: log, stub: stub, audit: sink, logs: logs}
}

// issue creates a link for a user and returns its token and identifier.
func (g *personalGateway) issue(subject, team string, roles ...string) (string, string) {
	g.t.Helper()
	token, _, info, err := g.links.Issue(context.Background(),
		userlinks.Identity{Subject: subject, Team: team, Roles: roles}, userlinks.IssueOptions{Label: "test"})
	if err != nil {
		g.t.Fatal(err)
	}
	return token, info.ID
}

func (g *personalGateway) do(method, path string, header ...string) *httptest.ResponseRecorder {
	g.t.Helper()
	req := httptest.NewRequest(method, "http://"+personalHost+path, nil)
	req.RemoteAddr = "10.20.1.15:40000"
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	rr := httptest.NewRecorder()
	g.handler.ServeHTTP(rr, req)
	return rr
}

func (g *personalGateway) entries() []downloadlog.Entry {
	g.t.Helper()
	res, err := g.log.Query(downloadlog.Query{Limit: -1})
	if err != nil {
		g.t.Fatal(err)
	}
	return res.Entries
}

// assertNoToken fails when the token appears in anything the proxy wrote down
// or sent on: its own log, the audit trail, the download log, the requests the
// upstream received.
func (g *personalGateway) assertNoToken(token string) {
	g.t.Helper()
	if strings.Contains(g.logs.String(), token) {
		g.t.Errorf("the proxy's log contains the link's token:\n%s", firstLineWith(g.logs.String(), token))
	}
	if data, _ := json.Marshal(g.audit.all()); strings.Contains(string(data), token) {
		g.t.Errorf("the audit trail contains the link's token: %s", firstLineWith(string(data), token))
	}
	if data, _ := json.Marshal(g.entries()); strings.Contains(string(data), token) {
		g.t.Errorf("the download log contains the link's token: %s", firstLineWith(string(data), token))
	}
	if strings.Contains(g.stub.requests(), token) {
		g.t.Errorf("the upstream received the link's token:\n%s", firstLineWith(g.stub.requests(), token))
	}
}

func firstLineWith(s, needle string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, needle) {
			if len(line) > 400 {
				line = line[:400] + "…"
			}
			return line
		}
	}
	return ""
}

// The whole point, with npm: a client configured with a personal registry URL
// is told to fetch the tarball from its personal URL, does so, and the download
// is recorded under the user's name — while nothing behind the edge, and
// nothing upstream, ever sees the token.
func TestPersonalLinkAttributesAnNpmInstall(t *testing.T) {
	g := newPersonalGateway(t, personalOptions{})
	token, linkID := g.issue("alice@example.com", "platform")
	personal := "/u/" + token

	// The packument, through the personal registry URL.
	rr := g.do("GET", personal+"/v1/npm/left-pad", "User-Agent", "npm/10.9.2 node/v22.11.0")
	if rr.Code != http.StatusOK {
		t.Fatalf("packument: %d %s", rr.Code, rr.Body)
	}
	var doc struct {
		Versions map[string]struct {
			Dist struct{ Tarball string } `json:"dist"`
		} `json:"versions"`
		Homepage string `json:"homepage"`
		Readme   string `json:"readme"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatalf("the rewritten packument is not valid JSON: %v\n%s", err, rr.Body)
	}
	tarball := doc.Versions["1.3.0"].Dist.Tarball
	if want := "http://" + personalHost + personal + "/v1/npm/left-pad/-/left-pad-1.3.0.tgz"; tarball != want {
		t.Fatalf("tarball URL = %q\nwant        %q", tarball, want)
	}
	if got := doc.Versions["1.2.0"].Dist.Tarball; !strings.Contains(got, personal+"/v1/npm/") {
		t.Fatalf("the second version's tarball URL was not rewritten: %q", got)
	}
	// What only looks like a link to the mount is left as it is.
	if doc.Homepage != "https://example.org/v1/npm/left-pad" || doc.Readme != "mirror at api/v1/npm/ too" {
		t.Fatalf("text that is not a link to the mount was rewritten: %q / %q", doc.Homepage, doc.Readme)
	}
	// The response was produced for one user, and has no promised length: its
	// length changed.
	if cc := rr.Header().Get("Cache-Control"); cc != "private, max-age=300" {
		t.Errorf("Cache-Control = %q, want the upstream's lifetime, made private", cc)
	}
	if rr.Header().Get("Content-Length") != "" {
		t.Errorf("a rewritten document announces a Content-Length: %q", rr.Header().Get("Content-Length"))
	}
	if rr.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("Referrer-Policy = %q", rr.Header().Get("Referrer-Policy"))
	}
	if got := rr.Header().Get("ETag"); got != `"packument-1"` {
		t.Errorf("ETag = %q: the validator must stay the upstream's, so revalidation keeps working", got)
	}

	// The tarball, from the URL the packument named.
	path := strings.TrimPrefix(tarball, "http://"+personalHost)
	rr = g.do("GET", path, "User-Agent", "npm/10.9.2 node/v22.11.0")
	if rr.Code != http.StatusOK || rr.Body.String() != npmTarball {
		t.Fatalf("tarball: %d %q", rr.Code, rr.Body)
	}
	if rr.Header().Get("Content-Length") != fmt.Sprint(len(npmTarball)) {
		t.Errorf("the artifact's Content-Length = %q", rr.Header().Get("Content-Length"))
	}

	entries := g.entries()
	if len(entries) != 1 {
		t.Fatalf("the download log holds %d entries, want the one tarball: %+v", len(entries), entries)
	}
	e := entries[0]
	if e.Subject != "alice@example.com" || e.Tenant != "platform" || e.AuthMethod != userlinks.MethodPersonalLink || e.Link != linkID {
		t.Fatalf("the download is not attributed to the user: %+v", e)
	}
	if e.Package != "left-pad" || e.Version != "1.3.0" || e.Outcome != downloadlog.OutcomeServed || e.ClientIP != "10.20.1.15" {
		t.Fatalf("entry = %+v", e)
	}
	// The path is the resource's, not the client's personal address of it.
	if e.Path != "/v1/npm/left-pad/-/left-pad-1.3.0.tgz" {
		t.Fatalf("entry path = %q", e.Path)
	}

	// The link's owner can see that, and from where, it was used.
	info, _ := g.links.Registry().Get(linkID)
	if info.LastUsedAt == nil || info.LastAddr != "10.20.1.15" || info.LastAgent != "npm/10.9.2 node/v22.11.0" {
		t.Fatalf("the link's usage = %+v", info)
	}

	// The audit record of the pull names user and link.
	var pull *audit.Event
	for _, ev := range g.audit.all() {
		if ev.Type == audit.EventPull && strings.HasSuffix(ev.Resource, ".tgz") {
			ev := ev
			pull = &ev
		}
	}
	if pull == nil || pull.Subject != "alice@example.com" || pull.Detail["authMethod"] != userlinks.MethodPersonalLink ||
		pull.Detail["link"] != linkID || pull.Resource != "/v1/npm/left-pad/-/left-pad-1.3.0.tgz" {
		t.Fatalf("audit record of the pull = %+v", pull)
	}

	g.assertNoToken(token)
	if !strings.Contains(g.logs.String(), "path=/u/<link>/v1/npm/left-pad") {
		t.Errorf("the request log does not show the redacted personal path:\n%s", g.logs.String())
	}

	// The same documents without a link: the mount's own links, nobody's name.
	rr = g.do("GET", "/v1/npm/left-pad")
	if strings.Contains(rr.Body.String(), "/u/") || !strings.Contains(rr.Body.String(), `"http://`+personalHost+`/v1/npm/left-pad/-/left-pad-1.3.0.tgz"`) {
		t.Fatalf("a request without a link was answered with personal links:\n%s", rr.Body)
	}
	if rr.Header().Get("Cache-Control") != "public, max-age=300" {
		t.Errorf("a request without a link had its Cache-Control changed: %q", rr.Header().Get("Cache-Control"))
	}
	rr = g.do("GET", "/v1/npm/left-pad/-/left-pad-1.3.0.tgz")
	if rr.Code != http.StatusOK || rr.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("the anonymous tarball request: %d, X-Cache %q", rr.Code, rr.Header().Get("X-Cache"))
	}
	if e := g.entries()[0]; e.Subject != "" || e.Link != "" || e.AuthMethod != "disabled" && e.AuthMethod != "" {
		t.Fatalf("the anonymous download carries an identity: %+v", e)
	}

	// Another user gets their own prefix on the same document, and their own
	// name on the same artifact.
	bobToken, bobLink := g.issue("bob@example.com", "payments")
	rr = g.do("GET", "/u/"+bobToken+"/v1/npm/left-pad")
	if !strings.Contains(rr.Body.String(), "/u/"+bobToken+"/v1/npm/left-pad/-/") || strings.Contains(rr.Body.String(), token) {
		t.Fatalf("the second user's packument:\n%s", rr.Body)
	}
	rr = g.do("GET", "/u/"+bobToken+"/v1/npm/left-pad/-/left-pad-1.3.0.tgz")
	if rr.Code != http.StatusOK || rr.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("the second user's tarball: %d, X-Cache %q", rr.Code, rr.Header().Get("X-Cache"))
	}
	if e := g.entries()[0]; e.Subject != "bob@example.com" || e.Link != bobLink {
		t.Fatalf("the second user's download = %+v", e)
	}
	g.assertNoToken(bobToken)

	m := g.gw.PersonalLinkMetrics()
	if m.Requests != 4 || m.Rewritten != 2 || m.Links != 4 {
		t.Fatalf("edge metrics = %+v, want 4 personal responses, 2 documents and 4 links rewritten", m)
	}
}

// pip: an HTML index and its JSON form, both with links to the proxy's file
// route, and the wheel behind them.
func TestPersonalLinkAttributesAPipInstall(t *testing.T) {
	g := newPersonalGateway(t, personalOptions{})
	token, linkID := g.issue("alice@example.com", "platform")
	personal := "/u/" + token
	stubHost := strings.TrimPrefix(g.stub.URL, "http://")
	filePath := personal + "/v1/pypi/files/http/" + stubHost + "/packages/requests-2.32.3-py3-none-any.whl"

	rr := g.do("GET", personal+"/v1/pypi/simple/requests/", "Accept", "text/html")
	if want := `href="http://` + personalHost + filePath + `#sha256=00"`; rr.Code != 200 || !strings.Contains(rr.Body.String(), want) {
		t.Fatalf("simple page (HTML): %d\n%s\nwant it to contain %s", rr.Code, rr.Body, want)
	}
	rr = g.do("GET", personal+"/v1/pypi/simple/requests/", "Accept", "application/vnd.pypi.simple.v1+json")
	if want := `"url":"http://` + personalHost + filePath + `"`; rr.Code != 200 || !strings.Contains(rr.Body.String(), want) {
		t.Fatalf("simple page (JSON): %d\n%s\nwant it to contain %s", rr.Code, rr.Body, want)
	}

	rr = g.do("GET", filePath, "User-Agent", "pip/24.2")
	if rr.Code != 200 || rr.Body.String() != wheelBody {
		t.Fatalf("wheel: %d %q", rr.Code, rr.Body)
	}
	entries := g.entries()
	if len(entries) != 1 || entries[0].Subject != "alice@example.com" || entries[0].Link != linkID || entries[0].Ecosystem != "pip" {
		t.Fatalf("download log = %+v", entries)
	}
	g.assertNoToken(token)

	// A HEAD of the index promises no length either: the GET has none.
	rr = g.do("HEAD", personal+"/v1/pypi/simple/requests/", "Accept", "text/html")
	if rr.Code != 200 || rr.Header().Get("Content-Length") != "" || rr.Body.Len() != 0 {
		t.Fatalf("HEAD of a rewritten document: %d, Content-Length %q, %d body bytes", rr.Code, rr.Header().Get("Content-Length"), rr.Body.Len())
	}
}

// cargo learns where to download crates from config.json; go asks the proxy by
// path alone and needs nothing rewritten.
func TestPersonalLinkAttributesCargoAndGo(t *testing.T) {
	g := newPersonalGateway(t, personalOptions{})
	token, linkID := g.issue("alice@example.com", "platform")
	personal := "/u/" + token

	rr := g.do("GET", personal+"/v1/cargo/config.json")
	var cfg map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("config.json: %v\n%s", err, rr.Body)
	}
	if want := "http://" + personalHost + personal + "/v1/cargo/api/v1/crates"; cfg["dl"] != want {
		t.Fatalf("dl = %q, want %q", cfg["dl"], want)
	}
	rr = g.do("GET", strings.TrimPrefix(cfg["dl"], "http://"+personalHost)+"/cfg-if/1.0.0/download", "User-Agent", "cargo/1.84.0")
	if rr.Code != 200 || rr.Body.String() != crateBody {
		t.Fatalf("crate: %d %q", rr.Code, rr.Body)
	}

	rr = g.do("GET", personal+"/v1/go/rsc.io/quote/@v/list")
	if rr.Code != 200 || rr.Body.String() != "v1.5.2\n" || rr.Header().Get("Content-Length") == "" {
		t.Fatalf("version list: %d %q (Content-Length %q)", rr.Code, rr.Body, rr.Header().Get("Content-Length"))
	}
	rr = g.do("GET", personal+"/v1/go/rsc.io/quote/@v/v1.5.2.zip", "User-Agent", "Go-http-client/1.1")
	if rr.Code != 200 || rr.Body.String() != moduleBody {
		t.Fatalf("module zip: %d %q", rr.Code, rr.Body)
	}

	entries := g.entries()
	if len(entries) != 2 {
		t.Fatalf("the download log holds %d entries, want the crate and the module: %+v", len(entries), entries)
	}
	for _, e := range entries {
		if e.Subject != "alice@example.com" || e.Link != linkID || e.AuthMethod != userlinks.MethodPersonalLink || strings.Contains(e.Path, "/u/") {
			t.Fatalf("entry = %+v", e)
		}
	}
	g.assertNoToken(token)
}

// What a client verifies against a digest it got elsewhere is never changed:
// not an artifact, not anything that came out of the cache, not a document of
// an ecosystem whose adapter writes no links.
func TestPersonalLinkLeavesContentAlone(t *testing.T) {
	g := newPersonalGateway(t, personalOptions{})
	token, _ := g.issue("alice@example.com", "platform")
	personal := "/u/" + token

	// A text payload that names the proxy's own mount — twice, so the second
	// request is served from the cache.
	want := "set registry=http://" + personalHost + "/v1/npm/ in your .npmrc\n"
	for i, cacheStatus := range []string{"MISS", "HIT"} {
		rr := g.do("GET", personal+"/v1/npm/docs-pkg/-/docs-pkg-1.0.0.tgz")
		if rr.Code != 200 || rr.Body.String() != want {
			t.Fatalf("request %d: the payload was changed:\n got  %q\n want %q", i, rr.Body, want)
		}
		if rr.Header().Get("X-Cache") != cacheStatus || rr.Header().Get("Content-Length") != fmt.Sprint(len(want)) {
			t.Fatalf("request %d: X-Cache %q, Content-Length %q", i, rr.Header().Get("X-Cache"), rr.Header().Get("Content-Length"))
		}
	}
	// A byte-exact, signed index of a backend that writes no links.
	rr := g.do("GET", personal+"/v1/apt/dists/stable/Release")
	if !strings.Contains(rr.Body.String(), "Origin: http://"+personalHost+"/v1/apt/\n") || strings.Contains(rr.Body.String(), "/u/") {
		t.Fatalf("a document of a backend that writes no links was rewritten:\n%s", rr.Body)
	}
	if rr.Header().Get("Content-Length") == "" {
		t.Error("an untouched document lost its Content-Length")
	}
	if m := g.gw.PersonalLinkMetrics(); m.Rewritten != 0 || m.Links != 0 {
		t.Fatalf("edge metrics = %+v, want nothing rewritten", m)
	}
}

// A link that cannot be honoured refuses the request. Nothing is fetched,
// nothing is served — and in particular the request is not served anonymously.
func TestPersonalLinkRefusals(t *testing.T) {
	g := newPersonalGateway(t, personalOptions{})
	token, linkID := g.issue("alice@example.com", "platform")
	if _, err := g.links.Revoke(context.Background(), linkID, "alice@example.com", "lost", ""); err != nil {
		t.Fatal(err)
	}
	unknown, _ := userlinks.NewToken()

	cases := map[string]struct {
		path   string
		reason string
	}{
		"revoked":   {"/u/" + token + "/v1/npm/left-pad/-/left-pad-1.3.0.tgz", "revoked"},
		"unknown":   {"/u/" + unknown + "/v1/npm/left-pad/-/left-pad-1.3.0.tgz", "not valid"},
		"malformed": {"/u/" + token[:20] + "/v1/npm/left-pad/-/left-pad-1.3.0.tgz", "not spelled like one"},
		"metadata":  {"/u/" + token + "/v1/npm/left-pad", "revoked"},
	}
	for name, tc := range cases {
		rr := g.do("GET", tc.path)
		if rr.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403 (a 401 makes pip and git prompt for a password; a 404 lets GOPROXY fall through)", name, rr.Code)
		}
		body := rr.Body.String()
		if !strings.Contains(body, tc.reason) || !strings.Contains(body, "http://"+personalHost+"/links/") {
			t.Errorf("%s: body %q does not say %q and where to get a new link", name, body, tc.reason)
		}
		if strings.Contains(body, token) || strings.Contains(body, unknown) {
			t.Errorf("%s: the refusal repeats the token: %q", name, body)
		}
		if rr.Header().Get("WWW-Authenticate") != "" {
			t.Errorf("%s: a refused link is answered with a challenge", name)
		}
	}
	if reqs := g.stub.requests(); reqs != "" {
		t.Fatalf("a refused request reached the upstream:\n%s", reqs)
	}
	if entries := g.entries(); len(entries) != 0 {
		t.Fatalf("a refused request is in the download log: %+v", entries)
	}

	// The audit trail names the revoked link and its owner; nothing names a token.
	var revokedDenials int
	for _, ev := range g.audit.all() {
		if ev.Type == audit.EventAuth && ev.Decision == audit.DecisionDeny && ev.Detail["link"] == linkID {
			revokedDenials++
			if ev.Subject != "alice@example.com" || ev.Status != http.StatusForbidden || ev.RemoteAddr != "10.20.1.15" ||
				strings.Contains(ev.Resource, "/u/") {
				t.Fatalf("audit record of the refusal = %+v", ev)
			}
		}
	}
	if revokedDenials != 2 {
		t.Fatalf("%d audit records name the revoked link, want 2", revokedDenials)
	}
	g.assertNoToken(token)
	g.assertNoToken(unknown)

	// A link presented as a credential that is not good is a wrong credential.
	rr := g.do("GET", "/v1/npm/left-pad", "Authorization", "Bearer "+token)
	if rr.Code != http.StatusUnauthorized || rr.Header().Get("WWW-Authenticate") == "" || !strings.Contains(rr.Body.String(), "revoked") {
		t.Fatalf("a revoked link as a credential: %d %q", rr.Code, rr.Body)
	}

	// Only package sources live under a personal prefix.
	good, _ := g.issue("alice@example.com", "platform")
	for _, path := range []string{"", "/", "/admin/", "/metrics", "/links/", "/healthz", "/v1", "/v3/x", "/../v1/npm/left-pad", "/v2/library/alpine/manifests/3.19"} {
		if rr := g.do("GET", "/u/"+good+path); rr.Code == http.StatusOK {
			t.Errorf("GET /u/<link>%s = 200", path)
		}
	}
	for _, path := range []string{"/u", "/u/", "/u//v1/npm/left-pad"} {
		if rr := g.do("GET", path); rr.Code == http.StatusOK {
			t.Errorf("GET %s = 200", path)
		}
	}
}

// The link as a credential: the client keeps the mount's own URL and presents
// the token the way it presents any password. Nothing is rewritten — which is
// the point: no URL the client stores contains the token.
func TestPersonalLinkAsCredential(t *testing.T) {
	g := newPersonalGateway(t, personalOptions{})
	token, linkID := g.issue("alice@example.com", "platform")
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:"+token))

	rr := g.do("GET", "/v1/npm/left-pad", "Authorization", "Bearer "+token)
	if rr.Code != 200 || strings.Contains(rr.Body.String(), "/u/") || rr.Header().Get("Content-Length") == "" {
		t.Fatalf("packument with the link as a bearer token: %d (Content-Length %q)\n%s", rr.Code, rr.Header().Get("Content-Length"), rr.Body)
	}
	rr = g.do("GET", "/v1/npm/left-pad/-/left-pad-1.3.0.tgz", "Authorization", basic)
	if rr.Code != 200 || rr.Body.String() != npmTarball {
		t.Fatalf("tarball with the link as a password: %d", rr.Code)
	}
	e := g.entries()[0]
	if e.Subject != "alice@example.com" || e.Link != linkID || e.AuthMethod != userlinks.MethodPersonalLink {
		t.Fatalf("entry = %+v", e)
	}
	// The credential is the proxy's to consume: it is not passed upstream.
	g.assertNoToken(token)
	if strings.Contains(g.stub.requests(), "Authorization") {
		t.Fatalf("the client's Authorization header reached the upstream:\n%s", g.stub.requests())
	}
}

// With access control on, a link is one more way to authenticate, and its
// user is authorized like any other caller.
func TestPersonalLinkWithAccessControl(t *testing.T) {
	az, err := auth.NewAuthorizer([]auth.Role{
		{Name: "npm-reader", Ecosystems: []string{"npm"}, Upstreams: []string{"*"}},
		{Name: "anon", Ecosystems: []string{"go"}, Upstreams: []string{"*"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ta, err := auth.NewTokenAuthenticator([]auth.TokenEntry{{Name: "ci", Team: "t", Roles: []string{"npm-reader"}, Secret: "static-token-0123456789abcdef"}})
	if err != nil {
		t.Fatal(err)
	}
	enforcer, err := auth.NewEnforcer(auth.EnforcerOptions{
		Authenticator: ta, Authorizer: az, Quota: auth.NewQuotaManager(auth.QuotaOptions{}),
		AllowAnonymous: true, Anonymous: &auth.Principal{Subject: "anonymous", Method: "anonymous", Roles: []string{"anon"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	g := newPersonalGateway(t, personalOptions{enforcer: enforcer})
	reader, readerLink := g.issue("alice@example.com", "platform", "npm-reader")
	noRole, _ := g.issue("bob@example.com", "payments")

	// The link's user holds a role that admits npm, and no role for PyPI.
	if rr := g.do("GET", "/u/"+reader+"/v1/npm/left-pad/-/left-pad-1.3.0.tgz"); rr.Code != 200 {
		t.Fatalf("a link whose user may pull npm: %d %s", rr.Code, rr.Body)
	}
	if e := g.entries()[0]; e.Subject != "alice@example.com" || e.Link != readerLink {
		t.Fatalf("entry = %+v", e)
	}
	if rr := g.do("GET", "/u/"+reader+"/v1/pypi/simple/requests/"); rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "no role") {
		t.Fatalf("a link whose user may not pull pip: %d %s", rr.Code, rr.Body)
	}
	if rr := g.do("GET", "/u/"+noRole+"/v1/npm/left-pad"); rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "no roles") {
		t.Fatalf("a link whose user holds no role: %d %s", rr.Code, rr.Body)
	}

	// The static token still works, and anonymous access is what it was.
	if rr := g.do("GET", "/v1/npm/left-pad", "Authorization", "Bearer static-token-0123456789abcdef"); rr.Code != 200 {
		t.Fatalf("the static token: %d", rr.Code)
	}
	if rr := g.do("GET", "/v1/go/rsc.io/quote/@v/v1.5.2.zip"); rr.Code != 200 {
		t.Fatalf("anonymous go: %d", rr.Code)
	}
	if rr := g.do("GET", "/v1/npm/left-pad"); rr.Code != http.StatusForbidden {
		t.Fatalf("anonymous npm: %d", rr.Code)
	}

	// A revoked link does not degrade to the anonymous identity — even for a
	// resource anonymous callers may have.
	revoked, revokedLink := g.issue("carol@example.com", "x", "npm-reader")
	if _, err := g.links.Revoke(context.Background(), revokedLink, "ops", "", ""); err != nil {
		t.Fatal(err)
	}
	before := len(g.entries())
	if rr := g.do("GET", "/u/"+revoked+"/v1/go/rsc.io/quote/@v/v1.5.2.zip"); rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "revoked") {
		t.Fatalf("a revoked link on a resource open to anonymous callers: %d %s", rr.Code, rr.Body)
	}
	if rr := g.do("GET", "/v1/go/rsc.io/quote/@v/v1.5.2.zip", "Authorization", "Bearer "+revoked); rr.Code != http.StatusUnauthorized {
		t.Fatalf("a revoked link as a credential on a resource open to anonymous callers: %d", rr.Code)
	}
	if len(g.entries()) != before {
		t.Fatal("a request with a revoked link was served")
	}
}

// When the link registry cannot be consulted, the request is to be retried —
// not refused as if the link were bad.
func TestPersonalLinkRegistryUnavailable(t *testing.T) {
	g := newPersonalGateway(t, personalOptions{})
	broken, err := userlinks.New(userlinks.Config{PublicURL: "http://" + personalHost, Store: failingStore{}})
	if err != nil {
		t.Fatal(err)
	}
	g.gw.deps.UserLinks = broken
	token, _ := userlinks.NewToken()
	rr := g.gw.Handler().ServeHTTP
	rec := httptest.NewRecorder()
	rr(rec, httptest.NewRequest("GET", "http://"+personalHost+"/u/"+token+"/v1/npm/left-pad", nil))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("with the registry unavailable: %d, Retry-After %q, %s", rec.Code, rec.Header().Get("Retry-After"), rec.Body)
	}
	if strings.Contains(rec.Body.String(), "create a new one") {
		t.Fatalf("the user is told to replace a link that may be fine: %s", rec.Body)
	}
	// Requests without a link are not affected by the registry being away.
	rec = httptest.NewRecorder()
	rr(rec, httptest.NewRequest("GET", "http://"+personalHost+"/v1/npm/left-pad", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("a request without a link while the registry is away: %d", rec.Code)
	}
}

type failingStore struct{}

func (failingStore) List(context.Context) ([]userlinks.Object, error) {
	return nil, fmt.Errorf("the store is down")
}
func (failingStore) Get(context.Context, string) ([]byte, error) {
	return nil, fmt.Errorf("the store is down")
}
func (failingStore) Put(context.Context, string, []byte) error {
	return fmt.Errorf("the store is down")
}
func (failingStore) Delete(context.Context, string) error { return fmt.Errorf("the store is down") }
func (failingStore) Close() error                         { return nil }

// A container client can only put a link where a repository path goes.
func TestPersonalLinkInARegistryPath(t *testing.T) {
	g := newPersonalGateway(t, personalOptions{registry: &RegistryRoot{Upstreams: []string{"dockerhub"}, DefaultUpstream: "dockerhub"}})
	token, linkID := g.issue("alice@example.com", "platform")

	for name, path := range map[string]string{
		"as leading repository components": "/v2/u/" + token + "/dockerhub/library/alpine/manifests/3.19",
		"with the default upstream":        "/v2/u/" + token + "/library/alpine/manifests/3.19",
		"as a path prefix":                 "/u/" + token + "/v2/dockerhub/library/alpine/manifests/3.19",
	} {
		rr := g.do("GET", path)
		if rr.Code != 200 || rr.Body.String() != `{"schemaVersion":2}` {
			t.Fatalf("%s: %d %s", name, rr.Code, rr.Body)
		}
		// Every form is a personal response: produced for one user, and not to
		// be passed on in a Referer.
		if cc := rr.Header().Get("Cache-Control"); !strings.HasPrefix(cc, "private") || rr.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Fatalf("%s: Cache-Control %q, Referrer-Policy %q", name, cc, rr.Header().Get("Referrer-Policy"))
		}
	}
	// Each of them was the user's request.
	var pulls int
	for _, ev := range g.audit.all() {
		if ev.Type == audit.EventPull {
			pulls++
			if ev.Subject != "alice@example.com" || ev.Detail["link"] != linkID || ev.Resource != "/v1/dockerhub/v2/library/alpine/manifests/3.19" {
				t.Fatalf("audit record = %+v", ev)
			}
		}
	}
	if pulls != 3 {
		t.Fatalf("%d pulls were audited, want 3", pulls)
	}
	g.assertNoToken(token)
	if !strings.Contains(g.logs.String(), "path=/v2/u/<link>/dockerhub/library/alpine/manifests/3.19") {
		t.Errorf("the request log does not show the redacted registry path:\n%s", g.logs.String())
	}

	// "u" is also just a name. A repository path that merely starts with it is
	// a repository path.
	rr := g.do("GET", "/v2/u/someone/alpine/manifests/3.19")
	if rr.Code != http.StatusNotFound || !strings.Contains(g.stub.requests(), "GET /v2/u/someone/alpine/manifests/3.19") {
		t.Fatalf("a repository named u/someone was not routed as one: %d\n%s", rr.Code, g.stub.requests())
	}
	// What a backend serves never runs as a page on the proxy's origin, where
	// the links page lives.
	if rr.Header().Get("Content-Security-Policy") != "sandbox" || rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("a backend response is not sandboxed: %v", rr.Header())
	}
	// A well-formed token nobody issued, in that position, is a refused link.
	unknown, _ := userlinks.NewToken()
	if rr := g.do("GET", "/v2/u/"+unknown+"/library/alpine/manifests/3.19"); rr.Code != http.StatusForbidden {
		t.Fatalf("an unknown link in a registry path: %d", rr.Code)
	}
	g.assertNoToken(unknown)

	// So is a link cut short or mistyped: it is not a repository named
	// "u/ptl1…", and nothing of it goes upstream — most of a link is a link.
	before := g.stub.requests()
	short := token[:len(token)-3]
	if rr := g.do("GET", "/v2/u/"+short+"/library/alpine/manifests/3.19"); rr.Code != http.StatusForbidden {
		t.Fatalf("a cut-short link in a registry path: %d %s", rr.Code, rr.Body)
	}
	if g.stub.requests() != before {
		t.Fatalf("the cut-short link was sent upstream:\n%s", strings.TrimPrefix(g.stub.requests(), before))
	}
	g.assertNoToken(short)

	// One request, one link: a second one in the path is not let past the first.
	if rr := g.do("GET", "/u/"+token+"/v2/u/"+unknown+"/library/alpine/manifests/3.19"); rr.Code != http.StatusBadRequest {
		t.Fatalf("two links in one path: %d %s", rr.Code, rr.Body)
	}
	g.assertNoToken(unknown)
}

// --- the response writer, by itself ---------------------------------------------

// serveThroughEdge sends one request through the personal-path handler to a
// handler standing in for the gateway's backend chain.
func serveThroughEdge(t *testing.T, method string, backend string, class backends.ArtifactClass, respond http.HandlerFunc) (*httptest.ResponseRecorder, *Gateway) {
	t.Helper()
	links, err := userlinks.New(userlinks.Config{PublicURL: testPublicURL, Store: userlinks.NewMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	gw, err := New(Dependencies{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Cache: cache.NewMemoryCache(),
		Backends: backends.NewRegistry(), UserLinks: links,
	}, Options{HTTPAddr: ":0", PublicURL: testPublicURL, LinkBackends: map[string]bool{"npm": true, "git": true, "terraform": true, "ansible": true}})
	if err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/u/") || strings.Contains(r.RequestURI, "/u/") {
			t.Errorf("the handler behind the edge sees the personal prefix: path %q, request URI %q", r.URL.Path, r.RequestURI)
		}
		if tok, ok := userlinks.PathToken(r.Context()); !ok || "/u/"+tok != testPrefix {
			t.Errorf("the token was not handed on: %q, %v", tok, ok)
		}
		notePersonalBackend(r.Context(), backend)
		if class != backends.ArtifactUnclassified {
			notePersonalResolved(r.Context(), &backends.Resolved{Artifact: backends.Artifact{Class: class}})
		}
		respond(w, r)
	})
	req := httptest.NewRequest(method, "http://internal-lb:8443"+testPrefix+"/v1/"+backend+"/thing?x=1", nil)
	rr := httptest.NewRecorder()
	gw.handlePersonalPath(next, nil).ServeHTTP(rr, req)
	return rr, gw
}

func TestPersonalWriterDecidesByTheResponse(t *testing.T) {
	const canonical = `{"url":"https://proxy.example.com/v1/npm/a.tgz"}`
	const personal = `{"url":"https://proxy.example.com` + testPrefix + `/v1/npm/a.tgz"}`
	gz := func(s string) string {
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		_, _ = w.Write([]byte(s))
		_ = w.Close()
		return buf.String()
	}
	cases := []struct {
		name      string
		backend   string
		class     backends.ArtifactClass
		status    int
		header    map[string]string
		body      string
		rewritten bool
	}{
		{name: "a JSON index document", status: 200, header: map[string]string{"Content-Type": "application/json", "X-Cache": "BYPASS"}, body: canonical, rewritten: true},
		{name: "a vendor JSON type", status: 200, header: map[string]string{"Content-Type": "application/vnd.npm.install-v1+json; charset=utf-8"}, body: canonical, rewritten: true},
		{name: "an index a static host calls a download", status: 200, header: map[string]string{"Content-Type": "application/octet-stream"}, body: canonical, rewritten: true},
		{name: "no content type, but text", status: 200, body: canonical, rewritten: true},
		{name: "unclassified, not cached, text", class: backends.ArtifactUnclassified, status: 200, header: map[string]string{"Content-Type": "application/json"}, body: canonical, rewritten: true},
		{name: "a payload", class: backends.ArtifactPayload, status: 200, header: map[string]string{"Content-Type": "application/json", "X-Cache": "BYPASS"}, body: canonical},
		{name: "out of the cache", status: 200, header: map[string]string{"Content-Type": "application/json", "X-Cache": "HIT"}, body: canonical},
		{name: "just fetched into the cache", status: 200, header: map[string]string{"Content-Type": "application/json", "X-Cache": "MISS"}, body: canonical},
		{name: "a byte range", status: 206, header: map[string]string{"Content-Type": "application/json", "Content-Range": "bytes 0-10/100"}, body: canonical},
		{name: "an error", status: 502, header: map[string]string{"Content-Type": "application/json"}, body: canonical},
		{name: "a not-found", status: 404, header: map[string]string{"Content-Type": "text/plain"}, body: canonical},
		{name: "compressed", status: 200, header: map[string]string{"Content-Type": "application/json", "Content-Encoding": "gzip"}, body: gz(canonical)},
		{name: "a binary type", status: 200, header: map[string]string{"Content-Type": "application/gzip"}, body: canonical},
		{name: "an image type", status: 200, header: map[string]string{"Content-Type": "image/png"}, body: canonical},
		{name: "a download that is not text", status: 200, header: map[string]string{"Content-Type": "application/octet-stream"}, body: "\x1f\x8b\x08\x00" + canonical},
		{name: "a backend that writes no links", backend: "apt", status: 200, header: map[string]string{"Content-Type": "application/json"}, body: `{"url":"https://proxy.example.com/v1/apt/a"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backend := tc.backend
			if backend == "" {
				backend = "npm"
			}
			class := tc.class
			if class == 0 && !strings.HasPrefix(tc.name, "unclassified") {
				class = backends.ArtifactMetadata
			}
			rr, gw := serveThroughEdge(t, "GET", backend, class, func(w http.ResponseWriter, r *http.Request) {
				for k, v := range tc.header {
					w.Header().Set(k, v)
				}
				w.Header().Set("Content-Length", fmt.Sprint(len(tc.body)))
				w.WriteHeader(tc.status)
				// In two writes, cutting the link in half.
				half := len(tc.body) / 2
				_, _ = io.WriteString(w, tc.body[:half])
				_, _ = io.WriteString(w, tc.body[half:])
			})
			if rr.Code != tc.status {
				t.Fatalf("status = %d, want %d", rr.Code, tc.status)
			}
			if tc.rewritten {
				if rr.Body.String() != personal {
					t.Fatalf("body = %q\nwant   %q", rr.Body, personal)
				}
				if rr.Header().Get("Content-Length") != "" {
					t.Errorf("a rewritten body announces the original's length: %q", rr.Header().Get("Content-Length"))
				}
			} else {
				if rr.Body.String() != tc.body {
					t.Fatalf("the body was changed:\n got  %q\n want %q", rr.Body, tc.body)
				}
				if rr.Header().Get("Content-Length") != fmt.Sprint(len(tc.body)) {
					t.Errorf("Content-Length = %q, want %d", rr.Header().Get("Content-Length"), len(tc.body))
				}
			}
			if !strings.HasPrefix(rr.Header().Get("Cache-Control"), "private") {
				t.Errorf("Cache-Control = %q: every response to a personal request is private", rr.Header().Get("Cache-Control"))
			}
			if m := gw.PersonalLinkMetrics(); m.Requests != 1 || (m.Rewritten == 1) != tc.rewritten {
				t.Errorf("edge metrics = %+v", m)
			}
		})
	}
}

// Links in headers: a redirect a backend relays, Terraform's module location.
func TestPersonalWriterRewritesLinkHeaders(t *testing.T) {
	rr, _ := serveThroughEdge(t, "GET", "ansible", backends.ArtifactMetadata, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/v1/ansible/api/v3/collections/?page=2")
		w.Header().Set("Content-Location", "https://proxy.example.com/v1/ansible/api/v3/x")
		w.WriteHeader(http.StatusFound)
	})
	if got := rr.Header().Get("Location"); rr.Code != http.StatusFound || got != testPrefix+"/v1/ansible/api/v3/collections/?page=2" {
		t.Fatalf("relayed redirect: %d Location %q", rr.Code, got)
	}
	if got := rr.Header().Get("Content-Location"); got != "https://proxy.example.com"+testPrefix+"/v1/ansible/api/v3/x" {
		t.Fatalf("Content-Location = %q", got)
	}

	rr, _ = serveThroughEdge(t, "GET", "terraform", backends.ArtifactMetadata, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Terraform-Get", "https://proxy.example.com/v1/terraform/v1/modules/a/b/c/1.0.0/archive//sub?archive=tar.gz")
		w.WriteHeader(http.StatusNoContent)
	})
	if got := rr.Header().Get("X-Terraform-Get"); got != "https://proxy.example.com"+testPrefix+"/v1/terraform/v1/modules/a/b/c/1.0.0/archive//sub?archive=tar.gz" {
		t.Fatalf("X-Terraform-Get = %q", got)
	}

	// A redirect to somewhere else is somewhere else; and a backend that writes
	// no links has its headers left alone.
	rr, _ = serveThroughEdge(t, "GET", "npm", backends.ArtifactMetadata, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://cdn.example.org/v1/npm/x.tgz")
		w.WriteHeader(http.StatusFound)
	})
	if got := rr.Header().Get("Location"); got != "https://cdn.example.org/v1/npm/x.tgz" {
		t.Fatalf("a redirect to another host was rewritten: %q", got)
	}
	rr, _ = serveThroughEdge(t, "GET", "apt", backends.ArtifactMetadata, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/v1/apt/x")
		w.WriteHeader(http.StatusFound)
	})
	if got := rr.Header().Get("Location"); got != "/v1/apt/x" {
		t.Fatalf("the header of a backend that writes no links was rewritten: %q", got)
	}
}

// The Git LFS adapter names the proxy by the host the request was addressed
// to, and its documents are not resolved through a backend at all.
func TestPersonalWriterRewritesGitLFSBatch(t *testing.T) {
	batch := `{"transfer":"basic","objects":[{"oid":"abc","size":3,"actions":{"download":{"href":"https://internal-lb:8443/v1/git/o/r.git/info/lfs/objects/abc?size=3"}}}]}`
	rr, _ := serveThroughEdge(t, "POST", "git", backends.ArtifactUnclassified, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.git-lfs+json")
		_, _ = io.WriteString(w, batch)
	})
	want := strings.Replace(batch, "/v1/git/", testPrefix+"/v1/git/", 1)
	if rr.Body.String() != want {
		t.Fatalf("LFS batch response:\n %s\nwant\n %s", rr.Body, want)
	}
	// A pack, on the other hand, is a pack.
	pack := "PACK\x00\x00\x00\x02https://internal-lb:8443/v1/git/x"
	rr, _ = serveThroughEdge(t, "POST", "git", backends.ArtifactUnclassified, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
		_, _ = io.WriteString(w, pack)
	})
	if rr.Body.String() != pack {
		t.Fatalf("a pack was changed: %q", rr.Body)
	}
}

func TestPersonalWriterEdgeCases(t *testing.T) {
	// A response the handler flushes before its first byte, then streams.
	rr, _ := serveThroughEdge(t, "GET", "npm", backends.ArtifactMetadata, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		for _, part := range []string{`{"url":"https://proxy.exam`, `ple.com/v1/n`, `pm/a.tgz","next":"/v1/npm`} {
			_, _ = io.WriteString(w, part)
			w.(http.Flusher).Flush()
		}
		_, _ = io.WriteString(w, `"}`)
	})
	want := `{"url":"https://proxy.example.com` + testPrefix + `/v1/npm/a.tgz","next":"` + testPrefix + `/v1/npm"}`
	if rr.Body.String() != want || !rr.Flushed {
		t.Fatalf("a flushed stream:\n %s\nwant\n %s", rr.Body, want)
	}

	// A handler that writes without setting a status.
	rr, _ = serveThroughEdge(t, "GET", "npm", backends.ArtifactMetadata, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "https://proxy.example.com/v1/npm/x\n")
	})
	if rr.Code != 200 || rr.Body.String() != "https://proxy.example.com"+testPrefix+"/v1/npm/x\n" {
		t.Fatalf("an implicit 200: %d %q", rr.Code, rr.Body)
	}

	// A handler that answers nothing at all is not given an answer by the edge.
	rr, gw := serveThroughEdge(t, "GET", "npm", backends.ArtifactMetadata, func(w http.ResponseWriter, r *http.Request) {})
	if rr.Body.Len() != 0 || len(rr.Header()) != 0 {
		t.Fatalf("the edge answered for a handler that did not: %v %q", rr.Header(), rr.Body)
	}
	if m := gw.PersonalLinkMetrics(); m.Requests != 0 {
		t.Fatalf("edge metrics = %+v", m)
	}

	// A second WriteHeader does not change the first.
	rr, _ = serveThroughEdge(t, "GET", "npm", backends.ArtifactMetadata, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		w.WriteHeader(http.StatusOK)
	})
	if rr.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want the first one set", rr.Code)
	}

	// A large document, written in small pieces: every link is found, and the
	// writer never holds more than a few bytes back.
	var doc strings.Builder
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&doc, `{"v":%d,"tarball":"https://proxy.example.com/v1/npm/p/-/p-%d.tgz"},`, i, i)
	}
	rr, gw = serveThroughEdge(t, "GET", "npm", backends.ArtifactMetadata, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := doc.String()
		for len(body) > 0 {
			n := min(37, len(body))
			_, _ = io.WriteString(w, body[:n])
			body = body[n:]
		}
	})
	if got := strings.Count(rr.Body.String(), testPrefix+"/v1/npm/p/-/"); got != 5000 {
		t.Fatalf("%d of 5000 links were rewritten", got)
	}
	if rr.Body.Len() != doc.Len()+5000*len(testPrefix) {
		t.Fatalf("the rewritten document has %d bytes, want %d", rr.Body.Len(), doc.Len()+5000*len(testPrefix))
	}
	if m := gw.PersonalLinkMetrics(); m.Links != 5000 {
		t.Fatalf("edge metrics = %+v", m)
	}
}

// The edge must not slow down requests it has nothing to do with.
func TestPersonalLinkEdgeIsOffThePathOfOrdinaryRequests(t *testing.T) {
	g := newPersonalGateway(t, personalOptions{})
	start := time.Now()
	for i := 0; i < 200; i++ {
		if rr := g.do("GET", "/v1/npm/left-pad/-/left-pad-1.3.0.tgz"); rr.Code != 200 {
			t.Fatal(rr.Code)
		}
	}
	if m := g.gw.PersonalLinkMetrics(); m.Requests != 0 {
		t.Fatalf("ordinary requests were counted as personal: %+v", m)
	}
	t.Logf("200 ordinary requests in %v", time.Since(start))
}
