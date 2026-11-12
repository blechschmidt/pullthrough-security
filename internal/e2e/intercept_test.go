//go:build integration
// +build integration

// TLS interception and NAT mode, end to end, for every ecosystem (Task 172).
//
// For every real ecosystem fixture in internal/testset this suite puts the
// interception listeners — the forward proxy and the NAT TLS and plain-HTTP
// listeners — in front of the same fully-wired in-process gateway the
// whole-pipeline suite drives, and pulls the fixture's resources the way a
// client that is NOT pointed at the proxy does: from the upstream's own host
// (a hostname of its own per fixture), through a CONNECT to the forward proxy,
// and through a connection the network sent to the NAT listener. It asserts,
// per fixture and mode:
//
//   - routing: the request is routed by host to the fixture's backend, and the
//     response carries the upstream's bytes;
//   - the cache: the artifact is fetched from the upstream once and served from
//     the cache to every later intercepted client, whichever listener it came
//     through — an intercepted request is the same request to the cache;
//   - admission: a coordinate the known-malicious gate refuses is refused
//     through interception too, before anything is fetched;
//   - refusal: a host no rule routes is not served.
//
// It needs no network and no Docker, so it runs in the `integration` CI job,
// which gates the image build. The same modes with every ecosystem's REAL
// client against the real registries are in internal/ecotest.
package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/intercept"
	"github.com/blechschmidt/pullthrough-security/internal/testset"
)

// interceptEnv is the interception listeners in front of one scenario.
type interceptEnv struct {
	ca                    *intercept.CA
	host                  string // the fixture's upstream host, as clients address it
	forward, nat, natHTTP string // listener addresses
	proxy                 *intercept.Proxy
}

var hostUnsafe = regexp.MustCompile(`[^a-z0-9-]+`)

// upstreamHost is the hostname a fixture's clients address: one of its own.
func upstreamHost(f testset.Fixture) string {
	return strings.Trim(hostUnsafe.ReplaceAllString(strings.ToLower(f.ID), "-"), "-") + ".registry.example"
}

func startInterception(t *testing.T, f testset.Fixture, serve http.Handler) *interceptEnv {
	t.Helper()
	dir := t.TempDir()
	ca, err := intercept.LoadOrGenerateCA(intercept.CAOptions{
		CertFile: filepath.Join(dir, "ca.crt"), KeyFile: filepath.Join(dir, "ca.key"), Generate: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	env := &interceptEnv{ca: ca, host: upstreamHost(f)}
	env.proxy, err = intercept.New(intercept.Options{
		Router:         intercept.NewRouter(map[string]string{env.host: f.Backend}),
		CA:             ca,
		AllowPlainHTTP: true,
	})
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
	fwd, nat, natHTTP := listen(), listen(), listen()
	env.forward, env.nat, env.natHTTP = fwd.Addr().String(), nat.Addr().String(), natHTTP.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for _, run := range []func() error{
		func() error { return env.proxy.Serve(ctx, fwd, serve) },
		func() error { return env.proxy.ServeNAT(ctx, nat, serve) },
		func() error { return env.proxy.ServeNATHTTP(ctx, natHTTP, serve) },
	} {
		wg.Add(1)
		go func(run func() error) { defer wg.Done(); _ = run() }(run)
	}
	t.Cleanup(func() { cancel(); wg.Wait() })
	return env
}

// client returns an HTTP client that reaches every host through the given
// interception mode, trusting the interception CA.
func (env *interceptEnv) client(t *testing.T, mode intercept.Mode) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(env.ca.CertPEM()) {
		t.Fatal("cannot load the interception CA")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}, DisableKeepAlives: true}
	switch mode {
	case intercept.ModeForward:
		u, _ := url.Parse("http://" + env.forward)
		tr.Proxy = http.ProxyURL(u)
	default:
		d := &net.Dialer{Timeout: 5 * time.Second}
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if _, port, _ := net.SplitHostPort(addr); port == "80" {
				return d.DialContext(ctx, network, env.natHTTP)
			}
			return d.DialContext(ctx, network, env.nat)
		}
	}
	return &http.Client{Transport: tr, Timeout: 15 * time.Second}
}

// upstreamURL is the URL a client not pointed at the proxy uses for a pull:
// the fixture's upstream host, and the path below the backend's mount.
func (env *interceptEnv) upstreamURL(scheme string, f testset.Fixture, pull testset.Pull) string {
	path := strings.TrimPrefix(pull.Path, "/v1/"+f.Backend)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return scheme + "://" + env.host + path
}

func fetch(t *testing.T, c *http.Client, target string) (int, []byte) {
	t.Helper()
	resp, err := c.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func TestInterceptionAllBackends(t *testing.T) {
	if err := testset.Validate(); err != nil {
		t.Fatalf("testset corpus invalid: %v", err)
	}
	modes := []intercept.Mode{intercept.ModeForward, intercept.ModeNAT}
	var covered []string
	for _, f := range testset.Corpus() {
		f := f
		t.Run(f.ID, func(t *testing.T) {
			sc, err := buildScenario(f, scenarioConfig{})
			if err != nil {
				t.Fatalf("build scenario: %v", err)
			}
			defer sc.cleanup()
			env := startInterception(t, f, sc.handler)

			// Routing: the index (or ref listing) the fixture's client fetches
			// first is served through every listener, over HTTPS and plain HTTP.
			if ip, ok := indexPull(f); ok {
				for _, mode := range modes {
					for _, scheme := range []string{"https", "http"} {
						target := env.upstreamURL(scheme, f, ip)
						if status, _ := fetch(t, env.client(t, mode), target); status < 200 || status >= 300 {
							t.Errorf("%s %s: status %d", mode, target, status)
						}
					}
				}
			}

			ap, ok := artifactPull(f)
			if !ok {
				covered = append(covered, f.ID)
				return // git: no artifact coordinate; the routing above is the coverage
			}
			rest := restOf(f.Backend, ap.Path)
			want := artifactBody(rest)

			// The artifact: fetched from the upstream for the first intercepted
			// client, out of the cache for every later one, whichever listener.
			for i, mode := range modes {
				status, body := fetch(t, env.client(t, mode), env.upstreamURL("https", f, ap))
				if status != http.StatusOK || string(body) != string(want) {
					t.Fatalf("%s artifact pull #%d: status %d, %d bytes (want 200, %d bytes)", mode, i+1, status, len(body), len(want))
				}
				if got := sc.up.count(rest); got != 1 {
					t.Errorf("after %s artifact pull #%d the upstream served the artifact %d time(s), want 1", mode, i+1, got)
				}
			}
			stats := env.proxy.Stats()
			for _, mode := range modes {
				if stats.Requests[mode] == 0 {
					t.Errorf("no request was dispatched via %s", mode)
				}
			}

			// A host no rule routes is not served.
			for _, mode := range modes {
				if resp, err := env.client(t, mode).Get("https://elsewhere.example/" + strings.TrimPrefix(rest, "/")); err == nil {
					resp.Body.Close()
					t.Errorf("%s: a host without a rule was served (%d)", mode, resp.StatusCode)
				}
			}

			// Admission: the known-malicious gate refuses the coordinate through
			// interception exactly as it does for an explicit request.
			blocked, err := buildScenario(f, scenarioConfig{malfeedCoord: true})
			if err != nil {
				t.Fatalf("build blocking scenario: %v", err)
			}
			defer blocked.cleanup()
			benv := startInterception(t, f, blocked.handler)
			for _, mode := range modes {
				status, body := fetch(t, benv.client(t, mode), benv.upstreamURL("https", f, ap))
				if status != http.StatusForbidden {
					t.Errorf("%s: a known-malicious coordinate was answered %d, want 403 (%s)", mode, status, firstLine(body))
				}
			}
			if got := blocked.up.count(rest); got != 0 {
				t.Errorf("the refused artifact was fetched from the upstream %d time(s)", got)
			}
			covered = append(covered, f.ID)
		})
	}
	t.Logf("interception and NAT exercised for %d fixture(s): %s", len(covered), strings.Join(covered, ", "))
	if len(covered) != len(testset.Corpus()) {
		t.Errorf("interception coverage gap: %d of %d fixtures", len(covered), len(testset.Corpus()))
	}
}

func firstLine(b []byte) string {
	s := string(b)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return fmt.Sprintf("%q", s)
}
