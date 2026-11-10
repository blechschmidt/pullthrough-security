package ansible

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
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// These tests drive the backend the way a real ansible-galaxy client does —
// API-root discovery, paging through a versions list by "links.next", reading a
// version detail, downloading "download_url" — against an in-process stand-in
// for galaxy.ansible.com, with the backend mounted beneath "/v1/ansible" exactly
// as the proxy core mounts it. Every link the client follows has to land back
// inside that mount; one that does not is a 404 at the host root, which is the
// failure a real client reported.

const (
	aliasPrefix   = "/api/v3/collections"                                                          // short alias Galaxy redirects away from
	hrefPrefix    = "/api/content/published/v3/plugin/ansible/content/published/collections/index" // form Galaxy uses for href
	contentPrefix = "/api/pulp/content/published"                                                  // where artifact downloads redirect to
)

// fakeGalaxy stands in for galaxy.ansible.com serving one collection,
// community.general. Like the real registry it redirects the short
// "/api/v3/collections/..." aliases to the canonical index path with a
// root-relative Location, links documents together with root-relative paths,
// and names the tarball with an absolute download_url.
type fakeGalaxy struct {
	srv      *httptest.Server
	versions []string // newest first
	// redirectArtifacts answers the artifact URL with a redirect into the content
	// tree, as galaxy.ansible.com does, rather than with the bytes.
	redirectArtifacts bool
}

// newFakeGalaxy starts a registry holding the given number of versions of
// community.general ("N.0.0" down to "1.0.0").
func newFakeGalaxy(t *testing.T, versions int, redirectArtifacts bool) *fakeGalaxy {
	t.Helper()
	g := &fakeGalaxy{redirectArtifacts: redirectArtifacts}
	for v := versions; v >= 1; v-- {
		g.versions = append(g.versions, fmt.Sprintf("%d.0.0", v))
	}
	g.srv = httptest.NewUnstartedServer(http.HandlerFunc(g.serve))
	g.srv.Start()
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGalaxy) tarball(version string) []byte {
	return []byte("collection tarball community.general " + version + "\n")
}

func (g *fakeGalaxy) hasVersion(version string) bool {
	for _, v := range g.versions {
		if v == version {
			return true
		}
	}
	return false
}

func (g *fakeGalaxy) serve(w http.ResponseWriter, r *http.Request) {
	const coll = "/community/general/"
	p := r.URL.Path
	redirect := func(status int, location string) {
		w.Header().Set("Location", location)
		w.WriteHeader(status)
	}
	writeJSON := func(v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}

	switch {
	case p == "/":
		// The registry root is the web UI, not the API.
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<!doctype html><a href="/api/">api</a>`)
	case p == "/api":
		redirect(http.StatusMovedPermanently, "/api/")
	case p == "/api/":
		writeJSON(map[string]any{"available_versions": map[string]string{"v3": "v3/", "v1": "v1/"}})
	case strings.HasPrefix(p, aliasPrefix+"/"):
		location := indexPrefix + strings.TrimPrefix(p, aliasPrefix)
		if r.URL.RawQuery != "" {
			location += "?" + r.URL.RawQuery
		}
		redirect(http.StatusFound, location)
	case p == indexPrefix+coll:
		writeJSON(map[string]any{
			"href":         hrefPrefix + coll,
			"namespace":    "community",
			"name":         "general",
			"versions_url": hrefPrefix + coll + "versions/",
			"highest_version": map[string]any{
				"href":    hrefPrefix + coll + "versions/" + g.versions[0] + "/",
				"version": g.versions[0],
			},
		})
	case p == indexPrefix+coll+"versions/":
		g.serveVersions(w, r)
	case strings.HasPrefix(p, indexPrefix+coll+"versions/"):
		version := strings.Trim(strings.TrimPrefix(p, indexPrefix+coll+"versions/"), "/")
		if !g.hasVersion(version) {
			http.NotFound(w, r)
			return
		}
		file := "community-general-" + version + ".tar.gz"
		sum := sha256.Sum256(g.tarball(version))
		writeJSON(map[string]any{
			"version":      version,
			"href":         hrefPrefix + coll + "versions/" + version + "/",
			"artifact":     map[string]any{"filename": file, "sha256": fmt.Sprintf("%x", sum), "size": len(g.tarball(version))},
			"collection":   map[string]any{"name": "general", "href": hrefPrefix + coll},
			"namespace":    map[string]any{"name": "community"},
			"download_url": g.srv.URL + artPrefix + "/" + file,
			"metadata":     map[string]any{"dependencies": map[string]string{}, "description": "/api/v3 is not a link here"},
		})
	case strings.HasPrefix(p, artPrefix+"/"), strings.HasPrefix(p, contentPrefix+"/"):
		file := p[strings.LastIndex(p, "/")+1:]
		version := strings.TrimSuffix(strings.TrimPrefix(file, "community-general-"), ".tar.gz")
		if !g.hasVersion(version) {
			http.NotFound(w, r)
			return
		}
		if g.redirectArtifacts && strings.HasPrefix(p, artPrefix+"/") {
			redirect(http.StatusFound, g.srv.URL+contentPrefix+"/"+file+"?validate_token=abc:def")
			return
		}
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(g.tarball(version))
	case p == "/api/offsite/":
		redirect(http.StatusFound, "https://objects.example.net/artifact/74/db5d?signature=x")
	case p == "/api/with-location-headers/":
		w.Header().Set("Location", "/api/v3/")
		w.Header().Set("Content-Location", g.srv.URL+"/api/v3/")
		writeJSON(map[string]any{"href": "/api/v3/"})
	default:
		http.NotFound(w, r)
	}
}

// serveVersions pages the versions list by limit/offset and links the pages
// with root-relative URLs, as Galaxy does (its default page size is 10).
func (g *fakeGalaxy) serveVersions(w http.ResponseWriter, r *http.Request) {
	const page = indexPrefix + "/community/general/versions/"
	limit, offset := 10, 0
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		limit = v
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && v > 0 {
		offset = v
	}
	link := func(offset int) string { return fmt.Sprintf("%s?limit=%d&offset=%d", page, limit, offset) }
	links := map[string]any{"first": link(0), "previous": nil, "next": nil, "last": link((len(g.versions) - 1) / limit * limit)}
	if offset > 0 {
		links["previous"] = link(max(offset-limit, 0))
	}
	if offset+limit < len(g.versions) {
		links["next"] = link(offset + limit)
	}
	data := []any{}
	for i := offset; i < len(g.versions) && i < offset+limit; i++ {
		data = append(data, map[string]any{
			"version": g.versions[i],
			"href":    hrefPrefix + "/community/general/versions/" + g.versions[i] + "/",
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"meta":  map[string]any{"count": len(g.versions)},
		"links": links,
		"data":  data,
	})
}

// proxyMount serves a backend the way the proxy core does: beneath
// "/v1/ansible", with every other path on the host answering 404 — which is
// where a link that lost its mount prefix ends up. A failed fetch is relayed
// with its upstream status and, for a redirect, the Location the backend mapped.
type proxyMount struct {
	srv *httptest.Server
	b   *Backend

	mu      sync.Mutex
	served  []string // request URIs served beneath the mount
	escaped []string // request URIs that missed the mount
}

// newProxyMount mounts a backend fronting galaxy. followRedirects selects
// whether the shared upstream client follows redirects (the default) or hands
// them back to the backend (egress.followRedirects: false); publicURL whether
// the proxy has been told its public URL (server.publicUrl).
func newProxyMount(t *testing.T, galaxy *fakeGalaxy, followRedirects, publicURL bool) *proxyMount {
	t.Helper()
	m := &proxyMount{}
	m.srv = httptest.NewUnstartedServer(m)
	t.Cleanup(m.srv.Close)

	hc := &http.Client{}
	if !followRedirects {
		hc = noRedirectClient()
	}
	opts := Options{
		Name:        "ansible",
		UpstreamURL: galaxy.srv.URL,
		Client:      upstream.NewWithHTTPClient(hc, "test/1"),
		Metrics:     &Metrics{},
	}
	if publicURL {
		opts.PublicBaseURL = "http://" + m.srv.Listener.Addr().String() + testMountPath
	}
	b, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.b = b
	m.srv.Start()
	return m
}

func (m *proxyMount) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rest, ok := strings.CutPrefix(r.URL.Path, testMountPath)
	if !ok || (rest != "" && rest[0] != '/') {
		m.record(&m.escaped, r)
		http.NotFound(w, r)
		return
	}
	m.record(&m.served, r)
	if rest == "" {
		rest = "/"
	}
	resolved, err := m.b.Resolve(r.Context(), &backends.Request{Method: r.Method, Path: rest, Query: r.URL.Query()})
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotImplemented)
		return
	}
	result, err := m.b.Fetch(r.Context(), resolved)
	if err != nil {
		if se, ok := backends.AsStatusError(err); ok {
			if se.Location != "" {
				w.Header().Set("Location", se.Location)
			}
			w.WriteHeader(se.Status)
			return
		}
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer result.Content.Close()
	for k, vs := range result.Header {
		w.Header()[k] = vs
	}
	if result.MediaType != "" {
		w.Header().Set("Content-Type", result.MediaType)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, result.Content)
}

func (m *proxyMount) record(list *[]string, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	*list = append(*list, r.URL.RequestURI())
}

func (m *proxyMount) requests() (served, escaped []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.served...), append([]string(nil), m.escaped...)
}

// galaxyClient walks the Galaxy API the way ansible-galaxy does. It follows
// HTTP redirects, as the real client does.
type galaxyClient struct {
	t      *testing.T
	hc     *http.Client
	server string // the configured server URL: "<proxy>/v1/ansible/"
	// legacy selects how ansible-core before 2.19 treats the links a server hands
	// it: a pagination link is spliced over the path of the URL that was
	// requested, and download_url is opened exactly as served. Otherwise both are
	// joined onto the API root, as ansible-core 2.19+ does.
	legacy bool
}

func (c *galaxyClient) get(rawURL string) (int, []byte) {
	c.t.Helper()
	resp, err := c.hc.Get(rawURL)
	if err != nil {
		c.t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatalf("GET %s: reading body: %v", rawURL, err)
	}
	return resp.StatusCode, body
}

func (c *galaxyClient) json(rawURL string) map[string]any {
	c.t.Helper()
	status, body := c.get(rawURL)
	if status != http.StatusOK {
		c.t.Fatalf("GET %s: HTTP %d", rawURL, status)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		c.t.Fatalf("GET %s: not JSON: %v", rawURL, err)
	}
	return doc
}

// install resolves one collection version and downloads its tarball, returning
// every version the server listed along the way and the verified tarball.
func (c *galaxyClient) install(namespace, name, version string, pageSize int) (versions []string, tarball []byte) {
	c.t.Helper()

	// Find the API root: the configured URL itself, else "<url>/api".
	apiServer := c.server
	var root map[string]any
	if status, body := c.get(apiServer); status != http.StatusOK || json.Unmarshal(body, &root) != nil || root["available_versions"] == nil {
		apiServer = strings.TrimRight(c.server, "/") + "/api"
		root = c.json(apiServer)
	}
	v3, _ := root["available_versions"].(map[string]any)["v3"].(string)
	api := apiServer + "/" + strings.Trim(v3, "/") + "/collections/" + namespace + "/" + name

	// List the versions, following links.next page by page.
	versionsURL := api + "/versions/?limit=" + strconv.Itoa(pageSize)
	for page := c.json(versionsURL); ; {
		for _, e := range page["data"].([]any) {
			versions = append(versions, e.(map[string]any)["version"].(string))
		}
		next, _ := page["links"].(map[string]any)["next"].(string)
		if next == "" {
			break
		}
		page = c.json(c.pageURL(apiServer, versionsURL, next))
	}

	// Read the version detail, then download and verify the tarball it names.
	detail := c.json(api + "/versions/" + version + "/")
	download, _ := detail["download_url"].(string)
	if c.legacy {
		if !strings.HasPrefix(download, "http://") && !strings.HasPrefix(download, "https://") {
			c.t.Fatalf("download_url %q is not absolute; this client opens it as served", download)
		}
	} else {
		download = c.join(apiServer, download)
	}
	status, tarball := c.get(download)
	if status != http.StatusOK {
		c.t.Fatalf("GET %s: HTTP %d", download, status)
	}
	want, _ := detail["artifact"].(map[string]any)["sha256"].(string)
	if got := fmt.Sprintf("%x", sha256.Sum256(tarball)); got != want {
		c.t.Fatalf("tarball sha256 = %s, version detail says %s", got, want)
	}
	return versions, tarball
}

// pageURL turns a pagination link into the URL of the next request.
func (c *galaxyClient) pageURL(apiServer, versionsURL, next string) string {
	c.t.Helper()
	if !c.legacy {
		return c.join(apiServer, next)
	}
	// ansible-core < 2.19: versions_url.replace(versions_url_info.path, next_link)
	u, err := url.Parse(versionsURL)
	if err != nil {
		c.t.Fatalf("parse %q: %v", versionsURL, err)
	}
	return strings.ReplaceAll(u.Scheme+"://"+u.Host+u.Path, u.Path, next)
}

// join resolves a server-supplied link against the API root, refusing a
// path-relative one, as ansible-core 2.19+ does.
func (c *galaxyClient) join(apiServer, link string) string {
	c.t.Helper()
	ref, err := url.Parse(link)
	if err != nil {
		c.t.Fatalf("parse link %q: %v", link, err)
	}
	if ref.Scheme == "" && !strings.HasPrefix(ref.Path, "/") {
		c.t.Fatalf("invalid non absolute link: %s", link)
	}
	base, err := url.Parse(apiServer)
	if err != nil {
		c.t.Fatalf("parse %q: %v", apiServer, err)
	}
	return base.ResolveReference(ref).String()
}

// TestInstallStaysInsideMount is the reported failure, end to end: a collection
// with more versions than fit on one page is resolved and downloaded, and no
// request the client makes may miss the mount.
func TestInstallStaysInsideMount(t *testing.T) {
	cases := []struct {
		name                      string
		follow, publicURL, legacy bool
	}{
		{"proxy follows redirects/public URL/ansible-core 2.19+", true, true, false},
		{"proxy follows redirects/public URL/ansible-core before 2.19", true, true, true},
		{"proxy follows redirects/no public URL/ansible-core 2.19+", true, false, false},
		{"proxy relays redirects/public URL/ansible-core 2.19+", false, true, false},
		{"proxy relays redirects/public URL/ansible-core before 2.19", false, true, true},
		{"proxy relays redirects/no public URL/ansible-core 2.19+", false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Galaxy serves a tarball through a redirect of its own. The proxy can
			// only fetch it when it follows redirects; it never relays that one.
			galaxy := newFakeGalaxy(t, 25, tc.follow)
			mount := newProxyMount(t, galaxy, tc.follow, tc.publicURL)
			client := &galaxyClient{t: t, hc: mount.srv.Client(), server: mount.srv.URL + testMountPath + "/", legacy: tc.legacy}

			versions, tarball := client.install("community", "general", "8.0.0", 10)

			if len(versions) != 25 || versions[0] != "25.0.0" || versions[24] != "1.0.0" {
				t.Errorf("listed %d versions %v; want all 25, paged through links.next", len(versions), versions)
			}
			if !bytes.Equal(tarball, galaxy.tarball("8.0.0")) {
				t.Errorf("downloaded tarball = %q", tarball)
			}
			served, escaped := mount.requests()
			if len(escaped) != 0 {
				t.Errorf("requests missed the %s mount: %v", testMountPath, escaped)
			}
			for _, want := range []string{
				testMountPath + indexPrefix + "/community/general/versions/?limit=10&offset=10",
				testMountPath + indexPrefix + "/community/general/versions/?limit=10&offset=20",
				testMountPath + artPrefix + "/community-general-8.0.0.tar.gz",
			} {
				if !contains(served, want) {
					t.Errorf("client never requested %s; served: %v", want, served)
				}
			}
			if st := mount.b.Metrics().Stats(); st.ArtifactsVerified != 1 || st.ChecksumMissing != 0 {
				t.Errorf("artifact was not verified against the version detail: %+v", st)
			}
		})
	}
}

// noRedirectClient returns a client that reports a redirect instead of
// following it, to inspect exactly what the mount answered.
func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// fetchURI resolves and fetches a mount-relative request URI ("/api/...?q").
func fetchURI(t *testing.T, b *Backend, uri string) (*backends.Resolved, *backends.FetchResult, []byte, error) {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("parse %q: %v", uri, err)
	}
	resolved, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: u.Path, Query: u.Query()})
	if err != nil {
		return nil, nil, nil, err
	}
	result, err := b.Fetch(context.Background(), resolved)
	if err != nil {
		return resolved, nil, nil, err
	}
	defer result.Content.Close()
	body, err := io.ReadAll(result.Content)
	return resolved, result, body, err
}

// The shapes a real client depends on: a pagination link stays root-relative
// even when the proxy knows its public URL (ansible-core before 2.19 splices it
// into the request URL, so an absolute one yields "http://hosthttp://host/..."),
// while download_url stays absolute whenever it can (that client opens it as
// served). Without a public URL both fall back to the root-relative mount path.
func TestServedLinkShapes(t *testing.T) {
	const next = testMountPath + indexPrefix + "/community/general/versions/?limit=10&offset=10"
	const artifact = testMountPath + artPrefix + "/community-general-8.0.0.tar.gz"

	for _, publicURL := range []bool{true, false} {
		galaxy := newFakeGalaxy(t, 25, false)
		mount := newProxyMount(t, galaxy, true, publicURL)

		// Requested through the alias, so the upstream redirect is followed first.
		_, result, body, err := fetchURI(t, mount.b, aliasPrefix+"/community/general/versions/?limit=10")
		if err != nil {
			t.Fatalf("publicURL=%v: versions list: %v", publicURL, err)
		}
		if result.Size != int64(len(body)) {
			t.Errorf("publicURL=%v: Size = %d, body is %d bytes", publicURL, result.Size, len(body))
		}
		list := decodeDoc(t, body)
		if got := at(t, list, "links", "next"); got != next {
			t.Errorf("publicURL=%v: links.next = %v, want %v", publicURL, got, next)
		}
		if got := at(t, list, "links", "previous"); got != nil {
			t.Errorf("publicURL=%v: links.previous = %v, want null", publicURL, got)
		}
		if got, want := at(t, list, "data", 0, "href"), testMountPath+hrefPrefix+"/community/general/versions/25.0.0/"; got != want {
			t.Errorf("publicURL=%v: data[0].href = %v, want %v", publicURL, got, want)
		}

		_, _, body, err = fetchURI(t, mount.b, aliasPrefix+"/community/general/versions/8.0.0/")
		if err != nil {
			t.Fatalf("publicURL=%v: version detail: %v", publicURL, err)
		}
		detail := decodeDoc(t, body)
		wantDownload := artifact
		if publicURL {
			wantDownload = mount.srv.URL + artifact
		}
		if got := at(t, detail, "download_url"); got != wantDownload {
			t.Errorf("publicURL=%v: download_url = %v, want %v", publicURL, got, wantDownload)
		}
		if got, want := at(t, detail, "href"), testMountPath+hrefPrefix+"/community/general/versions/8.0.0/"; got != want {
			t.Errorf("publicURL=%v: href = %v, want %v", publicURL, got, want)
		}
		if got := at(t, detail, "metadata", "description"); got != "/api/v3 is not a link here" {
			t.Errorf("publicURL=%v: description was rewritten: %v", publicURL, got)
		}
	}
}

// When the shared client does not follow redirects, the backend surfaces the
// upstream's redirect with its Location mapped onto the mount, so the proxy
// relays one the client can follow back through this backend.
func TestRedirectRelayedInsideMount(t *testing.T) {
	galaxy := newFakeGalaxy(t, 25, false)
	for _, publicURL := range []bool{true, false} {
		mount := newProxyMount(t, galaxy, false, publicURL)
		for _, tc := range []struct {
			uri      string
			status   int
			location string
		}{
			{aliasPrefix + "/community/general/", http.StatusFound, testMountPath + indexPrefix + "/community/general/"},
			{aliasPrefix + "/community/general/versions/?limit=100", http.StatusFound, testMountPath + indexPrefix + "/community/general/versions/?limit=100"},
			{aliasPrefix + "/community/general/versions/8.0.0/", http.StatusFound, testMountPath + indexPrefix + "/community/general/versions/8.0.0/"},
			{"/api", http.StatusMovedPermanently, testMountPath + "/api/"},
		} {
			_, _, _, err := fetchURI(t, mount.b, tc.uri)
			se, ok := backends.AsStatusError(err)
			if !ok {
				t.Fatalf("publicURL=%v %s: err = %v, want a StatusError carrying the redirect", publicURL, tc.uri, err)
			}
			if se.Status != tc.status || se.Location != tc.location {
				t.Errorf("publicURL=%v %s: relayed %d Location %q; want %d %q", publicURL, tc.uri, se.Status, se.Location, tc.status, tc.location)
			}
		}
	}
}

// expectNotRelayed asserts err is the gateway error for a redirect the proxy
// must not hand on: not a StatusError, so neither the upstream's 3xx nor any
// Location can reach the client.
func expectNotRelayed(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, errRedirectNotRelayed) {
		t.Fatalf("err = %v, want errRedirectNotRelayed", err)
	}
	if se, ok := backends.AsStatusError(err); ok {
		t.Errorf("redirect surfaced as a relayable status: %+v", se)
	}
}

// A redirect that leaves the registry is never relayed: the client would
// follow it straight past the proxy. The request fails as a gateway error
// rather than with a redirect that names no target.
func TestRedirectLeavingRegistryIsNotRelayed(t *testing.T) {
	galaxy := newFakeGalaxy(t, 1, false)
	mount := newProxyMount(t, galaxy, false, true)
	_, _, _, err := fetchURI(t, mount.b, "/api/offsite/")
	expectNotRelayed(t, err)

	resp, err := noRedirectClient().Get(mount.srv.URL + testMountPath + "/api/offsite/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || resp.Header.Get("Location") != "" {
		t.Errorf("client saw %d Location %q; want 502 and no Location", resp.StatusCode, resp.Header.Get("Location"))
	}
}

// A redirect answering an artifact request is never relayed either, even one
// that stays inside the registry: the client would fetch the tarball from the
// path it names, around the checksum verification and the cache.
func TestArtifactRedirectIsNeverRelayed(t *testing.T) {
	galaxy := newFakeGalaxy(t, 25, true)
	const artifact = artPrefix + "/community-general-8.0.0.tar.gz"

	relaying := newProxyMount(t, galaxy, false, true)
	resolved, _, _, err := fetchURI(t, relaying.b, artifact)
	expectNotRelayed(t, err)
	if !resolved.Cacheable {
		t.Error("artifact request should be cacheable")
	}
	if st := relaying.b.Metrics().Stats(); st.ArtifactsServed != 0 {
		t.Errorf("an artifact was counted as served: %+v", st)
	}

	// The same redirect, followed by the shared client, is served verified.
	following := newProxyMount(t, galaxy, true, true)
	resolved, result, body, err := fetchURI(t, following.b, artifact)
	if err != nil {
		t.Fatalf("artifact through a followed redirect: %v", err)
	}
	if !bytes.Equal(body, galaxy.tarball("8.0.0")) {
		t.Errorf("artifact body = %q", body)
	}
	if result.Header.Get("X-Checksum-Verified") != "sha256" || resolved.Metadata[MetaChecksumVerified] != "sha256" {
		t.Errorf("artifact not verified: header %q, metadata %q", result.Header.Get("X-Checksum-Verified"), resolved.Metadata[MetaChecksumVerified])
	}
	if resolved.Coordinate != (backends.Coordinate{Name: "community.general", Version: "8.0.0"}) {
		t.Errorf("coordinate = %+v", resolved.Coordinate)
	}
}

// A Location header on a served document would reach the client naming the
// upstream's own tree; only a redirect's mapped Location is ever relayed.
func TestServedDocumentDropsUpstreamLocationHeaders(t *testing.T) {
	galaxy := newFakeGalaxy(t, 1, false)
	mount := newProxyMount(t, galaxy, true, true)
	_, result, body, err := fetchURI(t, mount.b, "/api/with-location-headers/")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	for _, h := range []string{"Location", "Content-Location"} {
		if v := result.Header.Get(h); v != "" {
			t.Errorf("%s header relayed with a served document: %q", h, v)
		}
	}
	if got := at(t, decodeDoc(t, body), "href"); got != testMountPath+"/api/v3/" {
		t.Errorf("href = %v", got)
	}
}

// A non-redirect upstream failure carries no Location, whatever the upstream
// sent alongside it.
func TestUpstreamErrorCarriesNoLocation(t *testing.T) {
	galaxy := newFakeGalaxy(t, 1, false)
	mount := newProxyMount(t, galaxy, false, true)
	_, _, _, err := fetchURI(t, mount.b, "/api/v3/no-such-endpoint/")
	se, ok := backends.AsStatusError(err)
	if !ok || se.Status != http.StatusNotFound || se.Location != "" {
		t.Errorf("err = %v (%+v), want a bare 404 StatusError", err, se)
	}
}
