package remediation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// maxVersionListBytes bounds a single registry version-list response, protecting
// the advisor from a hostile or runaway upstream.
const maxVersionListBytes = 32 << 20 // 32 MiB

// Doer is the minimal HTTP client surface the version lister needs; *http.Client
// satisfies it and tests inject a stub.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// HTTPVersionLister enumerates the versions a package publishes by querying each
// ecosystem's public registry index. It mirrors the maturity gate's resolver
// (internal/maturity/resolver.go) in structure — same Doer seam, same per-
// ecosystem base-URL overrides, same bounded reads — but extracts the full
// version list rather than a single publish timestamp.
//
// It returns ok via a nil error and an empty slice for an ecosystem it does not
// support or a package the registry does not know, so the advisor degrades to
// "no candidates" rather than failing the whole request.
type HTTPVersionLister struct {
	// Client performs the index requests (default http.DefaultClient).
	Client Doer
	// UserAgent is sent with each request; some registries (crates.io) reject a
	// missing/empty User-Agent.
	UserAgent string
	// BaseURLs overrides the registry base URL per canonical ecosystem (private
	// mirrors or tests). An absent override uses the public default.
	BaseURLs map[string]string
}

// NewHTTPVersionLister builds a lister with sane defaults.
func NewHTTPVersionLister(client Doer, userAgent string) *HTTPVersionLister {
	if client == nil {
		client = http.DefaultClient
	}
	if strings.TrimSpace(userAgent) == "" {
		userAgent = "pullthrough-security-remediation/1.0"
	}
	return &HTTPVersionLister{Client: client, UserAgent: userAgent}
}

// defaultBaseURLs maps each supported ecosystem to its public registry base.
var defaultBaseURLs = map[string]string{
	"npm":      "https://registry.npmjs.org",
	"pip":      "https://pypi.org",
	"cargo":    "https://crates.io",
	"go":       "https://proxy.golang.org",
	"nuget":    "https://api.nuget.org",
	"rubygems": "https://rubygems.org",
	"composer": "https://repo.packagist.org",
	"maven":    "https://search.maven.org",
}

func (l *HTTPVersionLister) baseURL(eco string) string {
	if l.BaseURLs != nil {
		if u, ok := l.BaseURLs[eco]; ok && strings.TrimSpace(u) != "" {
			return strings.TrimRight(u, "/")
		}
	}
	return strings.TrimRight(defaultBaseURLs[eco], "/")
}

// Versions implements VersionLister. It dispatches on the canonical ecosystem to
// the appropriate registry index endpoint and parser.
func (l *HTTPVersionLister) Versions(ctx context.Context, ecosystem, name string) ([]string, error) {
	eco := normalizeEco(ecosystem)
	base := l.baseURL(eco)
	if base == "" {
		return nil, nil // unsupported ecosystem → no candidates
	}
	switch eco {
	case "npm":
		return l.listNpm(ctx, base, name)
	case "pip":
		return l.listPyPI(ctx, base, name)
	case "cargo":
		return l.listCargo(ctx, base, name)
	case "go":
		return l.listGo(ctx, base, name)
	case "nuget":
		return l.listNuGet(ctx, base, name)
	case "rubygems":
		return l.listRubyGems(ctx, base, name)
	case "composer":
		return l.listComposer(ctx, base, name)
	case "maven":
		return l.listMaven(ctx, base, name)
	default:
		return nil, nil
	}
}

// fetch performs a GET and returns the (bounded) body. A 404/410 is reported as
// a non-error empty body so the caller yields "no versions" rather than an error.
func (l *HTTPVersionLister) fetch(ctx context.Context, u string) (body []byte, found bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", l.UserAgent)
	req.Header.Set("Accept", "application/json, text/plain")
	resp, err := l.Client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
	}()
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return nil, false, nil
	case resp.StatusCode != http.StatusOK:
		return nil, false, fmt.Errorf("remediation: %s returned status %d", u, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxVersionListBytes))
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

// --- npm -------------------------------------------------------------------

func (l *HTTPVersionLister) listNpm(ctx context.Context, base, name string) ([]string, error) {
	data, found, err := l.fetch(ctx, base+"/"+npmEscape(name))
	if err != nil || !found {
		return nil, err
	}
	var doc struct {
		Versions map[string]json.RawMessage `json:"versions"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return keys(doc.Versions), nil
}

func npmEscape(name string) string {
	if strings.HasPrefix(name, "@") {
		if i := strings.IndexByte(name, '/'); i > 0 {
			return url.PathEscape(name[:i]) + "/" + url.PathEscape(name[i+1:])
		}
	}
	return url.PathEscape(name)
}

// --- PyPI ------------------------------------------------------------------

func (l *HTTPVersionLister) listPyPI(ctx context.Context, base, name string) ([]string, error) {
	data, found, err := l.fetch(ctx, base+"/pypi/"+url.PathEscape(name)+"/json")
	if err != nil || !found {
		return nil, err
	}
	var doc struct {
		Releases map[string]json.RawMessage `json:"releases"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return keys(doc.Releases), nil
}

// --- crates.io -------------------------------------------------------------

func (l *HTTPVersionLister) listCargo(ctx context.Context, base, name string) ([]string, error) {
	data, found, err := l.fetch(ctx, base+"/api/v1/crates/"+url.PathEscape(name))
	if err != nil || !found {
		return nil, err
	}
	var doc struct {
		Versions []struct {
			Num    string `json:"num"`
			Yanked bool   `json:"yanked"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(doc.Versions))
	for _, v := range doc.Versions {
		if v.Yanked {
			continue
		}
		out = append(out, v.Num)
	}
	return out, nil
}

// --- Go modules ------------------------------------------------------------

func (l *HTTPVersionLister) listGo(ctx context.Context, base, name string) ([]string, error) {
	mod := goModuleEscape(name)
	data, found, err := l.fetch(ctx, base+"/"+mod+"/@v/list")
	if err != nil || !found {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if v := strings.TrimSpace(line); v != "" {
			out = append(out, v)
		}
	}
	return out, nil
}

func goModuleEscape(s string) string {
	var b strings.Builder
	for _, ch := range s {
		if ch >= 'A' && ch <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(ch + ('a' - 'A'))
		} else {
			b.WriteRune(ch)
		}
	}
	return b.String()
}

// --- NuGet -----------------------------------------------------------------

func (l *HTTPVersionLister) listNuGet(ctx context.Context, base, name string) ([]string, error) {
	// The flat-container index lists all published versions of a package id.
	flatBase := base
	if l.BaseURLs == nil || l.BaseURLs["nuget"] == "" {
		flatBase = "https://api.nuget.org/v3-flatcontainer"
	}
	id := strings.ToLower(name)
	data, found, err := l.fetch(ctx, strings.TrimRight(flatBase, "/")+"/"+url.PathEscape(id)+"/index.json")
	if err != nil || !found {
		return nil, err
	}
	var doc struct {
		Versions []string `json:"versions"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return doc.Versions, nil
}

// --- RubyGems --------------------------------------------------------------

func (l *HTTPVersionLister) listRubyGems(ctx context.Context, base, name string) ([]string, error) {
	data, found, err := l.fetch(ctx, base+"/api/v1/versions/"+url.PathEscape(name)+".json")
	if err != nil || !found {
		return nil, err
	}
	var versions []struct {
		Number string `json:"number"`
	}
	if err := json.Unmarshal(data, &versions); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(versions))
	for _, v := range versions {
		out = append(out, v.Number)
	}
	return out, nil
}

// --- Composer / Packagist --------------------------------------------------

func (l *HTTPVersionLister) listComposer(ctx context.Context, base, name string) ([]string, error) {
	n := strings.ToLower(name)
	data, found, err := l.fetch(ctx, base+"/p2/"+n+".json")
	if err != nil || !found {
		return nil, err
	}
	var doc struct {
		Packages map[string][]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var out []string
	for _, v := range doc.Packages[n] {
		out = append(out, v.Version)
	}
	return out, nil
}

// --- Maven Central ---------------------------------------------------------

func (l *HTTPVersionLister) listMaven(ctx context.Context, base, name string) ([]string, error) {
	group, artifact, ok := splitMavenCoordinate(name)
	if !ok {
		return nil, nil
	}
	q := fmt.Sprintf("g:%q AND a:%q", group, artifact)
	u := base + "/solrsearch/select?core=gav&rows=200&wt=json&q=" + url.QueryEscape(q)
	data, found, err := l.fetch(ctx, u)
	if err != nil || !found {
		return nil, err
	}
	var doc struct {
		Response struct {
			Docs []struct {
				V string `json:"v"`
			} `json:"docs"`
		} `json:"response"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(doc.Response.Docs))
	for _, d := range doc.Response.Docs {
		if d.V != "" {
			out = append(out, d.V)
		}
	}
	return out, nil
}

func splitMavenCoordinate(name string) (group, artifact string, ok bool) {
	if i := strings.LastIndexByte(name, ':'); i > 0 && i < len(name)-1 {
		return name[:i], name[i+1:], true
	}
	if i := strings.LastIndexByte(name, '/'); i > 0 && i < len(name)-1 {
		return strings.ReplaceAll(name[:i], "/", "."), name[i+1:], true
	}
	return "", "", false
}

// --- shared helpers --------------------------------------------------------

// normalizeEco lower-cases and trims an ecosystem label, folding the common
// aliases onto the canonical registry keys used by defaultBaseURLs.
func normalizeEco(eco string) string {
	switch e := strings.ToLower(strings.TrimSpace(eco)); e {
	case "pypi", "python":
		return "pip"
	case "crates", "crates.io":
		return "cargo"
	case "golang", "gomod":
		return "go"
	case "gem", "gems":
		return "rubygems"
	case "packagist", "php":
		return "composer"
	default:
		return e
	}
}

func keys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
