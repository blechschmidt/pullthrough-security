package maturity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// maxMetadataBytes bounds a single registry metadata response the resolver
// parses, protecting against a hostile or runaway upstream.
const maxMetadataBytes = 32 << 20 // 32 MiB

// Doer is the minimal HTTP client surface the resolver needs; *http.Client
// satisfies it and tests inject a stub.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// HTTPResolver derives publish timestamps by querying the public metadata
// endpoint of each supported ecosystem's registry. It parses only the timestamp
// it needs and returns ok=false for any ecosystem it does not support or that
// exposes no usable timestamp, so the gate fails open for those.
//
// Endpoints can be overridden per ecosystem (keyed by canonical ecosystem name)
// for private mirrors or testing; an absent override uses the public default.
type HTTPResolver struct {
	// Client performs the metadata requests (default http.DefaultClient).
	Client Doer
	// UserAgent is sent with each request; some registries (crates.io) reject a
	// missing/empty User-Agent.
	UserAgent string
	// BaseURLs overrides the registry base URL per canonical ecosystem.
	BaseURLs map[string]string
}

// NewHTTPResolver builds an HTTPResolver with sane defaults.
func NewHTTPResolver(client Doer, userAgent string) *HTTPResolver {
	if client == nil {
		client = http.DefaultClient
	}
	if strings.TrimSpace(userAgent) == "" {
		userAgent = "pullthrough-security-maturity-gate/1.0"
	}
	return &HTTPResolver{Client: client, UserAgent: userAgent}
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

func (r *HTTPResolver) baseURL(eco string) string {
	if r.BaseURLs != nil {
		if u, ok := r.BaseURLs[eco]; ok && strings.TrimSpace(u) != "" {
			return strings.TrimRight(u, "/")
		}
	}
	return strings.TrimRight(defaultBaseURLs[eco], "/")
}

// PublishedAt implements TimestampResolver. It dispatches on the canonical
// ecosystem to the appropriate metadata endpoint and parser.
func (r *HTTPResolver) PublishedAt(ctx context.Context, c Coordinate) (time.Time, bool, error) {
	eco := normalizeEco(c.Ecosystem)
	base := r.baseURL(eco)
	if base == "" {
		return time.Time{}, false, nil // unsupported ecosystem → unknown, fail open
	}
	switch eco {
	case "npm":
		return r.resolveNpm(ctx, base, c)
	case "pip":
		return r.resolvePyPI(ctx, base, c)
	case "cargo":
		return r.resolveCargo(ctx, base, c)
	case "go":
		return r.resolveGo(ctx, base, c)
	case "nuget":
		return r.resolveNuGet(ctx, base, c)
	case "rubygems":
		return r.resolveRubyGems(ctx, base, c)
	case "composer":
		return r.resolveComposer(ctx, base, c)
	case "maven":
		return r.resolveMaven(ctx, base, c)
	default:
		return time.Time{}, false, nil
	}
}

// fetch performs a GET and returns the (bounded) body, or an error. A 404/410 is
// reported as a non-error "not found" via the second return value so the caller
// can distinguish "no such version" (unknown, fail open) from a transient error.
func (r *HTTPResolver) fetch(ctx context.Context, u string) (body []byte, found bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", r.UserAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := r.Client.Do(req)
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
		return nil, false, fmt.Errorf("maturity: %s returned status %d", u, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataBytes))
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

// --- npm -------------------------------------------------------------------

func (r *HTTPResolver) resolveNpm(ctx context.Context, base string, c Coordinate) (time.Time, bool, error) {
	u := base + "/" + npmEscape(c.Name)
	data, found, err := r.fetch(ctx, u)
	if err != nil || !found {
		return time.Time{}, false, err
	}
	return parseNpmTime(data, c.Version)
}

// parseNpmTime extracts the publish time of a version from a packument's "time"
// map (version -> ISO-8601). Exposed-as-helper to keep parsing unit-testable.
func parseNpmTime(data []byte, version string) (time.Time, bool, error) {
	var doc struct {
		Time map[string]string `json:"time"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return time.Time{}, false, err
	}
	v, ok := doc.Time[version]
	if !ok {
		return time.Time{}, false, nil
	}
	return parseTimestamp(v)
}

// npmEscape encodes a package name for a single registry path segment, keeping a
// scoped name's slash ("@scope/pkg") so the registry route resolves.
func npmEscape(name string) string {
	if strings.HasPrefix(name, "@") {
		if i := strings.IndexByte(name, '/'); i > 0 {
			return url.PathEscape(name[:i]) + "/" + url.PathEscape(name[i+1:])
		}
	}
	return url.PathEscape(name)
}

// --- PyPI ------------------------------------------------------------------

func (r *HTTPResolver) resolvePyPI(ctx context.Context, base string, c Coordinate) (time.Time, bool, error) {
	u := base + "/pypi/" + url.PathEscape(c.Name) + "/" + url.PathEscape(c.Version) + "/json"
	data, found, err := r.fetch(ctx, u)
	if err != nil || !found {
		return time.Time{}, false, err
	}
	return parsePyPITime(data)
}

// parsePyPITime extracts the earliest file upload time for a release from the
// PyPI JSON API's "urls" array, preferring the ISO-8601 field.
func parsePyPITime(data []byte) (time.Time, bool, error) {
	var doc struct {
		URLs []struct {
			UploadTimeISO string `json:"upload_time_iso_8601"`
			UploadTime    string `json:"upload_time"`
		} `json:"urls"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return time.Time{}, false, err
	}
	var earliest time.Time
	for _, f := range doc.URLs {
		raw := f.UploadTimeISO
		if raw == "" {
			raw = f.UploadTime
		}
		if raw == "" {
			continue
		}
		t, ok, err := parseTimestamp(raw)
		if err != nil || !ok {
			continue
		}
		if earliest.IsZero() || t.Before(earliest) {
			earliest = t
		}
	}
	if earliest.IsZero() {
		return time.Time{}, false, nil
	}
	return earliest, true, nil
}

// --- crates.io -------------------------------------------------------------

func (r *HTTPResolver) resolveCargo(ctx context.Context, base string, c Coordinate) (time.Time, bool, error) {
	u := base + "/api/v1/crates/" + url.PathEscape(c.Name) + "/" + url.PathEscape(c.Version)
	data, found, err := r.fetch(ctx, u)
	if err != nil || !found {
		return time.Time{}, false, err
	}
	return parseCargoTime(data)
}

func parseCargoTime(data []byte) (time.Time, bool, error) {
	var doc struct {
		Version struct {
			CreatedAt string `json:"created_at"`
		} `json:"version"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return time.Time{}, false, err
	}
	if doc.Version.CreatedAt == "" {
		return time.Time{}, false, nil
	}
	return parseTimestamp(doc.Version.CreatedAt)
}

// --- Go modules ------------------------------------------------------------

func (r *HTTPResolver) resolveGo(ctx context.Context, base string, c Coordinate) (time.Time, bool, error) {
	mod, err := goModuleEscape(c.Name)
	if err != nil {
		return time.Time{}, false, err
	}
	ver, err := goModuleEscape(c.Version)
	if err != nil {
		return time.Time{}, false, err
	}
	u := base + "/" + mod + "/@v/" + ver + ".info"
	data, found, err := r.fetch(ctx, u)
	if err != nil || !found {
		return time.Time{}, false, err
	}
	return parseGoInfoTime(data)
}

func parseGoInfoTime(data []byte) (time.Time, bool, error) {
	var doc struct {
		Time string `json:"Time"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return time.Time{}, false, err
	}
	if doc.Time == "" {
		return time.Time{}, false, nil
	}
	return parseTimestamp(doc.Time)
}

// goModuleEscape applies the Go module proxy's case-encoding (an uppercase
// letter is replaced by "!" + its lowercase form), then path-escapes the result.
func goModuleEscape(s string) (string, error) {
	var b strings.Builder
	for _, ch := range s {
		if ch >= 'A' && ch <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(ch + ('a' - 'A'))
		} else {
			b.WriteRune(ch)
		}
	}
	return b.String(), nil
}

// --- NuGet -----------------------------------------------------------------

func (r *HTTPResolver) resolveNuGet(ctx context.Context, base string, c Coordinate) (time.Time, bool, error) {
	id := strings.ToLower(c.Name)
	ver := strings.ToLower(c.Version)
	u := base + "/v3/registration5-gz-semver2/" + url.PathEscape(id) + "/" + url.PathEscape(ver) + ".json"
	data, found, err := r.fetch(ctx, u)
	if err != nil || !found {
		return time.Time{}, false, err
	}
	return parseNuGetTime(data)
}

func parseNuGetTime(data []byte) (time.Time, bool, error) {
	// A registration leaf carries "published" directly or under "catalogEntry".
	var doc struct {
		Published    string `json:"published"`
		CatalogEntry struct {
			Published string `json:"published"`
		} `json:"catalogEntry"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return time.Time{}, false, err
	}
	raw := doc.Published
	if raw == "" {
		raw = doc.CatalogEntry.Published
	}
	if raw == "" {
		return time.Time{}, false, nil
	}
	t, ok, err := parseTimestamp(raw)
	if err != nil || !ok {
		return time.Time{}, false, err
	}
	// NuGet uses a sentinel "1900-01-01" published date for unlisted/unknown.
	if t.Year() <= 1900 {
		return time.Time{}, false, nil
	}
	return t, true, nil
}

// --- RubyGems --------------------------------------------------------------

func (r *HTTPResolver) resolveRubyGems(ctx context.Context, base string, c Coordinate) (time.Time, bool, error) {
	u := base + "/api/v1/versions/" + url.PathEscape(c.Name) + ".json"
	data, found, err := r.fetch(ctx, u)
	if err != nil || !found {
		return time.Time{}, false, err
	}
	return parseRubyGemsTime(data, c.Version)
}

func parseRubyGemsTime(data []byte, version string) (time.Time, bool, error) {
	var versions []struct {
		Number    string `json:"number"`
		CreatedAt string `json:"created_at"`
		BuiltAt   string `json:"built_at"`
	}
	if err := json.Unmarshal(data, &versions); err != nil {
		return time.Time{}, false, err
	}
	for _, v := range versions {
		if v.Number != version {
			continue
		}
		raw := v.CreatedAt
		if raw == "" {
			raw = v.BuiltAt
		}
		if raw == "" {
			return time.Time{}, false, nil
		}
		return parseTimestamp(raw)
	}
	return time.Time{}, false, nil
}

// --- Composer / Packagist --------------------------------------------------

func (r *HTTPResolver) resolveComposer(ctx context.Context, base string, c Coordinate) (time.Time, bool, error) {
	name := strings.ToLower(c.Name)
	u := base + "/p2/" + name + ".json"
	data, found, err := r.fetch(ctx, u)
	if err != nil || !found {
		return time.Time{}, false, err
	}
	return parseComposerTime(data, name, c.Version)
}

func parseComposerTime(data []byte, name, version string) (time.Time, bool, error) {
	var doc struct {
		Packages map[string][]struct {
			Version string `json:"version"`
			Time    string `json:"time"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return time.Time{}, false, err
	}
	versions := doc.Packages[name]
	want := strings.TrimPrefix(strings.ToLower(version), "v")
	for _, v := range versions {
		if strings.TrimPrefix(strings.ToLower(v.Version), "v") != want {
			continue
		}
		if v.Time == "" {
			return time.Time{}, false, nil
		}
		return parseTimestamp(v.Time)
	}
	return time.Time{}, false, nil
}

// --- Maven Central ---------------------------------------------------------

func (r *HTTPResolver) resolveMaven(ctx context.Context, base string, c Coordinate) (time.Time, bool, error) {
	group, artifact, ok := splitMavenCoordinate(c.Name)
	if !ok {
		return time.Time{}, false, nil
	}
	q := fmt.Sprintf("g:%q AND a:%q AND v:%q", group, artifact, c.Version)
	u := base + "/solrsearch/select?core=gav&rows=1&wt=json&q=" + url.QueryEscape(q)
	data, found, err := r.fetch(ctx, u)
	if err != nil || !found {
		return time.Time{}, false, err
	}
	return parseMavenTime(data)
}

func parseMavenTime(data []byte) (time.Time, bool, error) {
	var doc struct {
		Response struct {
			Docs []struct {
				Timestamp int64 `json:"timestamp"`
			} `json:"docs"`
		} `json:"response"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return time.Time{}, false, err
	}
	if len(doc.Response.Docs) == 0 || doc.Response.Docs[0].Timestamp <= 0 {
		return time.Time{}, false, nil
	}
	// The solrsearch "timestamp" is epoch milliseconds.
	ms := doc.Response.Docs[0].Timestamp
	return time.UnixMilli(ms).UTC(), true, nil
}

// splitMavenCoordinate parses a Maven coordinate name into group and artifact,
// accepting either "group:artifact" or "group/artifact" (the latter with the
// final path segment as the artifact).
func splitMavenCoordinate(name string) (group, artifact string, ok bool) {
	if i := strings.LastIndexByte(name, ':'); i > 0 && i < len(name)-1 {
		return name[:i], name[i+1:], true
	}
	if i := strings.LastIndexByte(name, '/'); i > 0 && i < len(name)-1 {
		return strings.ReplaceAll(name[:i], "/", "."), name[i+1:], true
	}
	return "", "", false
}

// --- shared timestamp parsing ----------------------------------------------

// parseTimestamp parses the timestamp encodings the registries use: RFC 3339
// (with or without a 'Z'/offset), the PyPI "2006-01-02T15:04:05" form, and an
// epoch-seconds or -milliseconds integer string. It returns ok=false for an
// empty/zero value.
func parseTimestamp(raw string) (time.Time, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false, nil
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05 -0700",
		"2006-01-02 15:04:05 UTC",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC(), true, nil
		}
	}
	// Epoch seconds or milliseconds.
	if n, err := strconv.ParseInt(raw, 10, 64); err == nil && n > 0 {
		if n > 1e12 { // plausibly milliseconds
			return time.UnixMilli(n).UTC(), true, nil
		}
		return time.Unix(n, 0).UTC(), true, nil
	}
	return time.Time{}, false, fmt.Errorf("maturity: unrecognized timestamp %q", raw)
}
