package continuity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// maxMetadataBytes bounds a single registry metadata response the resolver
// parses, protecting against a hostile or runaway upstream.
const maxMetadataBytes = 32 << 20 // 32 MiB

// Doer is the minimal HTTP client surface the resolver needs; *http.Client
// satisfies it and tests inject a stub.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// HTTPResolver derives publisher identities by querying the public metadata
// endpoint of each supported ecosystem's registry. It extracts the maintainer
// roster where the registry exposes one (npm, PyPI, RubyGems, crates.io) and
// always derives the ownership namespace from the coordinate (npm @scope, Maven
// groupId, Go module path, Composer vendor). It returns ok=false for an ecosystem
// it does not support, so the gate fails open for those.
//
// Endpoints can be overridden per ecosystem (keyed by canonical ecosystem name)
// for private mirrors or testing; an absent override uses the public default.
type HTTPResolver struct {
	Client    Doer
	UserAgent string
	BaseURLs  map[string]string
}

// NewHTTPResolver builds an HTTPResolver with sane defaults.
func NewHTTPResolver(client Doer, userAgent string) *HTTPResolver {
	if client == nil {
		client = http.DefaultClient
	}
	if strings.TrimSpace(userAgent) == "" {
		userAgent = "pullthrough-security-continuity-gate/1.0"
	}
	return &HTTPResolver{Client: client, UserAgent: userAgent}
}

// defaultBaseURLs maps each supported ecosystem to its public registry base.
var defaultBaseURLs = map[string]string{
	"npm":      "https://registry.npmjs.org",
	"pip":      "https://pypi.org",
	"cargo":    "https://crates.io",
	"rubygems": "https://rubygems.org",
}

func (r *HTTPResolver) baseURL(eco string) string {
	if r.BaseURLs != nil {
		if u, ok := r.BaseURLs[eco]; ok && strings.TrimSpace(u) != "" {
			return strings.TrimRight(u, "/")
		}
	}
	return strings.TrimRight(defaultBaseURLs[eco], "/")
}

// Publishers implements PublisherResolver. It dispatches on the canonical
// ecosystem to the appropriate metadata endpoint and parser, then always layers
// the coordinate-derived ownership namespace on top so even an ecosystem without
// a maintainer roster contributes a namespace principal.
func (r *HTTPResolver) Publishers(ctx context.Context, c Coordinate) (Identity, bool, error) {
	eco := normalizeEco(c.Ecosystem)
	id := Identity{Namespace: namespaceFor(eco, c.Name)}

	var (
		fromRegistry Identity
		found        bool
		err          error
	)
	switch eco {
	case "npm":
		fromRegistry, found, err = r.resolveNpm(ctx, c)
	case "pip":
		fromRegistry, found, err = r.resolvePyPI(ctx, c)
	case "rubygems":
		fromRegistry, found, err = r.resolveRubyGems(ctx, c)
	case "cargo":
		fromRegistry, found, err = r.resolveCargo(ctx, c)
	}
	if err != nil {
		// A transient registry error still lets the namespace principal stand when we
		// have one, so a hijack across a namespace boundary is not silently missed.
		if id.Namespace != "" {
			return id, true, nil
		}
		return Identity{}, false, err
	}
	id.Maintainers = fromRegistry.Maintainers
	if id.Namespace == "" {
		id.Namespace = fromRegistry.Namespace
	}
	if id.empty() {
		return Identity{}, false, nil
	}
	return id, found || id.Namespace != "", nil
}

// namespaceFor derives the ownership namespace from a coordinate name: an npm
// @scope, a Maven groupId, a Go module path (host + first segment), or a Composer
// vendor. Ecosystems with no meaningful namespace return "".
func namespaceFor(eco, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	switch eco {
	case "npm":
		if strings.HasPrefix(name, "@") {
			if i := strings.IndexByte(name, '/'); i > 0 {
				return name[:i]
			}
		}
		return ""
	case "maven":
		if i := strings.LastIndexByte(name, ':'); i > 0 {
			return name[:i]
		}
		if i := strings.LastIndexByte(name, '/'); i > 0 {
			return strings.ReplaceAll(name[:i], "/", ".")
		}
		return ""
	case "go":
		// host + first path element, e.g. github.com/owner.
		parts := strings.SplitN(name, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
		return name
	case "composer":
		if i := strings.IndexByte(name, '/'); i > 0 {
			return name[:i]
		}
		return ""
	default:
		return ""
	}
}

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
		return nil, false, fmt.Errorf("continuity: %s returned status %d", u, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataBytes))
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

// --- npm -------------------------------------------------------------------

func (r *HTTPResolver) resolveNpm(ctx context.Context, c Coordinate) (Identity, bool, error) {
	base := r.baseURL("npm")
	if base == "" {
		return Identity{}, false, nil
	}
	data, found, err := r.fetch(ctx, base+"/"+npmEscape(c.Name))
	if err != nil || !found {
		return Identity{}, false, err
	}
	return parseNpmMaintainers(data), true, nil
}

// parseNpmMaintainers extracts the package-level maintainer roster from a
// packument. It is exported-as-helper for unit testing.
func parseNpmMaintainers(data []byte) Identity {
	var doc struct {
		Maintainers []struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"maintainers"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return Identity{}
	}
	var id Identity
	for _, m := range doc.Maintainers {
		if v := strings.TrimSpace(m.Name); v != "" {
			id.Maintainers = append(id.Maintainers, v)
		} else if v := strings.TrimSpace(m.Email); v != "" {
			id.Maintainers = append(id.Maintainers, v)
		}
	}
	return id
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

func (r *HTTPResolver) resolvePyPI(ctx context.Context, c Coordinate) (Identity, bool, error) {
	base := r.baseURL("pip")
	if base == "" {
		return Identity{}, false, nil
	}
	u := base + "/pypi/" + url.PathEscape(c.Name) + "/json"
	data, found, err := r.fetch(ctx, u)
	if err != nil || !found {
		return Identity{}, false, err
	}
	return parsePyPIMaintainers(data), true, nil
}

func parsePyPIMaintainers(data []byte) Identity {
	var doc struct {
		Info struct {
			Author          string `json:"author"`
			AuthorEmail     string `json:"author_email"`
			Maintainer      string `json:"maintainer"`
			MaintainerEmail string `json:"maintainer_email"`
		} `json:"info"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return Identity{}
	}
	var id Identity
	for _, v := range []string{doc.Info.Author, doc.Info.AuthorEmail, doc.Info.Maintainer, doc.Info.MaintainerEmail} {
		if v = strings.TrimSpace(v); v != "" {
			id.Maintainers = append(id.Maintainers, v)
		}
	}
	return id
}

// --- RubyGems --------------------------------------------------------------

func (r *HTTPResolver) resolveRubyGems(ctx context.Context, c Coordinate) (Identity, bool, error) {
	base := r.baseURL("rubygems")
	if base == "" {
		return Identity{}, false, nil
	}
	u := base + "/api/v1/gems/" + url.PathEscape(c.Name) + ".json"
	data, found, err := r.fetch(ctx, u)
	if err != nil || !found {
		return Identity{}, false, err
	}
	return parseRubyGemsMaintainers(data), true, nil
}

func parseRubyGemsMaintainers(data []byte) Identity {
	var doc struct {
		Authors string `json:"authors"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return Identity{}
	}
	var id Identity
	for _, a := range strings.Split(doc.Authors, ",") {
		if v := strings.TrimSpace(a); v != "" {
			id.Maintainers = append(id.Maintainers, v)
		}
	}
	return id
}

// --- crates.io -------------------------------------------------------------

func (r *HTTPResolver) resolveCargo(ctx context.Context, c Coordinate) (Identity, bool, error) {
	base := r.baseURL("cargo")
	if base == "" {
		return Identity{}, false, nil
	}
	u := base + "/api/v1/crates/" + url.PathEscape(c.Name) + "/owners"
	data, found, err := r.fetch(ctx, u)
	if err != nil || !found {
		return Identity{}, false, err
	}
	return parseCargoOwners(data), true, nil
}

func parseCargoOwners(data []byte) Identity {
	var doc struct {
		Users []struct {
			Login string `json:"login"`
			Name  string `json:"name"`
		} `json:"users"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return Identity{}
	}
	var id Identity
	for _, u := range doc.Users {
		if v := strings.TrimSpace(u.Login); v != "" {
			id.Maintainers = append(id.Maintainers, v)
		} else if v := strings.TrimSpace(u.Name); v != "" {
			id.Maintainers = append(id.Maintainers, v)
		}
	}
	return id
}
