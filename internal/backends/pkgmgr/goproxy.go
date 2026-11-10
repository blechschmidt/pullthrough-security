package pkgmgr

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
)

// defaultGoSumDB is the checksum database the go command uses by default.
const defaultGoSumDB = "sum.golang.org"

// goSumDBPrefix is the GOPROXY path under which a proxy serves checksum
// databases ("<proxy>/sumdb/<database-name>/<database-path>").
const goSumDBPrefix = "/sumdb/"

// metaGoSumDBSupported marks the synthesized "<proxy>/sumdb/<name>/supported"
// probe response, carried from Resolve to Fetch.
const metaGoSumDBSupported = "_gosumdb_supported"

// NewGoProxy builds a pull-through backend speaking the Go module proxy protocol
// (GOPROXY; the public default is https://proxy.golang.org).
//
// Protocol mapping (https://go.dev/ref/mod#goproxy-protocol). Every resource is
// addressed relative to the proxy base, so no URL rewriting is required — Go
// clients simply set GOPROXY to "<publicBase>".
//
//	/<module>/@v/list           list of versions          (mutable)
//	/<module>/@latest           latest version metadata    (mutable)
//	/<module>/@v/<version>.info  version metadata (JSON)   (immutable per version)
//	/<module>/@v/<version>.mod   go.mod file               (immutable)
//	/<module>/@v/<version>.zip   module zip                (immutable)
//
// The per-version .info/.mod/.zip resources are immutable and cached
// aggressively; @v/list and @latest are revalidated.
//
// # Checksum database
//
// The go command authenticates every module it downloads against a checksum
// database (sum.golang.org) and, by default, contacts that database directly.
// A client that may only reach the proxy — the normal posture where a
// pull-through proxy is deployed for supply-chain control — therefore fails
// every download with "verifying module: ... dial tcp: ..." unless checksum
// verification is switched off, which is exactly what must not happen. The
// GOPROXY protocol solves this: a proxy may serve the database itself under
//
//	/sumdb/<name>/supported      200 => "this proxy proxies database <name>"
//	/sumdb/<name>/<path>         the database's /latest, /lookup/…, /tile/…
//
// and the go command then routes its checksum lookups through the proxy. The
// backend implements this for the databases named in the "sumdb" setting. Doing
// so costs no trust: every response is a signed tree head or is verified against
// one with the database's public key built into the go command, so the proxy can
// relay the database but cannot forge it.
//
// Settings:
//
//	"sumdb"  space- or comma-separated checksum database names to proxy
//	         (default "sum.golang.org"; "off" disables it, so a database request
//	         is forwarded to the upstream proxy like any other path)
func NewGoProxy(opts Options) (backends.Backend, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	sumdbs, err := parseGoSumDBs(opts.setting("sumdb", defaultGoSumDB))
	if err != nil {
		return nil, fmt.Errorf("pkgmgr %q: %w", opts.Name, err)
	}

	inner, err := httpbackend.New(httpbackend.Options{
		Name:        opts.Name,
		BaseURL:     opts.UpstreamURL,
		Client:      opts.Client,
		Credentials: opts.Credentials,
		Cacheable:   goCacheable,
		Coordinator: goCoordinate,
		AbsoluteRouter: func(req *backends.Request) (string, bool) {
			return goSumDBURL(req.Path, sumdbs)
		},
	})
	if err != nil {
		return nil, err
	}
	if len(sumdbs) == 0 {
		return inner, nil
	}
	return &goBackend{Backend: inner, sumdbs: sumdbs}, nil
}

// parseGoSumDBs parses the "sumdb" setting into the set of checksum database
// names the backend proxies. "off" (or "none") yields the empty set.
func parseGoSumDBs(setting string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, name := range strings.FieldsFunc(setting, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		switch strings.ToLower(name) {
		case "off", "none":
			return map[string]bool{}, nil
		}
		if !validGoSumDBName(name) {
			return nil, fmt.Errorf("invalid checksum database name %q in the sumdb setting (want a host name such as %s)", name, defaultGoSumDB)
		}
		out[name] = true
	}
	return out, nil
}

// validGoSumDBName reports whether name is a plain host name. The name becomes
// the host of the URL the proxy fetches, so anything that could smuggle a path,
// a port, userinfo or a scheme into that URL is refused.
func validGoSumDBName(name string) bool {
	if name == "" || len(name) > 253 || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") ||
		strings.HasPrefix(name, "-") || !strings.Contains(name, ".") {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
		default:
			return false
		}
	}
	return true
}

// splitGoSumDBPath splits "/sumdb/<name>/<rest>" into its database name and the
// database-relative path. ok is false for any other path.
func splitGoSumDBPath(p string) (name, rest string, ok bool) {
	if !strings.HasPrefix(p, goSumDBPrefix) {
		return "", "", false
	}
	name, rest, found := strings.Cut(strings.TrimPrefix(p, goSumDBPrefix), "/")
	if !found || name == "" || rest == "" {
		return "", "", false
	}
	return name, rest, true
}

// goSumDBURL maps a "/sumdb/<name>/<path>" request for a proxied database onto
// the database's own URL ("https://<name>/<path>"). It returns ok=false for
// every other request — including a database that is not on the allowlist — so
// the backend never fetches a host the operator did not name (no open relay).
func goSumDBURL(p string, sumdbs map[string]bool) (string, bool) {
	name, rest, ok := splitGoSumDBPath(p)
	if !ok || !sumdbs[name] {
		return "", false
	}
	// A database path is one of latest, lookup/<module>@<version>,
	// tile/<height>/<level>/<n…>; reject traversal rather than normalize it.
	for _, seg := range strings.Split(rest, "/") {
		if seg == "." || seg == ".." {
			return "", false
		}
	}
	return "https://" + name + "/" + rest, true
}

// goBackend adds the one endpoint of the checksum-database proxy protocol that
// has no upstream counterpart: "/sumdb/<name>/supported", the probe by which the
// go command asks whether this proxy serves database <name>. The database
// itself has no such path; the proxy answers it. Every other request is served
// by the embedded generic backend (which routes the database's real paths to
// the database through goSumDBURL).
type goBackend struct {
	backends.Backend
	sumdbs map[string]bool
}

// Resolve implements backends.Backend.
func (b *goBackend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	if req != nil {
		if name, rest, ok := splitGoSumDBPath(req.Path); ok && rest == "supported" && b.sumdbs[name] {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return &backends.Resolved{
				UpstreamURL: "https://" + name + "/",
				CacheKey:    b.Name() + ":sumdb/" + name + "/supported",
				Cacheable:   false,
				MediaType:   "text/plain; charset=utf-8",
				Metadata:    map[string]string{"backend": b.Name(), metaGoSumDBSupported: "1"},
			}, nil
		}
	}
	return b.Backend.Resolve(ctx, req)
}

// Fetch implements backends.Backend.
func (b *goBackend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved != nil && resolved.Metadata[metaGoSumDBSupported] == "1" {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// The go command only inspects the status; the body is ignored.
		return &backends.FetchResult{
			Resolved:  resolved,
			Content:   io.NopCloser(strings.NewReader("")),
			Size:      0,
			MediaType: resolved.MediaType,
			Header:    http.Header{},
			Status:    http.StatusOK,
		}, nil
	}
	return b.Backend.Fetch(ctx, resolved)
}

// goCacheable caches immutable per-version resources (.info/.mod/.zip) forever
// while leaving the mutable listing endpoints (@v/list, @latest) to be
// revalidated on each request. Checksum-database paths are never cached: the
// tree head (/latest, and the one embedded in every /lookup) advances over time.
func goCacheable(req *backends.Request) bool {
	p := req.Path
	if strings.HasPrefix(p, goSumDBPrefix) {
		return false
	}
	if !strings.Contains(p, "/@v/") {
		return false // @latest and any non-versioned path
	}
	if strings.HasSuffix(p, "/@v/list") {
		return false
	}
	return strings.HasSuffix(p, ".info") ||
		strings.HasSuffix(p, ".mod") ||
		strings.HasSuffix(p, ".zip")
}
