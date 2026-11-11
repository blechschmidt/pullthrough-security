// Package pkgmgr implements the per-ecosystem pull-through backends for the
// common language package managers: pip (PyPI), npm, cargo (crates.io), Go
// modules (GOPROXY), and NuGet. Each backend maps its registry's wire protocol
// onto the generic HTTP pull-through engine (internal/backends/httpbackend) by
// supplying:
//
//   - a Router (and, for ecosystems whose artifacts live on a separate host, an
//     AbsoluteRouter) that translates inbound proxy paths to upstream URLs;
//   - a Cacheability policy that caches immutable artifacts (tarballs, wheels,
//     .crate/.nupkg/.zip files) aggressively while revalidating mutable index
//     documents;
//   - an index-document Rewriter that rewrites embedded artifact URLs so clients
//     fetch dependent content back through the proxy rather than going direct to
//     the upstream;
//   - a Classifier that tells the content gates which paths are installable
//     payloads and which are metadata documents, and says nothing about a path
//     the registry protocol does not define.
//
// Construct a backend with Build (dispatching on the ecosystem type) or with the
// per-ecosystem constructors (NewNPM, NewPyPI, NewCargo, NewGoProxy, NewNuGet).
//
// Client-side configuration to point each tool at the proxy is documented in
// docs/clients.md.
package pkgmgr

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// Options configures construction of an ecosystem backend.
type Options struct {
	// Name is the route identifier and cache-key prefix (e.g. "npm"). Required.
	Name string
	// UpstreamURL is the primary upstream base URL for the ecosystem (the index
	// host). Required.
	UpstreamURL string
	// PublicBaseURL is the externally reachable base URL under which this
	// backend is served, e.g. "https://proxy.example.com/v1/npm". It is used to
	// rewrite index documents so dependent artifacts route back through the
	// proxy. When empty, rewritten links fall back to the root-relative
	// "/v1/<name>" form (see PublicBase).
	PublicBaseURL string
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool can be injected in place
	// of the bare *upstream.Client to add failover transparently.
	Client upstream.Doer
	// Credentials authenticate the proxy to the upstream. Optional.
	Credentials upstream.Credentials
	// Settings carries ecosystem-specific tuning (see each constructor for the
	// keys it consults). Optional.
	Settings map[string]string
}

func (o Options) setting(key, def string) string {
	if o.Settings != nil {
		if v, ok := o.Settings[key]; ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return def
}

// publicBase returns the backend's public base URL with any trailing slash
// removed. When PublicBaseURL is empty it falls back to the root-relative
// "/v1/<name>" form, which most clients resolve correctly against the registry
// URL they were configured with.
func (o Options) publicBase() string {
	if b := strings.TrimRight(o.PublicBaseURL, "/"); b != "" {
		return b
	}
	return PublicBase("", o.Name)
}

// routePrefix is the path prefix under which the gateway mounts backends. It
// mirrors the gateway's routing ("/v1/<backend>/...") and is used to synthesize
// public artifact URLs during index rewriting.
const routePrefix = "/v1/"

// PublicBase composes the externally reachable base URL for a backend from the
// proxy's public URL and the backend name. When publicURL is empty the result is
// the root-relative form "/v1/<name>".
func PublicBase(publicURL, name string) string {
	base := strings.TrimRight(publicURL, "/")
	return base + routePrefix + name
}

// Build constructs the backend for the given ecosystem type. It returns an error
// for ecosystems handled by other backends (git, docker) or unknown types.
func Build(ecosystem string, opts Options) (backends.Backend, error) {
	switch ecosystem {
	case "npm":
		return NewNPM(opts)
	case "pip":
		return NewPyPI(opts)
	case "cargo":
		return NewCargo(opts)
	case "go":
		return NewGoProxy(opts)
	case "nuget":
		return NewNuGet(opts)
	default:
		return nil, fmt.Errorf("pkgmgr: no package-manager backend for ecosystem %q", ecosystem)
	}
}

// validate checks the fields common to every constructor.
func (o Options) validate() error {
	if strings.TrimSpace(o.Name) == "" {
		return fmt.Errorf("pkgmgr: name is required")
	}
	if strings.TrimSpace(o.UpstreamURL) == "" {
		return fmt.Errorf("pkgmgr %q: upstream URL is required", o.Name)
	}
	if o.Client == nil {
		return fmt.Errorf("pkgmgr %q: upstream client is required", o.Name)
	}
	return nil
}

// plainSegments splits a request path into its segments for the classifiers
// (npmClassify and its siblings) that decide whether the path names a metadata
// document. It reports ok=false unless the path is plain: a leading slash, then
// non-empty segments written only in the characters of package names, versions
// and the registries' fixed path elements.
//
// A resource classified as metadata is served without being examined, so the
// claim has to hold for the bytes the upstream actually answers with. The
// generic engine forwards a request path as written, and the gateway hands it
// over percent-decoded, so a client can send what no package manager would: "."
// and ".." segments, a doubled slash, a backslash, a ";" path parameter, a
// second layer of percent-encoding. Upstream servers resolve each of these in
// their own way — to a path other than the one the classifier read. Such a path
// names nothing a registry protocol defines: it is left unclassified, and a gate
// judges the response from its bytes.
func plainSegments(p string) (segs []string, ok bool) {
	if !strings.HasPrefix(p, "/") {
		return nil, false
	}
	segs = strings.Split(p[1:], "/")
	for _, s := range segs {
		if !plainSegment(s) {
			return nil, false
		}
	}
	return segs, true
}

// plainSegment reports whether s is a plain path segment: not empty, not a dot
// segment, and written only in plain path bytes.
func plainSegment(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !plainPathByte(s[i]) {
			return false
		}
	}
	return true
}

// plainPathByte reports whether c may appear in a plain path segment: letters,
// digits, and the punctuation names and versions are written with — "." "_" "-"
// "~", "+" (version build metadata), "!" (Go's case escape, a PEP 440 epoch) and
// "@" (an npm scope, the GOPROXY "@v" and "@latest" elements).
func plainPathByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '.', '_', '-', '~', '+', '!', '@':
		return true
	}
	return false
}

// hasAnySuffix reports whether s ends with one of suffixes.
func hasAnySuffix(s string, suffixes []string) bool {
	for _, sfx := range suffixes {
		if strings.HasSuffix(s, sfx) {
			return true
		}
	}
	return false
}

// rewriteRule maps an absolute upstream URL prefix onto a proxy prefix.
type rewriteRule struct {
	from string
	to   string
}

// applyRules performs literal prefix substitution for each rule, in order. It is
// used to rewrite absolute artifact URLs embedded in index documents (JSON or
// HTML) so they point back through the proxy. Literal substitution is sufficient
// because the upstream emits canonical, fully qualified URLs.
func applyRules(body []byte, rules []rewriteRule) []byte {
	for _, r := range rules {
		if r.from == "" || r.from == r.to {
			continue
		}
		body = bytes.ReplaceAll(body, []byte(r.from), []byte(r.to))
	}
	return body
}
