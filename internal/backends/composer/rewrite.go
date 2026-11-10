package composer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// A Composer client does exactly what the repository's documents tell it to: the
// root packages.json names the URL templates it expands for every later lookup,
// and each version in a v2 metadata document names the URL its archive is
// downloaded from. Served unmodified, both send the client straight back to the
// upstream — Packagist for metadata, GitHub for archives — so only the very first
// request would ever touch the proxy, and no archive would be cached, verified or
// admission-gated. This file rewrites both documents so that a client configured
// with nothing but the proxy repository keeps every metadata and dist request on
// the proxy.
//
// Rewritten URLs are built from the backend's public base. When the proxy knows
// its absolute public URL they are absolute. When it does not, the base is the
// root-relative mount ("/v1/<name>"): Composer resolves a root-relative template
// in packages.json against the repository's own scheme and host, so the lookups
// still work. A root-relative "dist.url" is different — Composer does not resolve
// it (it would read it as a local file path) — so in that mode the root document
// additionally advertises the dist endpoint as a preferred dist mirror, a
// template Composer does resolve against the repository host. Either way the
// upstream's dist URL is replaced, never merely supplemented: there is no
// upstream location left for a client to fall back to when the proxy refuses an
// archive.

// distMirrorTemplate is the dist endpoint expressed as a Composer dist-mirror
// template (relative to the public base). Composer substitutes the package name,
// the version as the metadata spells it, the dist reference and the dist type,
// which yields exactly the locator distPath builds for a version whose reference
// is a commit id.
//
// The expansion is Composer's, not the proxy's, and it is cruder than distPath:
// a reference that is not lowercase hex is replaced by its MD5, and the version
// is inserted without URL-encoding. A dist with such a reference, or a version
// containing a character like "#" or "?", is therefore not downloadable in the
// no-public-base mode (the request simply does not resolve); configuring the
// public URL lifts the limitation.
const distMirrorTemplate = "/dist/%package%/%prettyVersion%/%reference%.%type%"

// Lookup templates for the documents this backend serves itself. They are fixed
// rather than derived from the upstream's values because these are the only
// layouts the backend can route (see classify), and they are where it reads the
// upstream's documents from.
const (
	metadataURLTemplate      = "/p2/%package%.json"
	providersURLTemplate     = "/p/%package%$%hash%.json"
	providersLazyURLTemplate = "/p/%package%.json"
)

// rewriteRoot rewrites a packages.json repository root so that every lookup it
// advertises either comes back through this backend or is not advertised at all.
// The guiding rule: a client with no direct route to the upstream (or to the
// hosts the upstream delegates to) must still be able to install, and must not be
// told to send anything — telemetry least of all — around the proxy.
//
// Per key:
//
//   - "metadata-url", "providers-url", "providers-lazy-url": REWRITTEN to this
//     backend's own /p2 and /p routes under the public base. These are the
//     package lookups; the upstream's absolute or host-root-relative values would
//     take the client to the upstream, or to the proxy's host root instead of the
//     backend's mount.
//
//   - "notify-batch", "notify": REMOVED. They name the endpoint a client POSTs
//     its install statistics to. The proxy serves reads only, so it cannot relay
//     them, and leaving the upstream value would have every client report its
//     installs around the proxy.
//
//   - "search", "list", "providers-api": REMOVED. They are optional discovery
//     APIs (full-text search, package-name listing, "who provides X" hints) that
//     this backend does not front; on Packagist they even live on a different
//     host than the metadata. Left in place they leak queries around the proxy
//     and, for a client that cannot reach them, turn a clean "package not found"
//     into a network error. Without them `composer search` finds nothing in this
//     repository; installing, requiring and updating are unaffected.
//
//   - "metadata-changes-url": REMOVED. It is a change feed for mirroring tools,
//     not used by the client, and this backend does not front it.
//
//   - "mirrors": REMOVED, because an upstream-declared mirror is one more place a
//     client would download dists (or clone sources) from directly. When the
//     public base is not absolute it is REPLACED by this backend's own dist
//     endpoint as the preferred dist mirror (see the file comment).
//
//   - "security-advisories": the "api-url" is REMOVED — the client POSTs the list
//     of installed packages to it, which a read-only proxy cannot relay and which
//     would otherwise go around the proxy. When the upstream also embeds the
//     advisories in the v2 metadata ("metadata": true) the object is KEPT, so the
//     client reads them from the documents it already fetches through the proxy.
//     Composer only accepts an advisory configuration without an API when the
//     repository bounds the packages it serves, so in that case — and only if the
//     upstream declares no "available-packages" / "available-package-patterns" of
//     its own — the match-everything pattern ["*"] is ADDED; it tells the client
//     nothing it would not assume anyway (any package may exist here). When the
//     advisories are not in the metadata the whole object is REMOVED, since
//     nothing reachable through the proxy could answer for it.
//
//   - "filter" (Composer 2.11 malware/policy lists): the "api-url" is REMOVED (a
//     POST endpoint, as above). The "summary-url" is REWRITTEN to this backend's
//     mount when the upstream serves it from the repository itself and the
//     backend can route it (see kindFilterList), and REMOVED otherwise; without a
//     summary the client falls back to the per-package filter data embedded in
//     the v2 metadata, which it fetches through the proxy. Everything else in the
//     object is kept.
//
//   - everything else ("packages", "providers", "provider-includes", "includes",
//     "available-packages", "warning", …) is PASSED THROUGH unchanged: it is data
//     or a path the client resolves relative to the repository URL, i.e. the
//     proxy mount. Note that package definitions inlined there, like the legacy
//     v1 provider documents, are not rewritten: only the Composer 2 metadata
//     layout has its dist URLs routed through the proxy.
//
// It is an error if the document is not a JSON object; the backend then refuses
// to serve it rather than pass an unrewritten root to a client.
func (b *Backend) rewriteRoot(data []byte) ([]byte, error) {
	if len(data) > maxMetadataBytes {
		return nil, fmt.Errorf("composer: packages.json exceeds %d bytes", maxMetadataBytes)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("composer: parsing packages.json: %w", err)
	}
	if root == nil {
		return nil, errors.New("composer: packages.json is not a JSON object")
	}

	// Package lookups: route through this backend's mount.
	for _, lookup := range []struct{ key, template string }{
		{"metadata-url", metadataURLTemplate},
		{"providers-url", providersURLTemplate},
		{"providers-lazy-url", providersLazyURLTemplate},
	} {
		raw, present := root[lookup.key]
		if !present {
			continue
		}
		if s, ok := exactString(raw); !ok || s == "" {
			// Not a usable template; do not let an odd value reach the client.
			delete(root, lookup.key)
			continue
		}
		enc, err := marshalJSON(b.publicBase + lookup.template)
		if err != nil {
			return nil, err
		}
		root[lookup.key] = enc
	}

	// Endpoints the backend does not front, and upstream-declared mirrors.
	for _, key := range []string{
		"notify-batch", "notify",
		"search", "list", "providers-api",
		"metadata-changes-url",
		"mirrors",
	} {
		delete(root, key)
	}

	if err := b.rewriteSecurityAdvisories(root); err != nil {
		return nil, err
	}
	if err := b.rewriteFilter(root); err != nil {
		return nil, err
	}

	// Without an absolute public base a rewritten dist.url is root-relative, which
	// Composer cannot download from; advertise the dist endpoint as the preferred
	// dist mirror, whose template Composer resolves against the repository host.
	if !b.absolutePublicBase {
		enc, err := marshalJSON([]map[string]any{{
			"dist-url":  b.publicBase + distMirrorTemplate,
			"preferred": true,
		}})
		if err != nil {
			return nil, err
		}
		root["mirrors"] = enc
	}

	return encodeObject(root)
}

// rewriteSecurityAdvisories applies the "security-advisories" decision described
// on rewriteRoot.
func (b *Backend) rewriteSecurityAdvisories(root map[string]json.RawMessage) error {
	raw, present := root["security-advisories"]
	if !present {
		return nil
	}
	var config map[string]json.RawMessage
	if err := json.Unmarshal(raw, &config); err != nil || config == nil || !isJSONTrue(config["metadata"]) {
		delete(root, "security-advisories")
		return nil
	}
	delete(config, "api-url")
	enc, err := encodeObject(config)
	if err != nil {
		return err
	}
	root["security-advisories"] = enc
	if !isNonEmptyArray(root["available-packages"]) && !isNonEmptyArray(root["available-package-patterns"]) {
		root["available-package-patterns"] = json.RawMessage(`["*"]`)
	}
	return nil
}

// rewriteFilter applies the "filter" decision described on rewriteRoot.
func (b *Backend) rewriteFilter(root map[string]json.RawMessage) error {
	raw, present := root["filter"]
	if !present {
		return nil
	}
	var config map[string]json.RawMessage
	if err := json.Unmarshal(raw, &config); err != nil || config == nil {
		delete(root, "filter")
		return nil
	}
	delete(config, "api-url")
	if summary, ok := exactString(config["summary-url"]); ok {
		if rebased, ok := b.rebaseFilterSummary(summary); ok {
			enc, err := marshalJSON(rebased)
			if err != nil {
				return err
			}
			config["summary-url"] = enc
		} else {
			delete(config, "summary-url")
		}
	} else {
		delete(config, "summary-url")
	}
	enc, err := encodeObject(config)
	if err != nil {
		return err
	}
	root["filter"] = enc
	return nil
}

// rebaseFilterSummary maps an upstream "filter.summary-url" onto this backend's
// mount. It succeeds only when the URL lies beneath the upstream repository base
// (same scheme and host, path under the base path) and the path below the base is
// one the backend routes as a filter-list document; anything else is reported as
// not frontable. A root-relative value is first resolved against the upstream's
// scheme and host, the way Composer canonicalizes it.
func (b *Backend) rebaseFilterSummary(raw string) (string, bool) {
	if raw == "" {
		return "", false
	}
	if strings.HasPrefix(raw, "/") {
		raw = b.base.Scheme + "://" + b.base.Host + raw
	}
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, b.base.Scheme) || !strings.EqualFold(u.Host, b.base.Host) {
		return "", false
	}
	basePath := strings.TrimRight(b.base.EscapedPath(), "/")
	escaped := u.EscapedPath()
	if !strings.HasPrefix(escaped, basePath+"/") {
		return "", false
	}
	rest := escaped[len(basePath):]
	decoded, err := url.PathUnescape(rest)
	if err != nil {
		return "", false
	}
	if res, ok := classify(decoded); !ok || res.kind != kindFilterList {
		return "", false
	}
	out := b.publicBase + rest
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out, true
}

// rewriteMetadata rewrites a v2 metadata document (/p2/<vendor>/<package>.json
// or its "~dev" sibling) so that every version's dist is downloaded through this
// backend's dist endpoint:
//
//   - each version's "dist.url" becomes
//     <publicBase>/dist/<vendor>/<package>/<version>/<reference>.<type> (see
//     distPath), which carries the full coordinate the admission gates need;
//   - a "mirrors" list inside a dist is dropped, since the client would try those
//     locations too;
//   - a per-version "notification-url" is dropped, for the same reason the root's
//     "notify-batch" is (it overrides the root value).
//
// "source" is deliberately left alone: it describes the package's VCS origin,
// which this backend does not front.
//
// The minified delta encoding needs care. A version object that does not repeat
// "dist" inherits the previous version's — and real Packagist documents rely on
// that whenever two versions share a commit (a release candidate promoted to a
// release, two branches at the same head). Since the rewritten URL embeds the
// version, an inherited dist would silently carry the *previous* version's URL,
// and the gates would evaluate the wrong coordinate. So in a minified document
// every version that has an effective dist is given an explicit one.
//
// A dist the proxy cannot route is left exactly as listed: one that is not a
// well-formed dist object, whose URL is not http(s) (a local path, another
// scheme), or whose version or type cannot be carried in a URL path. None of
// these occur in metadata generated from a VCS host.
//
// It is an error if the document is not a JSON object; the backend then refuses
// to serve it rather than pass unrewritten metadata to a client.
func (b *Backend) rewriteMetadata(data []byte) ([]byte, error) {
	doc, err := parseDocument(data)
	if err != nil {
		return nil, err
	}
	changed := false
	for name, raw := range doc.packages {
		vendor, pkg, ok := splitPackageName(name)
		if !ok {
			// Not a name a client can ask this repository for.
			continue
		}
		list, ok := parseVersionList(raw)
		if !ok {
			continue
		}
		listChanged, err := b.rewriteVersions(vendor, pkg, list, doc.minified)
		if err != nil {
			return nil, err
		}
		if !listChanged {
			continue
		}
		enc, err := list.marshal()
		if err != nil {
			return nil, err
		}
		doc.packages[name] = enc
		changed = true
	}
	if !changed {
		return data, nil
	}
	packages, err := encodeObject(doc.packages)
	if err != nil {
		return nil, err
	}
	doc.top["packages"] = packages
	return encodeObject(doc.top)
}

// rewriteVersions rewrites one package's version collection in place and reports
// whether anything changed. It tracks the effective "version" and "dist" across
// the collection with the same rules expandMinified applies, so the version a
// rewritten URL names is the version a client will attribute that dist to.
func (b *Backend) rewriteVersions(vendor, pkg string, list *versionList, minified bool) (bool, error) {
	var (
		curVersion json.RawMessage // effective "version", nil when absent
		curDist    json.RawMessage // effective "dist", nil when absent
		changed    bool
	)
	for i, item := range list.items {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(item, &obj); err != nil || obj == nil {
			// Not a version object; a client cannot load it either.
			continue
		}
		if !minified {
			// Every object stands alone.
			curVersion, curDist = nil, nil
		}
		if v, ok := obj["version"]; ok {
			if minified && isUnset(v) {
				curVersion = nil
			} else {
				curVersion = v
			}
		}
		ownDist := false
		if d, ok := obj["dist"]; ok {
			if minified && isUnset(d) {
				curDist = nil
			} else {
				curDist, ownDist = d, true
			}
		}

		dirty := false
		if _, ok := obj["notification-url"]; ok {
			delete(obj, "notification-url")
			dirty = true
		}
		if curDist != nil && (ownDist || minified) {
			version, _ := exactString(curVersion)
			want := b.rewriteDist(vendor, pkg, version, curDist)
			if !ownDist || !bytes.Equal(want, obj["dist"]) {
				obj["dist"] = want
				dirty = true
			}
		}
		if !dirty {
			continue
		}
		enc, err := encodeObject(obj)
		if err != nil {
			return false, err
		}
		list.items[i] = enc
		changed = true
	}
	return changed, nil
}

// rewriteDist returns a version's dist object with its URL pointed at this
// backend's dist endpoint, or the dist unchanged when the proxy cannot route it
// (see rewriteMetadata).
func (b *Backend) rewriteDist(vendor, pkg, version string, dist json.RawMessage) json.RawMessage {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(dist, &obj); err != nil || obj == nil {
		return dist
	}
	d, ok := distFromObject(obj)
	if !ok {
		return dist
	}
	target, ok := b.distURL(vendor, pkg, version, d)
	if !ok {
		return dist
	}
	encURL, err := marshalJSON(target)
	if err != nil {
		return dist
	}
	obj["url"] = encURL
	delete(obj, "mirrors")
	enc, err := encodeObject(obj)
	if err != nil {
		return dist
	}
	return enc
}

// distURL returns the public URL of this backend's dist endpoint for a package
// version, or ok=false when the dist is not one the proxy can fetch and route.
func (b *Backend) distURL(vendor, pkg, version string, d Dist) (string, bool) {
	if !isHTTPURL(d.URL) {
		return "", false
	}
	path, ok := distPath(vendor, pkg, version, d.Reference, d.Type)
	if !ok {
		return "", false
	}
	return b.publicBase + path, true
}

// isHTTPURL reports whether s is an http(s) URL, using the same test a Composer
// client applies to decide between an HTTP download and a local file read.
func isHTTPURL(s string) bool {
	lower := strings.ToLower(s)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

// isJSONTrue reports whether a raw JSON value is the literal true.
func isJSONTrue(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("true"))
}

// isNonEmptyArray reports whether a raw JSON value is an array with at least one
// element.
func isNonEmptyArray(raw json.RawMessage) bool {
	var items []json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &items) != nil {
		return false
	}
	return len(items) > 0
}
