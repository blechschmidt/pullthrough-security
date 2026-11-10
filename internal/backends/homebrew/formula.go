package homebrew

import (
	"encoding/json"
	"net/url"
	"strings"
)

// A formula's JSON metadata records, for each supported platform ("os/arch"
// tag), a bottle: a precompiled binary tarball stored as an OCI blob in GitHub
// Packages. The backend rewrites each bottle's download URL in the served
// metadata to its own synthetic bottle endpoint so the client's download flows
// back through the proxy. Only the `bottle.stable.files.*.url` fields are
// touched; the rewrite is surgical (a literal substring replacement of each
// unique, digest-bearing URL), so every other byte of the document — key order,
// whitespace, fields the backend does not model — is preserved exactly.

// formulaDoc is the subset of a Homebrew formula's JSON the backend reads to
// locate and rewrite bottle URLs. Unmodeled fields are ignored by the decoder
// and preserved by the substring rewrite.
type formulaDoc struct {
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	Versions struct {
		Stable string `json:"stable"`
	} `json:"versions"`
	Bottle struct {
		Stable struct {
			Files map[string]struct {
				URL    string `json:"url"`
				SHA256 string `json:"sha256"`
			} `json:"files"`
		} `json:"stable"`
	} `json:"bottle"`
}

// bottleURL is one bottle download URL discovered in a formula document, paired
// with the formula coordinate it belongs to.
type bottleURL struct {
	original string
	name     string
	version  string
}

// decodeFormulae parses a formula document into the formulae it contains. The
// per-formula endpoint returns a single object; the full index returns an
// array. A leniently-decoded document that is neither is reported as not
// parseable (ok=false) so the caller serves it unchanged (fail-open).
func decodeFormulae(data []byte) (docs []formulaDoc, ok bool) {
	trimmed := strings.TrimLeftFunc(string(data), func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	switch {
	case strings.HasPrefix(trimmed, "["):
		if err := json.Unmarshal(data, &docs); err != nil {
			return nil, false
		}
		return docs, true
	case strings.HasPrefix(trimmed, "{"):
		var one formulaDoc
		if err := json.Unmarshal(data, &one); err != nil {
			return nil, false
		}
		return []formulaDoc{one}, true
	default:
		return nil, false
	}
}

// bottleURLsIn extracts every rewritable bottle URL from a formula document,
// paired with the formula's name and stable version. A formula whose name,
// version, or URL carries a path-unsafe "/" is skipped (its URL is left
// unchanged) so the synthetic bottle path's segment structure stays
// unambiguous.
func bottleURLsIn(doc formulaDoc) []bottleURL {
	name := strings.TrimSpace(doc.Name)
	if name == "" {
		name = strings.TrimSpace(doc.FullName)
	}
	version := strings.TrimSpace(doc.Versions.Stable)
	if name == "" || version == "" || strings.ContainsAny(name, "/") || strings.ContainsAny(version, "/") {
		return nil
	}
	out := make([]bottleURL, 0, len(doc.Bottle.Stable.Files))
	seen := make(map[string]bool, len(doc.Bottle.Stable.Files))
	for _, f := range doc.Bottle.Stable.Files {
		u := strings.TrimSpace(f.URL)
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, bottleURL{original: u, name: name, version: version})
	}
	return out
}

// proxyBottlePath rewrites a ghcr bottle URL to the proxy's synthetic bottle
// endpoint under publicBase, carrying the formula coordinate ahead of the
// verbatim OCI blob path. It returns ok=false when the URL is not an OCI blob
// reference on the configured bottle-registry host, in which case the caller
// leaves it unchanged (fail-open), so a bottle served from an unexpected host
// still reaches the client (fetched directly, un-proxied).
func proxyBottlePath(publicBase, registryHost, rawURL, name, version string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	if registryHost != "" && !strings.EqualFold(u.Host, registryHost) {
		return "", false
	}
	p := strings.TrimLeft(u.EscapedPath(), "/")
	if !isOCIBlobPath(p) {
		return "", false
	}
	return publicBase + "/" + bottlePrefix + name + "/" + version + "/" + p, true
}

// isOCIBlobPath reports whether p is an OCI distribution blob path of the form
// "v2/<repo>/blobs/sha256:<hex>" with a non-empty repository.
func isOCIBlobPath(p string) bool {
	segs := strings.Split(p, "/")
	if len(segs) < 4 {
		return false
	}
	if segs[0] != "v2" || segs[len(segs)-2] != ociBlobMarker {
		return false
	}
	if _, ok := parseSHA256Ref(segs[len(segs)-1]); !ok {
		return false
	}
	return strings.Join(segs[1:len(segs)-2], "/") != ""
}

// rewriteBottleURLs rewrites every rewritable bottle URL in a formula document
// to the proxy's bottle endpoint, returning the rewritten bytes and how many
// distinct URLs were rewritten. Each bottle URL embeds a unique SHA-256 digest,
// so a literal substring replacement is unambiguous and preserves the rest of
// the document verbatim. All replacements are applied in a single pass with a
// strings.Replacer — O(len(data)) regardless of how many URLs the full index
// (tens of MiB, thousands of bottles) carries. A document that does not parse is
// returned unchanged with count 0 (fail-open).
func rewriteBottleURLs(data []byte, publicBase, registryHost string) ([]byte, int) {
	docs, ok := decodeFormulae(data)
	if !ok {
		return data, 0
	}
	pairs := make([]string, 0, 64)
	seen := make(map[string]bool)
	for _, doc := range docs {
		for _, b := range bottleURLsIn(doc) {
			if seen[b.original] {
				continue
			}
			proxied, ok := proxyBottlePath(publicBase, registryHost, b.original, b.name, b.version)
			if !ok {
				continue
			}
			seen[b.original] = true
			pairs = append(pairs, b.original, proxied)
		}
	}
	if len(pairs) == 0 {
		return data, 0
	}
	out := strings.NewReplacer(pairs...).Replace(string(data))
	return []byte(out), len(pairs) / 2
}
