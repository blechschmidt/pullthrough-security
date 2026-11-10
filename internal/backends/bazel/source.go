package bazel

import (
	"encoding/json"
	"fmt"
	"strings"
)

// source.json is a Bzlmod module version's source descriptor. It names the
// external archive the module is built from and the Subresource-Integrity digest
// Bazel verifies it against:
//
//	{
//	  "url": "https://github.com/bazelbuild/platforms/releases/download/0.0.10/platforms-0.0.10.tar.gz",
//	  "integrity": "sha256-IY7+juc20mo1cmY7N0olPAErcW2K8MB+hC6dmLNQ+ts=",
//	  "strip_prefix": "",
//	  "patches": {"module_dot_bazel.patch": "sha256-..."},
//	  "patch_strip": 1
//	}
//
// Older or multi-mirror descriptors may use "urls" (an array of mirror URLs that
// all resolve to the same archive and therefore share one integrity) instead of
// (or in addition to) "url". The proxy reads the integrity and the primary URL
// to verify the archive, and rewrites the URL field(s) so archive fetches route
// through the proxy's synthetic archive endpoint (see rewriteSourceJSON).

// maxSourceBytes bounds how much of a source.json the backend will read. These
// descriptors are tiny (a few hundred bytes); the cap is generous while bounding
// memory against a hostile upstream.
const maxSourceBytes = 1 << 20 // 1 MiB

// sourceInfo is the subset of source.json the backend needs.
type sourceInfo struct {
	URL       string
	URLs      []string
	Integrity string
}

// parseSource decodes a source.json body into the fields the backend needs. A
// non-object or non-JSON body is an error.
func parseSource(b []byte) (sourceInfo, error) {
	var doc struct {
		URL       string   `json:"url"`
		URLs      []string `json:"urls"`
		Integrity string   `json:"integrity"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return sourceInfo{}, fmt.Errorf("bazel: source.json is not valid JSON: %w", err)
	}
	return sourceInfo{
		URL:       strings.TrimSpace(doc.URL),
		URLs:      doc.URLs,
		Integrity: strings.TrimSpace(doc.Integrity),
	}, nil
}

// primaryURL returns the first usable http(s) archive URL the descriptor
// declares, preferring the singular "url" and falling back to the first entry of
// "urls". A non-http(s) URL is rejected (ok=false) as a defense-in-depth measure
// against an upstream pointing the proxy at a non-web locator; the injected
// upstream client additionally enforces the egress allowlist.
func (s sourceInfo) primaryURL() (string, bool) {
	candidates := make([]string, 0, 1+len(s.URLs))
	if s.URL != "" {
		candidates = append(candidates, s.URL)
	}
	candidates = append(candidates, s.URLs...)
	for _, c := range candidates {
		c = strings.TrimSpace(c)
		if strings.HasPrefix(c, "http://") || strings.HasPrefix(c, "https://") {
			return c, true
		}
	}
	return "", false
}

// rewriteSourceJSON rewrites a source.json body so its archive URL points at the
// proxy's synthetic archive endpoint (archiveURL), while leaving every other
// field — crucially the "integrity", which Bazel re-verifies end-to-end —
// untouched. The singular "url" is set to the synthetic endpoint and any "urls"
// mirror array is removed (all its entries share one integrity and collapse to
// the single proxied endpoint). The decoded object is round-tripped through a
// generic map so unknown fields (patches, patch_strip, strip_prefix, …) are
// preserved verbatim. A body that does not decode to a JSON object yields an
// error, and the caller then serves the bytes unchanged (fail-open).
func rewriteSourceJSON(body []byte, archiveURL string) ([]byte, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, fmt.Errorf("bazel: source.json is not a JSON object: %w", err)
	}
	// Only rewrite when the descriptor actually references an archive URL; a
	// descriptor with no url/urls (e.g. a local_path or git_repository override)
	// is left untouched.
	if _, hasURL := obj["url"]; !hasURL {
		if _, hasURLs := obj["urls"]; !hasURLs {
			return nil, fmt.Errorf("bazel: source.json declares no archive url")
		}
	}
	enc, err := json.Marshal(archiveURL)
	if err != nil {
		return nil, err
	}
	obj["url"] = enc
	delete(obj, "urls")
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("bazel: re-encoding source.json: %w", err)
	}
	return out, nil
}
