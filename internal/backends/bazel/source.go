package bazel

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// source.json is a Bzlmod module version's source descriptor. For an archive
// source — the default, and all but a handful of BCR's 10,000+ descriptors — it
// names the external archive the module is built from and the Subresource-
// Integrity digest Bazel verifies it against:
//
//	{
//	  "url": "https://github.com/bazelbuild/platforms/releases/download/0.0.10/platforms-0.0.10.tar.gz",
//	  "integrity": "sha256-IY7+juc20mo1cmY7N0olPAErcW2K8MB+hC6C8jigp+4=",
//	  "strip_prefix": "",
//	  "patches": {"module_dot_bazel.patch": "sha256-..."},
//	  "patch_strip": 1
//	}
//
// The other fields the real registry uses, and what the proxy does with each:
//
//	mirror_urls   backup URLs for the same archive (same integrity). Bazel tries
//	              them after "url", so left in place they would let a client
//	              fall through to the internet whenever the proxy refuses or
//	              fails the archive. They are removed from the rewritten
//	              descriptor and used by the proxy itself as fallbacks.
//	archive_type  the archive format when the URL has no telling suffix
//	              (".../package_files/233618439/download" + "tar.gz"). Kept
//	              verbatim, and also folded into the synthetic file name.
//	patches       file -> integrity; Bazel fetches each from the registry's
//	overlay       patches/ and overlay/ directories, i.e. through the proxy.
//	              Kept verbatim.
//	type          "archive" when absent. A "git_repository" descriptor (remote +
//	              commit, no url) or a "local_path" one has no archive to proxy
//	              and is passed through untouched; Bazel then clones the remote
//	              itself, which this backend does not mediate.
//	docs_url      registry-UI metadata Bazel never fetches. Kept verbatim.
//
// A legacy "urls" array (never part of Bazel's schema, kept for compatibility
// with descriptors written against earlier versions of this backend) is treated
// like mirror_urls.

// maxSourceBytes bounds how much of a source.json the backend will read. These
// descriptors are tiny (a few hundred bytes); the cap is generous while bounding
// memory against a hostile upstream.
const maxSourceBytes = 1 << 20 // 1 MiB

// maxArchiveCandidates bounds how many of a descriptor's URLs the proxy will try
// for one archive request, so a hostile descriptor listing thousands of mirrors
// cannot turn a single pull into a fan-out of upstream requests. BCR descriptors
// carry at most a few.
const maxArchiveCandidates = 8

// errNotArchiveSource reports a descriptor whose "type" is not "archive".
var errNotArchiveSource = errors.New("bazel: source.json does not describe an archive source")

// sourceInfo is the subset of source.json the backend needs.
type sourceInfo struct {
	// Type is the descriptor's "type"; empty means the default, "archive".
	Type string
	// URL is the primary archive URL.
	URL string
	// MirrorURLs are the declared backup URLs for the same archive.
	MirrorURLs []string
	// URLs is the legacy mirror array (see the header comment).
	URLs []string
	// Integrity is the SRI digest shared by every URL above.
	Integrity string
	// ArchiveType is the declared archive format ("tar.gz", "zip", ...), if any.
	ArchiveType string
}

// decodeSource decodes a source.json body into its raw top-level object and the
// fields the backend needs. Keys are matched exactly, as Bazel matches them, and
// a field of an unexpected JSON type is treated as absent rather than failing the
// whole descriptor. A body that is not a JSON object is an error.
func decodeSource(b []byte) (map[string]json.RawMessage, sourceInfo, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(b, &obj); err != nil {
		return nil, sourceInfo{}, fmt.Errorf("bazel: source.json is not a JSON object: %w", err)
	}
	if obj == nil {
		// A literal null decodes into a nil map without an error.
		return nil, sourceInfo{}, errors.New("bazel: source.json is not a JSON object")
	}
	info := sourceInfo{
		URL:         rawString(obj, "url"),
		MirrorURLs:  rawStrings(obj, "mirror_urls"),
		URLs:        rawStrings(obj, "urls"),
		Integrity:   rawString(obj, "integrity"),
		ArchiveType: rawString(obj, "archive_type"),
	}
	if raw, ok := obj["type"]; ok {
		var t string
		if json.Unmarshal(raw, &t) != nil {
			// Present but not a string: certainly not the "archive" default.
			t = "invalid"
		}
		info.Type = strings.TrimSpace(t)
	}
	return obj, info, nil
}

// rawString returns obj[key] when it is a JSON string, trimmed; "" otherwise.
func rawString(obj map[string]json.RawMessage, key string) string {
	var s string
	if raw, ok := obj[key]; ok && json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}
	return ""
}

// rawStrings returns the string elements of obj[key] when it is a JSON array,
// skipping elements of any other type; nil otherwise.
func rawStrings(obj map[string]json.RawMessage, key string) []string {
	var elems []json.RawMessage
	if raw, ok := obj[key]; !ok || json.Unmarshal(raw, &elems) != nil {
		return nil
	}
	var out []string
	for _, e := range elems {
		var s string
		if json.Unmarshal(e, &s) == nil {
			out = append(out, s)
		}
	}
	return out
}

// parseSource decodes a source.json body into the fields the backend needs. A
// non-object or non-JSON body is an error.
func parseSource(b []byte) (sourceInfo, error) {
	_, info, err := decodeSource(b)
	return info, err
}

// isArchive reports whether the descriptor describes an archive source, which is
// what an absent "type" means.
func (s sourceInfo) isArchive() bool {
	return s.Type == "" || s.Type == "archive"
}

// archiveURLs returns the usable archive locators the descriptor declares, in
// the order Bazel itself would try them: the primary "url", then "mirror_urls",
// then a legacy "urls" array. Only http(s) URLs qualify — a defense-in-depth
// measure against an upstream pointing the proxy at a non-web locator (the
// injected upstream client additionally enforces the egress allowlist) —
// duplicates are dropped, and the list is capped at maxArchiveCandidates. A
// non-archive descriptor has none.
func (s sourceInfo) archiveURLs() []string {
	if !s.isArchive() {
		return nil
	}
	var out []string
	seen := make(map[string]bool)
	add := func(c string) {
		c = strings.TrimSpace(c)
		if len(out) >= maxArchiveCandidates || seen[c] || !isHTTPURL(c) {
			return
		}
		seen[c] = true
		out = append(out, c)
	}
	add(s.URL)
	for _, c := range s.MirrorURLs {
		add(c)
	}
	for _, c := range s.URLs {
		add(c)
	}
	return out
}

// primaryURL returns the first usable http(s) archive URL the descriptor
// declares (see archiveURLs), or ok=false when there is none.
func (s sourceInfo) primaryURL() (string, bool) {
	if urls := s.archiveURLs(); len(urls) > 0 {
		return urls[0], true
	}
	return "", false
}

// isHTTPURL reports whether raw parses as an absolute http or https URL with a
// host. The scheme comparison is case-insensitive, as it is for Bazel.
func isHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// archiveFileName derives the file name the synthetic archive URL should end in
// from the upstream archive URL and the descriptor's archive_type.
//
// Bazel decides how to unpack a download from the suffix of the file it saved,
// and it names that file after the last path segment of the URL (appending
// ".<archive_type>" when a type is declared and the name does not already end in
// it). Reusing the upstream archive's own base name therefore makes Bazel see
// exactly the name it would have seen fetching the archive directly — on every
// Bazel version, whether or not it knows archive_type. The name is sanitized to
// [A-Za-z0-9._+-] (any other byte becomes "_"; the suffix, which is all that
// matters, only uses those characters), and the declared type is appended the
// way Bazel would so the URL is self-describing even for an extension-less
// upstream URL. It returns "" when no acceptable name can be derived, in which
// case the bare endpoint is used.
func archiveFileName(rawURL, archiveType string) string {
	name := ""
	if u, err := url.Parse(strings.TrimSpace(rawURL)); err == nil {
		// u.Path is percent-decoded and excludes any query string or fragment.
		p := strings.TrimRight(u.Path, "/")
		name = sanitizeFileName(p[strings.LastIndexByte(p, '/')+1:])
	}
	if t := sanitizeArchiveType(archiveType); t != "" && !strings.HasSuffix(name, "."+t) {
		if name == "" {
			name = archiveEndpoint
		}
		name += "." + t
	}
	if len(name) > maxArchiveFileName {
		// Keep the tail: the suffix is the part that carries meaning.
		name = name[len(name)-maxArchiveFileName:]
	}
	if !isArchiveFileName(name) {
		return ""
	}
	return name
}

// sanitizeFileName maps every byte outside the conservative file-name alphabet
// to "_".
func sanitizeFileName(s string) string {
	b := []byte(s)
	for i, c := range b {
		if !isFileNameByte(c) {
			b[i] = '_'
		}
	}
	return string(b)
}

// sanitizeArchiveType returns the declared archive type as a bare suffix
// ("tar.gz", "zip") when it is a plausible one, and "" otherwise. Bazel's own
// documentation spells some types with a leading dot (".tar.zst"); that dot is
// dropped.
func sanitizeArchiveType(t string) string {
	t = strings.TrimLeft(strings.TrimSpace(t), ".")
	if t == "" || len(t) > 16 {
		return ""
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.') {
			return ""
		}
	}
	return t
}

// rewriteSourceJSON rewrites an archive-type source.json body so every archive
// fetch goes to the proxy's synthetic archive endpoint, while leaving every
// other field — crucially the "integrity", which Bazel re-verifies end-to-end —
// untouched.
//
// endpoint is the module version's archive endpoint
// ("<publicBase>/modules/<name>/<version>/archive"). "url" is set to that
// endpoint followed by the upstream archive's file name (see archiveFileName),
// and "mirror_urls" (and a legacy "urls") are removed: they name the same bytes
// under the same integrity, Bazel would try them whenever the proxy's endpoint
// refused or failed, and the proxy uses them itself as fallbacks instead. The
// decoded object is round-tripped through a generic map so unknown fields
// (patches, overlay, patch_strip, strip_prefix, archive_type, …) are preserved
// verbatim, and the output is deterministic (sorted keys) so the hash Bazel
// records for it in MODULE.bazel.lock is stable.
//
// A body that does not decode to a JSON object, a non-archive descriptor
// (git_repository, local_path), or one that declares no archive URL at all
// yields an error, and the caller then serves the bytes unchanged.
func rewriteSourceJSON(body []byte, endpoint string) ([]byte, error) {
	obj, info, err := decodeSource(body)
	if err != nil {
		return nil, err
	}
	if !info.isArchive() {
		return nil, errNotArchiveSource
	}
	// Rewrite whenever the descriptor references an archive at all, even through
	// a URL the proxy cannot fetch (not http(s)): the archive endpoint then fails
	// closed instead of the client fetching around the proxy.
	_, hasURL := obj["url"]
	_, hasMirrors := obj["mirror_urls"]
	_, hasURLs := obj["urls"]
	if !hasURL && !hasMirrors && !hasURLs {
		return nil, errors.New("bazel: source.json declares no archive url")
	}

	// Name the synthetic URL after the archive the proxy will actually fetch,
	// falling back to the declared primary URL when none is fetchable.
	nameFrom := info.URL
	if primary, ok := info.primaryURL(); ok {
		nameFrom = primary
	}
	target := endpoint
	if name := archiveFileName(nameFrom, info.ArchiveType); name != "" {
		target += "/" + name
	}

	enc, err := json.Marshal(target)
	if err != nil {
		return nil, err
	}
	obj["url"] = enc
	delete(obj, "mirror_urls")
	delete(obj, "urls")
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("bazel: re-encoding source.json: %w", err)
	}
	return out, nil
}
