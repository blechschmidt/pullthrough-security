package pkgmgr

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
)

// pipFilesPrefix is the synthetic path prefix under which PyPI artifacts are
// proxied. Artifact hosts differ from the index host (files.pythonhosted.org vs
// pypi.org) and may vary, so the proxy encodes the artifact's scheme and host in
// the path: "/files/<scheme>/<host>/<original-path>".
const pipFilesPrefix = "/files/"

// NewPyPI builds a pull-through backend for a PyPI-compatible index (the public
// default is https://pypi.org).
//
// Protocol mapping (PEP 503 Simple API, plus PEP 691 JSON):
//   - Simple page: GET /simple/<project>/ returns an HTML (or JSON) listing of
//     distribution files. The file URLs point at a separate artifact host
//     (files.pythonhosted.org). They are rewritten to "/files/<scheme>/<host>/…"
//     so downloads route through the proxy. Simple pages are mutable (new
//     releases appear) and revalidated rather than cached indefinitely.
//   - Artifact:    GET /files/<scheme>/<host>/<path> reconstructs the upstream
//     artifact URL and streams the immutable wheel/sdist, cached aggressively.
//
// Settings:
//
//	"filesUrl"  artifact host base (default https://files.pythonhosted.org)
//	"fileHosts" comma-separated allowlist of artifact hosts the proxy will fetch
//	            (defaults to the host of filesUrl). Hosts outside the allowlist
//	            are refused to prevent the proxy from acting as an open relay.
func NewPyPI(opts Options) (backends.Backend, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}

	filesURL := opts.setting("filesUrl", "https://files.pythonhosted.org")
	filesParsed, err := url.Parse(filesURL)
	if err != nil || filesParsed.Host == "" {
		return nil, fmt.Errorf("pkgmgr %q: invalid filesUrl %q", opts.Name, filesURL)
	}

	allowed := map[string]bool{filesParsed.Host: true}
	if list := opts.setting("fileHosts", ""); list != "" {
		for _, h := range strings.Split(list, ",") {
			if h = strings.TrimSpace(h); h != "" {
				allowed[h] = true
			}
		}
	}

	publicBase := opts.publicBase()
	rules := make([]rewriteRule, 0, len(allowed)*2)
	for host := range allowed {
		for _, scheme := range []string{"https", "http"} {
			rules = append(rules, rewriteRule{
				from: scheme + "://" + host + "/",
				to:   publicBase + pipFilesPrefix + scheme + "/" + host + "/",
			})
		}
	}

	return httpbackend.New(httpbackend.Options{
		Name:          opts.Name,
		BaseURL:       opts.UpstreamURL,
		Client:        opts.Client,
		Credentials:   opts.Credentials,
		Cacheable:     pipCacheable,
		Coordinator:   pipCoordinate,
		Index:         pipIsIndex,
		ForwardAccept: true, // honor PEP 691 content negotiation (HTML vs JSON)
		AbsoluteRouter: func(req *backends.Request) (string, bool) {
			return pipArtifactURL(req.Path, allowed)
		},
		Classify: func(req *backends.Request) backends.Artifact {
			return pipClassify(req.Path, allowed)
		},
		Rewrite: func(body []byte, _ string) ([]byte, error) {
			return applyRules(body, rules), nil
		},
	})
}

// pipArtifactURL reconstructs the upstream artifact URL from a
// "/files/<scheme>/<host>/<path>" request path, returning ok=false (so the
// request is not treated as an artifact fetch) when the path is not a files
// route or names a host outside the allowlist.
func pipArtifactURL(path string, allowed map[string]bool) (string, bool) {
	if !strings.HasPrefix(path, pipFilesPrefix) {
		return "", false
	}
	rest := strings.TrimPrefix(path, pipFilesPrefix)
	scheme, afterScheme, ok := strings.Cut(rest, "/")
	if !ok || (scheme != "https" && scheme != "http") {
		return "", false
	}
	host, tail, ok := strings.Cut(afterScheme, "/")
	if !ok || host == "" || !allowed[host] {
		return "", false
	}
	return scheme + "://" + host + "/" + tail, true
}

// pipCacheable caches reconstructed artifacts forever; Simple pages are
// revalidated.
func pipCacheable(req *backends.Request) bool {
	return strings.HasPrefix(req.Path, pipFilesPrefix)
}

// pipIsIndex classifies Simple-API pages (everything that is not a files route)
// as rewritable index documents.
func pipIsIndex(req *backends.Request) bool {
	if req.Method != "" && req.Method != "GET" && req.Method != "HEAD" {
		return false
	}
	return !strings.HasPrefix(req.Path, pipFilesPrefix)
}

// pipPayloadSuffixes are the file-name endings of the distributions an index
// lists for installation: wheels, sdists, and the legacy egg and Windows
// installer formats.
var pipPayloadSuffixes = []string{".whl", ".tar.gz", ".tgz", ".zip", ".tar.bz2", ".tar.xz", ".tar", ".egg", ".exe", ".msi"}

// pipSidecarSuffixes are the endings of the documents an index publishes next
// to a distribution, at the distribution's own URL plus the suffix: its core
// metadata (PEP 658), a detached signature, its provenance and attestations
// (PEP 740).
var pipSidecarSuffixes = []string{".metadata", ".asc", ".sig", ".provenance", ".attestation"}

// pipClassify classifies a PyPI path for the content gates. allowed is the
// artifact-host allowlist of the files route.
//
// Under the files route ("/files/<scheme>/<host>/<path>") the file name decides:
//   - a distribution file is the payload;
//   - a sidecar of one, fetched from an allowlisted host, is metadata;
//   - any other file is left unclassified.
//
// On the index host three API families are metadata, each matched in full:
//   - the Simple API (PEP 503/691): "/simple/" and "/simple/<project>/";
//   - the JSON API: "/pypi/<project>/json", "/pypi/<project>/<version>/json";
//   - the Integrity API (PEP 740):
//     "/integrity/<project>/<version>/<file>/provenance".
//
// Everything else is left unclassified. That includes whatever lies below a
// project page: an index that links its files relatively (a static index keeps
// them beside the page, as "/simple/<project>/<file>") has pip fetch them from
// exactly there. A project page is therefore one segment, and one that does not
// read as a file name — a normalized project name (PEP 503) has no dot.
func pipClassify(path string, allowed map[string]bool) backends.Artifact {
	if strings.HasPrefix(path, pipFilesPrefix) {
		file := strings.ToLower(path[strings.LastIndex(path, "/")+1:])
		switch {
		case hasAnySuffix(file, pipPayloadSuffixes):
			if strings.HasSuffix(file, ".exe") || strings.HasSuffix(file, ".msi") {
				// A legacy Windows installer is one executable, not an archive.
				return backends.PayloadFile()
			}
			return backends.Payload()
		case hasAnySuffix(file, pipSidecarSuffixes):
			// The allowlist vouches for the host; the path on it has to be plain.
			if _, routed := pipArtifactURL(path, allowed); routed {
				if parts := strings.SplitN(path, "/", 5); len(parts) == 5 {
					if _, plain := plainSegments("/" + parts[4]); plain {
						return backends.Metadata()
					}
				}
			}
		}
		return backends.Artifact{}
	}

	// The Simple API's URLs end in a slash; the others do not, but an index
	// answers both spellings alike.
	segs, ok := plainSegments(strings.TrimSuffix(path, "/"))
	if !ok {
		return backends.Artifact{}
	}
	n := len(segs)
	switch segs[0] {
	case "simple":
		if n == 1 || (n == 2 && !strings.Contains(segs[1], ".")) {
			return backends.Metadata()
		}
	case "pypi":
		if (n == 3 || n == 4) && segs[n-1] == "json" {
			return backends.Metadata()
		}
	case "integrity":
		if n == 5 && segs[4] == "provenance" {
			return backends.Metadata()
		}
	}
	return backends.Artifact{}
}
