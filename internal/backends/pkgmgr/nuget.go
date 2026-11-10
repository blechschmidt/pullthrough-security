package pkgmgr

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
)

// NewNuGet builds a pull-through backend for a NuGet v3 feed (the public default
// is https://api.nuget.org).
//
// Protocol mapping (NuGet v3):
//   - Service index:  GET /v3/index.json advertises resource endpoints (flat
//     container, registration, search) as absolute URLs. Same-host endpoints are
//     rewritten to route through the proxy; cross-host services (e.g. search on
//     azuresearch-*.nuget.org) are left pointing upstream.
//   - Registration:   GET /v3/registration*/<id>/index.json (and pages) carry
//     the package dependency graph and packageContent (.nupkg) URLs, which are
//     rewritten. These documents are mutable and revalidated.
//   - Flat container: GET /v3-flatcontainer/<id>/index.json lists versions
//     (mutable); GET /v3-flatcontainer/<id>/<version>/<id>.<version>.nupkg is the
//     immutable package, cached aggressively.
//
// All v3 resources on the configured feed share one host, so a single literal
// substitution of the upstream base for the proxy base rewrites every same-host
// endpoint across the service index and registration documents.
//
// Client configuration adds "<publicBase>/v3/index.json" as a package source
// (see docs/clients.md).
func NewNuGet(opts Options) (backends.Backend, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}

	upstreamBase := strings.TrimRight(opts.UpstreamURL, "/")
	publicBase := opts.publicBase()
	rules := []rewriteRule{{from: upstreamBase + "/", to: publicBase + "/"}}

	return httpbackend.New(httpbackend.Options{
		Name:          opts.Name,
		BaseURL:       opts.UpstreamURL,
		Client:        opts.Client,
		Credentials:   opts.Credentials,
		Cacheable:     nugetCacheable,
		Coordinator:   nugetCoordinate,
		Index:         nugetIsIndex,
		ForwardAccept: true,
		Rewrite: func(body []byte, _ string) ([]byte, error) {
			// NuGet's "*-gz-*" registration resources may arrive gzip-encoded. The
			// transport normally decompresses transparently, but guard against a
			// baked-in gzip body so rewriting still sees the JSON.
			decoded, err := maybeGunzip(body)
			if err != nil {
				return nil, err
			}
			return applyRules(decoded, rules), nil
		},
	})
}

// maxGunzipBytes bounds the decompressed size of an upstream gzip body so a
// maliciously crafted registry cannot exhaust proxy memory with a decompression
// bomb (a few KiB expanding to many GiB). NuGet metadata documents are small;
// 64 MiB is well above any legitimate index/registration response.
const maxGunzipBytes = 64 << 20 // 64 MiB

// maybeGunzip decompresses body if it carries the gzip magic header, otherwise
// returns it unchanged. The proxy serves the decompressed bytes and drops the
// Content-Encoding header, so clients receive plain JSON. Decompression is
// bounded by maxGunzipBytes: a body that expands past the limit is rejected
// rather than buffered without bound.
func maybeGunzip(body []byte) ([]byte, error) {
	if len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
		return body, nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	// Read one byte past the cap so an over-limit body is detected rather than
	// silently truncated.
	out, err := io.ReadAll(io.LimitReader(zr, maxGunzipBytes+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxGunzipBytes {
		return nil, fmt.Errorf("nuget: decompressed body exceeds %d bytes", maxGunzipBytes)
	}
	return out, nil
}

// nugetCacheable caches immutable .nupkg packages forever; JSON metadata
// documents (service index, registration, version lists) are revalidated.
func nugetCacheable(req *backends.Request) bool {
	return strings.HasSuffix(strings.ToLower(req.Path), ".nupkg")
}

// nugetIsIndex marks JSON metadata documents for URL rewriting.
func nugetIsIndex(req *backends.Request) bool {
	if req.Method != "" && req.Method != "GET" && req.Method != "HEAD" {
		return false
	}
	return strings.HasSuffix(strings.ToLower(req.Path), ".json")
}
