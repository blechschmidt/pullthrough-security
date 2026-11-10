package pkgmgr

import (
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
)

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
func NewGoProxy(opts Options) (backends.Backend, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	return httpbackend.New(httpbackend.Options{
		Name:        opts.Name,
		BaseURL:     opts.UpstreamURL,
		Client:      opts.Client,
		Credentials: opts.Credentials,
		Cacheable:   goCacheable,
		Coordinator: goCoordinate,
	})
}

// goCacheable caches immutable per-version resources (.info/.mod/.zip) forever
// while leaving the mutable listing endpoints (@v/list, @latest) to be
// revalidated on each request.
func goCacheable(req *backends.Request) bool {
	p := req.Path
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
