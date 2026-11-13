package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
)

// OCI / Docker images before the LLM package-scan gate (Task 174).
//
// A client pulls an image in pieces: the manifest, then the config blob and
// every layer blob, each a request of its own. What the image runs is spread
// over all of them, so the gate examines the image as a whole when its manifest
// is pulled — the config and build history, and the files of every layer — and
// stores the verdict under the manifest's digest. The manifest response is held
// until that verdict exists.
//
// The blobs then follow the image's verdict: a blob a refused image's verdict
// holds something against is refused; a blob an image scan read in full needs
// no scan of its own; a blob no image scan read — a layer the scan's budget did
// not reach, or one pulled by a client that got its manifest elsewhere — is
// examined by itself, as the layer archive it is.

// llmBlobFillTimeout bounds one background fetch of an image blob into the
// cache. It is deliberately longer than a scan: a layer download that outlives
// the scan that started it still completes, so the next attempt finds it
// cached instead of starting over.
const llmBlobFillTimeout = 30 * time.Minute

// gateLLMImage puts an image manifest before the gate. A manifest list (image
// index) names other manifests and holds nothing to install; the gate's report
// is then nil and the index is served.
func (g *Gateway) gateLLMImage(w http.ResponseWriter, r *http.Request, sub llmScanSubject, resolved *backends.Resolved) bool {
	backend, ok := g.deps.Backends.Get(sub.backend)
	if !ok {
		return g.admitLLMPkgScan(w, r, sub)
	}
	sub.art.Class = llmpkgscan.ClassPayload
	sub.image = g.llmImageSource(r, sub.backend, backend, resolved.Coordinate.Name)
	// An image is the same image under every tag that points at it, so a review
	// is opened for the repository and the manifest digest, not for the tag.
	sub.reviewCoordinate = imageReviewCoordinate(resolved.Coordinate.Name, sub.art.Digest)
	return g.admitLLMPkgScan(w, r, sub)
}

// imageReviewCoordinate is the coordinate a break-glass review of an image is
// scoped to: the repository and the manifest digest. The manifest and every
// blob of the image use the same one, so one grant releases the image whole.
func imageReviewCoordinate(repo, manifestDigest string) string {
	if repo == "" || manifestDigest == "" {
		return ""
	}
	return repo + "@" + manifestDigest
}

// llmImageSource returns the scan's access to the blobs of one repository. A
// blob is fetched through the content cache, under the very key a client's own
// request for it uses: the scan's download is the client's download, done once.
func (g *Gateway) llmImageSource(r *http.Request, name string, backend backends.Backend, repo string) *llmpkgscan.ImageSource {
	// With per-tenant cache namespacing the client's later blob requests look in
	// its tenant's namespace, so that is where the scan must put them.
	namespace := ""
	if g.opts.CacheNamespacing {
		if p, ok := auth.FromContext(r.Context()); ok && p != nil {
			namespace = p.Namespace() + "/"
		}
	}
	return &llmpkgscan.ImageSource{
		Blob: func(ctx context.Context, digest string, _ int64) (io.ReadCloser, error) {
			if strings.ContainsAny(digest, "/?#") {
				return nil, fmt.Errorf("invalid blob digest %q", digest)
			}
			res, err := backend.Resolve(ctx, &backends.Request{
				Method: http.MethodGet,
				Path:   "/v2/" + repo + "/blobs/" + digest,
				Header: http.Header{},
			})
			if err != nil {
				return nil, err
			}
			if !res.Cacheable || res.Artifact.Kind != backends.KindOCIBlob {
				return nil, errors.New("the backend did not resolve the blob as a cacheable blob")
			}
			res.CacheKey = namespace + res.CacheKey
			return g.llmFetchBlob(ctx, name, backend, res)
		},
	}
}

// llmFetchBlob returns a blob from the cache, fetching it on a miss.
//
// The fetch runs on a context of its own. A scan has a time limit, a layer
// download does not fit a short one, and a fetch tied to the scan would be
// thrown away with it — to be started from the first byte by the next attempt,
// which would time out the same way. Detached, it runs to completion and the
// next attempt (or the client's own request for the blob) finds it cached.
func (g *Gateway) llmFetchBlob(ctx context.Context, name string, backend backends.Backend, res *backends.Resolved) (io.ReadCloser, error) {
	if e, err := g.deps.Cache.Get(ctx, res.CacheKey); err == nil {
		return e.Content, nil
	}
	type result struct {
		entry *cache.Entry
		err   error
	}
	done := make(chan result, 1)
	fillCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), llmBlobFillTimeout)
	go func() {
		defer cancel()
		entry, err := g.deps.Cache.GetOrLoad(fillCtx, res.CacheKey, func(lctx context.Context) (io.Reader, map[string]string, error) {
			// An emergency freeze forbids every new upstream fetch, this one too.
			if g.lockdownBlocksFetch() {
				return nil, nil, lockdownFreezeError{}
			}
			start := time.Now()
			fetched, ferr := backend.Fetch(lctx, res)
			g.metrics().ObserveUpstreamLatency(name, time.Since(start).Seconds(), ferr == nil)
			if ferr != nil {
				return nil, nil, ferr
			}
			if fetched.NotModified || fetched.Content == nil {
				return nil, nil, fmt.Errorf("proxy: upstream returned no content for %s", res.UpstreamURL)
			}
			content := fetched.Content
			if verifier, on := newDigestVerifier(content, res.Digest, func() { g.serve.digestMismatch.Add(1) }); on {
				content = verifier
			}
			return content, metadataForFetch(res, fetched), nil
		})
		done <- result{entry, err}
	}()
	select {
	case out := <-done:
		if out.err != nil {
			return nil, out.err
		}
		return out.entry.Content, nil
	case <-ctx.Done():
		// The scan gave up waiting; the fetch goes on. Whoever it finishes for is
		// gone, so its stream is closed as soon as it arrives.
		go func() {
			if out := <-done; out.err == nil && out.entry != nil {
				_ = out.entry.Content.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

// gateLLMBlob puts a blob of an OCI repository before the gate.
func (g *Gateway) gateLLMBlob(w http.ResponseWriter, r *http.Request, sub llmScanSubject, resolved *backends.Resolved) bool {
	svc := g.deps.LLMPkgScan
	// The digest the client asked for names the blob; the cache verified the
	// bytes against it when it stored them.
	digest := resolved.Digest
	if digest == "" {
		digest = sub.art.Digest
	}
	switch st := svc.BlobStatus(r.Context(), digest); {
	case st.Refused:
		// A layer or the config of an image whose verdict the gate refuses: the
		// blob is refused on that verdict, and a review of it is a review of the
		// image.
		svc.NoteEnforced("blob")
		sub.stored = st.Verdict
		// The report is about the image: it carries the image's digest, so the
		// refusal names what was judged and a break-glass grant for the image
		// covers its blobs.
		sub.art.Digest = st.Verdict.Digest
		sub.reviewCoordinate = imageReviewCoordinate(resolved.Coordinate.Name, st.Verdict.Digest)
		return g.admitLLMPkgScan(w, r, sub)
	case st.Covered:
		// Read in full as part of an image the gate has a verdict on.
		noteLLMScan(r.Context(), &SystemLLMScan{NotApplicable: LLMCoveredByImage,
			NotApplicableReason: "the blob was read in full by the scan of an image that has it; the image's verdict covers it"})
		w.Header().Set("X-LLMPkgScan-Decision", "image")
		return true
	}
	// No image scan read this blob: no examined image contains it (the client
	// has its manifest from elsewhere), or the images that do ran out of budget
	// before they reached it — base layers, as a rule, which an image scan gets
	// to last. It is judged from its bytes, with a budget of its own: a layer is
	// an archive and is examined as one, as the piece of a root filesystem it is;
	// an image config is a JSON document and holds nothing to unpack.
	sub.art.Class = llmpkgscan.ClassUnknown
	sub.art.RootFS = true
	return g.admitLLMPkgScan(w, r, sub)
}
