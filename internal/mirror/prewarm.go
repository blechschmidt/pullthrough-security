package mirror

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// BackendProvider resolves a backend by its route name. *backends.Registry
// satisfies it; the Warmer depends on this narrow interface so it can be tested
// with a stub registry.
type BackendProvider interface {
	Get(name string) (backends.Backend, bool)
}

// WarmOptions configures a pre-warm run.
type WarmOptions struct {
	// Concurrency bounds how many artifacts are fetched in parallel. Values <= 0
	// default to 1 (sequential), which keeps the warm gentle on upstreams.
	Concurrency int
	// ContinueOnError keeps warming the remaining entries after a failure instead
	// of aborting at the first one. Failures are always collected in the report.
	ContinueOnError bool
}

// WarmEntryResult records the outcome of warming one manifest entry.
type WarmEntryResult struct {
	Entry PrewarmEntry
	// CacheKey is the key the artifact was stored under, when resolution
	// succeeded.
	CacheKey string
	// Status is one of "fetched" (pulled from upstream), "cached" (already
	// present), or "error".
	Status string
	// Bytes is the size of the warmed artifact, when known.
	Bytes int64
	// Err is the failure, when Status == "error".
	Err error
}

// WarmReport summarizes a pre-warm run. Results preserve manifest order.
type WarmReport struct {
	Results []WarmEntryResult
	Fetched int
	Cached  int
	Failed  int
	Bytes   int64
}

// Warmer pre-populates a cache by replaying artifact requests through the
// existing backend Resolve/Fetch pipeline — the very same code path the live
// proxy uses on a cache miss — so warmed entries land under exactly the keys the
// proxy will later read.
type Warmer struct {
	backends BackendProvider
	cache    cache.Cache
	logger   *slog.Logger
}

// NewWarmer constructs a Warmer over the backend registry and cache.
func NewWarmer(provider BackendProvider, c cache.Cache, logger *slog.Logger) (*Warmer, error) {
	if provider == nil {
		return nil, errors.New("mirror: warmer requires a backend provider")
	}
	if c == nil {
		return nil, errors.New("mirror: warmer requires a cache")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Warmer{backends: provider, cache: c, logger: logger}, nil
}

// Warm fetches every artifact in the manifest into the cache. It returns a
// per-entry report. When ContinueOnError is false it also returns the first
// error encountered; otherwise it returns nil and failures are recorded in the
// report.
func (w *Warmer) Warm(ctx context.Context, manifest *PrewarmManifest, opts WarmOptions) (*WarmReport, error) {
	if manifest == nil {
		return nil, errors.New("mirror: nil prewarm manifest")
	}
	if err := manifest.Validate(); err != nil {
		return nil, err
	}

	entries := manifest.Entries()
	results := make([]WarmEntryResult, len(entries))

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 1
	}

	grp, gctx := errgroup.WithContext(ctx)
	grp.SetLimit(concurrency)

	var mu sync.Mutex
	var firstErr error

	for i, entry := range entries {
		i, entry := i, entry
		grp.Go(func() error {
			res := w.warmOne(gctx, entry)
			results[i] = res
			if res.Err != nil && !opts.ContinueOnError {
				mu.Lock()
				if firstErr == nil {
					firstErr = res.Err
				}
				mu.Unlock()
				return res.Err // cancels the group
			}
			return nil
		})
	}

	// When aborting on error, Wait surfaces the cancellation; the recorded
	// firstErr is the meaningful cause. When continuing, Wait returns nil.
	_ = grp.Wait()

	report := &WarmReport{Results: results}
	for _, r := range results {
		switch r.Status {
		case "fetched":
			report.Fetched++
			report.Bytes += r.Bytes
		case "cached":
			report.Cached++
		case "error":
			report.Failed++
		}
	}

	if !opts.ContinueOnError && firstErr != nil {
		return report, firstErr
	}
	return report, nil
}

// warmOne resolves and fetches a single entry into the cache.
func (w *Warmer) warmOne(ctx context.Context, entry PrewarmEntry) WarmEntryResult {
	res := WarmEntryResult{Entry: entry}

	backend, ok := w.backends.Get(entry.Upstream)
	if !ok {
		res.Status = "error"
		res.Err = fmt.Errorf("mirror: no upstream named %q", entry.Upstream)
		return res
	}

	req := &backends.Request{
		Method: http.MethodGet,
		Path:   "/" + strings.TrimLeft(entry.Path, "/"),
		Query:  url.Values{},
		Header: http.Header{},
	}

	resolved, err := backend.Resolve(ctx, req)
	if err != nil {
		res.Status = "error"
		res.Err = fmt.Errorf("mirror: resolving %s%s: %w", entry.Upstream, entry.Path, err)
		return res
	}
	res.CacheKey = resolved.CacheKey

	if !resolved.Cacheable {
		// Non-cacheable resources (mutable index documents) cannot be pinned into
		// the cache; warming them would have no effect. Report rather than fetch.
		res.Status = "error"
		res.Err = fmt.Errorf("mirror: %s%s resolves to a non-cacheable resource and cannot be pre-warmed", entry.Upstream, entry.Path)
		return res
	}

	// Already cached? Report a hit without touching upstream.
	if stat, err := w.cache.Stat(ctx, resolved.CacheKey); err == nil {
		res.Status = "cached"
		res.Bytes = stat.Size
		return res
	} else if !errors.Is(err, cache.ErrNotFound) {
		res.Status = "error"
		res.Err = fmt.Errorf("mirror: stating cache for %s: %w", resolved.CacheKey, err)
		return res
	}

	loader := func(lctx context.Context) (io.Reader, map[string]string, error) {
		result, ferr := backend.Fetch(lctx, resolved)
		if ferr != nil {
			return nil, nil, ferr
		}
		if result.NotModified || result.Content == nil {
			return nil, nil, fmt.Errorf("mirror: upstream returned no content for %s", resolved.UpstreamURL)
		}
		return result.Content, metadataForFetch(resolved, result), nil
	}

	entryRes, err := w.cache.GetOrLoad(ctx, resolved.CacheKey, loader)
	if err != nil {
		res.Status = "error"
		res.Err = fmt.Errorf("mirror: warming %s%s: %w", entry.Upstream, entry.Path, err)
		return res
	}
	_ = entryRes.Content.Close()

	res.Status = "fetched"
	res.Bytes = entryRes.Stat.Size
	return res
}

// metadataForFetch assembles the cache metadata persisted alongside a warmed
// artifact, mirroring what the live proxy records: the resolved metadata plus
// the upstream origin and (when known) the content type.
func metadataForFetch(resolved *backends.Resolved, result *backends.FetchResult) map[string]string {
	meta := make(map[string]string, len(resolved.Metadata)+2)
	for k, v := range resolved.Metadata {
		meta[k] = v
	}
	meta[cache.MetaOrigin] = resolved.UpstreamURL
	if ct := result.MediaType; ct != "" {
		meta[cache.MetaContentType] = ct
	} else if resolved.MediaType != "" {
		meta[cache.MetaContentType] = resolved.MediaType
	}
	return meta
}
