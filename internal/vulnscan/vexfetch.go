package vulnscan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HTTPVEXFetcher retrieves a per-artifact VEX document over HTTP(S) from a URL
// built by expanding a template with the artifact's coordinate. It is the
// network-backed complement to the directory store; it is only consulted when the
// store is online (never in air-gapped mode).
//
// The template may contain the placeholders {ecosystem}, {name}, {version}, and
// {digest}; each is percent-safe-substituted with the artifact's value. A 404 is
// treated as "no VEX for this artifact" (empty result, nil error) rather than a
// failure, so a sparse VEX backend does not spam the logs.
type HTTPVEXFetcher struct {
	template string
	client   httpDoer
}

// HTTPVEXOption configures an HTTPVEXFetcher.
type HTTPVEXOption func(*HTTPVEXFetcher)

// WithVEXHTTPClient injects the HTTP client used for fetches.
func WithVEXHTTPClient(c httpDoer) HTTPVEXOption {
	return func(f *HTTPVEXFetcher) {
		if c != nil {
			f.client = c
		}
	}
}

// NewHTTPVEXFetcher constructs a fetcher over the given URL template. It returns
// an error when the template is empty or carries no artifact placeholder (which
// would fetch the same document for every artifact).
func NewHTTPVEXFetcher(template string, opts ...HTTPVEXOption) (*HTTPVEXFetcher, error) {
	template = strings.TrimSpace(template)
	if template == "" {
		return nil, fmt.Errorf("vex: fetch URL template is empty")
	}
	if !strings.Contains(template, "{name}") && !strings.Contains(template, "{digest}") {
		return nil, fmt.Errorf("vex: fetch URL template %q must contain {name} or {digest}", template)
	}
	f := &HTTPVEXFetcher{
		template: template,
		client:   &http.Client{Timeout: 15 * time.Second},
	}
	for _, o := range opts {
		o(f)
	}
	return f, nil
}

// vexFetchMaxBytes bounds how much of a fetched VEX document is read.
const vexFetchMaxBytes = 16 << 20 // 16 MiB

// FetchVEX implements VEXFetcher.
func (f *HTTPVEXFetcher) FetchVEX(ctx context.Context, art Artifact) ([]VEXStatement, error) {
	url := f.expand(art)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vex: fetching %s: %w", url, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, nil // no VEX for this artifact
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return nil, fmt.Errorf("vex: fetching %s: unexpected status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, vexFetchMaxBytes))
	if err != nil {
		return nil, fmt.Errorf("vex: reading %s: %w", url, err)
	}
	doc, err := ParseVEX(body, url)
	if err != nil {
		return nil, err
	}
	return doc.Statements, nil
}

// expand builds the fetch URL by substituting the artifact placeholders.
func (f *HTTPVEXFetcher) expand(art Artifact) string {
	r := strings.NewReplacer(
		"{ecosystem}", art.Ecosystem,
		"{name}", art.Name,
		"{version}", art.Version,
		"{digest}", art.Digest,
	)
	return r.Replace(f.template)
}
