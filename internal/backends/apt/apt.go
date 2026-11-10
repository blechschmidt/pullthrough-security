// Package apt implements a pull-through proxy backend for Debian/Ubuntu APT
// repositories (deb.debian.org, archive.ubuntu.com, and any reprepro/aptly/
// Artifactory/Nexus mirror serving the standard "dists" layout). It brings the
// OS-package surface to parity with the language-ecosystem backends
// (pip/npm/cargo/go/nuget/maven/rubygems/composer/helm): the Release trust
// anchor, the Packages indices, and the .deb pool artifacts are proxied and
// cached, and a fetched .deb is verified against the SHA-256 the chain of
// Release -> Packages declares before the bytes are cached or served.
//
// Protocol mapping (route prefix "/v1/<name>" stripped):
//
//	GET /dists/<suite>/InRelease                       inline-signed Release (mutable, GPG-checked).
//	GET /dists/<suite>/Release  + /Release.gpg         Release + detached signature.
//	GET /dists/<suite>/<comp>/binary-<arch>/Packages[.gz]  index (mutable, SHA-256-verified, parsed).
//	GET /pool/<comp>/.../<pkg>_<ver>_<arch>.deb        package (immutable, cached, SHA-256-verified).
//
// Security model: an APT repository is a single SHA-256 chain rooted at the
// GPG-signed Release file — Release publishes each Packages index's digest, and
// each Packages index publishes each .deb's digest. The backend records the
// (pool-path -> SHA-256) pairs from every Packages index it parses and verifies a
// fetched .deb against the recorded digest as the bytes stream through; a
// mismatch aborts the cache write and the response. When a trusted GPG keyring is
// configured for the upstream, the Release file's signature is validated at the
// client-facing boundary (a forged or stripped signature is refused), anchoring
// the whole chain to an operator-pinned key. This mirrors the checksum
// verification the Maven and Helm backends perform.
//
// Client configuration points APT at "<publicBase>/v1/<name>" via a sources.list
// entry, e.g. "deb <publicBase>/v1/<name> <suite> main" (see docs/clients.md).
package apt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// Internal metadata keys carry per-request decisions from Resolve into Fetch
// (which only receives the *Resolved). They mirror the convention used by the
// Maven, Helm, and Docker backends and are not persisted as meaningful cache data.
const (
	metaKind     = "_kind"     // resource class label, for diagnostics/gates
	metaVerify   = "_verify"   // "1" when the .deb must be checksum-verified
	metaSuite    = "_suite"    // distribution suite, for Release-anchored resources
	metaDistRel  = "_distRel"  // Packages index path relative to /dists/<suite>/
	metaPoolPath = "_poolPath" // .deb path relative to the repository root
	metaName     = "_name"     // parsed package name
	metaVersion  = "_version"  // parsed package version
)

// Persisted (caller-meaningful) metadata keys surfaced to downstream gates.
const (
	// MetaChecksumVerified records "sha256" when a .deb was verified against the
	// chain-declared digest, or "none" when no digest could be recovered for it.
	MetaChecksumVerified = "apt.checksumVerified"
	// MetaSignatureVerified records "trusted" when a served Release was validated
	// against the configured GPG keyring, "unsigned" when no keyring is configured.
	MetaSignatureVerified = "apt.signatureVerified"
)

// maxErrorBodySnippet bounds how much of an upstream error body is retained for
// diagnostics.
const maxErrorBodySnippet = 2 << 10 // 2 KiB

// maxIndexBufferBytes bounds how much of a Packages index the backend buffers in
// order to verify and parse it. Indices larger than this are streamed to the
// client live, unverified and unparsed (recorded via metrics); in practice the
// gzip-compressed Packages.gz an APT client fetches is well under this cap.
const maxIndexBufferBytes = 96 << 20 // 96 MiB

// maxReleaseSigBytes bounds a detached Release.gpg signature fetch.
const maxReleaseSigBytes = 64 << 10 // 64 KiB

// Options configures an APT Backend.
type Options struct {
	// Name is the route identifier and cache-key prefix (e.g. "debian"). Required.
	Name string
	// UpstreamURL is the repository base URL, e.g. "https://deb.debian.org/debian".
	// Required.
	UpstreamURL string
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool can be injected in place of
	// the bare *upstream.Client to add mirror failover transparently.
	Client upstream.Doer
	// Credentials authenticate the proxy to the upstream. Optional; public
	// repositories pull anonymously.
	Credentials upstream.Credentials
	// GPGKey is an ASCII-armored (or binary) public keyring used to validate the
	// repository's Release signature. When empty, GPG enforcement is disabled and
	// integrity rests on the SHA-256 content chain alone.
	GPGKey []byte
	// DigestStoreMax bounds the pool-path digest store; non-positive uses a default.
	DigestStoreMax int
	// Metrics, when set, records supply-chain telemetry. Optional.
	Metrics *Metrics
}

// Backend is a Debian/APT pull-through backend implementing backends.Backend.
type Backend struct {
	name    string
	base    *url.URL
	client  upstream.Doer
	creds   upstream.Credentials
	metrics *Metrics
	keyring *keyring
	digests *digestStore
}

var _ backends.Backend = (*Backend)(nil)

// New validates opts and constructs a Backend.
func New(opts Options) (*Backend, error) {
	if strings.TrimSpace(opts.Name) == "" {
		return nil, errors.New("apt: name is required")
	}
	if strings.TrimSpace(opts.UpstreamURL) == "" {
		return nil, fmt.Errorf("apt %q: upstream URL is required", opts.Name)
	}
	base, err := url.Parse(strings.TrimRight(opts.UpstreamURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("apt %q: invalid upstream URL: %w", opts.Name, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("apt %q: upstream URL must be http(s), got %q", opts.Name, base.Scheme)
	}
	if opts.Client == nil {
		return nil, fmt.Errorf("apt %q: upstream client is required", opts.Name)
	}
	kr, err := loadKeyring(opts.GPGKey)
	if err != nil {
		return nil, fmt.Errorf("apt %q: %w", opts.Name, err)
	}
	m := opts.Metrics
	if m == nil {
		m = &Metrics{}
	}
	return &Backend{
		name:    opts.Name,
		base:    base,
		client:  opts.Client,
		creds:   opts.Credentials,
		metrics: m,
		keyring: kr,
		digests: newDigestStore(opts.DigestStoreMax),
	}, nil
}

// Metrics returns the backend's telemetry counters so the cmd wiring can bridge
// them into the central Prometheus collector.
func (b *Backend) Metrics() *Metrics { return b.metrics }

// Name implements backends.Backend.
func (b *Backend) Name() string { return b.name }

// Resolve implements backends.Backend. It classifies the inbound path against the
// APT layout, derives the upstream URL and cache key, attaches the package
// coordinate for the admission gates, and decides cacheability (only immutable
// pool artifacts are cached; every dists/ index is revalidated live).
func (b *Backend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("apt: nil request")
	}

	res, ok := classify(req.Path)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not an APT repository path", backends.ErrNotSupported, req.Path)
	}

	abs := b.joinPath(req.Path)
	if enc := req.Query.Encode(); enc != "" {
		abs.RawQuery = enc
	}

	cacheable := res.cacheable() && isRead(req)
	resolved := &backends.Resolved{
		UpstreamURL: abs.String(),
		Cacheable:   cacheable,
		CacheKey:    b.cacheKey(req.Path),
		Metadata: map[string]string{
			"backend": b.name,
			metaKind:  res.kindLabel(),
		},
	}

	// Attach the package coordinate (pool artifacts only) so nameguard, policy,
	// provenance, vulnscan, license, riskscore, and policyengine can identify it.
	if res.kind == kindDeb {
		resolved.Metadata[metaVerify] = "1"
		resolved.Metadata[metaPoolPath] = res.poolPath
		resolved.Metadata[metaName] = res.name
		resolved.Metadata[metaVersion] = res.version
		if cn := res.coordinateName(); cn != "" {
			resolved.Coordinate = backends.Coordinate{Name: cn, Version: res.version}
		}
	}
	if res.kind == kindPackages {
		resolved.Metadata[metaSuite] = res.suite
		resolved.Metadata[metaDistRel] = res.distRelPath
	}
	if res.kind == kindInRelease || res.kind == kindRelease {
		resolved.Metadata[metaSuite] = res.suite
	}

	return resolved, nil
}

// Fetch implements backends.Backend. It dispatches on the resolved resource kind:
// pool .deb fetches are checksum-verified against the recorded chain digest;
// Packages indices are verified against Release and parsed to populate the digest
// store; Release/InRelease documents are GPG-validated when a keyring is
// configured; all other resources are proxied live.
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved == nil {
		return nil, errors.New("apt: nil resolved")
	}

	switch resolved.Metadata[metaKind] {
	case "deb":
		return b.fetchDeb(ctx, resolved)
	case "packages":
		return b.fetchPackages(ctx, resolved)
	case "inrelease", "release":
		return b.fetchRelease(ctx, resolved)
	default:
		return b.fetchPassthrough(ctx, resolved)
	}
}

// fetchPassthrough proxies a resource live, without verification (Release.gpg,
// Sources, Contents, Translation, by-hash, and anything outside the layout).
func (b *Backend) fetchPassthrough(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	resp, err := b.do(ctx, resolved.UpstreamURL, resolved.IfNoneMatch)
	if err != nil {
		return nil, err
	}
	if resp.NotModified {
		return notModified(resolved), nil
	}
	if !resp.IsSuccess() {
		return nil, b.statusError(resp, resolved.UpstreamURL)
	}
	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   resp.Body,
		Size:      resp.ContentLength,
		MediaType: resp.ContentType,
		Header:    upstreamHeader(resp),
		Status:    resp.Status,
	}, nil
}

// fetchDeb fetches a pool .deb and verifies it against the digest recorded from a
// previously parsed Packages index. A missing digest (no index parsed yet) is
// recorded and the package is served unverified — fail-open, observable via
// metrics — though an APT client fetches the index before the package it names.
func (b *Backend) fetchDeb(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	resp, err := b.do(ctx, resolved.UpstreamURL, resolved.IfNoneMatch)
	if err != nil {
		return nil, err
	}
	if resp.NotModified {
		return notModified(resolved), nil
	}
	if !resp.IsSuccess() {
		return nil, b.statusError(resp, resolved.UpstreamURL)
	}

	header := upstreamHeader(resp)
	content := resp.Body
	if expected, ok := b.digests.get(resolved.Metadata[metaPoolPath]); ok {
		resolved.Metadata[MetaChecksumVerified] = "sha256"
		header.Set("X-Checksum-Verified", "sha256")
		content = newVerifyingReader(resp.Body, expected, resolved.UpstreamURL, func(ok bool) {
			if ok {
				b.metrics.incDebsVerified()
			} else {
				b.metrics.incChecksumMismatch()
			}
		})
	} else {
		b.metrics.incChecksumMissing()
		resolved.Metadata[MetaChecksumVerified] = "none"
	}

	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   content,
		Size:      resp.ContentLength,
		MediaType: resp.ContentType,
		Header:    header,
		Status:    resp.Status,
	}, nil
}

// fetchPackages fetches a Packages index, buffers it (bounded), verifies it
// against the suite Release, parses it to populate the pool-path digest store,
// and serves the buffered bytes. A Release-declared digest mismatch is a hard
// failure (the tampered index is refused); an index larger than the buffer cap is
// streamed live, unverified and unparsed.
func (b *Backend) fetchPackages(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	resp, err := b.do(ctx, resolved.UpstreamURL, resolved.IfNoneMatch)
	if err != nil {
		return nil, err
	}
	if resp.NotModified {
		return notModified(resolved), nil
	}
	if !resp.IsSuccess() {
		return nil, b.statusError(resp, resolved.UpstreamURL)
	}

	header := upstreamHeader(resp)

	// Buffer up to the cap. If the index is larger, serve it live (unverified,
	// unparsed) rather than risk unbounded memory.
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxIndexBufferBytes+1))
	if err != nil {
		drainClose(resp.Body)
		return nil, fmt.Errorf("apt %q: reading Packages index: %w", b.name, err)
	}
	if int64(len(data)) > maxIndexBufferBytes {
		// Too large to buffer: stream the already-read prefix plus the remaining
		// body live, without verification or parsing.
		b.metrics.incPackagesErrors()
		drainClose(resp.Body)
		return &backends.FetchResult{
			Resolved:  resolved,
			Content:   io.NopCloser(bytes.NewReader(data)),
			Size:      int64(len(data)),
			MediaType: resp.ContentType,
			Header:    header,
			Status:    resp.Status,
		}, nil
	}
	drainClose(resp.Body)

	// Verify the index against the suite Release when the digest is recoverable.
	if rel, ok := b.suiteRelease(ctx, resolved.Metadata[metaSuite]); ok {
		if expected, ok := rel.Digest(resolved.Metadata[metaDistRel]); ok {
			if verr := verifyBytes(data, expected, resolved.UpstreamURL); verr != nil {
				b.metrics.incIndexMismatch()
				return nil, verr
			}
			b.metrics.incIndexVerified()
		}
	}

	// Decompress and parse to record the per-.deb digests.
	b.populateFromPackages(resolved.Metadata[metaDistRel], data)

	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   io.NopCloser(bytes.NewReader(data)),
		Size:      int64(len(data)),
		MediaType: resp.ContentType,
		Header:    header,
		Status:    resp.Status,
	}, nil
}

// populateFromPackages decompresses and parses an index and records every
// (pool-path -> SHA-256) it declares into the digest store.
func (b *Backend) populateFromPackages(distRel string, data []byte) {
	filename := distRel
	if i := strings.LastIndexByte(distRel, '/'); i >= 0 {
		filename = distRel[i+1:]
	}
	plain, derr := decompressPackages(filename, data)
	if derr != nil {
		if !errors.Is(derr, errUnsupportedCompression) {
			b.metrics.incPackagesErrors()
		}
		return
	}
	entries, perr := ParsePackages(plain)
	if perr != nil {
		b.metrics.incPackagesErrors()
		return
	}
	for _, e := range entries {
		b.digests.put(e.Filename, e.SHA256)
	}
	b.metrics.incPackagesParsed()
}

// fetchRelease fetches a Release/InRelease document, enforces the configured GPG
// signature at the client-facing boundary, and serves it. A configured-but-invalid
// signature is refused; with no keyring the document is served and the absence of
// enforcement is recorded.
func (b *Backend) fetchRelease(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	resp, err := b.do(ctx, resolved.UpstreamURL, resolved.IfNoneMatch)
	if err != nil {
		return nil, err
	}
	if resp.NotModified {
		return notModified(resolved), nil
	}
	if !resp.IsSuccess() {
		return nil, b.statusError(resp, resolved.UpstreamURL)
	}

	header := upstreamHeader(resp)
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxReleaseBytes+1))
	drainClose(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("apt %q: reading Release: %w", b.name, err)
	}
	if int64(len(data)) > maxReleaseBytes {
		return nil, fmt.Errorf("apt %q: Release exceeds %d bytes", b.name, maxReleaseBytes)
	}

	b.metrics.incReleaseServed()

	if b.keyring.enabled() {
		var verr error
		if resolved.Metadata[metaKind] == "inrelease" {
			verr = b.keyring.verifyClearsigned(data)
		} else {
			verr = b.verifyDetachedRelease(ctx, resolved, data)
		}
		if verr != nil {
			b.metrics.incSignatureFailures()
			return nil, verr
		}
		b.metrics.incSignatureVerified()
		resolved.Metadata[MetaSignatureVerified] = "trusted"
		header.Set("X-Repository-Signature", "trusted")
	} else {
		b.metrics.incSignatureSkipped()
		resolved.Metadata[MetaSignatureVerified] = "unsigned"
	}

	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   io.NopCloser(bytes.NewReader(data)),
		Size:      int64(len(data)),
		MediaType: resp.ContentType,
		Header:    header,
		Status:    resp.Status,
	}, nil
}

// verifyDetachedRelease fetches the detached Release.gpg and validates it over
// the Release bytes against the configured keyring.
func (b *Backend) verifyDetachedRelease(ctx context.Context, resolved *backends.Resolved, releaseData []byte) error {
	sigURL := resolved.UpstreamURL + ".gpg"
	resp, err := b.do(ctx, sigURL, "")
	if err != nil {
		return fmt.Errorf("apt %q: fetching Release.gpg: %w", b.name, err)
	}
	if !resp.IsSuccess() {
		drainClose(resp.Body)
		return fmt.Errorf("apt %q: Release.gpg unavailable (status %d); cannot validate signature", b.name, resp.Status)
	}
	sig, rerr := io.ReadAll(io.LimitReader(resp.Body, maxReleaseSigBytes+1))
	drainClose(resp.Body)
	if rerr != nil || int64(len(sig)) > maxReleaseSigBytes {
		return fmt.Errorf("apt %q: reading Release.gpg", b.name)
	}
	return b.keyring.verifyDetached(releaseData, sig)
}

// suiteRelease fetches and parses the suite Release for internal index
// verification. It prefers the inline-signed InRelease, falling back to Release.
// GPG enforcement is not applied here — the SHA-256 chain is what the backend
// consumes internally, and the client-facing Release fetch is where signatures
// are enforced.
func (b *Backend) suiteRelease(ctx context.Context, suite string) (*Release, bool) {
	if suite == "" {
		return nil, false
	}
	for _, name := range []string{"InRelease", "Release"} {
		u := b.joinPath("/dists/" + suite + "/" + name).String()
		resp, err := b.do(ctx, u, "")
		if err != nil {
			continue
		}
		if !resp.IsSuccess() {
			drainClose(resp.Body)
			continue
		}
		data, rerr := io.ReadAll(io.LimitReader(resp.Body, maxReleaseBytes+1))
		drainClose(resp.Body)
		if rerr != nil || int64(len(data)) > maxReleaseBytes {
			continue
		}
		rel, perr := ParseRelease(data)
		if perr != nil {
			continue
		}
		return rel, true
	}
	return nil, false
}

// do issues a GET against the upstream with the backend credentials.
func (b *Backend) do(ctx context.Context, rawURL, ifNoneMatch string) (*upstream.Response, error) {
	return b.client.Do(ctx, upstream.Request{
		URL:         rawURL,
		Method:      http.MethodGet,
		Creds:       b.creds,
		IfNoneMatch: ifNoneMatch,
	})
}

func (b *Backend) statusError(resp *upstream.Response, url string) error {
	snippet := readSnippet(resp.Body)
	drainClose(resp.Body)
	return &backends.StatusError{Status: resp.Status, URL: url, Body: snippet}
}

// joinPath appends the inbound APT path to the upstream base, preserving any
// base-path prefix (e.g. a repository served under "/debian").
func (b *Backend) joinPath(path string) *url.URL {
	out := *b.base
	basePath := strings.TrimRight(b.base.EscapedPath(), "/")
	out.Path = basePath + "/" + strings.TrimLeft(path, "/")
	out.RawPath = ""
	return &out
}

// cacheKey derives a stable cache key from the backend name and the layout path.
func (b *Backend) cacheKey(path string) string {
	return b.name + ":" + strings.TrimLeft(path, "/")
}

func notModified(resolved *backends.Resolved) *backends.FetchResult {
	return &backends.FetchResult{Resolved: resolved, Status: http.StatusNotModified, NotModified: true}
}

func upstreamHeader(resp *upstream.Response) http.Header {
	header := make(http.Header)
	upstream.PropagateResponseHeaders(header, resp.Header)
	if resp.ETag != "" {
		header.Set("ETag", resp.ETag)
	}
	if resp.LastModified != "" {
		header.Set("Last-Modified", resp.LastModified)
	}
	return header
}

func isRead(req *backends.Request) bool {
	return req.Method == http.MethodGet || req.Method == http.MethodHead || req.Method == ""
}

func readSnippet(r io.Reader) string {
	if r == nil {
		return ""
	}
	buf, _ := io.ReadAll(io.LimitReader(r, maxErrorBodySnippet))
	return strings.TrimSpace(string(buf))
}

// drainClose drains a small amount of the body (to allow connection reuse) and
// closes it. Safe to call with a nil body.
func drainClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 4096))
	_ = body.Close()
}
