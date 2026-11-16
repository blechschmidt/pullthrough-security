// Package yum implements a pull-through proxy backend for RPM/YUM/DNF
// repositories (Fedora, RHEL/CentOS, openSUSE, Amazon Linux, and any
// createrepo_c/Artifactory/Nexus mirror serving the standard repodata layout). It
// brings the RPM OS-package surface to parity with the language-ecosystem
// backends: the repomd.xml manifest, the primary.xml package list, and the .rpm
// packages are proxied and cached, and a fetched .rpm is verified against the
// checksum the chain of repomd.xml -> primary.xml declares before the bytes are
// cached or served.
//
// Protocol mapping (route prefix "/v1/<name>" stripped):
//
//	GET /repodata/repomd.xml               metadata manifest (mutable, GPG-checked).
//	GET /repodata/repomd.xml.asc           detached signature (served as-is).
//	GET /repodata/<hash>-primary.xml.gz    package list (mutable, verified, parsed).
//	GET /Packages/<n>-<v>-<r>.<arch>.rpm   package (immutable, cached, verified).
//
// Security model: an RPM repository is a checksum chain rooted at the (optionally
// GPG-signed) repomd.xml — repomd.xml publishes each metadata file's digest, and
// primary.xml publishes each .rpm's digest. The backend records the
// (rpm-path -> checksum) pairs of every primary.xml it parses whole after
// verifying it against repomd.xml (itself signature-checked when a keyring is
// configured), and verifies a fetched .rpm against the recorded digest as the
// bytes stream through; a mismatch aborts the cache write and the response.
// When a trusted GPG keyring is configured for the upstream, repomd.xml's
// signature is validated at the client-facing boundary too. This mirrors the
// checksum verification the Maven and Helm backends perform.
//
// Client configuration points the .repo file's baseurl at "<publicBase>/v1/<name>"
// (see docs/clients.md).
package yum

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// Internal metadata keys carry per-request decisions from Resolve into Fetch.
const (
	metaKind         = "_kind"         // resource class label, for diagnostics/gates
	metaVerify       = "_verify"       // "1" when the .rpm must be checksum-verified
	metaRpmPath      = "_rpmPath"      // .rpm path relative to the repository root
	metaRepodataPath = "_repodataPath" // repodata file path relative to the repository root
	metaName         = "_name"         // parsed package name
	metaVersion      = "_version"      // parsed package version
)

// Persisted (caller-meaningful) metadata keys surfaced to downstream gates.
const (
	// MetaChecksumVerified records the algorithm an .rpm was verified with
	// ("sha256", ...), or "none" when no digest could be recovered for it.
	MetaChecksumVerified = "yum.checksumVerified"
	// MetaSignatureVerified records "trusted" when repomd.xml was validated against
	// the configured GPG keyring, or "unsigned" when no keyring is configured.
	MetaSignatureVerified = "yum.signatureVerified"
)

const (
	maxErrorBodySnippet  = 2 << 10  // 2 KiB
	maxRepodataBufferB   = 96 << 20 // 96 MiB: cap for buffering a repodata file to verify+parse
	maxRepomdSigBytes    = 64 << 10 // 64 KiB
	maxRepomdFetchBytes  = maxRepomdBytes
	maxPrimaryFetchBytes = 256 << 20 // 256 MiB: cap on a compressed primary.xml fetch
)

// Options configures a YUM Backend.
type Options struct {
	// Name is the route identifier and cache-key prefix (e.g. "fedora"). Required.
	Name string
	// UpstreamURL is the repository base URL (the directory containing repodata/),
	// e.g. "https://dl.fedoraproject.org/.../os". Required.
	UpstreamURL string
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool can be injected for mirror
	// failover.
	Client upstream.Doer
	// Credentials authenticate the proxy to the upstream. Optional.
	Credentials upstream.Credentials
	// GPGKey is an ASCII-armored (or binary) public keyring used to validate
	// repomd.xml's signature. When empty, GPG enforcement is disabled and integrity
	// rests on the checksum content chain alone.
	GPGKey []byte
	// DigestStoreMax bounds the rpm-path digest store; non-positive uses a default.
	DigestStoreMax int
	// Metrics, when set, records supply-chain telemetry. Optional.
	Metrics *Metrics
}

// Backend is an RPM/YUM pull-through backend implementing backends.Backend.
type Backend struct {
	name    string
	base    *url.URL
	client  upstream.Doer
	creds   upstream.Credentials
	metrics *Metrics
	keyring *keyring
	digests *digestStore

	// populating admits one population of the digest store from the
	// repository at a time (populateFromRepo): the misses that arrive while
	// one runs wait for it, and then find the store loaded.
	populating chan struct{}
	// loadedMu guards loaded and loadedProbe: the primary whose digests were
	// recorded last (its location and the checksum repomd.xml declared for
	// it), and one path it lists — which the store holds as long as it holds
	// that primary's digests (it is cleared wholesale when full).
	loadedMu    sync.Mutex
	loaded      string
	loadedProbe string
}

var _ backends.Backend = (*Backend)(nil)

// New validates opts and constructs a Backend.
func New(opts Options) (*Backend, error) {
	if strings.TrimSpace(opts.Name) == "" {
		return nil, errors.New("yum: name is required")
	}
	if strings.TrimSpace(opts.UpstreamURL) == "" {
		return nil, fmt.Errorf("yum %q: upstream URL is required", opts.Name)
	}
	base, err := url.Parse(strings.TrimRight(opts.UpstreamURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("yum %q: invalid upstream URL: %w", opts.Name, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("yum %q: upstream URL must be http(s), got %q", opts.Name, base.Scheme)
	}
	if opts.Client == nil {
		return nil, fmt.Errorf("yum %q: upstream client is required", opts.Name)
	}
	kr, err := loadKeyring(opts.GPGKey)
	if err != nil {
		return nil, fmt.Errorf("yum %q: %w", opts.Name, err)
	}
	m := opts.Metrics
	if m == nil {
		m = &Metrics{}
	}
	return &Backend{
		name:       opts.Name,
		base:       base,
		client:     opts.Client,
		creds:      opts.Credentials,
		metrics:    m,
		keyring:    kr,
		digests:    newDigestStore(opts.DigestStoreMax),
		populating: make(chan struct{}, 1),
	}, nil
}

// Metrics returns the backend's telemetry counters so the cmd wiring can bridge
// them into the central Prometheus collector.
func (b *Backend) Metrics() *Metrics { return b.metrics }

// Name implements backends.Backend.
func (b *Backend) Name() string { return b.name }

// Resolve implements backends.Backend. It classifies the inbound path against the
// YUM layout, derives the upstream URL and cache key, attaches the package
// coordinate for the admission gates, and decides cacheability (only immutable
// .rpm packages are cached; every repodata document is revalidated live).
func (b *Backend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("yum: nil request")
	}

	res, ok := classify(req.Path)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a YUM repository path", backends.ErrNotSupported, req.Path)
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
		Artifact: res.artifact(),
	}

	switch res.kind {
	case kindRpm:
		resolved.Metadata[metaVerify] = "1"
		resolved.Metadata[metaRpmPath] = res.rpmPath
		resolved.Metadata[metaName] = res.name
		resolved.Metadata[metaVersion] = res.version
		if cn := res.coordinateName(); cn != "" {
			resolved.Coordinate = backends.Coordinate{Name: cn, Version: res.version}
		}
	case kindRepodata:
		resolved.Metadata[metaRepodataPath] = res.repodataPath
	}

	return resolved, nil
}

// Fetch implements backends.Backend, dispatching on the resolved resource kind.
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved == nil {
		return nil, errors.New("yum: nil resolved")
	}
	switch resolved.Metadata[metaKind] {
	case "rpm":
		return b.fetchRPM(ctx, resolved)
	case "repodata":
		return b.fetchRepodata(ctx, resolved)
	case "repomd":
		return b.fetchRepomd(ctx, resolved)
	default:
		return b.fetchPassthrough(ctx, resolved)
	}
}

// fetchPassthrough proxies a resource live, without verification (repomd.xml.asc,
// repomd.xml.key, and anything outside the layout).
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

// fetchRPM fetches a package and verifies it against the digest recorded from a
// previously parsed primary.xml. When the store holds none for it (a cold
// cache, a package newer than the primary last parsed), and the upstream has
// the package, it populates the store from the repository's own primary —
// verified against repomd.xml — before giving up and serving unverified
// (fail-open, observable via metrics).
func (b *Backend) fetchRPM(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
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
	rpmPath := resolved.Metadata[metaRpmPath]
	expected, ok := b.digests.get(rpmPath)
	if !ok {
		b.populateFromRepo(ctx)
		expected, ok = b.digests.get(rpmPath)
	}

	header := upstreamHeader(resp)
	content := resp.Body
	if ok {
		resolved.Metadata[MetaChecksumVerified] = expected.alg.name
		header.Set("X-Checksum-Verified", expected.alg.name)
		content = newVerifyingReader(resp.Body, expected, resolved.UpstreamURL, func(good bool) {
			if good {
				b.metrics.incRPMsVerified()
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

// fetchRepodata fetches a repodata metadata file, buffers it (bounded), verifies
// it against repomd.xml, and — for the primary.xml — parses it to populate the
// rpm-path digest store. A repomd-declared digest mismatch is a hard failure (the
// tampered metadata is refused); a file larger than the buffer cap is streamed
// live, unverified and unparsed.
func (b *Backend) fetchRepodata(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
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
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRepodataBufferB+1))
	if err != nil {
		drainClose(resp.Body)
		return nil, fmt.Errorf("yum %q: reading repodata file: %w", b.name, err)
	}
	if int64(len(data)) > maxRepodataBufferB {
		b.metrics.incPrimaryErrors()
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

	repodataPath := resolved.Metadata[metaRepodataPath]

	// Verify the file against repomd.xml when its digest is recoverable.
	var declared RepoData
	verified := false
	if rm, ok := b.repomd(ctx); ok {
		if d, ok := rm.FindByLocation(repodataPath); ok && d.HasSum {
			if verr := verifyBytes(data, d.Checksum, resolved.UpstreamURL); verr != nil {
				b.metrics.incRepodataMismatch()
				return nil, verr
			}
			b.metrics.incRepodataVerified()
			declared, verified = d, true
		}
	}

	// Parse primary.xml to record per-.rpm digests — only a primary repomd.xml
	// declares, and this file verified against it: an unverified one records
	// nothing (its .rpm fetches populate the store themselves).
	if verified && isPrimary(repodataPath) {
		b.populatePrimary(primaryKey(declared), repodataPath, data)
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

// fetchRepomd fetches repomd.xml, enforces the configured GPG signature at the
// client-facing boundary, and serves it. A configured-but-invalid signature is
// refused; with no keyring the document is served and the absence of enforcement
// is recorded.
func (b *Backend) fetchRepomd(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
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
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRepomdFetchBytes+1))
	drainClose(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("yum %q: reading repomd.xml: %w", b.name, err)
	}
	if int64(len(data)) > maxRepomdFetchBytes {
		return nil, fmt.Errorf("yum %q: repomd.xml exceeds %d bytes", b.name, maxRepomdFetchBytes)
	}

	b.metrics.incRepomdServed()
	if _, perr := ParseRepoMD(data); perr != nil {
		b.metrics.incRepomdErrors()
	} else {
		b.metrics.incRepomdParsed()
	}

	if b.keyring.enabled() {
		if verr := b.verifyRepomdSignature(ctx, resolved, data); verr != nil {
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

// verifyRepomdSignature fetches the detached repomd.xml.asc and validates it over
// the repomd.xml bytes against the configured keyring.
func (b *Backend) verifyRepomdSignature(ctx context.Context, resolved *backends.Resolved, repomdData []byte) error {
	return b.checkRepomdSignature(ctx, resolved.UpstreamURL+".asc", repomdData)
}

// checkRepomdSignature fetches a detached signature from sigURL and validates
// it over the repomd.xml bytes against the configured keyring.
func (b *Backend) checkRepomdSignature(ctx context.Context, sigURL string, repomdData []byte) error {
	resp, err := b.do(ctx, sigURL, "")
	if err != nil {
		return fmt.Errorf("yum %q: fetching repomd.xml.asc: %w", b.name, err)
	}
	if !resp.IsSuccess() {
		drainClose(resp.Body)
		return fmt.Errorf("yum %q: repomd.xml.asc unavailable (status %d); cannot validate signature", b.name, resp.Status)
	}
	sig, rerr := io.ReadAll(io.LimitReader(resp.Body, maxRepomdSigBytes+1))
	drainClose(resp.Body)
	if rerr != nil || int64(len(sig)) > maxRepomdSigBytes {
		return fmt.Errorf("yum %q: reading repomd.xml.asc", b.name)
	}
	return b.keyring.verifyDetached(repomdData, sig)
}

// repomd fetches and parses repomd.xml from the repository root for internal
// verification lookups. When a keyring is configured the document must carry a
// valid signature (repomd.xml.asc), as it must for a client: the digests the
// backend takes from the chain below it are no better anchored than it is.
func (b *Backend) repomd(ctx context.Context) (*RepoMD, bool) {
	u := b.joinPath("/" + repomdPath).String()
	resp, err := b.do(ctx, u, "")
	if err != nil {
		return nil, false
	}
	if !resp.IsSuccess() {
		drainClose(resp.Body)
		return nil, false
	}
	data, rerr := io.ReadAll(io.LimitReader(resp.Body, maxRepomdFetchBytes+1))
	drainClose(resp.Body)
	if rerr != nil || int64(len(data)) > maxRepomdFetchBytes {
		return nil, false
	}
	if b.keyring.enabled() {
		if err := b.checkRepomdSignature(ctx, u+".asc", data); err != nil {
			return nil, false
		}
	}
	rm, perr := ParseRepoMD(data)
	if perr != nil {
		return nil, false
	}
	return rm, true
}

// populateFromRepo performs an on-demand population of the digest store by
// fetching repomd.xml, locating primary.xml, verifying it against the checksum
// repomd.xml declares for it, and parsing it. Used to verify an .rpm requested
// before its primary.xml was proxied through the backend. One population runs
// at a time; it reads nothing more than repomd.xml when the store holds the
// digests of the primary repomd.xml names already (the .rpm is not in it). A
// primary repomd.xml declares no checksum for, or whose bytes do not match it,
// records nothing.
func (b *Backend) populateFromRepo(ctx context.Context) {
	select {
	case b.populating <- struct{}{}:
		defer func() { <-b.populating }()
	case <-ctx.Done():
		return
	}
	rm, ok := b.repomd(ctx)
	if !ok {
		return
	}
	d, ok := primaryData(rm)
	if !ok || !d.HasSum {
		return
	}
	key := primaryKey(d)
	if b.holdsPrimary(key) {
		return
	}
	u := b.joinPath("/" + d.Location).String()
	resp, err := b.do(ctx, u, "")
	if err != nil {
		return
	}
	if !resp.IsSuccess() {
		drainClose(resp.Body)
		return
	}
	data, rerr := io.ReadAll(io.LimitReader(resp.Body, maxPrimaryFetchBytes+1))
	drainClose(resp.Body)
	if rerr != nil || int64(len(data)) > maxPrimaryFetchBytes {
		return
	}
	if verifyBytes(data, d.Checksum, u) != nil {
		b.metrics.incRepodataMismatch()
		return
	}
	b.populatePrimary(key, d.Location, data)
}

// primaryData returns repomd.xml's primary entry.
func primaryData(rm *RepoMD) (RepoData, bool) {
	for _, d := range rm.Data {
		if d.Type == "primary" {
			return d, true
		}
	}
	return RepoData{}, false
}

// primaryKey names a primary: its location and the checksum repomd.xml
// declares for it.
func primaryKey(d RepoData) string {
	return d.Location + "\x00" + d.Checksum.alg.name + ":" + d.Checksum.hex
}

// holdsPrimary reports whether the store holds the digests of the primary key
// names: they were recorded last, and the store has not been cleared since.
func (b *Backend) holdsPrimary(key string) bool {
	b.loadedMu.Lock()
	loaded, probe := b.loaded, b.loadedProbe
	b.loadedMu.Unlock()
	if key == "" || key != loaded {
		return false
	}
	if probe == "" {
		return true // a primary without a package
	}
	_, ok := b.digests.get(probe)
	return ok
}

// populateFromPrimaryBytes records the digests a primary.xml declares (see
// populatePrimary), for a primary repomd.xml was not consulted about.
func (b *Backend) populateFromPrimaryBytes(location string, data []byte) bool {
	return b.populatePrimary("", location, data)
}

// errTooManyDigests marks a primary declaring more packages than the digest
// store holds.
var errTooManyDigests = errors.New("yum: primary.xml declares more packages than the digest store holds (raise DigestStoreMax)")

// populatePrimary decompresses and parses a primary.xml as a stream — gzip,
// xz or zstd, one package at a time (see OpenPrimary and StreamPrimary) — and
// records every (rpm-path -> checksum) it declares into the digest store: all
// of them once the whole document parsed, or none (a document that breaks
// off, or fails its decompressor's check at the end, is not the repository's
// declaration). key names the primary (primaryKey; "" when unknown), so that a
// later population can tell it is loaded. It reports whether it recorded.
func (b *Backend) populatePrimary(key, location string, data []byte) bool {
	filename := location
	if i := strings.LastIndexByte(location, '/'); i >= 0 {
		filename = location[i+1:]
	}
	r, release, derr := OpenPrimary(bytes.NewReader(data), filename, maxPrimaryBytes)
	if derr != nil {
		if !errors.Is(derr, errUnsupportedCompression) {
			b.metrics.incPrimaryErrors()
		}
		return false
	}
	defer release()
	staged := map[string]expectedChecksum{}
	probe := ""
	perr := StreamPrimary(r, func(e PrimaryEntry) error {
		href := strings.TrimLeft(e.Location, "/")
		if href == "" || strings.Contains(href, "..") {
			return nil
		}
		c, ok := parseChecksum(e.ChecksumType, e.Checksum)
		if !ok {
			return nil
		}
		if _, dup := staged[href]; !dup && len(staged) >= b.digests.max {
			return errTooManyDigests
		}
		if probe == "" {
			probe = href
		}
		staged[href] = c
		return nil
	})
	if perr != nil {
		b.metrics.incPrimaryErrors()
		return false
	}
	b.digests.putAll(staged)
	b.loadedMu.Lock()
	b.loaded, b.loadedProbe = key, probe
	b.loadedMu.Unlock()
	b.metrics.incPrimaryParsed()
	return true
}

// putAll records a primary's digests at once. When they do not fit beside the
// ones the store holds, the store starts over with them alone (as put does
// when it is full), so that it holds every digest of the primary or none.
func (s *digestStore) putAll(entries map[string]expectedChecksum) {
	s.mu.Lock()
	defer s.mu.Unlock()
	added := 0
	for k := range entries {
		if _, ok := s.entries[k]; !ok {
			added++
		}
	}
	if len(s.entries)+added > s.max {
		s.entries = make(map[string]expectedChecksum, len(entries))
	}
	for k, c := range entries {
		s.entries[k] = c
	}
}

// isPrimary reports whether a repodata path is a primary.xml metadata file.
func isPrimary(repodataPath string) bool {
	base := repodataPath
	if i := strings.LastIndexByte(repodataPath, '/'); i >= 0 {
		base = repodataPath[i+1:]
	}
	return strings.Contains(base, "primary.xml")
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
	return &backends.StatusError{Status: resp.Status, RetryAfter: resp.Header.Get("Retry-After"), URL: url, Body: snippet}
}

// joinPath appends the inbound YUM path to the upstream base, preserving any
// base-path prefix (the repository directory containing repodata/).
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

func drainClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 4096))
	_ = body.Close()
}
