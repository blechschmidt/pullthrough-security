// Package maven implements a pull-through proxy backend for the Maven repository
// layout (Maven Central, JFrog/Nexus mirrors, and any HTTP repository serving
// the standard GAV directory structure). It brings the JVM ecosystem to parity
// with the pip/npm/cargo/go/nuget backends: artifacts and their checksum and
// signature sidecars are proxied and cached, fetched bytes are verified against
// the upstream-declared checksum before they are cached or served, POMs are
// parsed to feed authoritative coordinates into the admission gates, and both
// release and snapshot resolution semantics (maven-metadata.xml) are supported.
//
// Protocol mapping (Maven 2/3 layout):
//
//	GET /<group>/<artifact>/<version>/<artifact>-<version>[-<classifier>].<ext>
//	    primary artifact (.jar/.pom/.war/.module/.aar/...). Immutable for a release
//	    version (and for a resolved/timestamped snapshot); cached and checksum-
//	    verified against its .sha256/.sha1/.md5 sidecar.
//	GET .../<file>.sha1|.sha256|.md5|.sha512   checksum sidecar (served as-is).
//	GET .../<file>.asc                          detached PGP signature (served as-is).
//	GET /<group>/<artifact>/maven-metadata.xml  release metadata (mutable, revalidated).
//	GET /<group>/<artifact>/<v>-SNAPSHOT/maven-metadata.xml  snapshot metadata (mutable).
//
// Security model: the checksum sidecar is the upstream's own declared digest of
// the artifact. The backend fetches it on a cache miss and verifies the artifact
// content against it as the bytes stream through (or, for small POMs parsed in
// memory, before they are returned). A mismatch aborts the cache write and the
// response, so a tampered or corrupt mirror can neither poison the cache nor
// reach a client. This mirrors the digest verification the Docker/OCI backend
// performs on content-addressed blobs.
//
// Client configuration points the build tool's repository at
// "<publicBase>/v1/<name>" (see docs/clients.md).
package maven

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
// generic httpbackend and the docker backend, and are not persisted to the cache
// as meaningful data.
const (
	metaKind       = "_kind"       // resource class label, for diagnostics/gates
	metaVerify     = "_verify"     // "1" when the artifact must be checksum-verified
	metaArtifact   = "_artifactID" // parsed artifactId, for POM cross-checking
	metaGroup      = "_groupID"    // parsed groupId
	metaVersion    = "_version"    // parsed version
	metaClassifier = "_classifier" // parsed classifier
	metaExt        = "_ext"        // parsed primary extension
	metaIsPOM      = "_pom"        // "1" when the artifact is a .pom to parse
)

// Persisted (caller-meaningful) metadata keys surfaced to downstream gates.
const (
	// MetaPackaging records the POM's declared packaging (jar, war, pom, ...).
	MetaPackaging = "maven.packaging"
	// MetaLicenses records a comma-separated list of license names declared in a
	// POM, for the license-compliance gate.
	MetaLicenses = "maven.licenses"
	// MetaChecksumVerified records the algorithm an artifact was verified with
	// ("sha256", "sha1", ...), or "none" when no sidecar was available.
	MetaChecksumVerified = "maven.checksumVerified"
)

// maxErrorBodySnippet bounds how much of an upstream error body is retained for
// diagnostics.
const maxErrorBodySnippet = 2 << 10 // 2 KiB

// maxChecksumSidecarBytes bounds a checksum-sidecar fetch. These files hold a
// single hex digest (plus optional filename), so a few KiB is generous; the cap
// stops a hostile upstream returning a huge body in place of a checksum.
const maxChecksumSidecarBytes = 16 << 10 // 16 KiB

// maxVerifiableBufferBytes bounds the in-memory buffering used to verify and
// parse a POM. POMs are small text documents; larger primary artifacts (.jar,
// .war) are never buffered — they are verified as they stream.
const maxVerifiableBufferBytes = maxPOMBytes

// Options configures a Maven Backend.
type Options struct {
	// Name is the route identifier and cache-key prefix (e.g. "maven-central").
	// Required.
	Name string
	// UpstreamURL is the repository base URL, e.g. "https://repo1.maven.org/maven2".
	// Required.
	UpstreamURL string
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool can be injected in place
	// of the bare *upstream.Client to add repository-mirror failover transparently.
	Client upstream.Doer
	// Credentials authenticate the proxy to the upstream repository. Optional;
	// public repositories pull anonymously.
	Credentials upstream.Credentials
	// Metrics, when set, records supply-chain telemetry (checksum verifications,
	// mismatches, POM parses, snapshot resolutions). Optional.
	Metrics *Metrics
}

// Backend is a Maven repository pull-through backend implementing
// backends.Backend.
type Backend struct {
	name    string
	base    *url.URL
	client  upstream.Doer
	creds   upstream.Credentials
	metrics *Metrics
}

var _ backends.Backend = (*Backend)(nil)

// New validates opts and constructs a Backend.
func New(opts Options) (*Backend, error) {
	if strings.TrimSpace(opts.Name) == "" {
		return nil, errors.New("maven: name is required")
	}
	if strings.TrimSpace(opts.UpstreamURL) == "" {
		return nil, fmt.Errorf("maven %q: upstream URL is required", opts.Name)
	}
	base, err := url.Parse(strings.TrimRight(opts.UpstreamURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("maven %q: invalid upstream URL: %w", opts.Name, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("maven %q: upstream URL must be http(s), got %q", opts.Name, base.Scheme)
	}
	if opts.Client == nil {
		return nil, fmt.Errorf("maven %q: upstream client is required", opts.Name)
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
	}, nil
}

// Metrics returns the backend's telemetry counters so the cmd wiring can bridge
// them into the central Prometheus collector.
func (b *Backend) Metrics() *Metrics { return b.metrics }

// Name implements backends.Backend.
func (b *Backend) Name() string { return b.name }

// Resolve implements backends.Backend. It classifies the inbound path against
// the Maven layout, derives the upstream URL and cache key, attaches the GAV
// coordinate for the admission gates, decides cacheability (immutable
// artifacts cached; mutable metadata and unresolved snapshots revalidated), and
// states for the content gates whether the resource is an installable payload
// or a metadata document (resource.artifact).
func (b *Backend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("maven: nil request")
	}

	res, ok := classify(req.Path)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a Maven layout path", backends.ErrNotSupported, req.Path)
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
			"backend":    b.name,
			metaKind:     res.kindLabel(),
			metaGroup:    res.groupID,
			metaArtifact: res.artifactID,
			metaVersion:  res.version,
		},
		// Payload or metadata is a property of the resource, not of its
		// cacheability: an unresolved snapshot jar is a payload that is never
		// cached.
		Artifact: res.artifact(req.Path),
	}

	// Attach the GAV coordinate so nameguard, policy, provenance, vulnscan,
	// license, and policyengine can identify the artifact. Versionless metadata
	// requests carry the name only.
	if cn := res.coordinateName(); cn != "" {
		resolved.Coordinate = backends.Coordinate{Name: cn, Version: res.version}
	}

	if res.verifiableArtifact() {
		resolved.Metadata[metaVerify] = "1"
		resolved.Metadata[metaClassifier] = res.classifier
		resolved.Metadata[metaExt] = res.ext
		if strings.EqualFold(res.ext, "pom") {
			resolved.Metadata[metaIsPOM] = "1"
		}
	}

	return resolved, nil
}

// Fetch implements backends.Backend. For primary artifacts it first fetches the
// upstream checksum sidecar and then verifies the artifact content against it —
// streaming for large artifacts, in memory for POMs (which it also parses to
// cross-check coordinates and surface packaging/licenses). Metadata and sidecar
// requests are proxied directly.
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved == nil {
		return nil, errors.New("maven: nil resolved")
	}

	resp, err := b.client.Do(ctx, upstream.Request{
		URL:         resolved.UpstreamURL,
		Method:      http.MethodGet,
		Creds:       b.creds,
		IfNoneMatch: resolved.IfNoneMatch,
	})
	if err != nil {
		return nil, err
	}
	if resp.NotModified {
		return &backends.FetchResult{Resolved: resolved, Status: http.StatusNotModified, NotModified: true}, nil
	}
	if !resp.IsSuccess() {
		snippet := readSnippet(resp.Body)
		drainClose(resp.Body)
		return nil, &backends.StatusError{Status: resp.Status, URL: resolved.UpstreamURL, Body: snippet}
	}

	b.recordMetadataMetric(resolved)

	header := make(http.Header)
	upstream.PropagateResponseHeaders(header, resp.Header)
	if resp.ETag != "" {
		header.Set("ETag", resp.ETag)
	}
	if resp.LastModified != "" {
		header.Set("Last-Modified", resp.LastModified)
	}

	// Non-artifact resources (metadata, checksum/signature sidecars) are proxied
	// without verification.
	if resolved.Metadata[metaVerify] != "1" {
		return &backends.FetchResult{
			Resolved:  resolved,
			Content:   resp.Body,
			Size:      resp.ContentLength,
			MediaType: resp.ContentType,
			Header:    header,
			Status:    resp.Status,
		}, nil
	}

	// Resolve the expected checksum from the strongest sidecar the upstream
	// serves. A missing sidecar is recorded and the artifact is served unverified
	// (fail-open is the only option when the upstream publishes no digest at all;
	// the absence is observable via metrics).
	expected, haveChecksum := b.fetchExpectedChecksum(ctx, resolved.UpstreamURL)
	if haveChecksum {
		// Persist the verifying algorithm with the cache entry. A mismatch aborts
		// the store, so a persisted entry is always one that verified.
		resolved.Metadata[MetaChecksumVerified] = expected.alg.name
	} else {
		b.metrics.incSidecarMissing()
		resolved.Metadata[MetaChecksumVerified] = "none"
	}

	// POMs are small and must be parsed; buffer, verify in memory, parse, and
	// return the buffered bytes.
	if resolved.Metadata[metaIsPOM] == "1" {
		return b.fetchPOM(resolved, resp, header, expected, haveChecksum)
	}

	// Large artifacts (.jar/.war/...) stream through a verifying reader so a hash
	// mismatch aborts the cache write and the client stream without buffering. The
	// outcome is only known at end-of-stream, so the reader reports it via the
	// callback for accurate verified/mismatch counts.
	content := resp.Body
	if haveChecksum {
		content = newVerifyingReader(resp.Body, expected, resolved.UpstreamURL, func(ok bool) {
			if ok {
				b.metrics.incArtifactsVerified()
			} else {
				b.metrics.incChecksumMismatch()
			}
		})
		header.Set("X-Checksum-Verified", expected.alg.name)
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

// fetchPOM buffers, verifies, and parses a POM. It cross-checks the declared GAV
// against the path and surfaces packaging/licenses as cache metadata for the
// downstream license gate.
func (b *Backend) fetchPOM(resolved *backends.Resolved, resp *upstream.Response, header http.Header, expected expectedChecksum, haveChecksum bool) (*backends.FetchResult, error) {
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxVerifiableBufferBytes+1))
	drainClose(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("maven %q: reading POM: %w", b.name, err)
	}
	if int64(len(data)) > maxVerifiableBufferBytes {
		return nil, fmt.Errorf("maven %q: POM exceeds %d bytes", b.name, maxVerifiableBufferBytes)
	}

	if haveChecksum {
		if verr := verifyBytes(data, expected, resolved.UpstreamURL); verr != nil {
			b.metrics.incChecksumMismatch()
			return nil, verr
		}
		b.metrics.incArtifactsVerified()
		header.Set("X-Checksum-Verified", expected.alg.name)
	}

	if pom, perr := ParsePOM(data); perr != nil {
		b.metrics.incPOMParseErrors()
	} else {
		b.metrics.incPOMsParsed()
		b.applyPOMMetadata(resolved, pom)
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

// applyPOMMetadata records the POM's packaging and licenses into the resolved
// metadata (persisted with the cache entry) and flags a coordinate mismatch
// between the POM and the path it was served at.
func (b *Backend) applyPOMMetadata(resolved *backends.Resolved, pom *POM) {
	if pom.Packaging != "" {
		resolved.Metadata[MetaPackaging] = pom.Packaging
	}
	if names := licenseNames(pom.Licenses); names != "" {
		resolved.Metadata[MetaLicenses] = names
	}
	if !pom.matchesPath(resolved.Metadata[metaGroup], resolved.Metadata[metaArtifact], resolved.Metadata[metaVersion]) {
		b.metrics.incCoordinateMismatch()
		resolved.Metadata["maven.coordinateMismatch"] = "1"
	}
}

// fetchExpectedChecksum fetches the strongest available checksum sidecar for the
// artifact at artifactURL and returns the parsed expected checksum. It tries the
// algorithms in preference order, stopping at the first that exists and parses.
func (b *Backend) fetchExpectedChecksum(ctx context.Context, artifactURL string) (expectedChecksum, bool) {
	for _, alg := range verifyAlgorithms {
		resp, err := b.client.Do(ctx, upstream.Request{
			URL:    artifactURL + alg.ext,
			Method: http.MethodGet,
			Creds:  b.creds,
		})
		if err != nil {
			continue
		}
		if !resp.IsSuccess() {
			drainClose(resp.Body)
			continue
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxChecksumSidecarBytes+1))
		drainClose(resp.Body)
		if rerr != nil || int64(len(body)) > maxChecksumSidecarBytes {
			continue
		}
		hex, perr := parseChecksumValue(body, alg)
		if perr != nil {
			continue
		}
		return expectedChecksum{alg: alg, hex: hex}, true
	}
	return expectedChecksum{}, false
}

// recordMetadataMetric counts served maven-metadata.xml documents by flavour.
func (b *Backend) recordMetadataMetric(resolved *backends.Resolved) {
	if resolved.Metadata[metaKind] != "metadata" {
		return
	}
	if resolved.Metadata[metaVersion] != "" {
		b.metrics.incSnapshotMetadata()
	} else {
		b.metrics.incReleaseMetadata()
	}
}

// licenseNames joins POM license names for the license-gate metadata, skipping
// empties.
func licenseNames(licenses []POMLicense) string {
	names := make([]string, 0, len(licenses))
	for _, l := range licenses {
		if l.Name != "" {
			names = append(names, l.Name)
		}
	}
	return strings.Join(names, ",")
}

// joinPath appends the inbound Maven path to the upstream base, preserving any
// base path prefix (e.g. a repository served under "/maven2" or
// "/repository/maven-public").
func (b *Backend) joinPath(path string) *url.URL {
	out := *b.base
	basePath := strings.TrimRight(b.base.EscapedPath(), "/")
	out.Path = basePath + "/" + strings.TrimLeft(path, "/")
	out.RawPath = ""
	return &out
}

// cacheKey derives a stable cache key from the backend name and the layout path.
// The Maven layout is itself coordinate-addressed, so the path alone is a stable
// key; query parameters are incidental and excluded.
func (b *Backend) cacheKey(path string) string {
	return b.name + ":" + strings.TrimLeft(path, "/")
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

// kindLabel returns a stable diagnostic label for a resource kind.
func (r resource) kindLabel() string {
	switch r.kind {
	case kindArtifact:
		return "artifact"
	case kindChecksum:
		return "checksum"
	case kindSignature:
		return "signature"
	case kindMetadata, kindMetadataChecksum:
		return "metadata"
	default:
		return "other"
	}
}
