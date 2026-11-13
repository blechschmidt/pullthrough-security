package proxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/approvals"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
)

// The LLM package-content scan gate's reading of objects the proxy fetched for
// itself (Task 181).
//
// The repository registry scans every dependency a repository's lock files pin.
// A dependency it fetches through the gated pipeline (SystemFetch) is judged by
// the gate on the way, and that reading is returned with the fetch. A release's
// dependencies are already pinned in the cache: SystemScan puts such an object
// before the gate without serving it — the verdict cache answers for bytes that
// already have a verdict, and a scan, when one is needed, is held to the gate's
// cost budget, concurrency limits and per-tenant share like any other.

// Why the gate does not examine an object (SystemLLMScan.NotApplicable).
const (
	// LLMOutOfScope: the gate does not scan the ecosystem, or the upstream is
	// excluded (llmPackageScan.include / exclude / excludeUpstreams).
	LLMOutOfScope = "out-of-scope"
	// LLMNotPackage: the object is not package content (a metadata document,
	// an index, an image index).
	LLMNotPackage = "not-package-content"
	// LLMCoveredByImage: an image blob the scan of its image read in full; the
	// image's verdict, on the manifest, covers it.
	LLMCoveredByImage = "covered-by-image"
)

// SystemLLMScan is the LLM package-content scan gate's reading of one object
// the proxy fetched or holds for itself.
type SystemLLMScan struct {
	// Applicable is false when the gate does not examine the object;
	// NotApplicable then says why (LLMOutOfScope, LLMNotPackage,
	// LLMCoveredByImage) and NotApplicableReason in a sentence.
	Applicable          bool
	NotApplicable       string
	NotApplicableReason string
	// Report is the gate's report: a verdict (from the verdict cache or a fresh
	// scan), or the reason there is none. Decision is how the configured action
	// and fail mode read it: what a client's pull of the object is told.
	Report   *llmpkgscan.Report
	Decision llmpkgscan.Decision
	// Deferred reports that the gate would have refused the object and the
	// fetch admitted it, the caller having asked to apply the ladder itself.
	Deferred bool
	// Pinned reports that a release pins the object: a refusal keeps its bytes.
	Pinned bool
	// ReviewCoordinate is the coordinate a break-glass review of the object is
	// scoped to (for an image or one of its blobs: the repository and the
	// manifest digest); BreakGlass is the request ID of an active grant
	// releasing the object, when there is one.
	ReviewCoordinate string
	BreakGlass       string
}

// ErrLLMScanDisabled is returned by SystemScan when the gate is off.
var ErrLLMScanDisabled = errors.New("proxy: the LLM package-content scan gate is not enabled")

// llmScopeReason says why the gate does not scan an ecosystem's artifacts
// fetched through an upstream.
func llmScopeReason(svc *llmpkgscan.Service, ecosystem, upstream string) string {
	if svc.Applies(ecosystem) {
		return "the upstream " + upstream + " is excluded from the LLM package scan (llmPackageScan.excludeUpstreams)"
	}
	return "the LLM package scan does not cover " + ecosystem + " artifacts (llmPackageScan.include / exclude)"
}

// activeBreakGlass returns the request ID of the active break-glass grant that
// releases an artifact the gate refuses, without consuming or opening anything.
func (g *Gateway) activeBreakGlass(r *http.Request, gate approvalGate, ecosystem, coordinate, reason string) string {
	if g.deps.Approvals == nil || !g.deps.Approvals.Enabled() || coordinate == "" {
		return ""
	}
	tenant := ""
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		tenant = p.Team
	}
	req, ok := g.deps.Approvals.Active(approvals.Scope{Tenant: tenant, Ecosystem: ecosystem, Coordinate: coordinate, Gate: string(gate), Reason: reason})
	if !ok {
		return ""
	}
	return req.ID
}

// SystemScanRequest asks for the gate's reading of one cached object.
type SystemScanRequest struct {
	// Backend is the upstream name; Path the backend-relative path the object
	// was fetched under; Accept the Accept header it was fetched with.
	Backend string
	Path    string
	Accept  string
	// Tenant, Subject and Roles are the system principal the scan runs as:
	// the tenant whose cache namespace holds the object, whose scan budget
	// pays, and who may read the verdict afterwards.
	Tenant  string
	Subject string
	Roles   []string
	// CacheKey is the key the object is stored under: the path must resolve
	// to it. Digest, when set, is the digest ("sha256:…") the stored object
	// must still have.
	CacheKey string
	Digest   string
}

// SystemScan puts one cached object before the LLM package-content scan gate
// without serving it, and returns the gate's reading. Bytes that already have
// a verdict cost no model call; otherwise the scan runs under the gate's
// budget and limits, as the tenant. Nothing is evicted, refused or reviewed:
// the caller reports. An error means the object could not be put before the
// gate at all (it is not in the cache any more, the path does not resolve to
// it, the principal may not read the upstream, the caller is gone).
func (g *Gateway) SystemScan(ctx context.Context, req SystemScanRequest) (*SystemLLMScan, error) {
	svc := g.deps.LLMPkgScan
	if !svc.Enabled() {
		return nil, ErrLLMScanDisabled
	}
	if req.Backend == "" || !strings.HasPrefix(req.Path, "/") || strings.ContainsAny(req.Path, "?#\r\n") {
		return nil, errors.New("proxy: a system scan needs a backend and an absolute path without query")
	}
	if backends.HasDotSegment(req.Path) {
		return nil, errors.New(`proxy: a system scan path has no "." or ".." segments`)
	}
	backend, ok := g.deps.Backends.Get(req.Backend)
	if !ok {
		return nil, fmt.Errorf("proxy: unknown backend %q", req.Backend)
	}
	ecosystem := g.ecosystemFor(req.Backend)
	if !svc.AppliesTo(ecosystem, req.Backend) {
		return &SystemLLMScan{NotApplicable: LLMOutOfScope, NotApplicableReason: llmScopeReason(svc, ecosystem, req.Backend)}, nil
	}
	if _, ok := backend.(backends.HTTPHandler); ok {
		// Git: served by its protocol handler, never from the package cache.
		return &SystemLLMScan{NotApplicable: LLMNotPackage, NotApplicableReason: "the object is served by a protocol handler, not from the package cache"}, nil
	}

	subject := req.Subject
	if subject == "" {
		subject = "system:repository-scanner"
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "/v1/"+req.Backend+req.Path, nil)
	if err != nil {
		return nil, fmt.Errorf("proxy: building system scan request: %w", err)
	}
	if req.Accept != "" {
		httpReq.Header.Set("Accept", req.Accept)
	}
	principal := &auth.Principal{Subject: subject, Team: req.Tenant, Method: "system", Roles: append([]string(nil), req.Roles...)}
	httpReq = httpReq.WithContext(auth.WithPrincipal(httpReq.Context(), principal))
	// The scan of an image may fetch its blobs: the principal must be one that
	// may read the upstream, as its fetches had to be.
	if g.deps.Enforcer != nil {
		if ok, reason := g.deps.Enforcer.Authorize(principal, req.Backend, ecosystem); !ok {
			return nil, fmt.Errorf("proxy: access control refuses the scan: %s", reason)
		}
	}

	resolved, err := backend.Resolve(ctx, &backends.Request{Method: http.MethodGet, Path: req.Path, Header: httpReq.Header})
	if err != nil {
		return nil, fmt.Errorf("proxy: resolving %s: %w", req.Path, err)
	}
	if !resolved.Cacheable {
		return nil, errors.New("proxy: the object is not cacheable, so the cache holds no copy to scan")
	}
	if g.opts.CacheNamespacing {
		resolved.CacheKey = principal.Namespace() + "/" + resolved.CacheKey
	}
	if req.CacheKey != "" && resolved.CacheKey != req.CacheKey {
		return nil, fmt.Errorf("proxy: the path resolves to cache key %q, not %q", resolved.CacheKey, req.CacheKey)
	}
	stat, err := g.deps.Cache.Stat(ctx, resolved.CacheKey)
	if err != nil {
		if errors.Is(err, cache.ErrNotFound) {
			return nil, errors.New("proxy: the object is not in the cache")
		}
		return nil, fmt.Errorf("proxy: reading the cached object: %w", err)
	}
	digest := stat.Metadata[cache.MetaDigest]
	if req.Digest != "" && digest != "" && !strings.EqualFold(digest, req.Digest) {
		return nil, fmt.Errorf("proxy: the cached object is %s now, not %s", digest, req.Digest)
	}

	sub := llmScanSubject{
		backend:   req.Backend,
		ecosystem: ecosystem,
		art:       llmPkgScanArtifactFor(ecosystem, req.Backend, resolved, digest, stat.Size),
		open:      g.llmScanCacheOpener(resolved.CacheKey, digest),
		pinned:    g.deps.Pins != nil && g.deps.Pins.IsPinned(resolved.CacheKey),
	}
	reviewCoordinate := sub.art.Coordinate()
	switch resolved.Artifact.Kind {
	case backends.KindOCIManifest:
		sub.art.Class = llmpkgscan.ClassPayload
		sub.image = g.llmImageSource(httpReq, req.Backend, backend, resolved.Coordinate.Name)
		if rc := imageReviewCoordinate(resolved.Coordinate.Name, sub.art.Digest); rc != "" {
			reviewCoordinate = rc
		}
	case backends.KindOCIBlob:
		blobDigest := resolved.Digest
		if blobDigest == "" {
			blobDigest = sub.art.Digest
		}
		switch st := svc.BlobStatus(ctx, blobDigest); {
		case st.Refused:
			sub.stored = st.Verdict
			sub.art.Digest = st.Verdict.Digest
			if rc := imageReviewCoordinate(resolved.Coordinate.Name, st.Verdict.Digest); rc != "" {
				reviewCoordinate = rc
			}
		case st.Covered:
			return &SystemLLMScan{NotApplicable: LLMCoveredByImage, Pinned: sub.pinned,
				NotApplicableReason: "the blob was read in full by the scan of an image that has it; the image's verdict covers it"}, nil
		default:
			sub.art.Class = llmpkgscan.ClassUnknown
			sub.art.RootFS = true
		}
	}

	var report *llmpkgscan.Report
	if sub.stored != nil {
		report = svc.ReportFor(sub.art, sub.stored)
	} else {
		report, err = svc.Assess(ctx, llmpkgscan.Request{Artifact: sub.art, Tenant: req.Tenant, Open: sub.open, Image: sub.image})
		if err != nil {
			return nil, err
		}
	}
	if report == nil {
		return &SystemLLMScan{NotApplicable: LLMNotPackage, Pinned: sub.pinned,
			NotApplicableReason: "the object is not package content the scan examines (a metadata document, an index)"}, nil
	}
	if report.Scanned() && !report.Cached && !report.Shared {
		g.meterScan(httpReq, "llmpkgscan")
	}
	decision := svc.Decide(report)
	sl := &SystemLLMScan{Applicable: true, Report: report, Decision: decision, Pinned: sub.pinned, ReviewCoordinate: reviewCoordinate}
	if !decision.Served() && llmPkgScanReviewable(report) {
		sl.BreakGlass = g.activeBreakGlass(httpReq, approvalGateLLMPkgScan, ecosystem, reviewCoordinate, llmPkgScanApprovalReason(report))
	}
	return sl, nil
}
