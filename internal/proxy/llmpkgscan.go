package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

// llmPkgScanRetryAfter is the Retry-After hint, in seconds, on a refusal whose
// cause is expected to clear by itself (the provider is failing, a scan ran out
// of time and is still finishing in the background).
const llmPkgScanRetryAfter = 30

// gateLLMPkgScan runs the sandboxed LLM package-content scan gate (Tasks 173,
// 174) on a cached resource: a language model reads the unpacked contents of
// the artifact — through a bounded, read-only view; nothing is ever executed —
// and returns a malicious / suspicious / benign verdict, which is stored under
// the artifact's sha256 digest. A pull of bytes that already have a verdict (a
// cache hit, or a re-fetch of an evicted artifact) consults the stored verdict
// and costs no model call.
//
// Which resources hold something to examine is the backend's to say: every
// backend classifies what it resolves (backends.Artifact). A payload is always
// examined; a metadata document or an unclassified resource is examined when
// its bytes turn out to be something a machine unpacks or runs. An OCI image is
// examined as a whole when its manifest is pulled, and its blobs follow the
// image's verdict (see gateLLMImage, gateLLMBlob).
//
// It runs after the deterministic content gates (contentscan, mlguard, avscan:
// they are cheap, and anything they refuse never reaches the model) and before
// the aggregating policy / risk gates, so its signal feeds them. The response
// is held until the verdict exists: not one byte of the artifact is written
// before the gate has decided — which is also what makes a Range request safe,
// since the range is cut from the entry only after the gate has passed.
//
//   - malicious under block or quarantine: refused (403, X-Policy-Code) and the
//     artifact is evicted from the cache.
//   - suspicious under quarantine: likewise refused and evicted, pending review.
//   - no verdict (the scan failed, timed out, was refused by the provider, the
//     budget is spent, the artifact is too large or cannot be unpacked): the
//     fail mode decides. It is never treated as a clean verdict.
//
// It returns true when the request may proceed and false when a response was
// written (or the client is gone).
func (g *Gateway) gateLLMPkgScan(w http.ResponseWriter, r *http.Request, name, ecosystem string, resolved *backends.Resolved, entry *cache.Entry) bool {
	svc := g.deps.LLMPkgScan
	// Scope first, before anything is read: an excluded upstream's artifacts are
	// never opened for scanning, let alone sent to the LLM provider.
	if !svc.AppliesTo(ecosystem, name) || entry == nil {
		if svc.Enabled() && entry != nil {
			noteLLMScan(r.Context(), &SystemLLMScan{NotApplicable: LLMOutOfScope, NotApplicableReason: llmScopeReason(svc, ecosystem, name)})
		}
		return true
	}
	digest := entry.Stat.Metadata[cache.MetaDigest]
	sub := llmScanSubject{
		backend:   name,
		ecosystem: ecosystem,
		art:       llmPkgScanArtifactFor(ecosystem, name, resolved, digest, entry.Stat.Size),
		open:      g.llmScanCacheOpener(resolved.CacheKey, digest),
		evict:     func(ctx context.Context) { g.evictLLMPkgScan(ctx, resolved) },
		// A release pins these bytes (Task 180): a refusal keeps them, for
		// forensics, and serving them stays refused all the same.
		pinned: resolved.Cacheable && g.deps.Pins != nil && g.deps.Pins.IsPinned(resolved.CacheKey),
	}
	switch resolved.Artifact.Kind {
	case backends.KindOCIManifest:
		return g.gateLLMImage(w, r, sub, resolved)
	case backends.KindOCIBlob:
		return g.gateLLMBlob(w, r, sub, resolved)
	}
	return g.admitLLMPkgScan(w, r, sub)
}

// llmScanSubject is one artifact put before the LLM package-scan gate, from
// whichever serve path it arrives on.
type llmScanSubject struct {
	backend   string
	ecosystem string
	art       llmpkgscan.Artifact
	// open yields a fresh stream of the artifact for the scan.
	open func(ctx context.Context) (io.ReadCloser, error)
	// image, when set, makes this the scan of an OCI image (art is its manifest).
	image *llmpkgscan.ImageSource
	// evict removes a refused artifact from wherever it is retained; nil when it
	// is retained nowhere.
	evict func(ctx context.Context)
	// stored, when set, is a verdict already on record that this subject is
	// judged by, instead of a scan: the verdict of the image a blob belongs to.
	stored *llmpkgscan.Verdict
	// reviewCoordinate and reviewDigest, when set, name the artifact a
	// break-glass review is opened for: for a blob, the image it belongs to.
	reviewCoordinate string
	// pinned reports that a release pins the cached artifact: a refusal does
	// not evict it (the cache would refuse to anyway), its bytes are kept.
	pinned bool
}

// llmScanCacheOpener returns the scan's way to read a cached artifact. The scan
// reads its own stream of the cached bytes, on its own context: it outlives a
// client that gives up, so the verdict is there for the retry.
//
// The verdict is bound to the digest the cache recorded for the entry being
// served. A full scan re-hashes what it reads and refuses to file a verdict if
// the two differ; a metadata-only scan does not read the artifact to its end,
// so the entry is checked here: one that was replaced under the same key since
// the request began is not the artifact the verdict would be filed under.
func (g *Gateway) llmScanCacheOpener(key, digest string) func(ctx context.Context) (io.ReadCloser, error) {
	return func(ctx context.Context) (io.ReadCloser, error) {
		e, err := g.deps.Cache.Get(ctx, key)
		if err != nil {
			return nil, err
		}
		if got := e.Stat.Metadata[cache.MetaDigest]; digest != "" && got != "" && got != digest {
			_ = e.Content.Close()
			return nil, errors.New("the cache entry changed while it was being scanned")
		}
		return e.Content, nil
	}
}

// admitLLMPkgScan puts one artifact before the gate and acts on the outcome. It
// is the one place a verdict becomes a response, shared by every serve path:
// the cache, a non-cacheable response, a Git LFS object, an image, a blob.
//
// It returns true when the artifact may be served (the gate's advisory headers
// are then set on w) and false when a refusal was written or the client is
// gone.
func (g *Gateway) admitLLMPkgScan(w http.ResponseWriter, r *http.Request, sub llmScanSubject) bool {
	svc := g.deps.LLMPkgScan
	name, ecosystem, art := sub.backend, sub.ecosystem, sub.art
	tenant := ""
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		tenant = p.Team
	}

	var report *llmpkgscan.Report
	if sub.stored != nil {
		report = svc.ReportFor(art, sub.stored)
	} else {
		var err error
		report, err = svc.Assess(r.Context(), llmpkgscan.Request{Artifact: art, Tenant: tenant, Open: sub.open, Image: sub.image})
		if err != nil {
			// Assess fails only when this request's own context ended while it
			// waited: as a rule the client is gone and there is no one to answer.
			// Nothing is served — and the response is given a status of its own, so
			// that whatever does still read it sees "not served", not the implicit
			// "200 OK" with an empty body a handler that writes nothing produces.
			w.Header().Set("Retry-After", strconv.Itoa(llmPkgScanRetryAfter))
			w.WriteHeader(http.StatusServiceUnavailable)
			return false
		}
	}
	if report == nil {
		// Nothing to examine: a metadata document, an index, an image index.
		noteLLMScan(r.Context(), &SystemLLMScan{NotApplicable: LLMNotPackage,
			NotApplicableReason: "the object is not package content the scan examines (a metadata document, an index)"})
		return true
	}
	if report.Scanned() && !report.Cached && !report.Shared {
		g.meterScan(r, "llmpkgscan")
	}

	// A system fetch that defers the gate's refusal (the release pinner and
	// the dependency scanner, Task 181) is no client decision: it is not
	// counted, and a deferred refusal is not handed on to the gates that run
	// after this one (policy, risk) either — they would only refuse the same
	// verdict the caller has taken on to act on.
	deferring := isSystemRequest(r) && deferringLLM(r.Context())
	var decision llmpkgscan.Decision
	if deferring {
		decision = svc.Decide(report)
	} else {
		decision = svc.Gate(report)
	}
	if !deferring || decision.Served() {
		recordLLMPkgScanSignal(r.Context(), svc, report)
	}
	coordinate := art.Coordinate()
	reviewCoordinate := coordinate
	if sub.reviewCoordinate != "" {
		reviewCoordinate = sub.reviewCoordinate
	}

	if isSystemRequest(r) {
		// The proxy asked itself (the repository registry, Tasks 180-181): its
		// caller is told what the gate read, and the active break-glass grant
		// that releases the bytes, if any.
		sl := &SystemLLMScan{Applicable: true, Report: report, Decision: decision, Pinned: sub.pinned,
			ReviewCoordinate: reviewCoordinate}
		if !decision.Served() && llmPkgScanReviewable(report) {
			sl.BreakGlass = g.activeBreakGlass(r, approvalGateLLMPkgScan, ecosystem, reviewCoordinate, llmPkgScanApprovalReason(report))
		}
		if !decision.Served() && deferring {
			// The release pinner and the dependency scanner apply the action
			// ladder themselves: the object is admitted — pinned, for a
			// release, and kept for forensics — and a client's own pull of it
			// is still judged, and refused, as always.
			sl.Deferred = true
			noteLLMScan(r.Context(), sl)
			// The findings document of the request still carries the gate's
			// reading: it is recorded after every gate ran, so it informs
			// without refusing (recordFindings).
			noteDeferredLLMSignal(r.Context(), llmPkgScanInput(svc, report))
			g.auditLLMPkgScanDeferred(r, name, ecosystem, report, decision)
			setLLMPkgScanHeaders(w.Header(), report, "deferred")
			return true
		}
		noteLLMScan(r.Context(), sl)
	}

	if !decision.Served() {
		// Human-in-the-loop break-glass (Task 50). A grant is scoped to the exact
		// bytes that were reviewed (see llmPkgScanApprovalReason). It is offered for
		// a verdict and for an artifact that cannot be scanned because of what it
		// is — never for a passing fault such as a provider outage, where it would
		// open a review for every package pulled while the fault lasts.
		if llmPkgScanReviewable(report) &&
			g.breakGlass(w, r, approvalGateLLMPkgScan, name, ecosystem, reviewCoordinate, llmPkgScanApprovalReason(report)) {
			setLLMPkgScanHeaders(w.Header(), report, "break-glass")
			return true
		}
		evicted := false
		switch {
		case decision.Evict && sub.pinned:
			// A release pins the bytes: they are kept, for forensics, and are
			// refused to every client while the verdict stands.
			decision.Evict = false
		case decision.Evict && sub.evict != nil:
			// Evict even if the client has gone: a refused artifact must not linger
			// because the request that found it was abandoned.
			sub.evict(context.WithoutCancel(r.Context()))
			evicted = true
		}
		g.auditLLMPkgScan(r, name, ecosystem, report, decision, sub.pinned)
		g.deps.Logger.Warn("LLM package-scan gate refused artifact",
			"backend", name, "ecosystem", ecosystem, "artifact", coordinate, "digest", report.Artifact.Digest,
			"disposition", string(report.Disposition), "code", decision.Code, "action", decision.Action,
			"evicted", evicted, "keptPinned", sub.pinned)
		if report.Scanned() && sub.stored == nil {
			g.notifyLLMPkgScan(r, name, ecosystem, report, decision)
		}
		writeLLMPkgScanBlock(w, report, decision)
		return false
	}

	// Served. Say how on the response, and leave a record of anything short of a
	// clean verdict.
	label := "clean"
	switch {
	case report.Unscanned != nil:
		label = "degraded"
		if report.Unscanned.Content {
			// The artifact itself defeated the scan: that is a decision worth a
			// record every time. A passing fault is counted in the metrics instead.
			g.auditLLMPkgScan(r, name, ecosystem, report, decision, sub.pinned)
		}
		g.deps.Logger.Debug("LLM package scan produced no verdict; served under fail-open policy",
			"backend", name, "ecosystem", ecosystem, "artifact", coordinate,
			"code", report.Unscanned.Code, "detail", report.Unscanned.Detail)
	case report.Disposition != llmpkgscan.DispositionBenign:
		label = "annotate"
		g.auditLLMPkgScan(r, name, ecosystem, report, decision, sub.pinned)
		g.deps.Logger.Warn("LLM package-scan gate flagged artifact (serving)",
			"backend", name, "ecosystem", ecosystem, "artifact", coordinate, "digest", report.Artifact.Digest,
			"disposition", string(report.Disposition), "action", decision.Action)
		if !report.Cached {
			// One alert per verdict, not one per pull of a flagged artifact.
			g.notifyLLMPkgScan(r, name, ecosystem, report, decision)
		}
	}
	setLLMPkgScanHeaders(w.Header(), report, label)
	return true
}

// llmPkgScanArtifactFor builds the scan artifact from a resolved resource: its
// coordinate and file name, the digest and size of the bytes in hand, and the
// backend's classification of what it is.
//
// The digest is the one computed over the bytes being served (by the cache when
// it wrote them, or by the gateway while it held a non-cacheable response). An
// upstream-declared digest (resolved.Digest) is a claim about what should have
// been fetched and is not used here.
func llmPkgScanArtifactFor(ecosystem, upstream string, resolved *backends.Resolved, digest string, size int64) llmpkgscan.Artifact {
	art := llmpkgscan.Artifact{
		Ecosystem: ecosystem,
		Upstream:  upstream,
		Name:      resolved.Coordinate.Name,
		Version:   resolved.Coordinate.Version,
		Filename:  resolved.ArtifactFilename(),
		Digest:    digest,
		Size:      size,
	}
	switch a := resolved.Artifact; a.Class {
	case backends.ArtifactPayload:
		art.Class = llmpkgscan.ClassPayload
		art.SingleFile = a.Kind == backends.KindFile
	case backends.ArtifactMetadata:
		art.Class = llmpkgscan.ClassMetadata
		art.IndexArchive = a.Kind == backends.KindIndexArchive
	default:
		art.Class = llmpkgscan.ClassUnknown
	}
	return art
}

// llmPkgScanReviewable reports whether a refusal can be released by a
// break-glass grant: a verdict, or an artifact unscannable because of its own
// bytes.
func llmPkgScanReviewable(report *llmpkgscan.Report) bool {
	if report.Unscanned != nil {
		return report.Unscanned.Content
	}
	return true
}

// llmPkgScanApprovalReason is the reason a break-glass review is scoped to. The
// approvals workflow matches a grant on (tenant, ecosystem, coordinate, gate,
// reason), so the reason carries the artifact digest: a grant releases exactly
// the bytes the reviewer looked at, and does not carry over to different bytes
// later served under the same coordinate. It deliberately omits the confidence
// and the model's wording, which would change on a re-scan and orphan the grant.
func llmPkgScanApprovalReason(report *llmpkgscan.Report) string {
	if report.Unscanned != nil {
		return "LLM content scan could not examine the artifact (" + report.Unscanned.Code + "): " + report.Artifact.Digest
	}
	return "LLM content scan judged the artifact " + string(report.Disposition) + ": " + report.Artifact.Digest
}

// evictLLMPkgScan removes a refused artifact from the content cache so it is
// neither served nor retained (quarantine). Its verdict stays in the verdict
// cache: a later pull re-fetches the bytes and is refused again without another
// model call.
func (g *Gateway) evictLLMPkgScan(ctx context.Context, resolved *backends.Resolved) {
	if !resolved.Cacheable {
		return // a non-cacheable resource is retained nowhere
	}
	if err := g.deps.Cache.Delete(ctx, resolved.CacheKey); err != nil && !errors.Is(err, cache.ErrNotFound) {
		g.deps.Logger.Warn("LLM package-scan gate: evicting cached artifact failed",
			"key", resolved.CacheKey, "error", err)
	}
}

// recordLLMPkgScanSignal captures the scan result into the admission signal
// accumulator for the policy-as-code and risk-scoring engines, the findings /
// SARIF layer and the dossier. No-op when no accumulator is attached.
func recordLLMPkgScanSignal(ctx context.Context, svc *llmpkgscan.Service, report *llmpkgscan.Report) {
	s := signalsFrom(ctx)
	if s == nil || report == nil {
		return
	}
	in := llmPkgScanInput(svc, report)
	s.mu.Lock()
	s.input.LLMPackage = in
	s.mu.Unlock()
}

// llmPkgScanInput is the admission document's section for a report.
func llmPkgScanInput(svc *llmpkgscan.Service, report *llmpkgscan.Report) *policyengine.LLMPackageInput {
	in := &policyengine.LLMPackageInput{
		Scanned:      report.Scanned(),
		Disposition:  string(report.Disposition),
		Action:       string(svc.Action()),
		Cached:       report.Cached,
		Reason:       report.Reason,
		FindingCount: len(report.Findings),
		Risk:         report.Risk,
	}
	if v := report.Verdict; v != nil {
		in.Verdict = v.Verdict
		in.Confidence = v.Confidence
		in.Model = v.Model
		in.Mode = v.Mode
		in.Truncated = v.Truncated
		in.StructuralRisk = v.StructuralRisk
		in.EvidenceCount = len(v.Evidence)
		for _, ev := range v.Evidence {
			if ev.Verified {
				in.VerifiedEvidence++
			}
		}
		seen := make(map[string]bool)
		for _, hit := range v.Injection {
			if !hit.Strong {
				continue
			}
			in.Injection = true
			if !seen[hit.Rule] {
				seen[hit.Rule] = true
				in.InjectionRules = append(in.InjectionRules, hit.Rule)
			}
		}
	}
	if u := report.Unscanned; u != nil {
		in.Unscanned = true
		in.UnscannedCode = u.Code
		in.ContentAttributable = u.Content
	}
	for _, f := range report.Findings {
		if severityRank(f.Severity) > severityRank(in.MaxSeverity) {
			in.MaxSeverity = f.Severity
		}
		in.Findings = append(in.Findings, policyengine.LLMPackageFinding{
			RuleID:   f.RuleID,
			Category: f.Category,
			Severity: f.Severity,
			Title:    f.Title,
			Detail:   f.Detail,
			File:     f.File,
			Line:     f.Line,
		})
	}
	return in
}

// severityRank orders finding severities; an unknown or empty one ranks lowest.
func severityRank(sev string) int {
	switch sev {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0
}

// setLLMPkgScanHeaders describes the gate's result on the response. Every value
// is either an enumerated token or a sentence the proxy wrote: nothing the
// model said in free text — which the package under review can shape — is put
// in a header.
func setLLMPkgScanHeaders(h http.Header, report *llmpkgscan.Report, decision string) {
	h.Set("X-LLMPkgScan-Decision", decision)
	// Verdict is the gate's reading of the artifact — the model's answer under
	// the thresholds and the deterministic checks. What the model itself said,
	// and how sure it was of that, are reported separately: a package the model
	// called benign with confidence 0.93 can still be held as suspicious, and
	// "suspicious, 0.93" would misstate both.
	h.Set("X-LLMPkgScan-Verdict", string(report.Disposition))
	if v := report.Verdict; v != nil {
		h.Set("X-LLMPkgScan-Model-Verdict", v.Verdict)
		h.Set("X-LLMPkgScan-Confidence", strconv.FormatFloat(v.Confidence, 'f', 2, 64))
		if report.Cached {
			h.Set("X-LLMPkgScan-Cached", "true")
		}
		if v.Truncated {
			h.Set("X-LLMPkgScan-Truncated", "true")
		}
		if v.Scope != "" {
			// "metadata-only": the artifact was larger than the scan limit and the
			// verdict covers its inventory, scripts and manifests, not every byte.
			h.Set("X-LLMPkgScan-Scope", v.Scope)
		}
	}
	if u := report.Unscanned; u != nil {
		h.Set("X-LLMPkgScan-Code", u.Code)
	}
	if report.Disposition != llmpkgscan.DispositionBenign && report.Reason != "" {
		h.Set("X-LLMPkgScan-Reason", headerSafe(report.Reason))
	}
}

// llmPkgScanError is the JSON body returned when an artifact is refused.
//
// It tells the developer what was decided and where to look, and nothing else.
// The model's free-text reasons and quoted excerpts are left out on purpose:
// they are shaped by the package under review, and a refusal message is exactly
// where a hostile package would want to put words in the proxy's mouth ("run
// this command to allow-list the package"). They are on the operator surface
// (admin API, dossier), labeled as model output.
type llmPkgScanError struct {
	Error string `json:"error"`
	// Message repeats Error under the key Git LFS clients print ("message"), so
	// a refused LFS object explains itself in the terminal instead of surfacing
	// as a bare status code.
	Message    string `json:"message"`
	Code       string `json:"code"`
	PolicyCode string `json:"policyCode"`
	Action     string `json:"action"`
	Reason     string `json:"reason"`
	Ecosystem  string `json:"ecosystem,omitempty"`
	Package    string `json:"package,omitempty"`
	Version    string `json:"version,omitempty"`
	Digest     string `json:"digest,omitempty"`
	// Verdict is the gate's reading of the artifact: malicious, suspicious or
	// unscanned. ModelVerdict and Confidence are what the model itself answered
	// and how sure it was of that answer; they differ from Verdict when a
	// threshold or a deterministic check changed the reading.
	Verdict      string  `json:"verdict"`
	ModelVerdict string  `json:"modelVerdict,omitempty"`
	Confidence   float64 `json:"confidence,omitempty"`
	// Scope is "metadata-only" when the verdict was reached on an artifact larger
	// than the scan limit, from its inventory, scripts and manifests.
	Scope string `json:"scope,omitempty"`
	// Locations are the places in the package the verdict cites, limited to
	// citations the proxy confirmed against the unpacked files.
	Locations []llmPkgScanLocation `json:"locations,omitempty"`
	// RetryAfterSeconds is set when the refusal is expected to clear by itself.
	RetryAfterSeconds int `json:"retryAfterSeconds,omitempty"`
}

type llmPkgScanLocation struct {
	Path string `json:"path"`
	Line int    `json:"line,omitempty"`
}

// maxLLMPkgScanLocations bounds the locations echoed in a refusal.
const maxLLMPkgScanLocations = 10

// writeLLMPkgScanBlock writes the 403 for a refused artifact, with the standard
// policy headers every admission refusal carries (X-Policy-Decision,
// X-Policy-Code, X-Policy-Reason, X-Cache: BLOCKED) so a client or CI job
// handles it like any other policy block.
func writeLLMPkgScanBlock(w http.ResponseWriter, report *llmpkgscan.Report, d llmpkgscan.Decision) {
	art := report.Artifact
	body := llmPkgScanError{
		Error:      "artifact blocked by LLM package-content scan policy",
		Code:       d.Code,
		PolicyCode: d.PolicyCode,
		Action:     d.Action,
		Reason:     d.Reason,
		Ecosystem:  art.Ecosystem,
		Package:    art.Name,
		Version:    art.Version,
		Digest:     art.Digest,
		Verdict:    string(report.Disposition),
	}
	h := w.Header()
	setLLMPkgScanHeaders(h, report, "block")
	if v := report.Verdict; v != nil {
		body.ModelVerdict = v.Verdict
		body.Confidence = v.Confidence
		body.Scope = v.Scope
		for _, ev := range v.Evidence {
			if !ev.Verified || len(body.Locations) >= maxLLMPkgScanLocations {
				continue
			}
			body.Locations = append(body.Locations, llmPkgScanLocation{Path: ev.Path, Line: ev.Line})
		}
	}
	if u := report.Unscanned; u != nil {
		body.Error = "artifact refused: it could not be examined by the LLM package-content scan (fail-closed policy)"
		if u.Transient {
			// A passing fault: worth retrying. A scan that timed out is usually
			// still running, and its verdict will be waiting. (An exhausted budget
			// is not transient: it lasts until the window resets.)
			body.RetryAfterSeconds = llmPkgScanRetryAfter
			h.Set("Retry-After", strconv.Itoa(llmPkgScanRetryAfter))
		}
	}
	body.Message = body.Error + ": " + d.Reason
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Policy-Decision", "block")
	h.Set("X-Policy-Code", d.PolicyCode)
	h.Set("X-Policy-Reason", headerSafe(d.Reason))
	h.Set("X-Cache", "BLOCKED")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}

// auditLLMPkgScan records a gate decision in the tamper-evident audit log. The
// record identifies the verdict by digest and cache key; the verdict's full
// text is kept in the verdict store rather than copied into every pull's record.
func (g *Gateway) auditLLMPkgScan(r *http.Request, backend, ecosystem string, report *llmpkgscan.Report, d llmpkgscan.Decision, keptPinned bool) {
	if g.deps.Audit == nil {
		return
	}
	art := report.Artifact
	decision := audit.DecisionDeny
	if d.Served() {
		decision = audit.DecisionAllow
	}
	detail := map[string]any{
		"action":      d.Action,
		"code":        d.Code,
		"package":     art.Name,
		"version":     art.Version,
		"digest":      art.Digest,
		"disposition": string(report.Disposition),
		"evicted":     d.Evict,
	}
	if keptPinned {
		// The bytes are pinned by a release (Task 180): refused, not deleted.
		detail["keptPinned"] = true
	}
	if v := report.Verdict; v != nil {
		detail["verdict"] = v.Verdict
		detail["confidence"] = v.Confidence
		detail["provider"] = v.Provider
		detail["model"] = v.Model
		detail["promptVersion"] = v.PromptVersion
		detail["verdictKey"] = v.Key
		detail["cached"] = report.Cached
		detail["truncated"] = v.Truncated
		detail["findings"] = len(report.Findings)
	}
	if u := report.Unscanned; u != nil {
		detail["unscannedCode"] = u.Code
		detail["contentAttributable"] = u.Content
	}
	ev := audit.Event{
		Type:       audit.EventPolicy,
		Method:     r.Method,
		Backend:    backend,
		Ecosystem:  ecosystem,
		Resource:   r.URL.Path,
		RemoteAddr: clientIP(r),
		Decision:   decision,
		Reason:     "llmpkgscan:" + d.Code,
		Detail:     detail,
	}
	if !d.Served() {
		ev.Status = http.StatusForbidden
	}
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
		ev.Team = p.Team
	}
	// A refusal is recorded even when the client hung up while it was being
	// decided.
	g.logAudit(context.WithoutCancel(r.Context()), ev)
}

// notifyLLMPkgScan dispatches a security alert for a flagged package.
func (g *Gateway) notifyLLMPkgScan(r *http.Request, backend, ecosystem string, report *llmpkgscan.Report, d llmpkgscan.Decision) {
	if g.deps.Notify == nil || report.Verdict == nil {
		return
	}
	sev := notify.SeverityMedium
	switch {
	case report.Disposition == llmpkgscan.DispositionMalicious:
		sev = notify.SeverityCritical
	case report.Disposition == llmpkgscan.DispositionSuspicious:
		for _, f := range report.Findings {
			if severityRank(f.Severity) >= severityRank("high") {
				sev = notify.SeverityHigh
			}
		}
	}
	v := report.Verdict
	ev := notify.LLMPackageScanEvent(sev, ecosystem, backend, report.Artifact.Coordinate(),
		string(report.Disposition), d.Action, v.Model, v.Confidence, d.Reason)
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
	}
	g.emit(context.WithoutCancel(r.Context()), ev)
}

// auditLLMPkgScanDeferred records a refusal the gate deferred to the system
// caller that asked for the object (DeferLLMRefusal): the release pinner keeps
// the bytes, the repository dependency scan applies the action ladder and
// reports it. The record says what a client would have been told.
func (g *Gateway) auditLLMPkgScanDeferred(r *http.Request, backend, ecosystem string, report *llmpkgscan.Report, d llmpkgscan.Decision) {
	if g.deps.Audit == nil {
		return
	}
	art := report.Artifact
	detail := map[string]any{
		"action":      d.Action,
		"code":        d.Code,
		"package":     art.Name,
		"version":     art.Version,
		"digest":      art.Digest,
		"disposition": string(report.Disposition),
		"deferred":    "repository-scan",
	}
	if v := report.Verdict; v != nil {
		detail["verdict"] = v.Verdict
		detail["confidence"] = v.Confidence
		detail["model"] = v.Model
		detail["verdictKey"] = v.Key
	}
	if u := report.Unscanned; u != nil {
		detail["unscannedCode"] = u.Code
	}
	ev := audit.Event{
		Type:      audit.EventPolicy,
		Method:    r.Method,
		Backend:   backend,
		Ecosystem: ecosystem,
		Resource:  r.URL.Path,
		Decision:  audit.DecisionAllow,
		Reason:    "llmpkgscan:deferred:" + d.Code,
		Detail:    detail,
	}
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
		ev.Team = p.Team
	}
	g.logAudit(context.WithoutCancel(r.Context()), ev)
}
