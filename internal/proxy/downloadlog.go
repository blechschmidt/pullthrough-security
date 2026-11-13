package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/clientip"
	"github.com/blechschmidt/pullthrough-security/internal/downloadlog"
	"github.com/blechschmidt/pullthrough-security/internal/intercept"
	"github.com/blechschmidt/pullthrough-security/internal/tracing"
)

// This file feeds the download log (internal/downloadlog, Task 176): the record
// of which package was downloaded from which client address.
//
// What a download-log entry needs is learned at different points of a request:
// the client address at the edge, the package coordinate once the backend has
// resolved the request, the refusing gate when one refuses, the size when the
// artifact is in hand, status and byte count when the response is done. A
// pullRecord is created at the edge, carried in the request context, filled in
// along the way and turned into a log entry when the handler returns.

// statusClientClosedRequest is recorded for a request whose client went away
// before the proxy answered. No response was written, so there is no real
// status; 499 is the conventional stand-in.
const statusClientClosedRequest = 499

// pullRecord is what is known so far about the request being served. It is
// written only by the goroutine serving the request.
type pullRecord struct {
	start time.Time
	// source is where the request came from, resolved once at the edge.
	source clientip.Info

	// described reports that the request has been resolved to a resource; the
	// fields below it are meaningful only then.
	described bool
	backend   string
	ecosystem string
	name      string
	version   string
	artifact  string
	digest    string
	kind      downloadlog.Kind

	// gate is the admission gate that refused the request, if one did.
	gate string
	// size is the full size of the artifact, when known.
	size int64
}

type pullRecordKey struct{}

// pullRecordFrom returns the request's pullRecord, or nil when the request did
// not come in through the client-facing handler chain (a synthetic pre-warm
// fetch, a handler driven directly by a test).
func pullRecordFrom(ctx context.Context) *pullRecord {
	rec, _ := ctx.Value(pullRecordKey{}).(*pullRecord)
	return rec
}

// withClientSource is the outermost middleware of the client-facing backend
// path. It resolves where the request came from — the TCP peer, or the client a
// trusted reverse proxy forwarded it for (Options.ClientIP) — exactly once, and
// attaches the pullRecord that carries that answer through the request. Every
// later use of the client address (the audit trail, anomaly scoping, the
// download log) reads it from there, so they cannot disagree.
func (g *Gateway) withClientSource(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &pullRecord{start: time.Now(), source: g.opts.ClientIP.Resolve(r)}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), pullRecordKey{}, rec)))
	})
}

// describe records what the request resolved to.
func (p *pullRecord) describe(backend, ecosystem string, resolved *backends.Resolved) {
	if p == nil || resolved == nil {
		return
	}
	p.described = true
	p.backend = backend
	p.ecosystem = ecosystem
	p.name = resolved.Coordinate.Name
	p.version = resolved.Coordinate.Version
	p.artifact = resolved.ArtifactFilename()
	p.digest = resolved.Digest
	p.kind = downloadKind(resolved.Artifact.Class)
}

// describeDownload records what a raw-HTTP backend (Git) says the request is.
func (p *pullRecord) describeDownload(backend, ecosystem string, d backends.Download) {
	if p == nil {
		return
	}
	p.described = true
	p.backend = backend
	p.ecosystem = ecosystem
	p.name = d.Name
	p.version = d.Version
	p.artifact = d.Artifact
	p.digest = d.Digest
	p.kind = downloadlog.KindPackage
}

// blockedBy notes the gate that refused the request. The first refusal stands:
// a request is refused once.
func (p *pullRecord) blockedBy(gate string) {
	if p != nil && p.gate == "" {
		p.gate = gate
	}
}

// noteRefusal records, for the download log, that the named admission gate
// refused the request — unless the request's own context has ended.
//
// A gate reports "do not serve" for two different reasons: it judged the
// artifact and refused it, or it was still judging when the client went away
// and there was no one left to serve. Only the first is a verdict. Recording
// the second as one would put "blocked by the package scan" in the log next to
// a package the scan never finished looking at; it is recorded as what it was,
// a request that failed because its client left.
func noteRefusal(r *http.Request, gate string) {
	refused(r.Context(), gate)
}

// refused is noteRefusal for a caller that holds the request's context.
func refused(ctx context.Context, gate string) {
	if ctx.Err() != nil {
		return
	}
	pullRecordFrom(ctx).blockedBy(gate)
}

// setSize notes the artifact's full size.
func (p *pullRecord) setSize(n int64) {
	if p != nil && n > 0 {
		p.size = n
	}
}

// coordinate returns the package coordinate the request resolved to, for
// records (the audit trail) that want it without the rest.
func (p *pullRecord) coordinate() (name, version string, ok bool) {
	if p == nil || !p.described || p.name == "" {
		return "", "", false
	}
	return p.name, p.version, true
}

// downloadKind maps a backend's artifact classification onto the log's kinds.
func downloadKind(class backends.ArtifactClass) downloadlog.Kind {
	switch class {
	case backends.ArtifactPayload:
		return downloadlog.KindPackage
	case backends.ArtifactMetadata:
		return downloadlog.KindMetadata
	default:
		return downloadlog.KindUnclassified
	}
}

// recordDownload turns the finished request into a download-log entry. It runs
// when the backend handler returns, whatever path the request took: served from
// cache or upstream, refused by a gate, failed.
//
// Not every request is a download. A request that never resolved to a resource
// (unknown backend, malformed path) names no package and is left to the audit
// log. A request for metadata, and a HEAD (which transfers nothing), are
// recorded only when they were refused: a client that is told "blocked" on its
// first request for a coordinate — its probe, or the version's metadata — never
// sends the request for the artifact, and the refused attempt must not go
// unrecorded for that.
func (g *Gateway) recordDownload(r *http.Request, mw *meteredWriter) {
	log := g.deps.DownloadLog
	if !log.Enabled() {
		return
	}
	rec := pullRecordFrom(r.Context())
	if rec == nil || !rec.described || isPrewarmRequest(r) {
		return
	}

	status := mw.status
	clientGone := r.Context().Err() != nil
	unanswered := false
	switch {
	case clientGone && (!mw.wroteHeader || status >= http.StatusInternalServerError):
		// The client went away while the proxy was still working on the answer:
		// nothing was sent, or only the error a handler produces when the
		// request it is serving is cancelled under it. That status describes the
		// cancellation, not the artifact.
		status = statusClientClosedRequest
	case !mw.wroteHeader:
		// The handler returned without answering although the client is still
		// there. The server then sends an empty "200 OK" on its behalf — which
		// is not a download, whatever the status says.
		status = http.StatusOK
		unanswered = true
	}
	blocked := rec.gate != ""
	outcome := downloadlog.Classify(status, blocked)
	if unanswered {
		outcome = downloadlog.OutcomeError
	}
	// Metadata requests are not downloads and are left out (unless the log is
	// configured to keep them) — except a refused one, which the log always
	// keeps: see downloadlog.Log.Wants.
	if !log.Wants(rec.kind, outcome) {
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodPost:
	default:
		if outcome != downloadlog.OutcomeBlocked {
			return
		}
	}

	entry := downloadlog.Entry{
		ClientIP:   rec.source.Client,
		Ecosystem:  rec.ecosystem,
		Upstream:   rec.backend,
		Package:    rec.name,
		Version:    rec.version,
		Artifact:   rec.artifact,
		Digest:     rec.digest,
		Kind:       rec.kind,
		Method:     r.Method,
		Path:       r.URL.Path,
		Status:     status,
		Outcome:    outcome,
		Cache:      mw.Header().Get("X-Cache"),
		Size:       rec.size,
		DurationMs: time.Since(rec.start).Milliseconds(),
		UserAgent:  r.UserAgent(),
	}
	// Bytes counts what the client received of the artifact. The body of a
	// refusal or an error is an explanation, not package content, and counting
	// it would make "how much of this package went out" unanswerable.
	if outcome == downloadlog.OutcomeServed {
		entry.Bytes = mw.bytes
	}
	if rec.source.Forwarded {
		entry.ForwardedBy = rec.source.Peer
	}
	// A request the interception listeners dispatched (Task 172) says how it
	// got here: the client addressed the upstream host, not the proxy.
	if info, ok := intercept.InfoFrom(r.Context()); ok {
		entry.Via = string(info.Mode)
	}
	// A request the proxy made of itself (Task 180) has no client address;
	// "via" says what made it.
	if via := systemVia(r.Context()); via != "" {
		entry.Via = via
	}
	if blocked {
		entry.Gate = rec.gate
		entry.Code, entry.Reason = blockExplanation(mw.errBody)
	}
	if unanswered {
		entry.Reason = "the proxy returned no response body"
	}
	// Record who the client was — when it was someone. With client
	// authentication switched off every request carries a placeholder principal,
	// and an anonymous request has no subject worth the name; neither is an
	// identity, and showing "anonymous" in every row would bury the real ones.
	if p, ok := auth.FromContext(r.Context()); ok && p != nil && p.Method != "disabled" {
		entry.Tenant = p.Team
		entry.AuthMethod = p.Method
		if p.Method != "anonymous" {
			entry.Subject = p.Subject
		}
		// The personal link the request came through (Task 177): the user may
		// hold several — one per machine — and "which of them" is what tells a
		// link that got out from one that did not.
		entry.Link = personalLinkID(p)
	}
	entry.TraceID = tracing.TraceIDFromContext(r.Context())
	log.Record(entry)
}

// blockExplanation extracts the machine reason code and the explanation from a
// gate's refusal body. Every gate answers a refusal with a small JSON document
// carrying "code" and "reason" (a Git LFS error carries "message"); a body that
// is something else (or was cut off) simply yields nothing.
func blockExplanation(body []byte) (code, reason string) {
	if len(body) == 0 {
		return "", ""
	}
	var doc struct {
		Code   string `json:"code"`
		Reason string `json:"reason"`
		// Message is what a Git LFS error document calls its explanation.
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", ""
	}
	if doc.Reason == "" {
		doc.Reason = doc.Message
	}
	return doc.Code, doc.Reason
}
