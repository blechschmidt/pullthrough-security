package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/clientip"
	"github.com/blechschmidt/pullthrough-security/internal/downloadlog"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

// System fetches (Task 180): requests the proxy makes of itself.
//
// The repository tracker pins a release by fetching every dependency its lock
// files pin. It does so through the very pipeline a client request takes —
// resolution, every admission gate, digest verification, the cache fill — so
// that a pinned object is one the proxy would have served, and the fetch is in
// the download log like any other. What differs is who asks: a system
// principal of the repository's tenant, with no client address. Client access
// control and rate limiting do not apply (the tracker is the proxy itself), nor
// does behavioural anomaly detection, which would read the burst of a release's
// dependencies as one identity fanning out and soft-block it; nor is the fetch
// reported to the pre-warming predictor as client demand. Authorization does
// apply: the principal holds the roles the repository was registered with, and
// an upstream none of them grants is refused (the lock files, not the
// operator, name the registries a release's dependencies come from).

// SystemFetchRequest is one request the proxy makes of itself.
type SystemFetchRequest struct {
	// Backend is the upstream name ("/v1/<backend>/…").
	Backend string
	// Path is the backend-relative path, starting with "/".
	Path string
	// Accept is the Accept header to send, if any.
	Accept string
	// Tenant is the tenant the request is made as; Subject the system
	// principal's name (default "system:release-pinner"); Roles the
	// access-control roles it holds. With access control on, the request is
	// authorized against them like a client's pull: an upstream no role grants
	// is refused.
	Tenant  string
	Subject string
	Roles   []string
	// Hold, when set, is called with the cache key of a cacheable object once
	// every admission gate has admitted it, before it is served.
	Hold func(cacheKey string)
}

// SystemGateVerdict is one admission gate's judgement of a system fetch.
type SystemGateVerdict struct {
	Gate    string `json:"gate"`
	Outcome string `json:"outcome"` // pass | refuse
	Detail  string `json:"detail,omitempty"`
}

// SystemFetchResult is what the pipeline did with a system fetch.
type SystemFetchResult struct {
	Status int
	// Cache is HIT, MISS, COALESCED-HIT, or BYPASS (served without caching).
	Cache string
	// CacheKey, Digest and Size describe the cache object served.
	CacheKey    string
	Digest      string
	Size        int64
	ContentType string
	// Gate, Code and Reason explain a refusal.
	Gate   string
	Code   string
	Reason string
	// Verdicts are the gates that judged the object.
	Verdicts []SystemGateVerdict
}

// systemReport collects what a system fetch learns along the pipeline.
type systemReport struct {
	mu       sync.Mutex
	hold     func(string)
	cacheKey string
	stat     cache.Stat
	admitted bool
	gates    []SystemGateVerdict
	// signals is the request's admission-signal accumulator, which the
	// verdicts are read from once the pipeline is done.
	signals *admissionSignals
}

type systemReportKey struct{}

func systemReportFrom(ctx context.Context) *systemReport {
	rep, _ := ctx.Value(systemReportKey{}).(*systemReport)
	return rep
}

// isSystemRequest reports whether r is a system fetch.
func isSystemRequest(r *http.Request) bool { return systemReportFrom(r.Context()) != nil }

// noteGate records a gate's decision on a system fetch.
func noteGate(ctx context.Context, gate string, allowed bool) {
	rep := systemReportFrom(ctx)
	if rep == nil {
		return
	}
	outcome := "pass"
	if !allowed {
		outcome = "refuse"
	}
	rep.mu.Lock()
	rep.gates = append(rep.gates, SystemGateVerdict{Gate: gate, Outcome: outcome})
	rep.mu.Unlock()
}

// noteAdmitted records the cache object every gate admitted, and holds it for
// the caller before a byte is served.
func noteAdmitted(ctx context.Context, key string, stat cache.Stat) {
	rep := systemReportFrom(ctx)
	if rep == nil {
		return
	}
	rep.mu.Lock()
	rep.cacheKey, rep.stat, rep.admitted = key, stat, true
	hold := rep.hold
	rep.mu.Unlock()
	if hold != nil {
		hold(key)
	}
}

// SystemFetch drives one request through the full gated serve pipeline as a
// system principal and writes the response body to body.
func (g *Gateway) SystemFetch(ctx context.Context, req SystemFetchRequest, body io.Writer) (SystemFetchResult, error) {
	if req.Backend == "" || !strings.HasPrefix(req.Path, "/") {
		return SystemFetchResult{}, errors.New("proxy: a system fetch needs a backend and an absolute path")
	}
	if strings.ContainsAny(req.Path, "?#\r\n") {
		return SystemFetchResult{}, errors.New("proxy: a system fetch path carries no query or fragment")
	}
	if body == nil {
		body = io.Discard
	}
	subject := req.Subject
	if subject == "" {
		subject = "system:release-pinner"
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "/v1/"+req.Backend+req.Path, nil)
	if err != nil {
		return SystemFetchResult{}, fmt.Errorf("proxy: building system request: %w", err)
	}
	if req.Accept != "" {
		httpReq.Header.Set("Accept", req.Accept)
	}
	httpReq.Header.Set("User-Agent", "pullthrough-release-pinner")
	rep := &systemReport{hold: req.Hold}
	// No client address: the download log records "system", via "system".
	rec := &pullRecord{start: time.Now(), source: clientip.Info{Client: downloadlog.ViaSystem}}
	sctx := context.WithValue(httpReq.Context(), systemReportKey{}, rep)
	sctx = context.WithValue(sctx, pullRecordKey{}, rec)
	sctx = context.WithValue(sctx, systemViaKey{}, downloadlog.ViaSystem)
	principal := &auth.Principal{Subject: subject, Team: req.Tenant, Method: "system", Roles: append([]string(nil), req.Roles...)}
	sctx = auth.WithPrincipal(sctx, principal)
	httpReq = httpReq.WithContext(sctx)

	if g.deps.Enforcer != nil {
		eco := g.ecosystemFor(req.Backend)
		if ok, reason := g.deps.Enforcer.Authorize(principal, req.Backend, eco); !ok {
			g.auditDecision(httpReq, req.Backend, eco, auth.Result{
				Principal: principal, Status: http.StatusForbidden, Reason: reason, Stage: auth.StageAuthz})
			if len(principal.Roles) == 0 {
				reason = "the release pinner holds no access-control role for this repository (repositories.roles, or the repository's roles)"
			}
			return SystemFetchResult{Status: http.StatusForbidden, Gate: "access-control", Code: "forbidden", Reason: reason}, nil
		}
	}

	w := &systemWriter{header: http.Header{}, body: body}
	g.withTracing(http.HandlerFunc(g.handleBackend)).ServeHTTP(w, httpReq)

	res := SystemFetchResult{Status: w.statusOrOK(), Cache: w.header.Get("X-Cache"), ContentType: w.header.Get("Content-Type")}
	rep.mu.Lock()
	if rep.admitted {
		res.CacheKey = rep.cacheKey
		res.Digest = rep.stat.Metadata[cache.MetaDigest]
		res.Size = rep.stat.Size
	}
	gates := append([]SystemGateVerdict(nil), rep.gates...)
	rep.mu.Unlock()
	if res.Cache == "" && res.Status == http.StatusOK && !rep.admitted {
		res.Cache = "BYPASS"
	}
	res.Gate = rec.gate
	if res.Gate != "" {
		res.Code, res.Reason = blockExplanation(w.errBody)
	} else if res.Status >= http.StatusBadRequest {
		_, res.Reason = blockExplanation(w.errBody)
		if res.Reason == "" {
			res.Reason = strings.TrimSpace(string(w.errBody))
			if len(res.Reason) > 300 {
				res.Reason = res.Reason[:300]
			}
		}
	}
	rep.mu.Lock()
	sig := rep.signals
	rep.mu.Unlock()
	res.Verdicts = systemVerdicts(sig, gates)
	if w.writeErr != nil {
		return res, fmt.Errorf("proxy: reading the response body: %w", w.writeErr)
	}
	return res, nil
}

type systemViaKey struct{}

// systemVia returns downloadlog.ViaSystem for a system request, or "".
func systemVia(ctx context.Context) string {
	v, _ := ctx.Value(systemViaKey{}).(string)
	return v
}

func firstNonEmptyString(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// systemWriter is the ResponseWriter of a system fetch: it streams the body to
// the caller's writer and keeps the start of an error body.
type systemWriter struct {
	header      http.Header
	status      int
	wroteHeader bool
	body        io.Writer
	errBody     []byte
	writeErr    error
}

func (w *systemWriter) Header() http.Header { return w.header }

func (w *systemWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status, w.wroteHeader = code, true
	}
}

func (w *systemWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.status >= http.StatusBadRequest {
		if len(w.errBody) < maxErrBody {
			w.errBody = append(w.errBody, b[:min(len(b), maxErrBody-len(w.errBody))]...)
		}
		return len(b), nil
	}
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	if _, err := w.body.Write(b); err != nil {
		w.writeErr = err
		return 0, err
	}
	return len(b), nil
}

func (w *systemWriter) statusOrOK() int {
	if !w.wroteHeader {
		return http.StatusOK
	}
	return w.status
}

// systemVerdicts lists the gates that judged a system fetch: every gate whose
// summary is in the admission signals (it looked at the object), and every gate
// that refused. Gates that are switched off pass everything without looking
// and are not listed.
func systemVerdicts(sig *admissionSignals, traced []SystemGateVerdict) []SystemGateVerdict {
	refused := map[string]bool{}
	for _, t := range traced {
		if t.Outcome == "refuse" {
			refused[t.Gate] = true
		}
	}
	var out []SystemGateVerdict
	seen := map[string]bool{}
	add := func(gate, detail string) {
		if seen[gate] {
			return
		}
		seen[gate] = true
		outcome := "pass"
		if refused[gate] {
			outcome = "refuse"
		}
		out = append(out, SystemGateVerdict{Gate: gate, Outcome: outcome, Detail: detail})
	}
	if sig != nil {
		sig.mu.Lock()
		in := sig.input
		risk, pol := sig.risk, sig.policy
		sig.mu.Unlock()
		for _, s := range signalSections(in) {
			add(s.gate, s.detail)
		}
		if risk != nil {
			add("riskscore", fmt.Sprintf("score %d (%s)", risk.Score, risk.Band))
		}
		if pol != nil {
			add("policyengine", pol.Action)
		}
	}
	for _, t := range traced {
		if t.Outcome == "refuse" {
			add(t.Gate, "")
		}
	}
	return out
}

type signalSection struct{ gate, detail string }

// signalSections summarizes the admission document's sections, one per gate.
func signalSections(in policyengine.Input) []signalSection {
	var out []signalSection
	if v := in.Nameguard; v != nil {
		out = append(out, signalSection{"nameguard", fmt.Sprintf("%d finding(s)", v.FindingCount)})
	}
	if v := in.Continuity; v != nil && v.Evaluated {
		d := "publisher unchanged"
		switch {
		case v.FirstUse:
			d = "first use"
		case v.Drift:
			d = "publisher drift"
		}
		out = append(out, signalSection{"continuity", d})
	}
	if v := in.Signature; v != nil && v.Checked {
		d := "unsigned"
		switch {
		case v.Verified:
			d = "signature verified"
		case v.HasSignature:
			d = "signature not verified"
		}
		out = append(out, signalSection{"sigverify", d})
	}
	if v := in.BuildProv; v != nil {
		out = append(out, signalSection{"buildprov", boolWord(v.Verified, "provenance verified", "provenance not verified")})
	}
	if v := in.RebuildVerify; v != nil {
		out = append(out, signalSection{"rebuildverify", v.Verdict})
	}
	if v := in.PyPIAttest; v != nil {
		d := boolWord(v.Verified, "attestation verified", "no verified attestation")
		if v.DigestMismatch {
			d = "attestation digest mismatch"
		}
		out = append(out, signalSection{"pypiattest", d})
	}
	if v := in.Vuln; v != nil && v.Scanned {
		d := fmt.Sprintf("%d vulnerabilit%s", v.Total, plural(v.Total, "y", "ies"))
		if v.MaxSeverity != "" {
			d += ", max " + v.MaxSeverity
		}
		out = append(out, signalSection{"vulnscan", d})
	}
	if v := in.License; v != nil {
		out = append(out, signalSection{"license", firstNonEmptyString(v.Action, boolWord(v.Allowed, "allowed", "not allowed"))})
	}
	if v := in.SbomDrift; v != nil {
		out = append(out, signalSection{"sbomdiff", fmt.Sprintf("drift %.1f", v.DriftScore)})
	}
	if v := in.InstallHooks; v != nil {
		out = append(out, signalSection{"installhooks", fmt.Sprintf("%d hook(s)", v.HookCount)})
	}
	if v := in.ContentScan; v != nil {
		out = append(out, signalSection{"contentscan", fmt.Sprintf("%d finding(s)", v.FindingCount)})
	}
	if v := in.MLGuard; v != nil {
		out = append(out, signalSection{"mlguard", boolWord(v.Unsafe, "unsafe", "safe")})
	}
	if v := in.AVScan; v != nil {
		out = append(out, signalSection{"avscan", firstNonEmptyString(v.Signature, "clean")})
	}
	if v := in.LLMPackage; v != nil {
		out = append(out, signalSection{"llmpkgscan", firstNonEmptyString(v.Verdict, v.Disposition)})
	}
	if v := in.RepoHealth; v != nil && v.Resolved {
		out = append(out, signalSection{"reposcore", fmt.Sprintf("risk %d", v.Risk)})
	}
	if v := in.Secret; v != nil {
		out = append(out, signalSection{"secretscan", fmt.Sprintf("%d finding(s)", v.FindingCount)})
	}
	return out
}

func boolWord(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
