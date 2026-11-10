package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/provenance"
	"github.com/blechschmidt/pullthrough-security/internal/rebuildverify"
)

// gateRebuildVerify runs the reproducible-build verification gate (Task 68) on a
// cached, signature-checked artifact. For an artifact already mapped to a source
// Git commit (by the provenance subsystem), it asks the subsystem to verify that
// the upstream-served artifact can be deterministically rebuilt from that source
// and the digests compared. Verification is asynchronous and non-blocking by
// default: the first pull schedules a bounded background rebuild and serves the
// artifact immediately; a subsequent pull observes the cached verdict. The
// verdict is folded into the per-request admission-signal accumulator (so the
// policy and risk engines and the SARIF findings layer see it).
//
// In the optional enforce mode a confirmed mismatch — the served binary does not
// derive from the attested source — is refused here (and the artifact evicted),
// composing with the break-glass workflow. It runs right after the signature gate
// and before the aggregating policy/risk gates.
//
// It returns true when the request may proceed (the default async/observe path,
// or any non-mismatch verdict) and false when an enforced mismatch was refused
// and a response has been written.
func (g *Gateway) gateRebuildVerify(w http.ResponseWriter, r *http.Request, name, ecosystem string, resolved *backends.Resolved, entry *cache.Entry) bool {
	if g.deps.RebuildVerify == nil || !g.deps.RebuildVerify.Enabled() {
		return true
	}
	art, ok := vulnArtifactFor(ecosystem, resolved, entry)
	if !ok {
		return true
	}

	source, _ := g.rebuildSourceFor(r.Context(), ecosystem, resolved)

	tenant := licenseTenant(r)
	req := rebuildverify.Request{
		Coordinate: rebuildverify.Coordinate{
			Ecosystem: ecosystem,
			Name:      art.Name,
			Version:   art.Version,
			Digest:    art.Digest,
		},
		Source:  source,
		Tenant:  tenant,
		Backend: name,
		// Open a fresh content stream for a builder that wants the upstream bytes,
		// independent of the one being served to the client.
		Upstream: func() (io.ReadCloser, error) {
			e, err := g.deps.Cache.Get(r.Context(), resolved.CacheKey)
			if err != nil {
				return nil, err
			}
			return e.Content, nil
		},
	}

	res := g.deps.RebuildVerify.Observe(r.Context(), req)

	// Only a terminal verdict feeds the admission signal; a pending async result
	// contributes nothing this request (a subsequent pull observes it).
	if res.Done {
		recordRebuildVerifySignal(r.Context(), res)
	}

	// Enforce mode: a confirmed mismatch is refused (and evicted), consulting the
	// break-glass workflow first.
	decision := g.deps.RebuildVerify.Gate(res, tenant)
	if decision.Block {
		if g.breakGlass(w, r, approvalGateRebuildVerify, name, ecosystem, artifactCoordinate(art), decision.Reason) {
			return true
		}
		g.evictArtifact(r.Context(), resolved)
		g.metrics().IncPolicyDecision(ecosystem, "block")
		g.auditRebuildVerify(r, name, ecosystem, art.Name, res, true)
		g.deps.Logger.Warn("reproducible-build gate quarantined artifact on confirmed mismatch",
			"backend", name, "ecosystem", ecosystem, "artifact", art.Name,
			"commit", res.CommitSHA, "upstreamDigest", res.UpstreamDigest, "rebuiltDigest", res.RebuiltDigest)
		g.notifyRebuildVerify(r, name, ecosystem, art.Name, res, "quarantine")
		writeRebuildVerifyBlock(w, art.Ecosystem, art.Name, art.Version, res)
		return false
	}

	// Observe path: surface the verdict for transparency.
	if res.Done && res.Verdict != "" {
		w.Header().Set("X-Rebuild-Verify", string(res.Verdict))
		if res.Mismatch {
			w.Header().Set("X-Rebuild-Verify-Reason", headerSafe(res.Reason))
		}
	} else if res.Pending {
		w.Header().Set("X-Rebuild-Verify", "pending")
	}
	return true
}

// rebuildSourceFor resolves the attested source revision for an artifact. It
// prefers the provenance signal the earlier gates already recorded on the
// per-request accumulator; absent that (e.g. the hard policy gate is off) it
// resolves directly via the provenance resolver, which caches.
func (g *Gateway) rebuildSourceFor(ctx context.Context, ecosystem string, resolved *backends.Resolved) (rebuildverify.Source, bool) {
	if s := signalsFrom(ctx); s != nil {
		s.mu.Lock()
		prov := s.input.Provenance
		s.mu.Unlock()
		if prov != nil && prov.Found && prov.CommitSHA != "" {
			return rebuildverify.Source{
				CommitSHA:     prov.CommitSHA,
				RepositoryURL: prov.RepositoryURL,
				Confidence:    prov.Confidence,
			}, true
		}
	}
	if g.deps.Provenance != nil {
		art := provenance.Artifact{
			Ecosystem: ecosystem,
			Name:      resolved.Coordinate.Name,
			Version:   resolved.Coordinate.Version,
			Digest:    resolved.Digest,
		}
		if link, err := g.deps.Provenance.Resolve(ctx, art); err == nil && link != nil && link.CommitSHA != "" {
			return rebuildverify.Source{
				CommitSHA:     link.CommitSHA,
				RepositoryURL: link.RepositoryURL,
				Confidence:    string(link.Confidence),
			}, true
		}
	}
	return rebuildverify.Source{}, false
}

// recordRebuildVerifySignal folds a terminal verification result into the
// per-request admission-signal accumulator. It is a no-op when no accumulator is
// attached.
func recordRebuildVerifySignal(ctx context.Context, res rebuildverify.Result) {
	s := signalsFrom(ctx)
	if s == nil || !res.Done {
		return
	}
	in := &policyengine.RebuildVerifyInput{
		Evaluated:      true,
		Verdict:        string(res.Verdict),
		Reproducible:   res.Reproducible,
		Mismatch:       res.Mismatch,
		CommitSHA:      res.CommitSHA,
		RepositoryURL:  res.RepositoryURL,
		Builder:        res.Builder,
		UpstreamDigest: res.UpstreamDigest,
		RebuiltDigest:  res.RebuiltDigest,
		Reason:         res.Reason,
	}
	s.mu.Lock()
	s.input.RebuildVerify = in
	s.mu.Unlock()
}

// rebuildVerifyError is the JSON body returned when an artifact is refused for a
// confirmed reproducible-build mismatch.
type rebuildVerifyError struct {
	Error          string `json:"error"`
	Verdict        string `json:"verdict"`
	Reason         string `json:"reason"`
	Ecosystem      string `json:"ecosystem,omitempty"`
	Package        string `json:"package,omitempty"`
	Version        string `json:"version,omitempty"`
	CommitSHA      string `json:"commitSha,omitempty"`
	Builder        string `json:"builder,omitempty"`
	UpstreamDigest string `json:"upstreamDigest,omitempty"`
	RebuiltDigest  string `json:"rebuiltDigest,omitempty"`
}

// writeRebuildVerifyBlock writes an actionable 403 describing the mismatch.
func writeRebuildVerifyBlock(w http.ResponseWriter, ecosystem, pkg, version string, res rebuildverify.Result) {
	body := rebuildVerifyError{
		Error:          "artifact refused: it could not be reproduced from its attested source commit",
		Verdict:        string(res.Verdict),
		Reason:         res.Reason,
		Ecosystem:      ecosystem,
		Package:        pkg,
		Version:        version,
		CommitSHA:      res.CommitSHA,
		Builder:        res.Builder,
		UpstreamDigest: res.UpstreamDigest,
		RebuiltDigest:  res.RebuiltDigest,
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Rebuild-Verify", string(res.Verdict))
	h.Set("X-Rebuild-Verify-Reason", headerSafe(res.Reason))
	h.Set("X-Cache", "BLOCKED")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}

// auditRebuildVerify records a reproducible-build verification decision in the
// tamper-evident audit log.
func (g *Gateway) auditRebuildVerify(r *http.Request, backend, ecosystem, pkg string, res rebuildverify.Result, blocked bool) {
	if g.deps.Audit == nil {
		return
	}
	decision := audit.DecisionAllow
	if blocked {
		decision = audit.DecisionDeny
	}
	ev := audit.Event{
		Type:       audit.EventPolicy,
		Method:     r.Method,
		Backend:    backend,
		Ecosystem:  ecosystem,
		Resource:   r.URL.Path,
		RemoteAddr: clientIP(r),
		Decision:   decision,
		Reason:     "rebuildverify:" + string(res.Verdict),
		Detail: map[string]any{
			"verdict":        string(res.Verdict),
			"package":        pkg,
			"commit":         res.CommitSHA,
			"builder":        res.Builder,
			"upstreamDigest": res.UpstreamDigest,
			"rebuiltDigest":  res.RebuiltDigest,
		},
	}
	if blocked {
		ev.Status = http.StatusForbidden
	}
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
		ev.Team = p.Team
	}
	g.logAudit(r.Context(), ev)
}

// notifyRebuildVerify dispatches a security alert for a reproducible-build
// verification decision. action is "mismatch" (observe) or "quarantine"
// (enforce).
func (g *Gateway) notifyRebuildVerify(r *http.Request, backend, ecosystem, coordinate string, res rebuildverify.Result, action string) {
	if g.deps.Notify == nil {
		return
	}
	ev := notify.RebuildVerifyEvent(ecosystem, backend, coordinate,
		res.CommitSHA, res.UpstreamDigest, res.RebuiltDigest, action, res.Reason)
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
	}
	g.emit(r.Context(), ev)
}
