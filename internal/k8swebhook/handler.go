package k8swebhook

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/dossier"
)

// maxBodyBytes bounds the AdmissionReview request body. A Pod spec is small; the
// API server never sends anything near this, so the cap exists purely to refuse
// a hostile oversized body.
const maxBodyBytes = 3 << 20 // 3 MiB

// Handler is the admission decision engine. It parses an AdmissionReview, folds
// the kill-switch and the per-image dossier verdicts into one admit/deny
// decision, and renders the AdmissionResponse. It is safe for concurrent use and
// has no network dependency beyond the injected VerdictSource, so it is driven
// directly in tests.
type Handler struct {
	cfg      Config
	source   VerdictSource
	lockdown LockdownOracle
	metrics  *metrics
	logger   *slog.Logger
}

// NewHandler builds the decision engine. source is required; lockdown may be nil
// (kill-switch integration inert). The config is defaulted and validated.
func NewHandler(cfg Config, source VerdictSource, lock LockdownOracle, logger *slog.Logger) (*Handler, error) {
	if source == nil {
		return nil, fmt.Errorf("k8swebhook: a verdict source is required")
	}
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{cfg: cfg, source: source, lockdown: lock, metrics: newMetrics(), logger: logger}, nil
}

// Metrics returns the current counter snapshot. Safe on a nil receiver.
func (h *Handler) Metrics() Snapshot {
	if h == nil {
		return Snapshot{ByVerdict: map[string]uint64{}}
	}
	return h.metrics.snapshot()
}

// Mux returns the HTTP handler tree: the validate path plus liveness/readiness
// probes.
func (h *Handler) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+h.cfg.Path, h.ServeValidate)
	mux.HandleFunc("GET "+h.cfg.HealthPath, h.serveHealth)
	mux.HandleFunc("GET "+h.cfg.ReadyPath, h.serveHealth)
	return mux
}

func (h *Handler) serveHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
}

// ServeValidate is the ValidatingWebhookConfiguration endpoint. It reads an
// AdmissionReview, computes the response, and writes an AdmissionReview back. A
// malformed envelope is answered per the failure policy (so the API server gets
// a well-formed response rather than a connection error, which its own
// failurePolicy would otherwise govern).
func (h *Handler) ServeValidate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		h.writeReview(w, "", h.failureResponse("", "reading request body: "+err.Error()))
		return
	}
	var review AdmissionReview
	if err := json.Unmarshal(body, &review); err != nil || review.Request == nil {
		uid := ""
		if review.Request != nil {
			uid = review.Request.UID
		}
		msg := "malformed AdmissionReview"
		if err != nil {
			msg += ": " + err.Error()
		}
		h.writeReview(w, uid, h.failureResponse(uid, msg))
		return
	}
	resp := h.Review(r.Context(), review.Request)
	h.writeReview(w, review.Request.UID, resp)
}

// writeReview wraps a response in the AdmissionReview envelope and writes it.
func (h *Handler) writeReview(w http.ResponseWriter, _ string, resp *AdmissionResponse) {
	out := AdmissionReview{APIVersion: admissionAPIVersion, Kind: admissionKind, Response: resp}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(out); err != nil {
		h.logger.Error("k8swebhook: writing admission response", "error", err)
	}
}

// failureResponse builds the admit/deny response applied when the request itself
// cannot be evaluated, honoring the server-side failure policy.
func (h *Handler) failureResponse(uid, reason string) *AdmissionResponse {
	if h.cfg.failClosed() {
		h.metrics.denied.Add(1)
		return &AdmissionResponse{
			UID:     uid,
			Allowed: false,
			Status:  &Status{Code: http.StatusForbidden, Reason: "Forbidden", Message: "pullthrough admission webhook (fail-closed): " + reason},
		}
	}
	h.metrics.admitted.Add(1)
	return &AdmissionResponse{
		UID:      uid,
		Allowed:  true,
		Warnings: []string{"pullthrough admission webhook could not evaluate the request (fail-open): " + reason},
	}
}

// Review computes the admission decision for a single request. It is the pure,
// testable core: given an AdmissionRequest it returns the AdmissionResponse,
// consulting only the injected verdict source and lockdown oracle.
func (h *Handler) Review(ctx context.Context, req *AdmissionRequest) *AdmissionResponse {
	h.metrics.reviews.Add(1)
	resp := &AdmissionResponse{UID: req.UID, Allowed: true}

	// Only Pods carry images; anything else is admitted untouched.
	if !isPodRequest(req) {
		h.metrics.bypassed.Add(1)
		return resp
	}
	// Namespace exemption (belt-and-suspenders alongside the webhook object's
	// namespaceSelector).
	if h.namespaceIgnored(req.Namespace) {
		h.metrics.bypassed.Add(1)
		resp.AuditAnnotations = map[string]string{"pullthrough.io/admission": "bypassed: namespace " + req.Namespace + " is exempt"}
		return resp
	}

	var pod podObject
	if len(req.Object) == 0 || json.Unmarshal(req.Object, &pod) != nil {
		return h.failureResponse(req.UID, "could not decode the Pod object")
	}
	images := extractImages(&pod)
	if len(images) == 0 {
		h.metrics.admitted.Add(1)
		return resp
	}

	tenant := strings.TrimSpace(h.cfg.Tenant)
	var denyReasons, warnings []string
	for _, img := range images {
		h.metrics.imagesChecked.Add(1)
		oc := h.evaluateImage(ctx, tenant, img)
		switch oc.action {
		case ActionDeny:
			h.metrics.imagesBlocked.Add(1)
			denyReasons = append(denyReasons, oc.message)
		case ActionWarn, ActionAdmit:
			if oc.message != "" {
				warnings = append(warnings, oc.message)
			}
		}
	}

	if len(denyReasons) > 0 {
		h.metrics.denied.Add(1)
		msg := fmt.Sprintf("pullthrough admission webhook denied Pod %s/%s: %s",
			nsOr(req.Namespace, pod.Metadata.Namespace), nameOr(req.Name, pod.Metadata.Name),
			strings.Join(denyReasons, "; "))
		h.logger.Warn("admission denied", "namespace", req.Namespace, "name", req.Name, "reasons", denyReasons)
		return &AdmissionResponse{
			UID:     req.UID,
			Allowed: false,
			Status:  &Status{Code: http.StatusForbidden, Reason: "Forbidden", Message: msg},
		}
	}

	h.metrics.admitted.Add(1)
	if len(warnings) > 0 {
		h.metrics.warned.Add(1)
		if h.cfg.AnnotateWarnings != nil && *h.cfg.AnnotateWarnings {
			resp.Warnings = warnings
		}
	}
	return resp
}

// imageOutcome is one image's contribution to the Pod decision.
type imageOutcome struct {
	action  Action
	message string // deny reason or advisory warning
}

// evaluateImage resolves and classifies a single container image.
func (h *Handler) evaluateImage(ctx context.Context, tenant string, img imageSource) imageOutcome {
	ref := ParseImageRef(img.Image)

	// Always-admit infrastructure images.
	if ref.matchesPrefix(h.cfg.IgnoreImages) {
		return imageOutcome{action: ActionAdmit}
	}

	eco := h.cfg.DefaultEcosystem
	strip := h.cfg.StripRegistryHost != nil && *h.cfg.StripRegistryHost
	name, version := ref.Coordinate(strip)

	// Kill-switch: a targeted lockdown block denies the image ahead of any
	// recorded verdict, cluster-wide.
	lockActive := false
	if h.cfg.EnforceLockdown && h.lockdown != nil {
		if blocked, reason, incident := h.lockdown.BlockedCoordinate(eco, name, version); blocked {
			h.metrics.lockdownDenies.Add(1)
			return imageOutcome{action: ActionDeny, message: fmt.Sprintf("%s denied by emergency lockdown (incident %s): %s", img.Image, incident, reason)}
		}
		lockActive, _, _ = h.lockdown.Active()
	}

	vctx, cancel := context.WithTimeout(ctx, h.cfg.Timeout)
	defer cancel()
	v, err := h.source.Verdict(vctx, tenant, ref, eco, strip)
	if err != nil {
		h.metrics.sourceErrors.Add(1)
		// During any active lockdown, an un-evaluable image is always denied.
		if h.cfg.failClosed() || lockActive {
			h.metrics.failClosed.Add(1)
			return imageOutcome{action: ActionDeny, message: fmt.Sprintf("%s: supply-chain verdict unavailable (fail-closed): %v", img.Image, err)}
		}
		h.metrics.failOpen.Add(1)
		return imageOutcome{action: ActionWarn, message: fmt.Sprintf("%s: admitted without a supply-chain verdict (fail-open): %v", img.Image, err)}
	}
	h.metrics.recordVerdict(v.Decision)

	// Cluster-side risk ceiling, independent of the headline verdict.
	if h.cfg.MinRiskScoreToDeny > 0 && v.RiskScore >= h.cfg.MinRiskScoreToDeny {
		return imageOutcome{action: ActionDeny, message: fmt.Sprintf("%s: risk score %d ≥ cluster ceiling %d (%s)", img.Image, v.RiskScore, h.cfg.MinRiskScoreToDeny, v.Summary)}
	}

	switch v.Decision {
	case dossier.VerdictBlock:
		return h.applyMappedAction(h.cfg.BlockAction, img, v, "blocked")
	case dossier.VerdictWarn:
		return h.applyMappedAction(h.cfg.WarnAction, img, v, "flagged")
	case dossier.VerdictAdmit:
		return imageOutcome{action: ActionAdmit}
	default: // unknown / no recorded signal
		if lockActive {
			h.metrics.lockdownDenies.Add(1)
			return imageOutcome{action: ActionDeny, message: fmt.Sprintf("%s: no supply-chain verdict recorded; denied while an emergency lockdown is engaged", img.Image)}
		}
		return h.applyMappedAction(h.cfg.UnknownAction, img, v, "unverified")
	}
}

// applyMappedAction turns a configured action ("deny"|"warn"|"admit") into the
// concrete outcome, attaching the dossier summary as the message.
func (h *Handler) applyMappedAction(action string, img imageSource, v Verdict, disposition string) imageOutcome {
	a, ok := ParseAction(action)
	if !ok {
		a = ActionDeny // validated at construction; defensive
	}
	detail := v.Summary
	if detail == "" {
		detail = strings.Join(v.Reasons, "; ")
	}
	msg := fmt.Sprintf("%s: %s by supply-chain policy", img.Image, disposition)
	if detail != "" {
		msg += " (" + detail + ")"
	}
	return imageOutcome{action: a, message: msg}
}

func (h *Handler) namespaceIgnored(ns string) bool {
	ns = strings.TrimSpace(ns)
	if ns == "" {
		return false
	}
	for _, ex := range h.cfg.IgnoreNamespaces {
		if strings.EqualFold(strings.TrimSpace(ex), ns) {
			return true
		}
	}
	return false
}

func nsOr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	if strings.TrimSpace(b) != "" {
		return b
	}
	return "default"
}

func nameOr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	if strings.TrimSpace(b) != "" {
		return b
	}
	return "(unnamed)"
}
