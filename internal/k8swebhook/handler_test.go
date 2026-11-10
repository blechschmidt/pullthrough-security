package k8swebhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/dossier"
)

// fakeSource returns a canned verdict keyed by repository, and an error for a
// repository registered as erroring.
type fakeSource struct {
	verdicts map[string]Verdict
	errs     map[string]bool
	calls    int
}

func (f *fakeSource) Verdict(_ context.Context, _ string, ref ImageRef, _ string, strip bool) (Verdict, error) {
	f.calls++
	name, _ := ref.Coordinate(strip)
	if f.errs[name] {
		return Verdict{}, errors.New("boom")
	}
	if v, ok := f.verdicts[name]; ok {
		return v, nil
	}
	return Verdict{Decision: dossier.VerdictUnknown}, nil
}

// fakeLock is a programmable LockdownOracle.
type fakeLock struct {
	active   bool
	mode     string
	incident string
	blocked  map[string]string // name -> reason
}

func (l *fakeLock) BlockedCoordinate(_, name, _ string) (bool, string, string) {
	if r, ok := l.blocked[name]; ok {
		return true, r, l.incident
	}
	return false, "", l.incident
}

func (l *fakeLock) Active() (bool, string, string) { return l.active, l.mode, l.incident }

func podReview(ns string, images ...string) *AdmissionRequest {
	cs := make([]container, 0, len(images))
	for i, img := range images {
		cs = append(cs, container{Name: "c" + string(rune('0'+i)), Image: img})
	}
	obj, _ := json.Marshal(podObject{
		Metadata: objectMeta{Name: "p", Namespace: ns},
		Spec:     podSpec{Containers: cs},
	})
	return &AdmissionRequest{
		UID:       "uid-1",
		Resource:  GroupVersionResource{Version: "v1", Resource: "pods"},
		Namespace: ns,
		Name:      "p",
		Operation: "CREATE",
		Object:    obj,
	}
}

func newTestHandler(t *testing.T, cfg Config, src VerdictSource, lock LockdownOracle) *Handler {
	t.Helper()
	h, err := NewHandler(cfg, src, lock, nil)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

func TestReviewAdmitsCleanImage(t *testing.T) {
	src := &fakeSource{verdicts: map[string]Verdict{"org/clean": {Decision: dossier.VerdictAdmit}}}
	h := newTestHandler(t, DefaultConfig(), src, nil)
	resp := h.Review(context.Background(), podReview("prod", "ghcr.io/org/clean:1.0"))
	if !resp.Allowed {
		t.Fatalf("expected admit, got deny: %+v", resp.Status)
	}
}

func TestReviewDeniesBlockVerdict(t *testing.T) {
	src := &fakeSource{verdicts: map[string]Verdict{
		"org/evil": {Decision: dossier.VerdictBlock, RiskScore: 90, Summary: "critical CVE"},
	}}
	h := newTestHandler(t, DefaultConfig(), src, nil)
	resp := h.Review(context.Background(), podReview("prod", "ghcr.io/org/evil:1.0"))
	if resp.Allowed {
		t.Fatal("expected deny for a block verdict")
	}
	if resp.Status == nil || resp.Status.Code != http.StatusForbidden {
		t.Fatalf("expected 403 status, got %+v", resp.Status)
	}
	if !strings.Contains(resp.Status.Message, "critical CVE") {
		t.Errorf("deny message should carry the dossier summary, got %q", resp.Status.Message)
	}
	if h.Metrics().Denied != 1 || h.Metrics().ImagesBlocked != 1 {
		t.Errorf("unexpected metrics: %+v", h.Metrics())
	}
}

func TestReviewWarnVerdictAdmitsWithWarning(t *testing.T) {
	src := &fakeSource{verdicts: map[string]Verdict{
		"org/meh": {Decision: dossier.VerdictWarn, Summary: "license requires review"},
	}}
	h := newTestHandler(t, DefaultConfig(), src, nil)
	resp := h.Review(context.Background(), podReview("prod", "ghcr.io/org/meh:1.0"))
	if !resp.Allowed {
		t.Fatal("warn verdict should admit by default")
	}
	if len(resp.Warnings) != 1 || !strings.Contains(resp.Warnings[0], "license requires review") {
		t.Errorf("expected an advisory warning, got %v", resp.Warnings)
	}
}

func TestReviewUnknownFailOpenVsClosed(t *testing.T) {
	// Fail-open (default): unknown admits.
	h := newTestHandler(t, DefaultConfig(), &fakeSource{}, nil)
	if resp := h.Review(context.Background(), podReview("prod", "org/mystery:1.0")); !resp.Allowed {
		t.Fatal("unknown should admit under fail-open default")
	}
	// unknownAction=deny: unknown denies.
	cfg := DefaultConfig()
	cfg.UnknownAction = "deny"
	h2 := newTestHandler(t, cfg, &fakeSource{}, nil)
	if resp := h2.Review(context.Background(), podReview("prod", "org/mystery:1.0")); resp.Allowed {
		t.Fatal("unknown should deny when unknownAction=deny")
	}
}

func TestReviewSourceErrorFailurePolicy(t *testing.T) {
	src := &fakeSource{errs: map[string]bool{"org/down": true}}
	// fail-open admits with a warning.
	h := newTestHandler(t, DefaultConfig(), src, nil)
	resp := h.Review(context.Background(), podReview("prod", "org/down:1.0"))
	if !resp.Allowed {
		t.Fatal("source error should admit under fail-open")
	}
	if h.Metrics().SourceErrors != 1 || h.Metrics().FailOpen != 1 {
		t.Errorf("unexpected metrics: %+v", h.Metrics())
	}
	// fail-closed denies.
	cfg := DefaultConfig()
	cfg.FailurePolicy = "closed"
	h2 := newTestHandler(t, cfg, &fakeSource{errs: map[string]bool{"org/down": true}}, nil)
	if resp := h2.Review(context.Background(), podReview("prod", "org/down:1.0")); resp.Allowed {
		t.Fatal("source error should deny under fail-closed")
	}
}

func TestReviewNamespaceBypass(t *testing.T) {
	src := &fakeSource{verdicts: map[string]Verdict{"org/evil": {Decision: dossier.VerdictBlock}}}
	cfg := DefaultConfig()
	cfg.IgnoreNamespaces = []string{"kube-system"}
	h := newTestHandler(t, cfg, src, nil)
	resp := h.Review(context.Background(), podReview("kube-system", "ghcr.io/org/evil:1.0"))
	if !resp.Allowed {
		t.Fatal("exempt namespace must bypass enforcement even for a block verdict")
	}
	if src.calls != 0 {
		t.Errorf("verdict source should not be consulted for an exempt namespace, got %d calls", src.calls)
	}
	if h.Metrics().Bypassed != 1 {
		t.Errorf("expected a bypass count, got %+v", h.Metrics())
	}
}

func TestReviewImageAllowlistBypass(t *testing.T) {
	src := &fakeSource{}
	cfg := DefaultConfig()
	cfg.UnknownAction = "deny" // would otherwise deny the unknown infra image
	cfg.IgnoreImages = []string{"registry.k8s.io/"}
	h := newTestHandler(t, cfg, src, nil)
	resp := h.Review(context.Background(), podReview("prod", "registry.k8s.io/pause:3.9"))
	if !resp.Allowed {
		t.Fatal("allowlisted infra image must be admitted")
	}
	if src.calls != 0 {
		t.Errorf("verdict source should not be consulted for an allowlisted image, got %d calls", src.calls)
	}
}

func TestReviewLockdownTargetedBlock(t *testing.T) {
	src := &fakeSource{verdicts: map[string]Verdict{"org/app": {Decision: dossier.VerdictAdmit}}}
	lock := &fakeLock{active: true, mode: "block", incident: "INC-7", blocked: map[string]string{"org/app": "known-malicious"}}
	h := newTestHandler(t, DefaultConfig(), src, lock)
	resp := h.Review(context.Background(), podReview("prod", "ghcr.io/org/app:1.0"))
	if resp.Allowed {
		t.Fatal("a targeted lockdown block must deny even a clean dossier verdict")
	}
	if !strings.Contains(resp.Status.Message, "INC-7") {
		t.Errorf("deny message should name the incident, got %q", resp.Status.Message)
	}
	if h.Metrics().LockdownDenies != 1 {
		t.Errorf("expected a lockdown-deny count, got %+v", h.Metrics())
	}
}

func TestReviewLockdownFlipsUnknownToDeny(t *testing.T) {
	// unknownAction defaults to admit, but an active lockdown flips it to deny.
	src := &fakeSource{}
	lock := &fakeLock{active: true, mode: "strict", incident: "INC-9"}
	h := newTestHandler(t, DefaultConfig(), src, lock)
	resp := h.Review(context.Background(), podReview("prod", "org/mystery:1.0"))
	if resp.Allowed {
		t.Fatal("unknown image must be denied while a lockdown is engaged")
	}
	if h.Metrics().LockdownDenies != 1 {
		t.Errorf("expected a lockdown-deny count, got %+v", h.Metrics())
	}
}

func TestReviewRiskCeiling(t *testing.T) {
	src := &fakeSource{verdicts: map[string]Verdict{
		"org/risky": {Decision: dossier.VerdictWarn, RiskScore: 72, Summary: "elevated risk"},
	}}
	cfg := DefaultConfig()
	cfg.MinRiskScoreToDeny = 70
	h := newTestHandler(t, cfg, src, nil)
	resp := h.Review(context.Background(), podReview("prod", "ghcr.io/org/risky:1.0"))
	if resp.Allowed {
		t.Fatal("image at/above the risk ceiling must be denied")
	}
}

func TestReviewNonPodAdmitted(t *testing.T) {
	src := &fakeSource{verdicts: map[string]Verdict{"org/evil": {Decision: dossier.VerdictBlock}}}
	h := newTestHandler(t, DefaultConfig(), src, nil)
	req := &AdmissionRequest{
		UID:       "uid-2",
		Resource:  GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
		Namespace: "prod",
		Operation: "CREATE",
	}
	resp := h.Review(context.Background(), req)
	if !resp.Allowed {
		t.Fatal("a non-Pod resource must be admitted untouched")
	}
	if src.calls != 0 {
		t.Errorf("verdict source should not run for a non-Pod resource, got %d calls", src.calls)
	}
}

func TestReviewMultiContainerDenyWins(t *testing.T) {
	src := &fakeSource{verdicts: map[string]Verdict{
		"org/clean": {Decision: dossier.VerdictAdmit},
		"org/evil":  {Decision: dossier.VerdictBlock, Summary: "malware"},
	}}
	h := newTestHandler(t, DefaultConfig(), src, nil)
	resp := h.Review(context.Background(), podReview("prod", "ghcr.io/org/clean:1.0", "ghcr.io/org/evil:1.0"))
	if resp.Allowed {
		t.Fatal("a single blocked image must deny the whole Pod")
	}
}

func TestServeValidateEndToEnd(t *testing.T) {
	src := &fakeSource{verdicts: map[string]Verdict{"org/evil": {Decision: dossier.VerdictBlock, Summary: "bad"}}}
	h := newTestHandler(t, DefaultConfig(), src, nil)

	review := AdmissionReview{
		APIVersion: admissionAPIVersion,
		Kind:       admissionKind,
		Request:    podReview("prod", "ghcr.io/org/evil:1.0"),
	}
	body, _ := json.Marshal(review)
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeValidate(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 envelope, got %d", rec.Code)
	}
	var out AdmissionReview
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if out.Response == nil || out.Response.Allowed {
		t.Fatalf("expected a deny response, got %+v", out.Response)
	}
	if out.Response.UID != "uid-1" {
		t.Errorf("response UID must echo the request, got %q", out.Response.UID)
	}
}

func TestServeValidateMalformedBody(t *testing.T) {
	h := newTestHandler(t, DefaultConfig(), &fakeSource{}, nil)
	req := httptest.NewRequest(http.MethodPost, "/validate", strings.NewReader("{not json"))
	rec := httptest.NewRecorder()
	h.ServeValidate(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("malformed body should still yield a 200 AdmissionReview, got %d", rec.Code)
	}
	var out AdmissionReview
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	// Default fail-open: malformed request is admitted with a warning.
	if out.Response == nil || !out.Response.Allowed {
		t.Fatalf("malformed body should admit under fail-open, got %+v", out.Response)
	}
}

func TestConfigValidate(t *testing.T) {
	bad := DefaultConfig()
	bad.BlockAction = "nonsense"
	if _, err := NewHandler(bad, &fakeSource{}, nil, nil); err == nil {
		t.Fatal("expected validation error for an invalid blockAction")
	}
	if _, err := NewHandler(DefaultConfig(), nil, nil, nil); err == nil {
		t.Fatal("expected an error when no verdict source is supplied")
	}
}
