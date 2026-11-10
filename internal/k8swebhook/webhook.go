// Package k8swebhook implements a Kubernetes ValidatingAdmissionWebhook (and a
// lightweight embeddable controller handler) that extends the proxy's
// supply-chain enforcement from the pull path to the cluster runtime (Task 111).
//
// The proxy already renders a single, opinionated supply-chain verdict for every
// artifact coordinate it has seen: the per-coordinate security dossier (Task 87),
// which folds the explainable risk score (Task 37), the admission findings, the
// vulnerability/quarantine state, signature/provenance status and more into one
// headline verdict of block|warn|admit|unknown. This package reuses that verdict
// as the admission decision for Pod image references at deploy time: when a Pod
// is created or updated, the webhook extracts every container image, resolves the
// proxy's verdict for each, and admits or rejects the Pod accordingly.
//
// The enforcement point is deliberately the SAME verdict the pull path enforces,
// so a policy change (a new block threshold, a fresh CVE, a targeted lockdown)
// propagates to both boundaries without a second rule set. Two kill-switch
// integrations make the cluster boundary a first-class incident-response lever:
//   - A targeted emergency lockdown (Task 74, ModeBlock) on an (ecosystem,name
//     [,version]) coordinate denies any Pod referencing that image, cluster-wide,
//     ahead of any recorded dossier verdict.
//   - While any lockdown posture is engaged (freeze/strict/block), an image with
//     no recorded supply-chain signal ("unknown") is denied rather than admitted,
//     so an incident instantly flips the webhook from fail-open to fail-closed on
//     un-vetted images.
//
// The package owns no source of truth. The verdict is read through a narrow
// VerdictSource seam that is satisfied both in-process (wrapping *dossier.Builder,
// the default when the webhook runs inside the proxy binary) and over HTTP
// (calling the proxy's existing /admin/api/dossier endpoint, for a split
// deployment). A nil lockdown oracle simply disables the kill-switch integration.
//
// All exported methods are safe for concurrent use.
package k8swebhook

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Action is the admission outcome applied to a Pod (or a single image verdict).
type Action string

const (
	// ActionAdmit admits the Pod.
	ActionAdmit Action = "admit"
	// ActionDeny rejects the Pod with a 403-style admission failure.
	ActionDeny Action = "deny"
	// ActionWarn admits the Pod but attaches an advisory warning.
	ActionWarn Action = "warn"
)

// ParseAction normalizes an operator-supplied action string.
func ParseAction(s string) (Action, bool) {
	switch Action(strings.ToLower(strings.TrimSpace(s))) {
	case ActionAdmit:
		return ActionAdmit, true
	case ActionDeny:
		return ActionDeny, true
	case ActionWarn:
		return ActionWarn, true
	default:
		return "", false
	}
}

// Defaults for the subsystem. Everything is off until an operator opts in; once
// enabled, the defaults are conservative-but-usable: block a block verdict, admit
// everything else, and fail open on an internal error (so a webhook outage never
// wedges every deploy in the cluster — the operator raises failurePolicy to
// "closed" once the enforcement path is trusted).
const (
	defaultAddr       = ":8443"
	defaultPath       = "/validate"
	defaultEcosystem  = "docker"
	defaultTimeout    = 5 * time.Second
	defaultHealthPath = "/healthz"
	defaultReadyPath  = "/readyz"
)

// Config configures the admission webhook server and its decision policy. The
// zero value is disabled; DefaultConfig is the opinionated enabled baseline.
type Config struct {
	// Enabled turns on the webhook server, its handler, and the metrics.
	Enabled bool

	// Addr is the HTTPS listen address. Defaults to ":8443".
	Addr string
	// Path is the URL path the ValidatingWebhookConfiguration points at.
	// Defaults to "/validate".
	Path string
	// HealthPath / ReadyPath serve liveness/readiness probes. Default
	// "/healthz" / "/readyz".
	HealthPath string
	ReadyPath  string

	// TLSCertFile / TLSKeyFile is the serving certificate the API server
	// connects to (its CA bundle must be the issuer, wired as caBundle in the
	// ValidatingWebhookConfiguration). Required when Enabled.
	TLSCertFile string
	TLSKeyFile  string
	// ClientCAFile, when set, enables mutual TLS: the API server's client
	// certificate is verified against this CA bundle. Optional.
	ClientCAFile string

	// FailurePolicy governs what the server does when it cannot compute a verdict
	// for an image (the verdict source errors or times out): "open" admits,
	// "closed" denies. Defaults to "open". This is the server-side analogue of the
	// ValidatingWebhookConfiguration's own failurePolicy (which governs the webhook
	// being unreachable); set both consistently.
	FailurePolicy string

	// BlockAction / WarnAction / UnknownAction map a dossier headline verdict to an
	// admission outcome. Defaults: block->deny, warn->admit, unknown->admit.
	BlockAction   string
	WarnAction    string
	UnknownAction string

	// MinRiskScoreToDeny, when > 0, denies any image whose dossier risk score is at
	// or above it even when the headline verdict is not "block" (a cluster-side
	// risk ceiling independent of the pull-path threshold). 0 disables it.
	MinRiskScoreToDeny int

	// EnforceLockdown wires the emergency-lockdown kill-switch (Task 74): a
	// targeted block denies matching images cluster-wide, and while any lockdown is
	// engaged an "unknown" image is denied regardless of UnknownAction. Default true
	// (inert when no lockdown oracle is wired).
	EnforceLockdown bool

	// DefaultEcosystem labels image coordinates for the dossier lookup. Defaults to
	// "docker".
	DefaultEcosystem string
	// Tenant scopes the tenant-bearing dossier sources. Empty aggregates across
	// tenants (the usual cluster-wide posture).
	Tenant string

	// StripRegistryHost drops a leading registry host from the image repository
	// when building the lookup coordinate (so "ghcr.io/org/app" matches the
	// proxy-recorded "org/app"). Default true.
	StripRegistryHost *bool

	// IgnoreNamespaces are admitted without inspection (kube-system, etc.). A Pod
	// in one of these namespaces bypasses the webhook entirely.
	IgnoreNamespaces []string
	// IgnoreImages are image-reference prefixes always admitted (cluster
	// infrastructure images the proxy never fronts, e.g. "registry.k8s.io/").
	IgnoreImages []string

	// AnnotateWarnings attaches a per-image advisory to the AdmissionResponse
	// warnings for a warn verdict (surfaced by kubectl). Default true.
	AnnotateWarnings *bool

	// Timeout bounds the per-image verdict lookup. Defaults to 5s.
	Timeout time.Duration
}

// DefaultConfig returns the opinionated enabled baseline (still gated by Enabled,
// which the caller sets from config).
func DefaultConfig() Config {
	strip := true
	warn := true
	return Config{
		Addr:              defaultAddr,
		Path:              defaultPath,
		HealthPath:        defaultHealthPath,
		ReadyPath:         defaultReadyPath,
		FailurePolicy:     "open",
		BlockAction:       string(ActionDeny),
		WarnAction:        string(ActionAdmit),
		UnknownAction:     string(ActionAdmit),
		EnforceLockdown:   true,
		DefaultEcosystem:  defaultEcosystem,
		StripRegistryHost: &strip,
		AnnotateWarnings:  &warn,
		Timeout:           defaultTimeout,
	}
}

// withDefaults fills only the zero-valued fields, leaving meaningful empties
// (IgnoreNamespaces, Tenant) untouched.
func (c Config) withDefaults() Config {
	if strings.TrimSpace(c.Addr) == "" {
		c.Addr = defaultAddr
	}
	if strings.TrimSpace(c.Path) == "" {
		c.Path = defaultPath
	}
	if strings.TrimSpace(c.HealthPath) == "" {
		c.HealthPath = defaultHealthPath
	}
	if strings.TrimSpace(c.ReadyPath) == "" {
		c.ReadyPath = defaultReadyPath
	}
	if strings.TrimSpace(c.FailurePolicy) == "" {
		c.FailurePolicy = "open"
	}
	if strings.TrimSpace(c.BlockAction) == "" {
		c.BlockAction = string(ActionDeny)
	}
	if strings.TrimSpace(c.WarnAction) == "" {
		c.WarnAction = string(ActionAdmit)
	}
	if strings.TrimSpace(c.UnknownAction) == "" {
		c.UnknownAction = string(ActionAdmit)
	}
	if strings.TrimSpace(c.DefaultEcosystem) == "" {
		c.DefaultEcosystem = defaultEcosystem
	}
	if c.Timeout <= 0 {
		c.Timeout = defaultTimeout
	}
	if c.StripRegistryHost == nil {
		v := true
		c.StripRegistryHost = &v
	}
	if c.AnnotateWarnings == nil {
		v := true
		c.AnnotateWarnings = &v
	}
	return c
}

// failClosed reports whether the server denies on an internal/source error.
func (c Config) failClosed() bool {
	return strings.EqualFold(strings.TrimSpace(c.FailurePolicy), "closed") ||
		strings.EqualFold(strings.TrimSpace(c.FailurePolicy), "fail")
}

// validate checks the decision-policy knobs. TLS file presence is validated at
// server construction (so the decision engine stays unit-testable without certs).
func (c Config) validate() error {
	switch strings.ToLower(strings.TrimSpace(c.FailurePolicy)) {
	case "open", "closed", "ignore", "fail":
	default:
		return fmt.Errorf("k8swebhook: invalid failurePolicy %q (want open|closed)", c.FailurePolicy)
	}
	for field, v := range map[string]string{
		"blockAction":   c.BlockAction,
		"warnAction":    c.WarnAction,
		"unknownAction": c.UnknownAction,
	} {
		if _, ok := ParseAction(v); !ok {
			return fmt.Errorf("k8swebhook: invalid %s %q (want admit|deny|warn)", field, v)
		}
	}
	if c.MinRiskScoreToDeny < 0 || c.MinRiskScoreToDeny > 100 {
		return fmt.Errorf("k8swebhook: minRiskScoreToDeny must be within [0,100], got %d", c.MinRiskScoreToDeny)
	}
	if c.Timeout < 0 {
		return fmt.Errorf("k8swebhook: timeout must not be negative, got %s", c.Timeout)
	}
	return nil
}

// metrics holds the subsystem's cumulative counters. All fields are read
// atomically by the Prometheus bridge at scrape time.
type metrics struct {
	reviews        atomic.Uint64 // AdmissionReview requests handled
	admitted       atomic.Uint64 // Pods admitted
	denied         atomic.Uint64 // Pods denied
	warned         atomic.Uint64 // Pods admitted with a warning
	bypassed       atomic.Uint64 // Pods bypassed (ignored namespace/non-pod)
	imagesChecked  atomic.Uint64 // container images evaluated
	imagesBlocked  atomic.Uint64 // images whose verdict denied the Pod
	lockdownDenies atomic.Uint64 // denials driven by the lockdown kill-switch
	sourceErrors   atomic.Uint64 // verdict-source errors/timeouts
	failOpen       atomic.Uint64 // images admitted despite a source error (fail-open)
	failClosed     atomic.Uint64 // images denied due to a source error (fail-closed)

	mu        sync.Mutex
	byVerdict map[string]uint64 // dossier verdict -> count (block|warn|admit|unknown)
}

func newMetrics() *metrics { return &metrics{byVerdict: make(map[string]uint64)} }

func (m *metrics) recordVerdict(v string) {
	if v == "" {
		v = "unknown"
	}
	m.mu.Lock()
	m.byVerdict[v]++
	m.mu.Unlock()
}

// Snapshot is an immutable copy of the subsystem's counters, read by the metrics
// bridge. Safe on a nil receiver.
type Snapshot struct {
	Reviews        uint64
	Admitted       uint64
	Denied         uint64
	Warned         uint64
	Bypassed       uint64
	ImagesChecked  uint64
	ImagesBlocked  uint64
	LockdownDenies uint64
	SourceErrors   uint64
	FailOpen       uint64
	FailClosed     uint64
	ByVerdict      map[string]uint64
}

func (m *metrics) snapshot() Snapshot {
	if m == nil {
		return Snapshot{ByVerdict: map[string]uint64{}}
	}
	m.mu.Lock()
	by := make(map[string]uint64, len(m.byVerdict))
	for k, v := range m.byVerdict {
		by[k] = v
	}
	m.mu.Unlock()
	return Snapshot{
		Reviews:        m.reviews.Load(),
		Admitted:       m.admitted.Load(),
		Denied:         m.denied.Load(),
		Warned:         m.warned.Load(),
		Bypassed:       m.bypassed.Load(),
		ImagesChecked:  m.imagesChecked.Load(),
		ImagesBlocked:  m.imagesBlocked.Load(),
		LockdownDenies: m.lockdownDenies.Load(),
		SourceErrors:   m.sourceErrors.Load(),
		FailOpen:       m.failOpen.Load(),
		FailClosed:     m.failClosed.Load(),
		ByVerdict:      by,
	}
}
