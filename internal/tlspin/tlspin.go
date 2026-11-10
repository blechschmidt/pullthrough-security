// Package tlspin implements optional per-upstream TLS certificate/CA pinning for
// the proxy's outbound (egress) fetch path (Task 128).
//
// The SSRF / egress allowlist (internal/egress, Task 89) and the TLS-interception
// forward proxy (internal/intercept, Task 100) control *where* the proxy may
// fetch from, but neither protects against a man-in-the-middle or a
// compromised/mis-issued CA on the connection to an upstream registry itself: a
// certificate that still chains to a publicly-trusted root would be accepted.
// Certificate pinning closes that gap by additionally requiring the peer's
// certificate chain to match an operator-configured pin before any artifact is
// fetched over it.
//
// A pin is a SHA-256 over one of three things (see Kind): the leaf's
// SubjectPublicKeyInfo (RFC 7469 / HPKP, the recommended default; survives
// re-issue under the same key), the full leaf certificate, or a CA certificate
// that must appear in the chain. Multiple pins may be configured per upstream so
// a key/CA rotation can be staged by listing both the current and the next pin.
//
// Enforcement is installed as a tls.Config.VerifyConnection hook on the shared
// outbound transport (internal/upstream), so it runs on every TLS handshake to a
// pinned upstream and covers every HTTP backend (pip, npm, cargo, Docker/OCI,
// Git-over-HTTPS, …) uniformly. In the default enforce mode a mismatch aborts the
// handshake fail-closed, so a served artifact can never be fetched over a
// connection whose chain does not satisfy the pin. A report-only mode logs,
// audits, and counts mismatches without failing, so operators can validate a pin
// set against live traffic before switching to enforcement.
//
// Every check feeds pullthrough_upstream_tls_pin_* metrics; every violation
// additionally emits a notification and a tamper-evident audit event. A nil
// *Guard is a valid no-op, and VerifierFor returns a nil hook when an upstream
// configures no pins, so unpinned upstreams keep their existing behavior.
package tlspin

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
)

// AuditLogger is the narrow audit surface a pin violation is recorded to.
// *audit.Logger satisfies it; a nil value disables audit recording.
type AuditLogger interface {
	Log(ctx context.Context, ev audit.Event) error
}

// Options carries the guard's optional dependencies.
type Options struct {
	// Notifier receives an EventTLSPinViolation for each violation. Optional.
	Notifier notify.Emitter
	// Audit records each violation as a deny decision. Optional; typically
	// attached after construction via SetAuditLogger because the audit log is
	// built after the client pool.
	Audit AuditLogger
	// Logger receives structured warnings. Defaults to slog.Default().
	Logger *slog.Logger
	// Clock is the time source (overridable in tests). Defaults to time.Now.
	Clock func() time.Time
}

// EndpointConfig describes the pin policy for one upstream endpoint (the primary
// URL or a mirror). The zero value (no pins) disables pinning for that endpoint.
type EndpointConfig struct {
	// Pins are the pin specs (see ParsePins). Empty means "do not pin".
	Pins []string
	// ReportOnly logs/audits/counts mismatches but still allows the connection.
	ReportOnly bool
}

// PinError is returned by an enforcing VerifyConnection hook when the peer's
// chain satisfies none of the configured pins. It aborts the TLS handshake, so
// it surfaces to the backend as a transport error; callers can detect it with
// errors.As to distinguish a pin failure from an ordinary TLS error.
type PinError struct {
	Host      string
	Presented Presented
}

func (e *PinError) Error() string {
	return fmt.Sprintf("tls pin violation: upstream %q presented a certificate "+
		"(leaf spki-sha256:%s) that satisfied no configured pin", e.Host, e.Presented.SPKISHA256)
}

// Violation is a single recorded pin mismatch, surfaced to the admin API ring.
type Violation struct {
	Time       time.Time `json:"time"`
	Host       string    `json:"host,omitempty"`
	ReportOnly bool      `json:"reportOnly"`
	SPKISHA256 string    `json:"spkiSha256,omitempty"`
	CertSHA256 string    `json:"certSha256,omitempty"`
}

const recentLimit = 100

// Guard aggregates the counters, recent-violation ring, and audit/notify
// dependencies shared across every pinned upstream. Per-endpoint verification
// closures (see VerifierFor) record into it. It is safe for concurrent use.
type Guard struct {
	notifier notify.Emitter
	auditLog AuditLogger
	logger   *slog.Logger
	clock    func() time.Time

	mu                 sync.Mutex
	pinnedEndpoints    int
	checks             uint64
	matches            uint64
	violationsEnforced uint64
	violationsReport   uint64
	byHostMode         map[hostMode]uint64
	recent             []Violation
}

type hostMode struct {
	host string
	mode string
}

const (
	modeEnforce    = "enforce"
	modeReportOnly = "report_only"
)

// New constructs a Guard. It is always safe to construct one even when no
// upstream configures pins; such a guard simply never records anything.
func New(opts Options) *Guard {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Guard{
		notifier:   opts.Notifier,
		auditLog:   opts.Audit,
		logger:     logger,
		clock:      clock,
		byHostMode: make(map[hostMode]uint64),
		recent:     make([]Violation, 0, recentLimit),
	}
}

// SetAuditLogger attaches an audit sink after construction. The guard is built
// before the audit log exists (so its verify hooks can be wired into the client
// pool at startup), so the wiring layer attaches the logger once available. It
// must be called during single-threaded startup, before any handshake. A nil
// guard is a no-op.
func (g *Guard) SetAuditLogger(l AuditLogger) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.auditLog = l
}

// VerifierFor compiles ep's pins and returns a tls.Config.VerifyConnection hook
// that enforces them, recording every check into g. It returns (nil, nil) when
// ep configures no pins, so the caller installs no hook and the endpoint keeps
// ordinary system-trust verification. It returns an error only when a pin spec
// is malformed. A nil guard yields no hook.
func (g *Guard) VerifierFor(ep EndpointConfig) (func(tls.ConnectionState) error, error) {
	pins, err := ParsePins(ep.Pins)
	if err != nil {
		return nil, err
	}
	if len(pins) == 0 {
		return nil, nil
	}
	if g == nil {
		// Pins configured but no guard to record into: still enforce (fail-closed),
		// just without metrics/audit. This should not happen in normal wiring.
		reportOnly := ep.ReportOnly
		return func(cs tls.ConnectionState) error {
			if matched, present := matchPins(cs, pins); !matched && !reportOnly {
				return &PinError{Host: cs.ServerName, Presented: present}
			}
			return nil
		}, nil
	}

	g.mu.Lock()
	g.pinnedEndpoints++
	g.mu.Unlock()

	reportOnly := ep.ReportOnly
	return func(cs tls.ConnectionState) error {
		matched, present := matchPins(cs, pins)
		if matched {
			g.recordMatch()
			return nil
		}
		g.recordViolation(cs.ServerName, reportOnly, present)
		if reportOnly {
			return nil
		}
		return &PinError{Host: cs.ServerName, Presented: present}
	}, nil
}

func (g *Guard) recordMatch() {
	g.mu.Lock()
	g.checks++
	g.matches++
	g.mu.Unlock()
}

func (g *Guard) recordViolation(host string, reportOnly bool, present Presented) {
	mode := modeEnforce
	if reportOnly {
		mode = modeReportOnly
	}

	g.mu.Lock()
	g.checks++
	if reportOnly {
		g.violationsReport++
	} else {
		g.violationsEnforced++
	}
	g.byHostMode[hostMode{host: host, mode: mode}]++
	v := Violation{
		Time:       g.clock().UTC(),
		Host:       host,
		ReportOnly: reportOnly,
		SPKISHA256: present.SPKISHA256,
		CertSHA256: present.CertSHA256,
	}
	if len(g.recent) >= recentLimit {
		copy(g.recent, g.recent[1:])
		g.recent[len(g.recent)-1] = v
	} else {
		g.recent = append(g.recent, v)
	}
	notifier := g.notifier
	auditLog := g.auditLog
	g.mu.Unlock()

	if g.logger != nil {
		g.logger.Warn("upstream TLS pin violation",
			"host", host, "mode", mode,
			"presentedSpki", present.SPKISHA256,
			"presentedCert", present.CertSHA256)
	}

	ctx := context.Background()
	if notifier != nil {
		notifier.Emit(ctx, pinEvent(host, reportOnly, present))
	}
	if auditLog != nil {
		reason := "upstream TLS pin violation"
		if reportOnly {
			reason += " (report-only)"
		}
		_ = auditLog.Log(ctx, audit.Event{
			Type:     audit.EventTLSPin,
			Backend:  host,
			Resource: host,
			Decision: audit.DecisionDeny,
			Reason:   reason,
			Detail: map[string]any{
				"mode":          mode,
				"host":          host,
				"presentedSpki": present.SPKISHA256,
				"presentedCert": present.CertSHA256,
			},
		})
	}
}

// pinEvent builds the notification for a pin violation. An enforced violation
// (fail-closed) is the highest signal — a likely live MITM on the upstream — so
// it escalates to critical; a report-only mismatch is high (still actionable,
// but not yet blocking, often an un-staged rotation).
func pinEvent(host string, reportOnly bool, present Presented) notify.Event {
	sev := notify.SeverityCritical
	title := "Upstream TLS pin violation (connection refused)"
	if reportOnly {
		sev = notify.SeverityHigh
		title = "Upstream TLS pin mismatch (report-only)"
	}
	return notify.Event{
		Type:     notify.EventTLSPinViolation,
		Severity: sev,
		Title:    title,
		Summary: fmt.Sprintf("upstream %q presented a certificate that satisfied no configured pin "+
			"(leaf spki-sha256:%s)", host, present.SPKISHA256),
		Subject: host,
	}.WithField("host", host).
		WithField("reportOnly", fmt.Sprintf("%t", reportOnly)).
		WithField("presentedSpki", present.SPKISHA256).
		WithField("presentedCert", present.CertSHA256)
}

// Snapshot is the admin/JSON view of the guard's counters and recent violations.
type Snapshot struct {
	PinnedEndpoints    int         `json:"pinnedEndpoints"`
	Checks             uint64      `json:"checks"`
	Matches            uint64      `json:"matches"`
	ViolationsEnforced uint64      `json:"violationsEnforced"`
	ViolationsReport   uint64      `json:"violationsReportOnly"`
	Recent             []Violation `json:"recent,omitempty"`
}

// Snapshot returns the guard's current counters and recent violations. It is
// nil-safe.
func (g *Guard) Snapshot() Snapshot {
	if g == nil {
		return Snapshot{}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	recent := make([]Violation, len(g.recent))
	copy(recent, g.recent)
	return Snapshot{
		PinnedEndpoints:    g.pinnedEndpoints,
		Checks:             g.checks,
		Matches:            g.matches,
		ViolationsEnforced: g.violationsEnforced,
		ViolationsReport:   g.violationsReport,
		Recent:             recent,
	}
}

// Totals returns the aggregate check/match/violation counters for the metrics
// bridge. enforced and reportOnly are the two violation sub-totals. Nil-safe.
func (g *Guard) Totals() (checks, matches, violationsEnforced, violationsReport uint64) {
	if g == nil {
		return 0, 0, 0, 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.checks, g.matches, g.violationsEnforced, g.violationsReport
}

// ViolationsByHost returns per-(host,mode) violation counts for the labeled
// metrics bridge. Nil-safe.
func (g *Guard) ViolationsByHost() map[[2]string]float64 {
	out := map[[2]string]float64{}
	if g == nil {
		return out
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for hm, v := range g.byHostMode {
		out[[2]string{hm.host, hm.mode}] = float64(v)
	}
	return out
}

// PinnedEndpoints reports how many endpoints installed a pin verifier. It lets
// the metrics bridge and admin surface report whether pinning is active without
// enabling it globally. Nil-safe.
func (g *Guard) PinnedEndpoints() int {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.pinnedEndpoints
}
