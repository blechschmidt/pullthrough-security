package main

import (
	"log/slog"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/metrics"
	"github.com/blechschmidt/pullthrough-security/internal/webauthn"
)

// buildWebAuthn constructs the WebAuthn/passkey step-up service (Task 161) from
// configuration. It returns nil when the subsystem is disabled so callers can
// cheaply nil-check. A construction error (invalid config or an unreadable
// credential store) is surfaced so the operator sees a misconfiguration at
// startup rather than silently losing the second factor.
func buildWebAuthn(cfg *config.Config, auditLog *audit.Logger, logger *slog.Logger) (*webauthn.Service, error) {
	wc := cfg.WebAuthn
	if !wc.Enabled {
		return nil, nil
	}
	rpName := wc.RPName
	if rpName == "" {
		rpName = "Pullthrough Admin"
	}
	svc, err := webauthn.New(webauthn.Config{
		Enabled:                    wc.Enabled,
		Enforce:                    wc.EnforceOrDefault(),
		RPID:                       wc.RPID,
		RPName:                     rpName,
		Origins:                    wc.Origins,
		RequireUserVerification:    wc.RequireUserVerificationOrDefault(),
		ChallengeTTL:               wc.ChallengeTTL,
		StepUpTTL:                  wc.StepUpTTL,
		AllowUnverifiedAttestation: wc.AllowUnverifiedAttestationOrDefault(),
		ProtectedActions:           wc.ProtectedActions,
		StorePath:                  wc.StorePath,
	},
		webauthn.WithAudit(auditLog),
		webauthn.WithMetrics(webauthn.NewMetrics()),
		webauthn.WithLogger(logger),
	)
	if err != nil {
		return nil, err
	}
	logger.Info("webauthn passkey step-up enabled",
		"rpId", wc.RPID, "enforcing", svc.Enforcing(),
		"requireUV", wc.RequireUserVerificationOrDefault())
	return svc, nil
}

// bindWebAuthnMetrics registers the pullthrough_webauthn_* scrape-time callbacks
// over the subsystem's atomic counters and live gauges. Safe to call with a
// nil/disabled service (binds nothing).
func bindWebAuthnMetrics(c *metrics.Collector, svc *webauthn.Service) {
	if svc == nil || !svc.Enabled() {
		return
	}
	snap := func() webauthn.Snapshot { return svc.Snapshot() }
	c.BindCounter("pullthrough_webauthn_registrations_total",
		"Total completed passkey enrolments.",
		func() float64 { return float64(snap().Registrations) })
	c.BindCounter("pullthrough_webauthn_registration_failures_total",
		"Total failed passkey registration ceremonies.",
		func() float64 { return float64(snap().RegistrationFailures) })
	c.BindCounter("pullthrough_webauthn_assertions_total",
		"Total successful step-up assertion ceremonies.",
		func() float64 { return float64(snap().Assertions) })
	c.BindCounter("pullthrough_webauthn_assertion_failures_total",
		"Total failed step-up assertion ceremonies.",
		func() float64 { return float64(snap().AssertionFailures) })
	c.BindCounter("pullthrough_webauthn_counter_rollbacks_total",
		"Total signature-counter regressions detected (possible cloned authenticator).",
		func() float64 { return float64(snap().CounterRollbacks) })
	c.BindCounter("pullthrough_webauthn_challenges_issued_total",
		"Total registration + assertion challenges minted.",
		func() float64 { return float64(snap().ChallengesIssued) })
	c.BindCounter("pullthrough_webauthn_challenges_expired_total",
		"Total ceremonies rejected for an unknown or expired challenge.",
		func() float64 { return float64(snap().ChallengesExpired) })
	c.BindCounter("pullthrough_webauthn_stepup_required_total",
		"Total protected requests that demanded a step-up token.",
		func() float64 { return float64(snap().StepUpRequired) })
	c.BindCounter("pullthrough_webauthn_stepup_verified_total",
		"Total protected requests admitted by a fresh step-up assertion.",
		func() float64 { return float64(snap().StepUpVerified) })
	c.BindCounter("pullthrough_webauthn_stepup_denied_total",
		"Total protected requests blocked for a missing or invalid step-up token.",
		func() float64 { return float64(snap().StepUpDenied) })
	c.BindGauge("pullthrough_webauthn_active_credentials",
		"Registered passkey credentials across all identities.",
		func() float64 { return float64(snap().ActiveCredentials) })
	c.BindGauge("pullthrough_webauthn_enrolled_subjects",
		"Distinct admin identities with at least one registered passkey.",
		func() float64 { return float64(snap().EnrolledSubjects) })
	c.BindGauge("pullthrough_webauthn_pending_challenges",
		"Outstanding (un-consumed, un-expired) ceremony challenges.",
		func() float64 { return float64(snap().PendingChallenges) })
}
