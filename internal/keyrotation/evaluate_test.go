package keyrotation

import (
	"testing"
	"time"
)

func TestEvaluate_HardExpiryBands(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	th := Thresholds{Warn: 14 * 24 * time.Hour, Critical: 3 * 24 * time.Hour}

	cases := []struct {
		name string
		in   time.Duration // time until NotAfter from now
		want Status
	}{
		{"healthy", 30 * 24 * time.Hour, StatusOK},
		{"warning", 10 * 24 * time.Hour, StatusWarning},
		{"critical", 2 * 24 * time.Hour, StatusCritical},
		{"expired", -time.Hour, StatusExpired},
		{"exactly-warn-boundary", 14 * 24 * time.Hour, StatusWarning}, // <= warn
		{"exactly-critical-boundary", 3 * 24 * time.Hour, StatusCritical},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := Material{ID: "c", Kind: KindTLSCert, NotAfter: now.Add(tc.in)}
			got := Evaluate(now, m, th)
			if got.Status != tc.want {
				t.Fatalf("status = %q, want %q (remaining=%s)", got.Status, tc.want, tc.in)
			}
			if !got.HasExpiry {
				t.Fatal("expected HasExpiry for a material with NotAfter")
			}
			if got.ExpirySource != expirySourceNotAfter {
				t.Fatalf("expiry source = %q, want notAfter", got.ExpirySource)
			}
		})
	}
}

func TestEvaluate_PolicySoftExpiry(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	th := Thresholds{Warn: 14 * 24 * time.Hour, Critical: 3 * 24 * time.Hour}

	// A bare key with no NotAfter but a rotate-every policy anchored to a known
	// install time derives a soft expiry.
	m := Material{
		ID:          "audit.hmac",
		Kind:        KindAuditHMAC,
		LastRotated: now.Add(-80 * 24 * time.Hour),
		RotateEvery: 90 * 24 * time.Hour, // 10 days of life left
	}
	got := Evaluate(now, m, th)
	if got.Status != StatusWarning {
		t.Fatalf("status = %q, want warning", got.Status)
	}
	if got.ExpirySource != expirySourcePolicy {
		t.Fatalf("expiry source = %q, want policy", got.ExpirySource)
	}
	if !got.HasExpiry {
		t.Fatal("policy expiry should set HasExpiry")
	}
}

func TestEvaluate_EarliestOfHardAndPolicy(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	th := Thresholds{Warn: 14 * 24 * time.Hour, Critical: 3 * 24 * time.Hour}

	// Hard NotAfter in 2 days (critical), policy in 100 days: the earliest (hard)
	// wins.
	m := Material{
		ID:          "k",
		NotAfter:    now.Add(2 * 24 * time.Hour),
		LastRotated: now,
		RotateEvery: 100 * 24 * time.Hour,
	}
	got := Evaluate(now, m, th)
	if got.ExpirySource != expirySourceNotAfter {
		t.Fatalf("expiry source = %q, want notAfter (earliest wins)", got.ExpirySource)
	}
	if got.Status != StatusCritical {
		t.Fatalf("status = %q, want critical", got.Status)
	}
}

func TestEvaluate_NoExpiryIsUnknown(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m := Material{ID: "attest.signer", Kind: KindAttestSigner}
	got := Evaluate(now, m, Thresholds{})
	if got.Status != StatusUnknown {
		t.Fatalf("status = %q, want unknown", got.Status)
	}
	if got.HasExpiry {
		t.Fatal("material with no expiry/policy must not report HasExpiry")
	}
	if got.Note == "" {
		t.Fatal("unknown status should carry an explanatory note")
	}
}

func TestEvaluate_OverlapSuppressesFalsePositive(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	th := Thresholds{Warn: 14 * 24 * time.Hour, Critical: 3 * 24 * time.Hour}

	// An expired/near-expired material inside a staged overlap window must NOT
	// alarm: the near/past expiry is the retiring previous key. This is the
	// "no drift false-positives" guarantee.
	m := Material{
		ID:       "cache.kek",
		Kind:     KindCacheKEK,
		NotAfter: now.Add(-time.Hour), // would otherwise be StatusExpired
		Overlap:  true,
	}
	got := Evaluate(now, m, th)
	if got.Status != StatusOK {
		t.Fatalf("overlap material status = %q, want ok (suppressed)", got.Status)
	}
	if got.Note == "" {
		t.Fatal("overlap suppression should record a note")
	}

	// Without the overlap flag the same material is expired.
	m.Overlap = false
	if got := Evaluate(now, m, th); got.Status != StatusExpired {
		t.Fatalf("non-overlap status = %q, want expired", got.Status)
	}
}

func TestStatusOrdering(t *testing.T) {
	if !StatusExpired.worseThan(StatusCritical) ||
		!StatusCritical.worseThan(StatusWarning) ||
		!StatusWarning.worseThan(StatusUnknown) ||
		!StatusUnknown.worseThan(StatusOK) {
		t.Fatal("status severity ordering is wrong")
	}
	if StatusOK.alerting() || StatusUnknown.alerting() {
		t.Fatal("ok/unknown must not be alerting")
	}
	if !StatusWarning.alerting() || !StatusCritical.alerting() || !StatusExpired.alerting() {
		t.Fatal("warning/critical/expired must be alerting")
	}
}
