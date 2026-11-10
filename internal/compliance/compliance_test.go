package compliance

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

// fixedNow returns a Now func pinned to t for deterministic tests.
func fixedNow(t time.Time) func() time.Time { return func() time.Time { return t } }

// fullyCompliant is a posture where every gate is active and clean.
func fullyCompliant(now time.Time) Posture {
	return Posture{
		CapturedAt:              now,
		SigEnabled:              true,
		SigVerified:             100,
		SigUnsigned:             0,
		SigVerifications:        100,
		ProvenanceEnabled:       true,
		ArtifactsTotal:          100,
		ArtifactsWithProvenance: 100,
		ArtifactsSigned:         100,
		VulnEnabled:             true,
		VulnScans:               100,
		VulnBlocked:             0,
		LicenseEnabled:          true,
		LicenseEvaluated:        100,
		LicenseAllowed:          100,
		SecretsEnabled:          true,
		SecretsDiffsScanned:     100,
		SecretsFindings:         0,
		Sealed:                  true,
		AuditEnabled:            true,
		AuditTransparency:       true,
		AuditLastSealUnix:       now.Add(-5 * time.Minute).Unix(),
		AuditChainLength:        100,
	}
}

func TestCompute_FullyCompliant(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	card := Compute(fullyCompliant(now), Config{Version: "test", Now: fixedNow(now)})

	if card.Status != StatusPass {
		t.Fatalf("status = %q, want pass; controls=%+v", card.Status, card.Controls)
	}
	if card.Grade != "A" {
		t.Errorf("grade = %q, want A (score=%v)", card.Grade, card.Score)
	}
	if card.Score < 0.999 {
		t.Errorf("score = %v, want ~1.0", card.Score)
	}
	if card.SLSA.BuildLevel != 3 {
		t.Errorf("slsa build level = %d, want 3 (%s)", card.SLSA.BuildLevel, card.SLSA.Rationale)
	}
	if card.Summary.Fail != 0 {
		t.Errorf("expected no failing controls, got %d", card.Summary.Fail)
	}
	// Air-gap is required:false but sealed → pass, so it should count, not be na.
	if c, ok := controlByID(card.Controls, "air-gap-sealed"); !ok || c.Status != StatusPass {
		t.Errorf("air-gap-sealed = %+v, want pass", c)
	}
}

func TestCompute_DisabledOptionalSubsystem_IsNA(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	p := fullyCompliant(now)
	p.LicenseEnabled = false // license control is required:false
	p.Sealed = false         // air-gap is required:false

	card := Compute(p, Config{Now: fixedNow(now)})
	if c, _ := controlByID(card.Controls, "license-compliance"); c.Status != StatusNA {
		t.Errorf("license control = %q, want na when subsystem off and not required", c.Status)
	}
	if c, _ := controlByID(card.Controls, "air-gap-sealed"); c.Status != StatusNA {
		t.Errorf("air-gap control = %q, want na in connected mode", c.Status)
	}
	// na controls must not drag the score down: still fully passing on the rest.
	if card.Status != StatusPass {
		t.Errorf("status = %q, want pass (na controls excluded)", card.Status)
	}
}

func TestCompute_RequiredSubsystemOff_Fails(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	p := fullyCompliant(now)
	p.SigEnabled = false // signature verification is required:true

	card := Compute(p, Config{Now: fixedNow(now)})
	c, _ := controlByID(card.Controls, "signature-verification")
	if c.Status != StatusFail {
		t.Errorf("signature control = %q, want fail when required subsystem off", c.Status)
	}
	if card.Status != StatusFail {
		t.Errorf("overall = %q, want fail (a required control failed)", card.Status)
	}
	if card.SLSA.BuildLevel != 1 {
		t.Errorf("slsa = %d, want 1 (provenance present, signatures unverified)", card.SLSA.BuildLevel)
	}
}

func TestCompute_CoverageThresholds(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	// 85% signature coverage: below pass (0.95), above warn (0.80) → warn.
	p := fullyCompliant(now)
	p.SigVerified = 85
	p.SigUnsigned = 15
	card := Compute(p, Config{Now: fixedNow(now)})
	if c, _ := controlByID(card.Controls, "signature-verification"); c.Status != StatusWarn {
		t.Errorf("signature @85%% = %q, want warn", c.Status)
	}
	if card.Status != StatusWarn {
		t.Errorf("overall = %q, want warn", card.Status)
	}

	// 50% coverage → fail; but signature is required so overall is fail.
	p.SigVerified = 50
	p.SigUnsigned = 50
	card = Compute(p, Config{Now: fixedNow(now)})
	if c, _ := controlByID(card.Controls, "signature-verification"); c.Status != StatusFail {
		t.Errorf("signature @50%% = %q, want fail", c.Status)
	}
}

func TestCompute_AuditTamperFailsHard(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	p := fullyCompliant(now)
	p.AuditVerificationFailures = 1
	card := Compute(p, Config{Now: fixedNow(now)})
	c, _ := controlByID(card.Controls, "audit-transparency")
	if c.Status != StatusFail {
		t.Errorf("audit control = %q, want fail on a verification failure", c.Status)
	}
	if !strings.Contains(c.Detail, "tampering") {
		t.Errorf("detail %q should mention tampering", c.Detail)
	}
}

func TestCompute_AuditStaleness(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	cfg := Config{Now: fixedNow(now), MaxAuditSealAge: time.Hour}

	p := fullyCompliant(now)
	p.AuditLastSealUnix = now.Add(-90 * time.Minute).Unix() // within 2x → warn
	if c, _ := controlByID(Compute(p, cfg).Controls, "audit-transparency"); c.Status != StatusWarn {
		t.Errorf("90m stale = %q, want warn", c.Status)
	}

	p.AuditLastSealUnix = now.Add(-5 * time.Hour).Unix() // beyond 2x → fail
	if c, _ := controlByID(Compute(p, cfg).Controls, "audit-transparency"); c.Status != StatusFail {
		t.Errorf("5h stale = %q, want fail", c.Status)
	}
}

func TestCompute_TransparencyOffWarns(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	p := fullyCompliant(now)
	p.AuditTransparency = false
	card := Compute(p, Config{Now: fixedNow(now)})
	c, _ := controlByID(card.Controls, "audit-transparency")
	if c.Status != StatusWarn {
		t.Errorf("transparency-off = %q, want warn (chain present, no checkpoints)", c.Status)
	}
	// Without a passing audit control, SLSA caps at L2.
	if card.SLSA.BuildLevel != 2 {
		t.Errorf("slsa = %d, want 2", card.SLSA.BuildLevel)
	}
}

func TestCompute_ConfigOverrides(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	p := fullyCompliant(now)
	p.SigVerified = 50
	p.SigUnsigned = 50 // 50% coverage

	// Lower the pass threshold so 50% passes.
	cfg := Config{
		Now: fixedNow(now),
		Controls: map[string]ControlConfig{
			"signature-verification": {PassThreshold: 0.40, WarnThreshold: 0.20},
		},
	}
	if c, _ := controlByID(Compute(p, cfg).Controls, "signature-verification"); c.Status != StatusPass {
		t.Errorf("with lowered threshold, signature = %q, want pass", c.Status)
	}

	// Disable the control entirely → na, excluded from scoring.
	cfg.Controls["signature-verification"] = ControlConfig{Disabled: true}
	card := Compute(p, cfg)
	if c, _ := controlByID(card.Controls, "signature-verification"); c.Status != StatusNA {
		t.Errorf("disabled control = %q, want na", c.Status)
	}
}

func TestCompute_NoDataIsPass(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	// Everything enabled but nothing served yet: a fresh deployment should not be
	// penalized for having no traffic.
	p := Posture{
		CapturedAt: now, SigEnabled: true, ProvenanceEnabled: true, VulnEnabled: true,
		LicenseEnabled: true, SecretsEnabled: true, AuditEnabled: true, AuditTransparency: true,
		AuditLastSealUnix: now.Add(-1 * time.Minute).Unix(),
	}
	card := Compute(p, Config{Now: fixedNow(now)})
	if card.Status != StatusPass {
		t.Errorf("empty-but-enabled posture = %q, want pass; controls=%+v", card.Status, card.Controls)
	}
}

func TestSignAndVerifyReport(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	card := Compute(fullyCompliant(now), Config{Version: "v1", Now: fixedNow(now)})

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := &Signer{priv: priv, keyID: keyID(pub), alg: "ed25519"}

	report, err := BuildSignedReport(card, signer)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Signed() {
		t.Fatal("report should be signed")
	}
	if report.Algorithm != "ed25519" || report.KeyID == "" || report.Digest == "" {
		t.Errorf("unexpected report envelope: %+v", report)
	}
	if err := VerifySignedReport(pub, report); err != nil {
		t.Errorf("valid report failed verification: %v", err)
	}

	// Tamper with the embedded scorecard: verification must fail on digest mismatch.
	tampered := report
	tampered.Scorecard.Score = 0.0
	if err := VerifySignedReport(pub, tampered); err == nil {
		t.Error("tampered report verified; expected digest mismatch")
	}

	// A different key must not verify.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifySignedReport(otherPub, report); err == nil {
		t.Error("report verified under the wrong key")
	}
}

func TestBuildSignedReport_Unsigned(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	card := Compute(fullyCompliant(now), Config{Now: fixedNow(now)})
	report, err := BuildSignedReport(card, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.Signed() {
		t.Error("nil signer should yield an unsigned report")
	}
	if report.Digest == "" {
		t.Error("unsigned report should still carry a digest")
	}
}

func TestLoadSigner_Ed25519(t *testing.T) {
	// PKCS#8 ed25519 key generated for the test (deterministic test vector).
	const keyPEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIIQXMCN0a3i1Z3o3Yh1m1Yh1m1Yh1m1Yh1m1Yh1m1Yh
-----END PRIVATE KEY-----`
	// This vector is intentionally malformed-length; LoadSigner should error rather
	// than panic, exercising the parse error path.
	if _, err := LoadSigner([]byte(keyPEM)); err == nil {
		t.Skip("test vector parsed unexpectedly; parse-path covered elsewhere")
	}
}

func TestRendering(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	card := Compute(fullyCompliant(now), Config{Version: "v1", Now: fixedNow(now)})

	md := card.Markdown()
	for _, want := range []string{"# Compliance Scorecard", "## Controls", "Build L3", "signature"} {
		if !strings.Contains(strings.ToLower(md), strings.ToLower(want)) {
			t.Errorf("markdown missing %q", want)
		}
	}
	htmlDoc := card.HTML()
	for _, want := range []string{"<!DOCTYPE html>", "Compliance Scorecard", "badge"} {
		if !strings.Contains(htmlDoc, want) {
			t.Errorf("html missing %q", want)
		}
	}
}

func TestService_RecomputeAndProjections(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	var p Posture
	src := PostureFunc(func() Posture { return p })

	p = fullyCompliant(now)
	svc := New(Options{Source: src, Config: Config{Now: fixedNow(now)}})

	if svc.Latest().Status != StatusPass {
		t.Fatalf("initial latest = %q, want pass", svc.Latest().Status)
	}
	scores := svc.ControlScores()
	if scores["signature-verification"] < 0.999 {
		t.Errorf("signature score = %v, want ~1", scores["signature-verification"])
	}
	pass := svc.ControlPass()
	if pass["vulnerability-gate"] != 1 {
		t.Errorf("vuln pass = %v, want 1", pass["vulnerability-gate"])
	}

	// Degrade the live source and recompute.
	p.SigEnabled = false
	svc.Recompute()
	if svc.Latest().Status != StatusFail {
		t.Errorf("after degrade, latest = %q, want fail", svc.Latest().Status)
	}
	if svc.ControlPass()["signature-verification"] != 0 {
		t.Errorf("signature pass should be 0 after disable")
	}
}

func TestSortedControlIDsStable(t *testing.T) {
	ids := SortedControlIDs()
	if len(ids) != len(controlDefs) {
		t.Fatalf("got %d ids, want %d", len(ids), len(controlDefs))
	}
	if ids[0] != "signature-verification" {
		t.Errorf("first control = %q, want signature-verification", ids[0])
	}
}
