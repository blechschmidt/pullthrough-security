package sigverify

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"
)

// goldenSchemes are the PQC/hybrid schemes with committed golden vectors under
// testdata/pqc (generated once; verification is deterministic).
var goldenSchemes = []string{"ML-DSA-65", "SLH-DSA-SHA2-128f", "Ed25519-Dilithium2"}

func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "pqc", name))
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	return data
}

// loadGoldenKey loads a committed PQC public key from its PEM.
func loadGoldenKey(t *testing.T, scheme string) sign.PublicKey {
	t.Helper()
	pub, err := ParsePublicKeyPEM(readGolden(t, scheme+".pub.pem"))
	if err != nil {
		t.Fatalf("parse golden key %s: %v", scheme, err)
	}
	spub, ok := pub.(sign.PublicKey)
	if !ok {
		t.Fatalf("golden key %s is %T, not a PQC key", scheme, pub)
	}
	return spub
}

// TestGoldenPQCSignatureVerifies verifies each committed golden simple-signing
// signature against its public key through the full keyed verification path.
func TestGoldenPQCSignatureVerifies(t *testing.T) {
	for _, scheme := range goldenSchemes {
		t.Run(scheme, func(t *testing.T) {
			pub := loadGoldenKey(t, scheme)
			payload := readGolden(t, scheme+".sig.payload.json")
			sig := readGolden(t, scheme+".sig.bin")

			v, err := NewVerifierWithPQC(nil, nil, []TrustedKey{{Name: scheme + "-key", Public: pub}}, nil,
				PQCOptions{Enabled: true, Policy: PQCPolicyAllowHybrid})
			if err != nil {
				t.Fatalf("NewVerifierWithPQC: %v", err)
			}
			check := v.verifySignature(SimpleSignature{Payload: payload, Signature: sig}, testDigest)
			if !check.Trusted() {
				t.Fatalf("golden %s signature not trusted: crypto=%v err=%q", scheme, check.CryptoValid, check.Err)
			}
			if check.Algorithm != scheme {
				t.Errorf("algorithm = %q, want %q", check.Algorithm, scheme)
			}
			if !check.PostQuantum {
				t.Errorf("expected PostQuantum for %s", scheme)
			}

			// Tampered payload must not verify.
			bad := append([]byte(nil), payload...)
			bad[len(bad)-3] ^= 0xff
			if v.verifySignature(SimpleSignature{Payload: bad, Signature: sig}, testDigest).CryptoValid {
				// bad payload may still be valid JSON binding the digest but the signature
				// is over the original bytes, so crypto must fail.
				t.Errorf("tampered %s payload verified cryptographically", scheme)
			}

			// Tampered signature must not verify.
			badSig := append([]byte(nil), sig...)
			badSig[0] ^= 0xff
			if v.verifySignature(SimpleSignature{Payload: payload, Signature: badSig}, testDigest).CryptoValid {
				t.Errorf("tampered %s signature verified", scheme)
			}
		})
	}
}

// TestGoldenPQCAttestationVerifies verifies each committed golden DSSE
// attestation signature through the attestation path.
func TestGoldenPQCAttestationVerifies(t *testing.T) {
	for _, scheme := range goldenSchemes {
		t.Run(scheme, func(t *testing.T) {
			pub := loadGoldenKey(t, scheme)
			payload := readGolden(t, scheme+".att.payload.json")
			sigB64 := strings.TrimSpace(string(readGolden(t, scheme+".att.sig.b64")))

			env := &Envelope{
				PayloadType: dssePayloadType,
				Payload:     base64.StdEncoding.EncodeToString(payload),
				Signatures:  []EnvelopeSignature{{Sig: sigB64}},
			}
			v, err := NewVerifierWithPQC(nil, nil, []TrustedKey{{Name: scheme + "-key", Public: pub}}, nil,
				PQCOptions{Enabled: true, Policy: PQCPolicyAllowHybrid})
			if err != nil {
				t.Fatalf("NewVerifierWithPQC: %v", err)
			}
			check, statement := v.verifyAttestation(DSSEAttestation{Envelope: env}, testDigest)
			if !check.Trusted() {
				t.Fatalf("golden %s attestation not trusted: err=%q", scheme, check.Err)
			}
			if statement == nil || !statement.IsSLSAProvenance() {
				t.Errorf("expected parsed SLSA statement for %s", scheme)
			}
			if check.Algorithm != scheme {
				t.Errorf("algorithm = %q, want %q", check.Algorithm, scheme)
			}
		})
	}
}

// generateKeyed builds a trusted PQC/hybrid keyed signature over the standard
// test digest using a freshly-generated keypair for the named scheme.
func generateKeyed(t *testing.T, scheme string) (TrustedKey, SimpleSignature) {
	t.Helper()
	s := schemes.ByName(scheme)
	if s == nil {
		t.Fatalf("unknown scheme %q", scheme)
	}
	pub, priv, err := s.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey %s: %v", scheme, err)
	}
	payload := simpleSigningPayloadJSON(t, testDigest)
	sig := s.Sign(priv, payload, nil)
	return TrustedKey{Name: scheme + "-gen", Public: pub}, SimpleSignature{Payload: payload, Signature: sig}
}

// TestPQCPolicyEnforcement exercises the three PQC policies and the disabled
// feature flag against a generated ML-DSA keyed signature.
func TestPQCPolicyEnforcement(t *testing.T) {
	key, sig := generateKeyed(t, "ML-DSA-65")

	cases := []struct {
		name         string
		enabled      bool
		policy       PQCPolicy
		wantTrusted  bool
		wantRejected bool
	}{
		{"disabled", false, "", false, true},
		{"classical-only", true, PQCPolicyClassicalOnly, false, true},
		{"allow-hybrid", true, PQCPolicyAllowHybrid, true, false},
		{"require-pqc", true, PQCPolicyRequirePQC, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := NewVerifierWithPQC(nil, nil, []TrustedKey{key}, nil,
				PQCOptions{Enabled: tc.enabled, Policy: tc.policy})
			if err != nil {
				t.Fatalf("NewVerifierWithPQC: %v", err)
			}
			check := v.verifySignature(sig, testDigest)
			if !check.CryptoValid {
				t.Fatalf("expected cryptographic validity regardless of policy")
			}
			if got := check.Trusted(); got != tc.wantTrusted {
				t.Errorf("Trusted() = %v, want %v (err=%q)", got, tc.wantTrusted, check.Err)
			}
			if check.PQCRejected != tc.wantRejected {
				t.Errorf("PQCRejected = %v, want %v", check.PQCRejected, tc.wantRejected)
			}
		})
	}
}

// TestServiceRequirePQCFindings checks the gate flags a classical-only trusted
// signature as quantum-vulnerable under require-pqc, and admits a PQC one.
func TestServiceRequirePQCFindings(t *testing.T) {
	// A classical keyed signature.
	classicalKey := newKey(t)
	classicalSig := keyedSignature(t, classicalKey, testDigest)
	// A PQC keyed signature.
	pqcKey, pqcSig := generateKeyed(t, "ML-DSA-65")

	newSvc := func(t *testing.T, keys []TrustedKey, policy PQCPolicy) *Service {
		svc, err := NewService(Config{
			Action:       policy2Action(),
			FailSeverity: SeverityHigh,
			PQCEnabled:   true,
			PQCPolicy:    policy,
			Keys:         keys,
		}, nil, nil)
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}
		return svc
	}

	t.Run("classical under require-pqc is quantum-vulnerable", func(t *testing.T) {
		svc := newSvc(t, []TrustedKey{{Name: "classical", Public: &classicalKey.PublicKey}}, PQCPolicyRequirePQC)
		report := svc.verify(Artifact{Ecosystem: "docker", Digest: testDigest},
			&Material{Source: "test", Signatures: []SimpleSignature{classicalSig}})
		if !report.VerifiedSignature {
			t.Fatalf("classical signature should be a trusted signature")
		}
		if report.PostQuantum {
			t.Errorf("classical signature must not be marked post-quantum")
		}
		worst := report.Worst()
		if worst == nil || worst.Kind != KindQuantumVulnerable {
			t.Fatalf("expected quantum-vulnerable finding, got %+v", worst)
		}
		if d := svc.Gate(report); !d.Action.Blocked() {
			t.Errorf("require-pqc should block a classical-only artifact, got %s", d.Action)
		}
	})

	t.Run("pqc under require-pqc is clean", func(t *testing.T) {
		svc := newSvc(t, []TrustedKey{pqcKey}, PQCPolicyRequirePQC)
		report := svc.verify(Artifact{Ecosystem: "docker", Digest: testDigest},
			&Material{Source: "test", Signatures: []SimpleSignature{pqcSig}})
		if !report.VerifiedSignature || !report.PostQuantum {
			t.Fatalf("pqc signature should be trusted and post-quantum: %+v", report)
		}
		if w := report.Worst(); w != nil {
			t.Fatalf("expected no finding, got %+v", w)
		}
		if got := report.Algorithms; len(got) != 1 || got[0] != "ML-DSA-65" {
			t.Errorf("Algorithms = %v, want [ML-DSA-65]", got)
		}
	})

	t.Run("pqc under classical-only is rejected", func(t *testing.T) {
		svc := newSvc(t, []TrustedKey{pqcKey}, PQCPolicyClassicalOnly)
		report := svc.verify(Artifact{Ecosystem: "docker", Digest: testDigest},
			&Material{Source: "test", Signatures: []SimpleSignature{pqcSig}})
		if report.VerifiedSignature {
			t.Fatalf("classical-only must not trust a PQC signature")
		}
		worst := report.Worst()
		if worst == nil || worst.Kind != KindPQCRejected {
			t.Fatalf("expected pqc-rejected finding, got %+v", worst)
		}
	})
}

func policy2Action() policy.Action { return policy.ActionBlock }

// TestServicePQCMetrics checks the PQC counters and per-algorithm tally.
func TestServicePQCMetrics(t *testing.T) {
	pqcKey, pqcSig := generateKeyed(t, "ML-DSA-65")
	svc, err := NewService(Config{
		PQCEnabled: true,
		PQCPolicy:  PQCPolicyAllowHybrid,
		Keys:       []TrustedKey{pqcKey},
	}, nil, nil)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	report := svc.verify(Artifact{Ecosystem: "docker", Digest: testDigest},
		&Material{Source: "test", Signatures: []SimpleSignature{pqcSig}})
	svc.Gate(report)

	m := svc.Metrics()
	if m.PQCSignatures != 1 {
		t.Errorf("PQCSignatures = %d, want 1", m.PQCSignatures)
	}
	if m.PQCVerified != 1 {
		t.Errorf("PQCVerified = %d, want 1", m.PQCVerified)
	}
	if m.PQCRejected != 0 {
		t.Errorf("PQCRejected = %d, want 0", m.PQCRejected)
	}
	var found bool
	for _, u := range m.AlgorithmUsage {
		if u.Algorithm == "ML-DSA-65" {
			found = true
			if u.Class != ClassPQC || u.Count != 1 {
				t.Errorf("usage = %+v, want class=pqc count=1", u)
			}
		}
	}
	if !found {
		t.Errorf("AlgorithmUsage missing ML-DSA-65: %+v", m.AlgorithmUsage)
	}
}

// TestClassifyPublicKey covers algorithm classification across classes.
func TestClassifyPublicKey(t *testing.T) {
	ec := newKey(t)
	if alg, ok := classifyPublicKey(&ec.PublicKey); !ok || alg.Class != ClassClassical || alg.PostQuantum() {
		t.Errorf("ecdsa classified wrong: %+v ok=%v", alg, ok)
	}

	cases := map[string]AlgorithmClass{
		"ML-DSA-65":          ClassPQC,
		"SLH-DSA-SHA2-128f":  ClassPQC,
		"Ed25519-Dilithium2": ClassHybrid,
	}
	for name, wantClass := range cases {
		s := schemes.ByName(name)
		pub, _, err := s.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey %s: %v", name, err)
		}
		alg, ok := classifyPublicKey(pub)
		if !ok {
			t.Fatalf("classify %s: not ok", name)
		}
		if alg.Class != wantClass {
			t.Errorf("%s class = %q, want %q", name, alg.Class, wantClass)
		}
		if !alg.PostQuantum() {
			t.Errorf("%s should be post-quantum", name)
		}
		if alg.Name != name {
			t.Errorf("%s name = %q", name, alg.Name)
		}
	}
}

// TestMarshalParsePQCRoundTrip checks the PQC PEM encoder/parser round-trip.
func TestMarshalParsePQCRoundTrip(t *testing.T) {
	for _, name := range []string{"ML-DSA-44", "SLH-DSA-SHA2-128f", "Ed25519-Dilithium2"} {
		s := schemes.ByName(name)
		pub, _, err := s.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey %s: %v", name, err)
		}
		pemBytes, err := MarshalPQCPublicKeyPEM(pub)
		if err != nil {
			t.Fatalf("Marshal %s: %v", name, err)
		}
		got, err := ParsePublicKeyPEM(pemBytes)
		if err != nil {
			t.Fatalf("Parse %s: %v", name, err)
		}
		gpub, ok := got.(sign.PublicKey)
		if !ok {
			t.Fatalf("parsed %s is %T", name, got)
		}
		if !gpub.Equal(pub) {
			t.Errorf("%s round-trip key mismatch", name)
		}
	}
}

func TestParsePQCErrors(t *testing.T) {
	// Missing Scheme header.
	noHeader := "-----BEGIN PQC PUBLIC KEY-----\nAAAA\n-----END PQC PUBLIC KEY-----\n"
	if _, err := ParsePublicKeyPEM([]byte(noHeader)); err == nil {
		t.Error("expected error for missing Scheme header")
	}
	// Unknown scheme.
	unknown := "-----BEGIN PQC PUBLIC KEY-----\nScheme: NOPE-123\n\nAAAA\n-----END PQC PUBLIC KEY-----\n"
	if _, err := ParsePublicKeyPEM([]byte(unknown)); err == nil {
		t.Error("expected error for unknown scheme")
	}
}

func TestNormalizeAndValidatePQCPolicy(t *testing.T) {
	cases := map[string]PQCPolicy{
		"":                PQCPolicyAllowHybrid,
		"classical-only":  PQCPolicyClassicalOnly,
		"classical_only":  PQCPolicyClassicalOnly,
		"  Require-PQC  ": PQCPolicyRequirePQC,
		"allow-hybrid":    PQCPolicyAllowHybrid,
		"garbage":         PQCPolicyAllowHybrid,
	}
	for in, want := range cases {
		if got := NormalizePQCPolicy(in); got != want {
			t.Errorf("NormalizePQCPolicy(%q) = %q, want %q", in, got, want)
		}
	}
	for _, valid := range []string{"", "classical-only", "allow-hybrid", "require-pqc", "require_pqc"} {
		if !ValidPQCPolicy(valid) {
			t.Errorf("ValidPQCPolicy(%q) = false, want true", valid)
		}
	}
	if ValidPQCPolicy("nonsense") {
		t.Error("ValidPQCPolicy(nonsense) = true, want false")
	}
}

func TestPQCProviderNotFIPSValidated(t *testing.T) {
	// The migration/FIPS preflight depends on this being honestly false.
	if PQCProviderFIPSValidated {
		t.Error("PQCProviderFIPSValidated must be false until the provider completes FIPS 140-3 validation")
	}
	if PQCProviderName == "" {
		t.Error("PQCProviderName must be set")
	}
	if len(SupportedPQCSchemes()) == 0 {
		t.Error("SupportedPQCSchemes must not be empty")
	}
}

// TestPQCDisabledServiceIgnoresPQC confirms that with PQC disabled, a PQC
// signature never establishes trust and surfaces a clear finding.
func TestPQCDisabledServiceIgnoresPQC(t *testing.T) {
	pqcKey, pqcSig := generateKeyed(t, "ML-DSA-65")
	svc, err := NewService(Config{Keys: []TrustedKey{pqcKey}}, nil, nil) // PQC disabled
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	report := svc.verify(Artifact{Ecosystem: "docker", Digest: testDigest},
		&Material{Source: "test", Signatures: []SimpleSignature{pqcSig}})
	if report.VerifiedSignature {
		t.Fatalf("PQC-disabled service must not trust a PQC signature")
	}
	if w := report.Worst(); w == nil || w.Kind != KindPQCRejected {
		t.Fatalf("expected pqc-rejected finding, got %+v", w)
	}
	if m := svc.Metrics(); m.PQCRejected != 1 {
		t.Errorf("PQCRejected = %d, want 1", m.PQCRejected)
	}
}
