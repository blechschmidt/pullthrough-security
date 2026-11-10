package provenance

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func digestOf(b []byte) string {
	return "sha256:" + fmt.Sprintf("%x", sha256.Sum256(b))
}

func TestVerifyBundle_AttestedWithTrustedRoot(t *testing.T) {
	id := newSigningIdentity(t, "https://github.com/acme/widget/.github/workflows/release.yml@refs/tags/v1.0.0")
	artifact := []byte("artifact-bytes")
	subjectDigest := digestOf(artifact)
	stmt := statementFor(subjectDigest, "https://github.com/acme/widget", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	bundle := id.signBundle(t, stmt)

	v := NewVerifier(id.rootPool())
	att, err := v.VerifyBundle(bundle)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if !att.SignatureValid {
		t.Error("SignatureValid = false, want true")
	}
	if !att.ChainTrusted {
		t.Error("ChainTrusted = false, want true (root is trusted)")
	}
	if att.confidence() != ConfidenceAttested {
		t.Errorf("confidence = %q, want attested", att.confidence())
	}
	if !strings.Contains(att.SignerIdentity, "release.yml") {
		t.Errorf("SignerIdentity = %q, want the workflow SAN", att.SignerIdentity)
	}
	if !att.Statement.BindsDigest(subjectDigest) {
		t.Error("statement does not bind its own subject digest")
	}
}

func TestVerifyBundle_NoTrustRootDowngradesToClaimed(t *testing.T) {
	id := newSigningIdentity(t, "https://example.com/ci")
	stmt := statementFor(digestOf([]byte("x")), "https://github.com/acme/widget", "")
	bundle := id.signBundle(t, stmt)

	// No roots configured: signature is authentic but not anchored to trust.
	v := NewVerifier(nil)
	att, err := v.VerifyBundle(bundle)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if !att.SignatureValid {
		t.Error("SignatureValid = false, want true")
	}
	if att.ChainTrusted {
		t.Error("ChainTrusted = true, want false (no roots)")
	}
	if att.confidence() != ConfidenceClaimed {
		t.Errorf("confidence = %q, want claimed", att.confidence())
	}
}

func TestVerifyBundle_RejectsTamperedPayload(t *testing.T) {
	id := newSigningIdentity(t, "")
	stmt := statementFor(digestOf([]byte("x")), "https://github.com/acme/widget", "")
	bundle := id.signBundle(t, stmt)

	// Tamper: replace the payload with a different statement, keep the signature.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(bundle, &raw); err != nil {
		t.Fatal(err)
	}
	var env map[string]json.RawMessage
	_ = json.Unmarshal(raw["dsseEnvelope"], &env)
	tampered := statementFor(digestOf([]byte("y")), "https://github.com/evil/repo", "")
	env["payload"], _ = json.Marshal(b64(tampered))
	raw["dsseEnvelope"], _ = json.Marshal(env)
	bad, _ := json.Marshal(raw)

	v := NewVerifier(id.rootPool())
	if _, err := v.VerifyBundle(bad); err == nil {
		t.Fatal("expected verification to fail on a tampered payload, got nil")
	}
}

func TestVerifyBundle_RejectsWrongKey(t *testing.T) {
	signer := newSigningIdentity(t, "")
	stmt := statementFor(digestOf([]byte("x")), "https://github.com/acme/widget", "")
	bundle := signer.signBundle(t, stmt)

	// Swap in a different certificate (different key) — the signature must not
	// verify against it.
	other := newSigningIdentity(t, "")
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(bundle, &raw)
	vm := map[string]any{"certificate": map[string]any{"rawBytes": b64(other.der)}}
	raw["verificationMaterial"], _ = json.Marshal(vm)
	bad, _ := json.Marshal(raw)

	v := NewVerifier(other.rootPool())
	if _, err := v.VerifyBundle(bad); err == nil {
		t.Fatal("expected verification to fail when the certificate does not match the signing key")
	}
}

func TestChainTrusted_UntrustedRootIsNotTrusted(t *testing.T) {
	signer := newSigningIdentity(t, "")
	stmt := statementFor(digestOf([]byte("x")), "https://github.com/acme/widget", "")
	bundle := signer.signBundle(t, stmt)

	// A pool that trusts a *different* identity must not vouch for signer.
	stranger := newSigningIdentity(t, "")
	v := NewVerifier(stranger.rootPool())
	att, err := v.VerifyBundle(bundle)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if att.ChainTrusted {
		t.Error("ChainTrusted = true against an unrelated root pool, want false")
	}
}

func TestDSSEPAE(t *testing.T) {
	// Golden vector from the DSSE spec shape: "DSSEv1 <lt> <type> <lp> <payload>".
	got := string(dssePAE("application/vnd.in-toto+json", []byte("hello")))
	want := "DSSEv1 28 application/vnd.in-toto+json 5 hello"
	if got != want {
		t.Errorf("PAE = %q, want %q", got, want)
	}
}

func b64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
