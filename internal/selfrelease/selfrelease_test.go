package selfrelease

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/rekor"
)

// fakeRelease builds a complete, internally-consistent signed release directory
// around a synthetic binary and returns (releaseDir, binaryPath).
type fakeRelease struct {
	dir      string
	binary   string
	key      *ecdsa.PrivateKey
	identity string
	issuer   string
	builder  string
}

func newFakeRelease(t *testing.T) *fakeRelease {
	t.Helper()
	dir := t.TempDir()
	fr := &fakeRelease{
		dir:      dir,
		binary:   filepath.Join(dir, "ptctl"),
		identity: "https://github.com/blechschmidt/pullthrough-security/.github/workflows/release.yml@refs/tags/v1.2.3",
		issuer:   CertificateOIDCIssuer,
		builder:  "https://github.com/blechschmidt/pullthrough-security/.github/workflows/release.yml@refs/tags/v1.2.3",
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	fr.key = key

	// Synthetic binary content.
	if err := os.WriteFile(fr.binary, []byte("fake pullthrough binary\n"), 0o755); err != nil {
		t.Fatalf("write binary: %v", err)
	}

	fr.writeSBOM(t)
	fr.writeChecksumsAndSign(t)
	fr.writeProvenance(t, fr.builder)
	fr.writeRekor(t)
	return fr
}

// writeRekor drops a genuine Rekor log-entry sidecar (and the log's public key)
// next to the binary, as the release pipeline does after submitting to the log.
func (fr *fakeRelease) writeRekor(t *testing.T) {
	t.Helper()
	log := rekor.NewFakeLog(nil)
	entry := log.Append([]byte("ptctl-release-attestation"))
	b, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		t.Fatalf("marshal rekor entry: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fr.dir, "ptctl.rekor.json"), b, 0o644); err != nil {
		t.Fatalf("write rekor sidecar: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fr.dir, "rekor-pubkey.pem"), log.PublicKeyPEM(), 0o644); err != nil {
		t.Fatalf("write rekor key: %v", err)
	}
}

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return fmt.Sprintf("%x", s[:])
}

func (fr *fakeRelease) read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fr.dir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return b
}

func (fr *fakeRelease) writeSBOM(t *testing.T) {
	t.Helper()
	sbom := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"components": []map[string]any{
			{"name": "github.com/blechschmidt/pullthrough-security", "type": "application"},
		},
	}
	b, _ := json.MarshalIndent(sbom, "", "  ")
	if err := os.WriteFile(filepath.Join(fr.dir, "ptctl.sbom.cdx.json"), b, 0o644); err != nil {
		t.Fatalf("write sbom: %v", err)
	}
}

func (fr *fakeRelease) writeChecksumsAndSign(t *testing.T) {
	t.Helper()
	binBytes, _ := os.ReadFile(fr.binary)
	sbomBytes := fr.read(t, "ptctl.sbom.cdx.json")
	manifest := fmt.Sprintf("%s  ptctl\n%s  ptctl.sbom.cdx.json\n", sha256hex(binBytes), sha256hex(sbomBytes))
	if err := os.WriteFile(filepath.Join(fr.dir, "SHA256SUMS"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	// Sign the manifest: ECDSA over its SHA-256, DER, base64 — cosign's layout.
	digest := sha256.Sum256([]byte(manifest))
	der, err := ecdsa.SignASN1(rand.Reader, fr.key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(der)
	if err := os.WriteFile(filepath.Join(fr.dir, "SHA256SUMS.sig"), []byte(sigB64), 0o644); err != nil {
		t.Fatalf("write sig: %v", err)
	}

	// Fulcio-like leaf certificate: SAN URI identity + OIDC-issuer extension.
	certPEM := fr.makeCert(t, fr.identity, fr.issuer)
	if err := os.WriteFile(filepath.Join(fr.dir, "SHA256SUMS.pem"), certPEM, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
}

func (fr *fakeRelease) makeCert(t *testing.T, identity, issuer string) []byte {
	t.Helper()
	u, err := url.Parse(identity)
	if err != nil {
		t.Fatalf("parse identity uri: %v", err)
	}
	issuerDER, err := asn1.Marshal(issuer)
	if err != nil {
		t.Fatalf("marshal issuer: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sigstore"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         []*url.URL{u},
		ExtraExtensions: []pkix.Extension{
			{Id: oidFulcioIssuerV2, Value: issuerDER},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &fr.key.PublicKey, fr.key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func (fr *fakeRelease) writeProvenance(t *testing.T, builder string) {
	t.Helper()
	binBytes, _ := os.ReadFile(fr.binary)
	stmt := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": []map[string]any{
			{"name": "ptctl", "digest": map[string]string{"sha256": sha256hex(binBytes)}},
		},
		"predicate": map[string]any{
			"runDetails": map[string]any{
				"builder": map[string]any{"id": builder},
			},
		},
	}
	payload, _ := json.Marshal(stmt)
	env := map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(payload),
		"signatures":  []map[string]any{{"sig": "AAAA"}},
	}
	b, _ := json.Marshal(env)
	if err := os.WriteFile(filepath.Join(fr.dir, "ptctl.intoto.jsonl"), append(b, '\n'), 0o644); err != nil {
		t.Fatalf("write provenance: %v", err)
	}
}

func okCosign(args []string) ([]byte, error) { return []byte("Verified OK"), nil }

func (fr *fakeRelease) opts() Options {
	return Options{
		BinaryPath: fr.binary,
		ReleaseDir: fr.dir,
		runCosign:  okCosign,
	}
}

func checkStatus(r *Report, name string) Status {
	for _, c := range r.Checks {
		if c.Name == name {
			return c.Status
		}
	}
	return "missing"
}

func TestEmbeddedIdentityCompiles(t *testing.T) {
	id := EmbeddedIdentity() // panics on a malformed constant
	if id.OIDCIssuer == "" || id.CertIdentity == nil || id.BuilderID == nil {
		t.Fatal("embedded identity is incomplete")
	}
}

func TestVerifyHappyPath(t *testing.T) {
	fr := newFakeRelease(t)
	rep, err := Verify(fr.opts())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.OK {
		t.Fatalf("expected OK; report:\n%s", rep.Describe())
	}
	for _, c := range rep.Checks {
		if c.Status != StatusPass {
			t.Errorf("check %q = %s (%s); want pass", c.Name, c.Status, c.Detail)
		}
	}
}

func TestVerifyTamperedBinary(t *testing.T) {
	fr := newFakeRelease(t)
	// Modify the binary after the manifest was written.
	if err := os.WriteFile(fr.binary, []byte("tampered\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(fr.opts())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.OK {
		t.Fatal("expected failure for a tampered binary")
	}
	if checkStatus(rep, "checksums") != StatusFail {
		t.Errorf("checksums check = %s; want fail", checkStatus(rep, "checksums"))
	}
}

func TestVerifyWrongSignerIdentity(t *testing.T) {
	fr := newFakeRelease(t)
	// Re-issue the cert with an attacker-controlled identity and re-sign is not
	// needed: the identity check runs before the signature math.
	bad := fr.makeCert(t, "https://github.com/evil/repo/.github/workflows/release.yml@refs/tags/v9", fr.issuer)
	if err := os.WriteFile(filepath.Join(fr.dir, "SHA256SUMS.pem"), bad, 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(fr.opts())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.OK {
		t.Fatal("expected failure for an untrusted signer identity")
	}
	if checkStatus(rep, "signature-identity") != StatusFail {
		t.Errorf("signature-identity = %s; want fail", checkStatus(rep, "signature-identity"))
	}
}

func TestVerifyTamperedManifestSignature(t *testing.T) {
	fr := newFakeRelease(t)
	// Append a line to the manifest after signing: the signature must no longer
	// verify, even though the identity is still trusted.
	manifest := fr.read(t, "SHA256SUMS")
	manifest = append(manifest, []byte("deadbeef  extra\n")...)
	if err := os.WriteFile(filepath.Join(fr.dir, "SHA256SUMS"), manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(fr.opts())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.OK {
		t.Fatal("expected failure for a tampered manifest")
	}
	if checkStatus(rep, "signature-identity") != StatusFail {
		t.Errorf("signature-identity = %s; want fail", checkStatus(rep, "signature-identity"))
	}
}

func TestVerifyWrongBuilder(t *testing.T) {
	fr := newFakeRelease(t)
	fr.writeProvenance(t, "https://github.com/evil/repo/.github/workflows/build.yml@refs/heads/main")
	rep, err := Verify(fr.opts())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.OK {
		t.Fatal("expected failure for an untrusted builder")
	}
	if checkStatus(rep, "provenance") != StatusFail {
		t.Errorf("provenance = %s; want fail", checkStatus(rep, "provenance"))
	}
}

func TestVerifyMissingProvenance(t *testing.T) {
	fr := newFakeRelease(t)
	if err := os.Remove(filepath.Join(fr.dir, "ptctl.intoto.jsonl")); err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(fr.opts())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.OK {
		t.Fatal("expected failure when provenance is absent")
	}
	if checkStatus(rep, "provenance") != StatusFail {
		t.Errorf("provenance = %s; want fail", checkStatus(rep, "provenance"))
	}
}

func TestCosignUnavailableWarnsThenStrictFails(t *testing.T) {
	fr := newFakeRelease(t)
	o := fr.opts()
	o.runCosign = nil
	o.CosignPath = filepath.Join(fr.dir, "does-not-exist-cosign")

	// Without --require-cosign: a missing cosign is a WARN, overall still OK
	// because the offline identity check passed.
	rep, err := Verify(o)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if checkStatus(rep, "signature-transparency") != StatusWarn {
		t.Errorf("transparency = %s; want warn", checkStatus(rep, "signature-transparency"))
	}
	if !rep.OK {
		t.Errorf("expected OK with offline identity verified; report:\n%s", rep.Describe())
	}

	// With --require-cosign the WARN becomes a hard failure.
	o.RequireCosign = true
	rep2, err := Verify(o)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep2.OK {
		t.Fatal("expected failure under --require-cosign without cosign")
	}
	if checkStatus(rep2, "signature-transparency") != StatusFail {
		t.Errorf("transparency = %s; want fail under require-cosign", checkStatus(rep2, "signature-transparency"))
	}
}

func TestParseChecksumsVariants(t *testing.T) {
	data := []byte("# comment\n" +
		"ABCDEF0000000000000000000000000000000000000000000000000000000000  file-upper\n" +
		"0123456789012345678901234567890123456789012345678901234567890123 *binmode\n" +
		"not-a-checksum line\n")
	m := parseChecksums(data)
	if _, ok := m["file-upper"]; !ok {
		t.Error("uppercase hex entry not parsed/lowercased-keyed")
	}
	if m["file-upper"].Hex != "abcdef0000000000000000000000000000000000000000000000000000000000" {
		t.Errorf("hex not lowercased: %s", m["file-upper"].Hex)
	}
	if _, ok := m["binmode"]; !ok {
		t.Error("binary-mode (*) entry not parsed")
	}
}
