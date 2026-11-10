package selfrelease

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Fulcio OIDC-issuer certificate extension OIDs (legacy plain-string and the
// current DER-encoded form). Mirrors internal/sigverify so the offline path
// extracts the same identity/issuer the inbound signature gate does.
var (
	oidFulcioIssuerV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidFulcioIssuerV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
)

// cosignRunner runs cosign verify-blob and returns combined output + error. It
// is an injection point for tests.
type cosignRunner func(args []string) ([]byte, error)

// sigArtifacts locates the detached-signature material over the checksums
// manifest. Two layouts are supported:
//
//   - a cosign sign-blob pair: SHA256SUMS.sig (base64) + SHA256SUMS.pem (the
//     Fulcio signing certificate), the layout `make release` emits;
//   - a cosign bundle: SHA256SUMS.bundle / SHA256SUMS.cosign.bundle.
type sigArtifacts struct {
	sigPath    string
	certPath   string
	bundlePath string
}

func findSigArtifacts(dir, manifestBase string) sigArtifacts {
	var a sigArtifacts
	if p, ok := firstExisting(dir, manifestBase+".sig", manifestBase+".sig.b64"); ok {
		a.sigPath = p
	}
	if p, ok := firstExisting(dir, manifestBase+".pem", manifestBase+".crt", manifestBase+".cert"); ok {
		a.certPath = p
	}
	if p, ok := firstExisting(dir, manifestBase+".bundle", manifestBase+".cosign.bundle", manifestBase+".sigstore"); ok {
		a.bundlePath = p
	}
	return a
}

// verifySignature verifies the cosign keyless signature over the checksums
// manifest and returns the checks performed. manifestPath is the signed file;
// manifestBase its basename.
//
// It runs two complementary verifications:
//
//  1. identity: parse the signing certificate, extract its SAN identity and OIDC
//     issuer, and confirm they match the embedded expected identity, and that the
//     signature over the manifest verifies under the certificate's public key.
//     This is done in-process and works offline/air-gapped.
//  2. transparency: when the cosign CLI is available, invoke `cosign verify-blob`
//     with the embedded identity constraints for full Fulcio-root + Rekor
//     inclusion verification (which the offline path cannot do). Unavailable
//     cosign yields a WARN (FAIL under --require-cosign).
func verifySignature(opts Options, id Identity, dir, manifestPath, manifestBase string, manifestData []byte) []Check {
	art := findSigArtifacts(dir, manifestBase)

	if art.certPath == "" && art.sigPath == "" && art.bundlePath == "" {
		return []Check{{
			Name:   "signature",
			Status: StatusFail,
			Detail: fmt.Sprintf("no signature material found for %s (expected %s.sig + %s.pem, or %s.bundle)", manifestBase, manifestBase, manifestBase, manifestBase),
		}}
	}

	var checks []Check

	// --- (1) in-process identity + signature check ---------------------------
	if art.certPath != "" && art.sigPath != "" {
		checks = append(checks, offlineCertVerify(id, art.certPath, art.sigPath, manifestData))
	} else if art.bundlePath != "" {
		// A bundle requires cosign to unpack; the offline check is a skip, but the
		// cosign path below covers it.
		checks = append(checks, Check{
			Name:   "signature-identity",
			Status: StatusSkip,
			Detail: "only a cosign bundle is present; identity is verified via the cosign CLI path",
		})
	}

	// --- (2) cosign transparency-log verification ----------------------------
	checks = append(checks, cosignVerify(opts, id, manifestPath, art))

	return checks
}

// offlineCertVerify performs the in-process certificate-identity + signature
// check.
func offlineCertVerify(id Identity, certPath, sigPath string, signed []byte) Check {
	const name = "signature-identity"

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return Check{Name: name, Status: StatusFail, Detail: "reading signing certificate: " + err.Error()}
	}
	cert, err := parseCert(certPEM)
	if err != nil {
		return Check{Name: name, Status: StatusFail, Detail: err.Error()}
	}

	// Extract and match the signer identity and OIDC issuer.
	identity := certIdentity(cert)
	issuer := certIssuer(cert)
	if identity == "" {
		return Check{Name: name, Status: StatusFail, Detail: "signing certificate carries no SAN identity"}
	}
	if !id.CertIdentity.MatchString(identity) {
		return Check{Name: name, Status: StatusFail, Detail: fmt.Sprintf("signer identity %q does not match the embedded expected identity %q", identity, id.IdentityRaw)}
	}
	if id.OIDCIssuer != "" && !strings.EqualFold(issuer, id.OIDCIssuer) {
		return Check{Name: name, Status: StatusFail, Detail: fmt.Sprintf("signer OIDC issuer %q does not match the embedded expected issuer %q", issuer, id.OIDCIssuer)}
	}

	// Verify the signature over the signed bytes under the certificate's key.
	sigRaw, err := os.ReadFile(sigPath)
	if err != nil {
		return Check{Name: name, Status: StatusFail, Detail: "reading signature: " + err.Error()}
	}
	sig, err := decodeSignature(sigRaw)
	if err != nil {
		return Check{Name: name, Status: StatusFail, Detail: err.Error()}
	}
	if !verifyBlobSignature(cert.PublicKey, signed, sig) {
		return Check{Name: name, Status: StatusFail, Detail: fmt.Sprintf("signature over the checksums manifest does not verify under the signing certificate (signer %q)", identity)}
	}

	return Check{
		Name:   name,
		Status: StatusPass,
		Detail: fmt.Sprintf("checksums signed by %q (issuer %q); signature verifies offline [Fulcio root & Rekor inclusion require the cosign path]", identity, issuer),
	}
}

// cosignVerify shells out to the cosign CLI for full keyless verification.
func cosignVerify(opts Options, id Identity, manifestPath string, art sigArtifacts) Check {
	const name = "signature-transparency"

	runner := opts.runCosign
	if runner == nil {
		bin := strings.TrimSpace(opts.CosignPath)
		if bin == "" {
			bin = "cosign"
		}
		resolved, lookErr := exec.LookPath(bin)
		if lookErr != nil {
			detail := "cosign CLI not found on PATH; skipped Fulcio-root + Rekor transparency verification (offline identity check above still applies)"
			if opts.RequireCosign {
				return Check{Name: name, Status: StatusFail, Detail: "--require-cosign set but " + detail}
			}
			return Check{Name: name, Status: StatusWarn, Detail: detail}
		}
		runner = func(args []string) ([]byte, error) {
			cmd := exec.Command(resolved, args...)
			return cmd.CombinedOutput()
		}
	}

	var args []string
	if art.bundlePath != "" {
		args = []string{"verify-blob",
			"--bundle", art.bundlePath,
			"--certificate-identity-regexp", id.IdentityRaw,
			"--certificate-oidc-issuer", id.OIDCIssuer,
			manifestPath,
		}
	} else {
		args = []string{"verify-blob",
			"--certificate", art.certPath,
			"--signature", art.sigPath,
			"--certificate-identity-regexp", id.IdentityRaw,
			"--certificate-oidc-issuer", id.OIDCIssuer,
			manifestPath,
		}
	}

	out, err := runner(args)
	if err != nil {
		return Check{Name: name, Status: StatusFail, Detail: fmt.Sprintf("cosign verify-blob failed: %v: %s", err, strings.TrimSpace(string(out)))}
	}
	return Check{Name: name, Status: StatusPass, Detail: "cosign verify-blob confirmed the keyless signature, Fulcio chain, and Rekor inclusion"}
}

// parseCert decodes the first CERTIFICATE PEM block.
func parseCert(pemData []byte) (*x509.Certificate, error) {
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("no CERTIFICATE PEM block in signing certificate")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
}

// decodeSignature accepts a base64-encoded (cosign's default) or raw-DER
// signature.
func decodeSignature(raw []byte) ([]byte, error) {
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return nil, fmt.Errorf("empty signature file")
	}
	if dec, err := base64.StdEncoding.DecodeString(s); err == nil && len(dec) > 0 {
		return dec, nil
	}
	// Not base64; treat the bytes as a raw signature.
	return raw, nil
}

// verifyBlobSignature verifies a cosign sign-blob signature over data. cosign
// signs the SHA-256 digest of the blob with ECDSA (ASN.1 DER) or RSA; Ed25519
// signs the message directly.
func verifyBlobSignature(pub crypto.PublicKey, data, sig []byte) bool {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(data)
		return ecdsa.VerifyASN1(k, digest[:], sig)
	case *rsa.PublicKey:
		digest := sha256.Sum256(data)
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig) == nil
	case ed25519.PublicKey:
		return ed25519.Verify(k, data, sig)
	default:
		return false
	}
}

// certIdentity returns the signer identity from a Fulcio certificate's SAN: a
// URI (workflow identity) or, failing that, an email.
func certIdentity(cert *x509.Certificate) string {
	for _, u := range cert.URIs {
		if u != nil {
			return u.String()
		}
	}
	if len(cert.EmailAddresses) > 0 {
		return cert.EmailAddresses[0]
	}
	return ""
}

// certIssuer extracts the OIDC issuer from a Fulcio certificate's issuer
// extension (current DER-encoded OID, then the legacy plain-string OID).
func certIssuer(cert *x509.Certificate) string {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidFulcioIssuerV2) {
			var s string
			if _, err := asn1.Unmarshal(ext.Value, &s); err == nil && s != "" {
				return s
			}
			return strings.TrimSpace(string(ext.Value))
		}
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidFulcioIssuerV1) {
			return strings.TrimSpace(string(ext.Value))
		}
	}
	return ""
}
