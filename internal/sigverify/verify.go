package sigverify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/rekor"
	"github.com/cloudflare/circl/sign"
)

// Verifier holds the trust material and performs the cryptographic checks. It is
// immutable after construction and safe for concurrent use.
//
// Two trust models are supported, matching cosign:
//
//   - Keyless (Fulcio/Rekor): the signing certificate is short-lived and issued
//     by Fulcio against an OIDC identity. Trust requires (a) the certificate
//     chaining to a configured Fulcio root, (b) the certificate's identity
//     (Subject Alternative Name) and OIDC issuer matching a configured allowed
//     identity, and (optionally) (c) a Rekor transparency-log inclusion proof
//     (Signed Entry Timestamp) verifying against a configured Rekor public key.
//   - Keyed: the signature verifies against one of a set of operator-configured
//     public keys.
type Verifier struct {
	roots      *x509.CertPool
	identities []Identity
	keys       []TrustedKey
	rekorKeys  []crypto.PublicKey
	rekor      *rekor.Verifier
	now        func() time.Time

	// pqcEnabled gates post-quantum / hybrid signature verification (Task 151).
	// When false the verifier is classical-only: a presented PQC/hybrid signature
	// is cryptographically checked for reporting but never establishes trust.
	pqcEnabled bool
	// pqcPolicy selects how PQC/hybrid algorithms participate in trust once
	// enabled (classical-only, allow-hybrid, or require-pqc).
	pqcPolicy PQCPolicy
}

// Identity is an allowed keyless signer: an OIDC issuer (exact match when set)
// and a regular expression the certificate identity (SAN URI/email) must match.
type Identity struct {
	// Issuer is the OIDC issuer URL embedded in the Fulcio certificate (e.g.
	// "https://token.actions.githubusercontent.com"). Empty matches any issuer.
	Issuer string
	// SubjectPattern is an anchored regular expression the signer identity must
	// match (e.g. "^https://github\\.com/acme/.*"). Empty matches any subject.
	SubjectPattern string

	re *regexp.Regexp
}

// TrustedKey is an operator-configured public key for keyed verification.
type TrustedKey struct {
	// Name identifies the key for reporting (e.g. "release-signing-key").
	Name string
	// Public is the parsed public key (ECDSA, RSA, or Ed25519).
	Public crypto.PublicKey
}

// PQCOptions configures post-quantum / hybrid signature verification on a
// Verifier (Task 151). The zero value is classical-only (PQC disabled).
type PQCOptions struct {
	// Enabled turns on post-quantum / hybrid signature verification.
	Enabled bool
	// Policy selects how PQC/hybrid algorithms participate in trust. Empty
	// defaults to allow-hybrid once Enabled.
	Policy PQCPolicy
}

// NewVerifier constructs a Verifier from trust material, compiling identity
// patterns. An invalid SubjectPattern is a configuration error. The verifier is
// classical-only; use [NewVerifierWithPQC] to enable post-quantum / hybrid
// algorithms.
func NewVerifier(roots *x509.CertPool, identities []Identity, keys []TrustedKey, rekorKeys []crypto.PublicKey) (*Verifier, error) {
	return NewVerifierWithPQC(roots, identities, keys, rekorKeys, PQCOptions{})
}

// NewVerifierWithPQC constructs a Verifier that additionally verifies
// post-quantum (ML-DSA / SLH-DSA) and hybrid classical+PQC signatures per the
// supplied options.
func NewVerifierWithPQC(roots *x509.CertPool, identities []Identity, keys []TrustedKey, rekorKeys []crypto.PublicKey, pqc PQCOptions) (*Verifier, error) {
	compiled := make([]Identity, 0, len(identities))
	for i, id := range identities {
		if p := strings.TrimSpace(id.SubjectPattern); p != "" {
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("sigverify: identity[%d] subjectPattern %q is not a valid regular expression: %w", i, p, err)
			}
			id.re = re
		}
		compiled = append(compiled, id)
	}
	policy := pqc.Policy
	if pqc.Enabled && policy == "" {
		policy = PQCPolicyAllowHybrid
	}
	return &Verifier{
		roots:      roots,
		identities: compiled,
		keys:       keys,
		rekorKeys:  rekorKeys,
		rekor:      rekor.NewVerifier(rekorKeys),
		now:        time.Now,
		pqcEnabled: pqc.Enabled,
		pqcPolicy:  policy,
	}, nil
}

// sigCheck is the outcome of verifying a single signature or attestation.
type sigCheck struct {
	// CryptoValid reports that the signature verified against its public key.
	CryptoValid bool
	// Keyless reports that verification used a Fulcio certificate (vs a configured key).
	Keyless bool
	// ChainTrusted reports the signing certificate chained to a configured root.
	ChainTrusted bool
	// IdentityTrusted reports the signer identity matched a configured allowed identity.
	IdentityTrusted bool
	// RekorVerified reports a transparency-log Signed Entry Timestamp (SET) verified.
	RekorVerified bool
	// RekorInclusionVerified reports an RFC 6962 Merkle inclusion proof verified to
	// a trusted log root (a stronger claim than the SET alone).
	RekorInclusionVerified bool
	// Identity is the signer identity (SAN URI/email for keyless, key name for keyed).
	Identity string
	// Issuer is the keyless OIDC issuer, when present.
	Issuer string
	// Algorithm is the signature algorithm name (e.g. "ECDSA-P256", "ML-DSA-65").
	Algorithm string
	// AlgorithmClass is the quantum-resistance class of the algorithm.
	AlgorithmClass AlgorithmClass
	// PostQuantum reports the algorithm provides post-quantum protection (pure PQC
	// or hybrid).
	PostQuantum bool
	// PQCRejected reports a cryptographically-valid post-quantum/hybrid signature
	// that the PQC policy (or a disabled PQC feature flag) refused to trust.
	PQCRejected bool
	// Err describes a verification failure, for diagnostics.
	Err string
}

// Trusted reports whether the signature is both cryptographically valid and
// anchored to a trusted signer (chain + identity for keyless, a configured key
// for keyed). A post-quantum/hybrid signature that the PQC policy rejected is
// never trusted even when cryptographically valid.
func (c sigCheck) Trusted() bool {
	if !c.CryptoValid || c.PQCRejected {
		return false
	}
	if c.Keyless {
		return c.ChainTrusted && c.IdentityTrusted
	}
	return true // a keyed signature only verifies against a configured (trusted) key
}

// verifySignature verifies a cosign image (simple-signing) signature: it
// confirms the signature over the payload, that the payload pins the artifact
// digest, and resolves signer trust (keyless chain+identity or a configured key).
func (v *Verifier) verifySignature(sig SimpleSignature, digest string) sigCheck {
	var c sigCheck

	var payload simpleSigningPayload
	if err := json.Unmarshal(sig.Payload, &payload); err != nil {
		c.Err = "signature payload is not a cosign simple-signing document: " + err.Error()
		return c
	}
	if digest != "" && !payload.bindsDigest(digest) {
		c.Err = "signature does not bind the artifact manifest digest"
		return c
	}

	if sig.Cert != nil {
		return v.verifyKeyless(sig.Payload, sig.Signature, sig.Cert, sig.Chain, sig.RekorBundle)
	}
	return v.verifyKeyed(sig.Payload, sig.Signature, sig.RekorBundle)
}

// verifyAttestation verifies a DSSE attestation envelope, parses the in-toto
// statement, confirms it binds the artifact digest, and resolves signer trust.
// On success the parsed statement is returned for predicate inspection.
func (v *Verifier) verifyAttestation(att DSSEAttestation, digest string) (sigCheck, *Statement) {
	var c sigCheck
	if att.Envelope == nil || len(att.Envelope.Signatures) == 0 {
		c.Err = "attestation has no DSSE envelope/signatures"
		return c, nil
	}
	payload, err := att.Envelope.decodePayload()
	if err != nil {
		c.Err = "attestation payload is not valid base64: " + err.Error()
		return c, nil
	}
	statement, err := parseStatement(payload)
	if err != nil {
		c.Err = "attestation payload is not a valid in-toto statement: " + err.Error()
		return c, nil
	}
	if digest != "" && !statement.BindsDigest(digest) {
		c.Err = "attestation does not bind the artifact digest"
		return c, nil
	}

	// DSSE signs the pre-authentication encoding (PAE) of (payloadType, payload).
	pae := dssePAE(att.Envelope.PayloadType, payload)
	rawSig, err := base64.StdEncoding.DecodeString(att.Envelope.Signatures[0].Sig)
	if err != nil {
		c.Err = "attestation signature is not valid base64: " + err.Error()
		return c, nil
	}

	if att.Cert != nil {
		return v.verifyKeyless(pae, rawSig, att.Cert, att.Chain, att.RekorBundle), statement
	}
	return v.verifyKeyed(pae, rawSig, att.RekorBundle), statement
}

// VerifyAttestation verifies a single discovered DSSE attestation against the
// artifact content digest and projects the outcome onto the exported
// AttestationResult: cryptographic validity, signer trust (keyless chain +
// identity policy, or a configured key), and — for SLSA provenance — the bound
// source repository, commit, and builder identity. The parsed in-toto Statement
// is also returned for predicate inspection (nil when the payload was not a
// parseable in-toto statement).
//
// It is exported so sibling admission gates that consume the same Sigstore
// material but apply their own policy — notably the inbound build-provenance gate
// (internal/buildprov), which cross-checks the bound source commit against the
// package-to-commit association — reuse this package's verification core rather
// than duplicating the DSSE/PAE/Fulcio/SLSA logic.
func (v *Verifier) VerifyAttestation(att DSSEAttestation, digest string) (AttestationResult, *Statement) {
	check, statement := v.verifyAttestation(att, digest)
	res := AttestationResult{SignatureResult: toSignatureResult(check)}
	if statement != nil {
		res.PredicateType = statement.PredicateType
		res.SLSAProvenance = statement.IsSLSAProvenance()
		if src, ok := statement.SourceRef(); ok {
			res.RepositoryURL = src.RepositoryURL
			res.CommitSHA = src.CommitSHA
			res.BuilderID = src.BuilderID
		}
	}
	return res, statement
}

// verifyKeyless verifies a signature against a Fulcio certificate, then resolves
// chain trust, identity policy, and (optionally) a Rekor inclusion proof.
func (v *Verifier) verifyKeyless(message, sig []byte, cert *x509.Certificate, chain []*x509.Certificate, bundle *rekorBundle) sigCheck {
	c := sigCheck{Keyless: true}
	kc := v.verifyWithKey(cert.PublicKey, message, sig)
	c.setAlgorithm(kc.Algorithm)
	if !kc.CryptoValid {
		c.Err = "signature does not verify against the signing certificate"
		return c
	}
	c.CryptoValid = true
	c.Identity = certIdentity(cert)
	c.Issuer = certIssuer(cert)
	c.ChainTrusted = v.chainTrusted(cert, chain)
	c.IdentityTrusted = v.identityAllowed(c.Identity, c.Issuer)
	c.RekorVerified, c.RekorInclusionVerified = v.verifyRekor(bundle)
	switch {
	case kc.Reason != "":
		// Cryptographically valid, but the PQC policy refused to trust it.
		c.PQCRejected = true
		c.Err = kc.Reason
	case !c.ChainTrusted:
		c.Err = "signing certificate does not chain to a configured trust root"
	case !c.IdentityTrusted:
		c.Err = fmt.Sprintf("signer identity %q (issuer %q) is not in the allowed-identity policy", c.Identity, c.Issuer)
	}
	return c
}

// verifyKeyed verifies a signature against each configured public key, accepting
// the first that both validates and is permitted by the PQC policy. A key that
// verifies cryptographically but is refused by the PQC policy is remembered so a
// clear reason is reported when no acceptable key is found.
func (v *Verifier) verifyKeyed(message, sig []byte, bundle *rekorBundle) sigCheck {
	var c sigCheck
	var rejected *sigCheck
	for _, k := range v.keys {
		kc := v.verifyWithKey(k.Public, message, sig)
		if !kc.CryptoValid {
			continue
		}
		if kc.Reason != "" {
			// Cryptographically valid, but refused by the PQC policy. Keep scanning
			// in case another configured key is acceptable.
			rc := sigCheck{CryptoValid: true, Identity: k.Name, PQCRejected: true, Err: kc.Reason}
			rc.setAlgorithm(kc.Algorithm)
			rejected = &rc
			continue
		}
		c.CryptoValid = true
		c.Identity = k.Name
		c.setAlgorithm(kc.Algorithm)
		c.RekorVerified, c.RekorInclusionVerified = v.verifyRekor(bundle)
		return c
	}
	if rejected != nil {
		return *rejected
	}
	if len(v.keys) == 0 {
		c.Err = "signature carries no certificate and no trusted keys are configured"
	} else {
		c.Err = "signature does not verify against any configured trusted key"
	}
	return c
}

// keyCheck is the outcome of verifying a message against one public key,
// including the algorithm and a PQC-policy rejection reason.
type keyCheck struct {
	// CryptoValid reports the signature verified against the key.
	CryptoValid bool
	// Algorithm is the classified signature algorithm.
	Algorithm Algorithm
	// Reason is non-empty when the signature verified cryptographically but the
	// PQC feature flag / policy refused to trust the algorithm.
	Reason string
}

// verifyWithKey verifies a signature against a single public key and classifies
// the algorithm. Post-quantum / hybrid signatures are only verified when the
// provider is wired; the PQC feature flag and policy are then applied: when PQC
// is disabled, or the policy is classical-only, a cryptographically-valid
// PQC/hybrid signature is reported (CryptoValid=true) but carries a rejection
// Reason so it never establishes trust.
func (v *Verifier) verifyWithKey(pub crypto.PublicKey, message, sig []byte) keyCheck {
	alg, known := classifyPublicKey(pub)
	if !known {
		return keyCheck{}
	}
	if !verifyRawSignature(pub, message, sig) {
		return keyCheck{Algorithm: alg}
	}
	kc := keyCheck{CryptoValid: true, Algorithm: alg}
	if alg.PostQuantum() {
		switch {
		case !v.pqcEnabled:
			kc.Reason = fmt.Sprintf("a valid %s (%s) signature was presented but post-quantum verification is disabled (set sigverify.pqc.enabled)", alg.Name, alg.Class)
		case v.pqcPolicy == PQCPolicyClassicalOnly:
			kc.Reason = fmt.Sprintf("a valid %s (%s) signature was presented but the PQC policy is classical-only", alg.Name, alg.Class)
		}
	}
	return kc
}

// setAlgorithm records the classified algorithm onto the check.
func (c *sigCheck) setAlgorithm(alg Algorithm) {
	c.Algorithm = alg.Name
	c.AlgorithmClass = alg.Class
	c.PostQuantum = alg.PostQuantum()
}

// chainTrusted reports whether the leaf certificate chains to a configured root
// pool, using the supplied intermediates and the verifier's clock.
func (v *Verifier) chainTrusted(leaf *x509.Certificate, chain []*x509.Certificate) bool {
	if v.roots == nil {
		return false
	}
	intermediates := x509.NewCertPool()
	for _, c := range chain {
		if c != nil && !c.Equal(leaf) {
			intermediates.AddCert(c)
		}
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: intermediates,
		CurrentTime:   v.now(),
		// Fulcio leaf certs carry ExtKeyUsageCodeSigning; accept any so a valid
		// chain is not rejected over EKU pedantry (identity policy is the real gate).
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err == nil
}

// identityAllowed reports whether the signer identity and issuer satisfy the
// configured allowed-identity policy. An empty policy accepts any identity that
// chained to a trusted root.
func (v *Verifier) identityAllowed(identity, issuer string) bool {
	if len(v.identities) == 0 {
		return true
	}
	for _, id := range v.identities {
		if id.Issuer != "" && !strings.EqualFold(id.Issuer, issuer) {
			continue
		}
		if id.re != nil {
			if !id.re.MatchString(identity) {
				continue
			}
		}
		return true
	}
	return false
}

// verifyRekor verifies a cosign/Rekor bundle via the shared internal/rekor
// verifier: the Signed Entry Timestamp (setVerified) proves a trusted log key
// witnessed the entry, and — when the bundle carries an inclusion proof — the
// RFC 6962 Merkle audit path (inclusionVerified) proves membership up to that
// root. Both are false when no bundle/keys are present or verification fails.
func (v *Verifier) verifyRekor(bundle *rekorBundle) (setVerified, inclusionVerified bool) {
	if bundle == nil || v.rekor == nil {
		return false, false
	}
	res := v.rekor.VerifyEntry(bundle.toLogEntry())
	return res.SETVerified, res.InclusionVerified
}

// Fulcio OIDC-issuer certificate extension OIDs (the legacy plain-string form
// and the current DER-encoded form). See the Fulcio certificate specification.
var (
	oidFulcioIssuerV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidFulcioIssuerV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
)

// certIdentity returns the signer identity from a Fulcio certificate's Subject
// Alternative Name: a URI (workflow identity) or, failing that, an email.
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
// extension, trying the current DER-encoded OID then the legacy plain-string OID.
func certIssuer(cert *x509.Certificate) string {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidFulcioIssuerV2) {
			var s string
			if _, err := asn1.Unmarshal(ext.Value, &s); err == nil && s != "" {
				return s
			}
			// Some issuers DER-encode as UTF8String; fall back to raw bytes.
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

// dssePAE produces the DSSE pre-authentication encoding bound by the signature:
// "DSSEv1 <len(type)> <type> <len(payload)> <payload>".
func dssePAE(payloadType string, payload []byte) []byte {
	const prefix = "DSSEv1"
	out := make([]byte, 0, len(prefix)+len(payloadType)+len(payload)+24)
	out = append(out, prefix...)
	out = append(out, ' ')
	out = append(out, strconv.Itoa(len(payloadType))...)
	out = append(out, ' ')
	out = append(out, payloadType...)
	out = append(out, ' ')
	out = append(out, strconv.Itoa(len(payload))...)
	out = append(out, ' ')
	out = append(out, payload...)
	return out
}

// verifyRawSignature verifies a signature over a message, dispatching on the
// public key type. ECDSA and RSA sign the SHA-256 digest; Ed25519 signs the
// message directly. ECDSA signatures are expected in ASN.1 DER form (cosign's).
func verifyRawSignature(pub crypto.PublicKey, message, sig []byte) bool {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(message)
		return ecdsa.VerifyASN1(key, digest[:], sig)
	case *rsa.PublicKey:
		digest := sha256.Sum256(message)
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig) == nil
	case ed25519.PublicKey:
		return ed25519.Verify(key, message, sig)
	case sign.PublicKey:
		// Post-quantum (ML-DSA / SLH-DSA) and hybrid classical+PQC composite
		// signatures (Task 151). The circl scheme hashes the message internally per
		// its specification, so the raw message is passed (not a pre-hash). A nil
		// options is the pure/no-context variant used by cosign PQC signing.
		return pqcVerify(key, message, sig)
	default:
		return false
	}
}

// pqcVerify verifies a post-quantum / hybrid signature via the key's circl
// scheme. scheme.Verify panics on a wrong-type key or unsupported context; the
// key supplies its own scheme and no context is used, so neither occurs, but the
// recover is defense-in-depth against a malformed signature blob.
func pqcVerify(pub sign.PublicKey, message, sig []byte) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	scheme := pub.Scheme()
	if scheme == nil {
		return false
	}
	return scheme.Verify(pub, message, sig, nil)
}
