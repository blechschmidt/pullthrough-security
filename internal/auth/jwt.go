package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// jwtHeader is the JOSE header of a compact JWS.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// jwtClaims holds the registered claims this package validates, plus the raw
// claim set for extracting deployment-specific subject/team/role claims.
type jwtClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  audience `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	NotBefore int64    `json:"nbf"`
	IssuedAt  int64    `json:"iat"`
	raw       map[string]any
}

// audience handles the "aud" claim which may be a string or an array of
// strings per RFC 7519.
type audience []string

func (a *audience) UnmarshalJSON(data []byte) error {
	data = []byte(strings.TrimSpace(string(data)))
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if data[0] == '[' {
		var arr []string
		if err := json.Unmarshal(data, &arr); err != nil {
			return err
		}
		*a = arr
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*a = []string{s}
	return nil
}

func (a audience) contains(want string) bool {
	for _, v := range a {
		if v == want {
			return true
		}
	}
	return false
}

// verifyParams configures token validation beyond the signature.
type verifyParams struct {
	issuer   string
	audience string
	now      time.Time
	leeway   time.Duration
}

// parseAndVerifyJWT parses a compact JWS, verifies its signature against keys
// and validates the registered claims (exp/nbf/iss/aud) per params. It returns
// the validated claims. All failure paths return an error and a nil claim set —
// callers must never trust an unverified token.
func parseAndVerifyJWT(token string, keys *keySet, params verifyParams) (*jwtClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("auth: malformed JWT (want 3 segments)")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("auth: decoding JWT header: %w", err)
	}
	var hdr jwtHeader
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return nil, fmt.Errorf("auth: parsing JWT header: %w", err)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("auth: decoding JWT payload: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("auth: decoding JWT signature: %w", err)
	}

	// The signing input is the ASCII "header.payload" exactly as transmitted.
	signingInput := []byte(parts[0] + "." + parts[1])
	if err := verifySignature(hdr, signingInput, sig, keys); err != nil {
		return nil, err
	}

	var claims jwtClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("auth: parsing JWT claims: %w", err)
	}
	if err := json.Unmarshal(payloadBytes, &claims.raw); err != nil {
		return nil, fmt.Errorf("auth: parsing JWT claims: %w", err)
	}
	if err := validateClaims(&claims, params); err != nil {
		return nil, err
	}
	return &claims, nil
}

// validateClaims enforces temporal and issuer/audience constraints.
func validateClaims(c *jwtClaims, p verifyParams) error {
	now := p.now
	if now.IsZero() {
		now = time.Now()
	}
	leeway := p.leeway
	if c.ExpiresAt == 0 {
		return errors.New("auth: JWT has no exp claim")
	}
	exp := time.Unix(c.ExpiresAt, 0)
	if now.After(exp.Add(leeway)) {
		return fmt.Errorf("%w: token expired", ErrUnauthenticated)
	}
	if c.NotBefore != 0 {
		nbf := time.Unix(c.NotBefore, 0)
		if now.Add(leeway).Before(nbf) {
			return fmt.Errorf("%w: token not yet valid", ErrUnauthenticated)
		}
	}
	if p.issuer != "" && c.Issuer != p.issuer {
		return fmt.Errorf("%w: issuer %q not accepted", ErrForbidden, c.Issuer)
	}
	if p.audience != "" && !c.Audience.contains(p.audience) {
		return fmt.Errorf("%w: audience does not include %q", ErrForbidden, p.audience)
	}
	return nil
}

// verifySignature dispatches on the JOSE alg and verifies sig over signingInput
// using a matching key from the set. Only asymmetric algorithms are supported;
// "none" and HMAC algorithms are explicitly rejected to avoid algorithm-
// confusion attacks where an attacker downgrades to a symmetric/none alg.
func verifySignature(hdr jwtHeader, signingInput, sig []byte, keys *keySet) error {
	alg := hdr.Alg
	hashFor := func() (crypto.Hash, []byte) {
		switch alg {
		case "RS256", "ES256":
			h := sha256.Sum256(signingInput)
			return crypto.SHA256, h[:]
		case "RS384", "ES384":
			h := sha512.Sum384(signingInput)
			return crypto.SHA384, h[:]
		case "RS512", "ES512":
			h := sha512.Sum512(signingInput)
			return crypto.SHA512, h[:]
		}
		return 0, nil
	}

	switch alg {
	case "RS256", "RS384", "RS512":
		hash, digest := hashFor()
		var lastErr error
		for _, k := range keys.candidates(hdr.Kid, "RSA") {
			rsaKey, ok := k.(*rsa.PublicKey)
			if !ok {
				continue
			}
			if err := rsa.VerifyPKCS1v15(rsaKey, hash, digest, sig); err == nil {
				return nil
			} else {
				lastErr = err
			}
		}
		return signatureFailure(lastErr)

	case "ES256", "ES384", "ES512":
		hash, digest := hashFor()
		_ = hash
		var lastErr error
		for _, k := range keys.candidates(hdr.Kid, "EC") {
			ecKey, ok := k.(*ecdsa.PublicKey)
			if !ok {
				continue
			}
			// ECDSA JWS signatures are the raw concatenation r||s, each padded to
			// the curve's byte size.
			n := (ecKey.Curve.Params().BitSize + 7) / 8
			if len(sig) != 2*n {
				lastErr = fmt.Errorf("auth: bad ECDSA signature length")
				continue
			}
			r := new(big.Int).SetBytes(sig[:n])
			s := new(big.Int).SetBytes(sig[n:])
			if ecdsa.Verify(ecKey, digest, r, s) {
				return nil
			}
			lastErr = errors.New("auth: ECDSA verification failed")
		}
		return signatureFailure(lastErr)

	case "", "none":
		return errors.New("auth: unsigned (alg=none) tokens are rejected")
	case "HS256", "HS384", "HS512":
		return errors.New("auth: HMAC-signed tokens are not accepted (asymmetric only)")
	default:
		return fmt.Errorf("auth: unsupported JWT alg %q", alg)
	}
}

func signatureFailure(last error) error {
	if last == nil {
		return fmt.Errorf("%w: no key matched the token's key id", ErrUnauthenticated)
	}
	return fmt.Errorf("%w: signature verification failed", ErrUnauthenticated)
}
