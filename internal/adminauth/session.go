package adminauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// errBadSession indicates a cookie that is malformed, tampered with, or expired.
// It is deliberately opaque so the caller treats it as "no session" without
// leaking why.
var errBadSession = errors.New("adminauth: invalid session")

// sessionClaims is the payload of an admin session cookie. After the browser
// completes the OIDC authorization-code flow, the validated identity is captured
// here and signed so subsequent requests need not re-validate the ID token on
// every call (the cookie itself carries an independent expiry).
type sessionClaims struct {
	Subject   string   `json:"sub"`
	Roles     []string `json:"roles"`
	Issuer    string   `json:"iss,omitempty"`
	Tenant    string   `json:"tnt,omitempty"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
}

// flowClaims is the payload of the short-lived cookie that carries OIDC
// authorization-code-flow state across the redirect to the IdP and back: the
// CSRF state token, the PKCE verifier, the OIDC nonce, and where to send the
// browser afterwards.
type flowClaims struct {
	State     string `json:"state"`
	Verifier  string `json:"verifier"`
	Nonce     string `json:"nonce"`
	ReturnTo  string `json:"returnTo,omitempty"`
	ExpiresAt int64  `json:"exp"`
}

// sessionCodec signs and verifies cookie payloads with HMAC-SHA256 under a
// secret key. The signed value is "base64url(json).base64url(mac)"; verification
// is constant-time and rejects any expired or altered payload.
type sessionCodec struct {
	key []byte
	now func() time.Time
}

func newSessionCodec(key []byte, now func() time.Time) *sessionCodec {
	if now == nil {
		now = time.Now
	}
	return &sessionCodec{key: key, now: now}
}

// encode marshals v to JSON and returns the signed cookie value.
func (c *sessionCodec) encode(v any) (string, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("adminauth: encoding cookie: %w", err)
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	mac := c.sign([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(mac), nil
}

// decode verifies the signature of a signed cookie value and unmarshals the
// payload into v. It does not interpret expiry; callers check the typed exp
// field so they can map "expired" onto a clean re-login.
func (c *sessionCodec) decode(value string, v any) error {
	body, sig, ok := strings.Cut(value, ".")
	if !ok {
		return errBadSession
	}
	gotMac, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return errBadSession
	}
	wantMac := c.sign([]byte(body))
	if !hmac.Equal(gotMac, wantMac) {
		return errBadSession
	}
	payload, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return errBadSession
	}
	if err := json.Unmarshal(payload, v); err != nil {
		return errBadSession
	}
	return nil
}

// sign computes the HMAC-SHA256 of body under the codec key.
func (c *sessionCodec) sign(body []byte) []byte {
	m := hmac.New(sha256.New, c.key)
	m.Write(body)
	return m.Sum(nil)
}

// decodeSession verifies and decodes a session cookie, enforcing its expiry. It
// returns an Identity on success.
func (c *sessionCodec) decodeSession(value string) (*Identity, error) {
	var claims sessionClaims
	if err := c.decode(value, &claims); err != nil {
		return nil, err
	}
	if claims.ExpiresAt == 0 || c.now().After(time.Unix(claims.ExpiresAt, 0)) {
		return nil, errBadSession
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return nil, errBadSession
	}
	roles := make([]Role, 0, len(claims.Roles))
	for _, r := range claims.Roles {
		if cr, ok := ParseRole(r); ok {
			roles = append(roles, cr)
		}
	}
	return newIdentity(claims.Subject, "oidc-session", claims.Issuer, claims.Tenant, roles), nil
}

// encodeSession signs a session cookie for the given identity with the supplied
// TTL.
func (c *sessionCodec) encodeSession(id *Identity, ttl time.Duration) (string, error) {
	now := c.now()
	return c.encode(sessionClaims{
		Subject:   id.Subject,
		Roles:     id.RoleStrings(),
		Issuer:    id.Issuer,
		Tenant:    id.Tenant,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
	})
}

// decodeFlow verifies and decodes a login-flow cookie, enforcing its (short)
// expiry.
func (c *sessionCodec) decodeFlow(value string) (*flowClaims, error) {
	var claims flowClaims
	if err := c.decode(value, &claims); err != nil {
		return nil, err
	}
	if claims.ExpiresAt == 0 || c.now().After(time.Unix(claims.ExpiresAt, 0)) {
		return nil, errBadSession
	}
	return &claims, nil
}

// encodeFlow signs a login-flow cookie with the supplied TTL.
func (c *sessionCodec) encodeFlow(fc flowClaims, ttl time.Duration) (string, error) {
	fc.ExpiresAt = c.now().Add(ttl).Unix()
	return c.encode(fc)
}
