package userlinks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// errBadCookie is returned for a cookie that is malformed, was not signed by
// this proxy, was signed for another purpose, or has expired. It is deliberately
// one error: the caller treats every case as "not signed in".
var errBadCookie = errors.New("userlinks: invalid cookie")

// maxCookieValue bounds the size of a cookie value the codec will look at. A
// browser sends at most about 4 KiB per cookie; anything larger is not one of
// ours.
const maxCookieValue = 8 << 10

// sessionClaims is the content of the sign-in session cookie: who the user is,
// as established by the identity provider when they signed in, and for how long
// that is believed. The session is stateless — any replica can verify it — and
// short-lived: it only serves the self-service page.
type sessionClaims struct {
	Identity
	IssuedAt  int64 `json:"iat"`
	ExpiresAt int64 `json:"exp"`
}

// flowClaims is the content of the short-lived cookie that carries an OIDC
// sign-in across the redirect to the identity provider and back: the CSRF state,
// the PKCE verifier and the nonce the ID token must repeat.
type flowClaims struct {
	State     string `json:"state"`
	Verifier  string `json:"verifier"`
	Nonce     string `json:"nonce"`
	ExpiresAt int64  `json:"exp"`
}

// cookieCodec signs and verifies cookie values: "base64url(json).base64url(mac)"
// with HMAC-SHA256.
//
// Each kind of cookie is signed with its own key, derived from the configured
// one. A cookie of one kind therefore cannot be presented as another — a
// sign-in flow cookie, which anyone can obtain by starting a sign-in, is not a
// session however its content is arranged.
type cookieCodec struct {
	sessionKey []byte
	flowKey    []byte
	now        func() time.Time
}

func newCookieCodec(key []byte, now func() time.Time) *cookieCodec {
	derive := func(purpose string) []byte {
		m := hmac.New(sha256.New, key)
		m.Write([]byte("pullthrough/userlinks/" + purpose))
		return m.Sum(nil)
	}
	if now == nil {
		now = time.Now
	}
	return &cookieCodec{sessionKey: derive("session"), flowKey: derive("flow"), now: now}
}

func sign(key []byte, body string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(body))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func encodeSigned(key []byte, v any) (string, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return "", errorf("encoding a cookie: %w", err)
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	return body + "." + sign(key, body), nil
}

func decodeSigned(key []byte, value string, v any) error {
	if len(value) > maxCookieValue {
		return errBadCookie
	}
	body, mac, ok := strings.Cut(value, ".")
	if !ok || !hmac.Equal([]byte(mac), []byte(sign(key, body))) {
		return errBadCookie
	}
	payload, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return errBadCookie
	}
	if err := json.Unmarshal(payload, v); err != nil {
		return errBadCookie
	}
	return nil
}

// encodeSession signs a session for id that lasts ttl.
func (c *cookieCodec) encodeSession(id Identity, ttl time.Duration) (string, error) {
	now := c.now()
	return encodeSigned(c.sessionKey, sessionClaims{
		Identity:  id,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
	})
}

// decodeSession verifies a session cookie and returns who it is for and when it
// was issued.
func (c *cookieCodec) decodeSession(value string) (Identity, time.Time, error) {
	var claims sessionClaims
	if err := decodeSigned(c.sessionKey, value, &claims); err != nil {
		return Identity{}, time.Time{}, err
	}
	if claims.ExpiresAt == 0 || !c.now().Before(time.Unix(claims.ExpiresAt, 0)) {
		return Identity{}, time.Time{}, errBadCookie
	}
	id, err := claims.Identity.normalize()
	if err != nil {
		return Identity{}, time.Time{}, errBadCookie
	}
	return id, time.Unix(claims.IssuedAt, 0), nil
}

// encodeFlow signs a sign-in flow cookie that lasts ttl.
func (c *cookieCodec) encodeFlow(fc flowClaims, ttl time.Duration) (string, error) {
	fc.ExpiresAt = c.now().Add(ttl).Unix()
	return encodeSigned(c.flowKey, fc)
}

// decodeFlow verifies a sign-in flow cookie.
func (c *cookieCodec) decodeFlow(value string) (flowClaims, error) {
	var claims flowClaims
	if err := decodeSigned(c.flowKey, value, &claims); err != nil {
		return flowClaims{}, err
	}
	if claims.ExpiresAt == 0 || !c.now().Before(time.Unix(claims.ExpiresAt, 0)) {
		return flowClaims{}, errBadCookie
	}
	if claims.State == "" || claims.Verifier == "" || claims.Nonce == "" {
		return flowClaims{}, errBadCookie
	}
	return claims, nil
}
