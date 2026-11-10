package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// signRS256 builds a signed compact JWS from the given claims using key.
func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	if kid != "" {
		header["kid"] = kid
	}
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signingInput := enc(header) + "." + enc(claims)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// jwksFor builds a JWK Set document containing the RSA public key.
func jwksFor(t *testing.T, key *rsa.PrivateKey, kid string) []byte {
	t.Helper()
	pub := key.Public().(*rsa.PublicKey)
	doc := map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"kid": kid,
			"alg": "RS256",
			"use": "sig",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return b
}

func newOIDC(t *testing.T, key *rsa.PrivateKey, kid string) *OIDCAuthenticator {
	t.Helper()
	a, err := NewOIDCAuthenticator(OIDCOptions{
		Issuer:     "https://issuer.example.com",
		Audience:   "pullthrough",
		StaticJWKS: jwksFor(t, key, kid),
		TeamClaim:  "team",
		RolesClaim: "roles",
		Now:        func() time.Time { return time.Unix(1_700_000_000, 0) },
	})
	if err != nil {
		t.Fatalf("oidc: %v", err)
	}
	return a
}

func bearerReq(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/v1/npm/x", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

func TestOIDCValidToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	a := newOIDC(t, key, "key-1")
	tok := signRS256(t, key, "key-1", map[string]any{
		"iss":   "https://issuer.example.com",
		"aud":   "pullthrough",
		"sub":   "user-42",
		"team":  "team-a",
		"roles": []string{"npm-reader", "pip-reader"},
		"exp":   1_700_000_000 + 3600,
	})
	p, err := a.Authenticate(context.Background(), bearerReq(tok))
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if p.Subject != "user-42" || p.Team != "team-a" {
		t.Fatalf("bad principal: %+v", p)
	}
	if !p.HasRole("npm-reader") || !p.HasRole("pip-reader") {
		t.Fatalf("roles not mapped: %+v", p.Roles)
	}
	if p.Method != "oidc" {
		t.Fatalf("method should be oidc")
	}
}

func TestOIDCRejectsExpired(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	a := newOIDC(t, key, "key-1")
	tok := signRS256(t, key, "key-1", map[string]any{
		"iss": "https://issuer.example.com",
		"aud": "pullthrough",
		"sub": "user-42",
		"exp": 1_700_000_000 - 3600, // expired
	})
	if _, err := a.Authenticate(context.Background(), bearerReq(tok)); err == nil {
		t.Fatalf("expired token must be rejected")
	}
}

func TestOIDCRejectsWrongIssuer(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	a := newOIDC(t, key, "key-1")
	tok := signRS256(t, key, "key-1", map[string]any{
		"iss": "https://evil.example.com",
		"aud": "pullthrough",
		"sub": "user-42",
		"exp": 1_700_000_000 + 3600,
	})
	if _, err := a.Authenticate(context.Background(), bearerReq(tok)); err == nil {
		t.Fatalf("wrong issuer must be rejected")
	}
}

func TestOIDCRejectsWrongAudience(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	a := newOIDC(t, key, "key-1")
	tok := signRS256(t, key, "key-1", map[string]any{
		"iss": "https://issuer.example.com",
		"aud": "some-other-service",
		"sub": "user-42",
		"exp": 1_700_000_000 + 3600,
	})
	if _, err := a.Authenticate(context.Background(), bearerReq(tok)); err == nil {
		t.Fatalf("wrong audience must be rejected")
	}
}

func TestOIDCRejectsTamperedSignature(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	a := newOIDC(t, key, "key-1")
	tok := signRS256(t, key, "key-1", map[string]any{
		"iss": "https://issuer.example.com",
		"aud": "pullthrough",
		"sub": "user-42",
		"exp": 1_700_000_000 + 3600,
	})
	// Corrupt the first char of the signature segment. The first base64 char
	// carries the top six (fully significant) bits of the signature's first
	// byte, so flipping it always changes the decoded signature. (Mutating the
	// *last* char is unreliable: for a 256-byte RSA signature the final RawURL
	// char holds non-significant trailing bits that the decoder ignores, so the
	// decoded bytes — and thus the verification result — can be unchanged.)
	lastDot := strings.LastIndexByte(tok, '.')
	if lastDot < 0 || lastDot+1 >= len(tok) {
		t.Fatalf("unexpected token shape: %q", tok)
	}
	sigStart := lastDot + 1
	flipped := byte('A')
	if tok[sigStart] == 'A' {
		flipped = 'B'
	}
	tampered := tok[:sigStart] + string(flipped) + tok[sigStart+1:]
	if _, err := a.Authenticate(context.Background(), bearerReq(tampered)); err == nil {
		t.Fatalf("tampered signature must be rejected")
	}
}

func TestOIDCRejectsWrongKey(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	a := newOIDC(t, key, "key-1")
	// Token signed with a key the verifier does not know.
	tok := signRS256(t, other, "key-1", map[string]any{
		"iss": "https://issuer.example.com",
		"aud": "pullthrough",
		"sub": "user-42",
		"exp": 1_700_000_000 + 3600,
	})
	if _, err := a.Authenticate(context.Background(), bearerReq(tok)); err == nil {
		t.Fatalf("token signed by an unknown key must be rejected")
	}
}

func TestOIDCRejectsAlgNone(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	a := newOIDC(t, key, "key-1")
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	// alg=none token with no signature — the classic JWT downgrade attack.
	header := enc(map[string]any{"alg": "none", "typ": "JWT"})
	payload := enc(map[string]any{
		"iss": "https://issuer.example.com", "aud": "pullthrough",
		"sub": "user-42", "exp": 1_700_000_000 + 3600,
	})
	tok := header + "." + payload + "."
	if _, err := a.Authenticate(context.Background(), bearerReq(tok)); err == nil {
		t.Fatalf("alg=none must be rejected")
	}
}

func TestOIDCRemoteJWKS(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := jwksFor(t, key, "remote-1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	}))
	defer srv.Close()

	a, err := NewOIDCAuthenticator(OIDCOptions{
		Issuer:   "https://issuer.example.com",
		Audience: "pullthrough",
		JWKSURL:  srv.URL,
		Now:      func() time.Time { return time.Unix(1_700_000_000, 0) },
	})
	if err != nil {
		t.Fatalf("oidc: %v", err)
	}
	tok := signRS256(t, key, "remote-1", map[string]any{
		"iss": "https://issuer.example.com", "aud": "pullthrough",
		"sub": "u", "exp": 1_700_000_000 + 3600,
	})
	if _, err := a.Authenticate(context.Background(), bearerReq(tok)); err != nil {
		t.Fatalf("remote jwks auth: %v", err)
	}
}

func TestChainTokenThenOIDC(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	oidc := newOIDC(t, key, "key-1")
	ta, _ := NewTokenAuthenticator([]TokenEntry{{Name: "bot", Secret: "static-token-abcdefghij"}})
	chain := Chain{ta, oidc}

	// Static token resolves via the token authenticator.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer static-token-abcdefghij")
	if p, err := chain.Authenticate(context.Background(), r); err != nil || p.Subject != "bot" {
		t.Fatalf("token via chain: %v %+v", err, p)
	}

	// JWT resolves via OIDC.
	tok := signRS256(t, key, "key-1", map[string]any{
		"iss": "https://issuer.example.com", "aud": "pullthrough",
		"sub": "jwt-user", "exp": 1_700_000_000 + 3600,
	})
	if p, err := chain.Authenticate(context.Background(), bearerReq(tok)); err != nil || p.Subject != "jwt-user" {
		t.Fatalf("jwt via chain: %v %+v", err, p)
	}
}
