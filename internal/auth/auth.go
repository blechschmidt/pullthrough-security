package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
)

// ErrUnauthenticated indicates the request carried no valid credentials. The
// gateway maps it to 401. ErrForbidden indicates a valid identity that is not
// permitted; the gateway maps it to 403.
var (
	ErrUnauthenticated = errors.New("auth: unauthenticated")
	ErrForbidden       = errors.New("auth: forbidden")
)

// Authenticator validates client credentials on an inbound request and returns
// the resulting Principal. Implementations return ErrUnauthenticated when no
// usable credential is present or a presented credential is invalid.
type Authenticator interface {
	Authenticate(ctx context.Context, r *http.Request) (*Principal, error)
}

// Chain tries each authenticator in order, returning the first principal
// produced. An authenticator that returns ErrUnauthenticated is treated as
// "not my credential" and the chain continues; any other error is returned
// immediately (it indicates a present-but-invalid credential, e.g. an expired
// JWT, which should not silently fall through). If every authenticator declines,
// Chain returns ErrUnauthenticated.
type Chain []Authenticator

// Authenticate implements Authenticator.
func (c Chain) Authenticate(ctx context.Context, r *http.Request) (*Principal, error) {
	for _, a := range c {
		p, err := a.Authenticate(ctx, r)
		if err == nil {
			return p, nil
		}
		if !errors.Is(err, ErrUnauthenticated) {
			return nil, err
		}
	}
	return nil, ErrUnauthenticated
}

// bearerToken extracts a bearer-style token from the Authorization header,
// accepting both "Bearer <t>" and "token <t>" (the latter used by some
// registry clients). It returns "" when no such token is present.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	for _, prefix := range []string{"Bearer ", "bearer ", "token ", "Token "} {
		if strings.HasPrefix(h, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(h, prefix))
		}
	}
	return ""
}

// candidateTokens returns every place a static API token might appear in a
// request, in priority order. Package-manager clients present credentials
// inconsistently — npm uses Bearer, pip/Go use HTTP Basic, cargo sends a raw
// Authorization value — so the token authenticator probes all of them.
func candidateTokens(r *http.Request) []string {
	var out []string
	add := func(s string) {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}

	// Authorization: Bearer/token <t>
	add(bearerToken(r))

	// Authorization: Basic <base64(user:pass)> — token may be the password or,
	// for tools that put it in the username field, the username.
	if h := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(h), "basic ") {
		if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h[len("basic "):])); err == nil {
			if user, pass, ok := strings.Cut(string(raw), ":"); ok {
				add(pass)
				add(user)
			}
		}
	}

	// Dedicated headers some clients/CI systems use.
	add(r.Header.Get("X-Api-Token"))
	add(r.Header.Get("X-Auth-Token"))

	return out
}

// CandidateTokens returns every place a bearer-style credential might appear in
// a request, in priority order: the Authorization header as "Bearer"/"token",
// HTTP Basic (the password, then the username), and the X-Api-Token /
// X-Auth-Token headers. It is the one definition of where a package manager may
// have put a token, shared by every authenticator that accepts one — the static
// token authenticator here, and the personal-link authenticator (Task 177).
func CandidateTokens(r *http.Request) []string { return candidateTokens(r) }

// looksLikeJWT reports whether a token has the three-segment JWS compact shape.
// It lets the token authenticator skip JWTs (handled by the OIDC authenticator)
// and vice versa.
func looksLikeJWT(tok string) bool {
	return strings.Count(tok, ".") == 2 && !strings.ContainsAny(tok, " ")
}

// withPrincipalAndError is a small helper to wrap an unauthenticated outcome.
func unauthenticated(ctx context.Context) (*Principal, error) {
	_ = ctx
	return nil, ErrUnauthenticated
}
