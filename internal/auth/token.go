package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// TokenEntry declares one static API token and the identity it authenticates.
// Exactly one of Secret (the plaintext token) or Hash ("sha256:<hex>") must be
// set. Plaintext secrets are hashed in memory at construction and never
// retained, so a heap dump does not reveal the live token.
type TokenEntry struct {
	// Name is the principal's subject (a human-meaningful token label).
	Name string
	// Team binds the token to a tenant.
	Team string
	// Roles are the role names granted to the token holder.
	Roles []string
	// Secret is the plaintext token. Mutually exclusive with Hash.
	Secret string
	// Hash is a precomputed "sha256:<hex>" digest of the token, so the plaintext
	// need not appear in configuration at all. Mutually exclusive with Secret.
	Hash string
}

// TokenAuthenticator authenticates static API tokens. Tokens are matched by the
// SHA-256 digest of the presented secret against a precomputed table, so the
// plaintext is never stored and the lookup does not branch on secret contents.
// SHA-256 (rather than a slow password hash) is appropriate here because API
// tokens are high-entropy random strings, not user-chosen passwords.
type TokenAuthenticator struct {
	byHash map[string]*Principal
}

// NewTokenAuthenticator builds the authenticator from the given entries. Tokens
// must be at least minTokenLen bytes to ensure adequate entropy.
func NewTokenAuthenticator(entries []TokenEntry) (*TokenAuthenticator, error) {
	const minTokenLen = 16
	byHash := make(map[string]*Principal, len(entries))
	for i, e := range entries {
		name := strings.TrimSpace(e.Name)
		if name == "" {
			return nil, fmt.Errorf("auth: token %d has empty name", i)
		}
		if (e.Secret == "") == (e.Hash == "") {
			return nil, fmt.Errorf("auth: token %q must set exactly one of secret or hash", name)
		}

		var digest string
		if e.Secret != "" {
			if len(e.Secret) < minTokenLen {
				return nil, fmt.Errorf("auth: token %q secret too short (need >= %d chars)", name, minTokenLen)
			}
			digest = hashToken(e.Secret)
		} else {
			h := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(e.Hash)), "sha256:")
			if len(h) != hex.EncodedLen(sha256.Size) {
				return nil, fmt.Errorf("auth: token %q hash must be sha256:<64 hex chars>", name)
			}
			if _, err := hex.DecodeString(h); err != nil {
				return nil, fmt.Errorf("auth: token %q hash is not valid hex: %w", name, err)
			}
			digest = h
		}

		if existing, dup := byHash[digest]; dup {
			return nil, fmt.Errorf("auth: token %q collides with token %q", name, existing.Subject)
		}
		byHash[digest] = &Principal{
			Subject: name,
			Team:    strings.TrimSpace(e.Team),
			Roles:   dedupeSorted(e.Roles),
			Method:  "token",
		}
	}
	return &TokenAuthenticator{byHash: byHash}, nil
}

// Authenticate implements Authenticator. It probes every place a token may
// appear; the first candidate whose digest matches a known token wins. JWT-
// shaped candidates are skipped so they fall through to the OIDC authenticator.
func (a *TokenAuthenticator) Authenticate(ctx context.Context, r *http.Request) (*Principal, error) {
	for _, tok := range candidateTokens(r) {
		if looksLikeJWT(tok) {
			continue
		}
		if p, ok := a.byHash[hashToken(tok)]; ok {
			// Return a copy so callers cannot mutate the shared template.
			cp := *p
			cp.Roles = append([]string(nil), p.Roles...)
			return &cp, nil
		}
	}
	return unauthenticated(ctx)
}

// Len reports the number of configured tokens.
func (a *TokenAuthenticator) Len() int { return len(a.byHash) }

// hashToken returns the lowercase hex SHA-256 digest of a token.
func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// HashToken is the exported form of hashToken, useful for tooling that
// precomputes token hashes for configuration.
func HashToken(tok string) string { return hashToken(tok) }
