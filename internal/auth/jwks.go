package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// jwk is a single JSON Web Key (RFC 7517). Only the fields needed to
// reconstruct RSA and EC public keys are modeled.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	// RSA
	N string `json:"n"`
	E string `json:"e"`
	// EC
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// jwksDocument is a JWK Set.
type jwksDocument struct {
	Keys []jwk `json:"keys"`
}

// parsedKey pairs a public key with its key id and type for lookup.
type parsedKey struct {
	kid string
	kty string
	key crypto.PublicKey
}

// keySet is an immutable, indexed collection of verification keys.
type keySet struct {
	keys []parsedKey
}

// candidates returns keys eligible to verify a token: when kid is present and
// matches, only those keys; otherwise all keys of the requested type (so a
// token without a kid, or pointing at a rotated-away kid, can still be checked
// against every key of the right family).
func (s *keySet) candidates(kid, kty string) []crypto.PublicKey {
	var byKid []crypto.PublicKey
	var byType []crypto.PublicKey
	for _, k := range s.keys {
		if k.kty != kty {
			continue
		}
		byType = append(byType, k.key)
		if kid != "" && k.kid == kid {
			byKid = append(byKid, k.key)
		}
	}
	if len(byKid) > 0 {
		return byKid
	}
	return byType
}

// empty reports whether the set has no keys.
func (s *keySet) empty() bool { return s == nil || len(s.keys) == 0 }

// parseJWKS decodes a JWK Set document into a keySet.
func parseJWKS(data []byte) (*keySet, error) {
	var doc jwksDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("auth: parsing JWKS: %w", err)
	}
	ks := &keySet{}
	for i, k := range doc.Keys {
		pub, err := k.publicKey()
		if err != nil {
			// Skip keys we cannot use (e.g. symmetric/oct keys) rather than
			// failing the whole set.
			if pub == nil {
				continue
			}
			return nil, fmt.Errorf("auth: JWKS key %d: %w", i, err)
		}
		ks.keys = append(ks.keys, parsedKey{kid: k.Kid, kty: k.Kty, key: pub})
	}
	if ks.empty() {
		return nil, fmt.Errorf("auth: JWKS contains no usable RSA/EC keys")
	}
	return ks, nil
}

// publicKey reconstructs the crypto public key from the JWK. It returns
// (nil, nil) for key types this package does not verify with (so the caller
// skips them).
func (k jwk) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("decoding modulus: %w", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("decoding exponent: %w", err)
		}
		e := new(big.Int).SetBytes(eBytes)
		if !e.IsInt64() || e.Int64() < 2 {
			return nil, fmt.Errorf("invalid RSA exponent")
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(e.Int64()),
		}, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve %q", k.Crv)
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("decoding x: %w", err)
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, fmt.Errorf("decoding y: %w", err)
		}
		x := new(big.Int).SetBytes(xBytes)
		y := new(big.Int).SetBytes(yBytes)
		if !curve.IsOnCurve(x, y) {
			return nil, fmt.Errorf("EC point is not on curve %s", k.Crv)
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	default:
		// oct (HMAC) and unknown types are not used for asymmetric verification.
		return nil, nil
	}
}

// keyProvider supplies the current verification key set. Implementations must
// be safe for concurrent use.
type keyProvider interface {
	get(ctx context.Context) (*keySet, error)
}

// staticKeyProvider always returns a fixed key set.
type staticKeyProvider struct{ ks *keySet }

func (p staticKeyProvider) get(_ context.Context) (*keySet, error) { return p.ks, nil }

// remoteKeyProvider fetches a JWKS document over HTTP and caches it for a TTL,
// refreshing on expiry. A fetch failure after a successful initial load serves
// the last good set (fail-open on refresh, never on first load) so transient
// IdP outages do not reject all traffic.
type remoteKeyProvider struct {
	url    string
	client *http.Client
	ttl    time.Duration
	now    func() time.Time

	mu        sync.Mutex
	cached    *keySet
	fetchedAt time.Time
}

func newRemoteKeyProvider(url string, client *http.Client, ttl time.Duration, now func() time.Time) *remoteKeyProvider {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	if now == nil {
		now = time.Now
	}
	return &remoteKeyProvider{url: url, client: client, ttl: ttl, now: now}
}

func (p *remoteKeyProvider) get(ctx context.Context) (*keySet, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cached != nil && p.now().Sub(p.fetchedAt) < p.ttl {
		return p.cached, nil
	}
	ks, err := p.fetch(ctx)
	if err != nil {
		if p.cached != nil {
			// Serve stale keys rather than failing closed on a refresh error.
			return p.cached, nil
		}
		return nil, err
	}
	p.cached = ks
	p.fetchedAt = p.now()
	return ks, nil
}

func (p *remoteKeyProvider) fetch(ctx context.Context) (*keySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth: fetching JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth: JWKS endpoint returned %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("auth: reading JWKS: %w", err)
	}
	return parseJWKS(data)
}
