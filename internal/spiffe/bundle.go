package spiffe

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// BundleFormat selects how a trust-bundle file is decoded.
type BundleFormat string

const (
	// FormatAuto sniffs the file contents: a leading '{' is treated as the
	// SPIFFE JSON bundle format, otherwise PEM.
	FormatAuto BundleFormat = "auto"
	// FormatPEM decodes a concatenation of PEM CERTIFICATE blocks. Every root is
	// associated with the configured default trust domain. This is the simplest
	// offline/air-gapped form: an operator exports the SPIRE CA bundle as PEM.
	FormatPEM BundleFormat = "pem"
	// FormatSPIFFE decodes the SPIFFE Trust Bundle JSON format (a JWKS-style
	// document). Two shapes are accepted: a single-domain document with a
	// top-level "keys" array (associated with the configured default trust
	// domain) and a federated document with a "trust_domains" map keyed by trust
	// domain, each carrying its own "keys" array.
	FormatSPIFFE BundleFormat = "spiffe"
)

// TrustBundle holds the trusted X.509 roots for one or more SPIFFE trust
// domains. It is immutable once built; reloads produce a new instance which the
// BundleSource swaps in atomically.
type TrustBundle struct {
	roots map[string]*x509.CertPool      // trust domain -> roots
	certs map[string][]*x509.Certificate // trust domain -> roots (for inspection)
}

// Roots returns the trusted root pool for a trust domain and whether the domain
// is configured. An unknown trust domain has no roots, so a certificate
// presenting it cannot be validated (deny by default).
func (b *TrustBundle) Roots(trustDomain string) (*x509.CertPool, bool) {
	if b == nil {
		return nil, false
	}
	pool, ok := b.roots[strings.ToLower(strings.TrimSpace(trustDomain))]
	return pool, ok
}

// Domains returns the configured trust domains, sorted, for logging/inspection.
func (b *TrustBundle) Domains() []string {
	if b == nil {
		return nil
	}
	out := make([]string, 0, len(b.roots))
	for d := range b.roots {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// SoonestExpiry returns the earliest NotAfter across every trusted root, or the
// zero time when the bundle is empty. Operators chart the time remaining so a
// trust-anchor rotation is not missed in an air-gapped deployment.
func (b *TrustBundle) SoonestExpiry() time.Time {
	if b == nil {
		return time.Time{}
	}
	var soonest time.Time
	for _, certs := range b.certs {
		for _, c := range certs {
			if soonest.IsZero() || c.NotAfter.Before(soonest) {
				soonest = c.NotAfter
			}
		}
	}
	return soonest
}

// Count returns the total number of trusted roots across all domains.
func (b *TrustBundle) Count() int {
	if b == nil {
		return 0
	}
	n := 0
	for _, certs := range b.certs {
		n += len(certs)
	}
	return n
}

// ParseTrustBundle decodes a trust bundle from raw bytes. defaultDomain is the
// trust domain assigned to roots that carry no domain of their own (PEM input
// and single-domain SPIFFE JSON); it may be empty only when the input is a
// federated SPIFFE document that names every domain explicitly.
func ParseTrustBundle(data []byte, format BundleFormat, defaultDomain string) (*TrustBundle, error) {
	defaultDomain = strings.ToLower(strings.TrimSpace(defaultDomain))
	switch resolveFormat(format, data) {
	case FormatSPIFFE:
		return parseSPIFFEBundle(data, defaultDomain)
	default:
		return parsePEMBundle(data, defaultDomain)
	}
}

// resolveFormat applies FormatAuto sniffing: JSON documents start with '{'.
func resolveFormat(format BundleFormat, data []byte) BundleFormat {
	if format != FormatAuto && format != "" {
		return format
	}
	for _, b := range data {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		case '{':
			return FormatSPIFFE
		default:
			return FormatPEM
		}
	}
	return FormatPEM
}

func parsePEMBundle(data []byte, defaultDomain string) (*TrustBundle, error) {
	if defaultDomain == "" {
		return nil, errors.New("spiffe: a default trust domain is required for a PEM trust bundle")
	}
	certs, err := parsePEMCerts(data)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, errors.New("spiffe: PEM trust bundle contained no certificates")
	}
	return newBundle(map[string][]*x509.Certificate{defaultDomain: certs}), nil
}

// parsePEMCerts decodes every CERTIFICATE block in a PEM document.
func parsePEMCerts(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("spiffe: parsing trust-bundle certificate: %w", err)
		}
		certs = append(certs, c)
	}
	return certs, nil
}

// spiffeBundleDoc models both accepted SPIFFE JSON shapes. A single-domain
// document populates Keys; a federated document populates TrustDomains.
type spiffeBundleDoc struct {
	Keys         []spiffeJWK               `json:"keys"`
	TrustDomains map[string]spiffeBundleTD `json:"trust_domains"`
}

type spiffeBundleTD struct {
	Keys []spiffeJWK `json:"keys"`
}

// spiffeJWK is the subset of a JWK the X.509 trust bundle uses: the "x509-svid"
// use with the DER certificate carried in x5c[0].
type spiffeJWK struct {
	Use string   `json:"use"`
	X5c []string `json:"x5c"`
}

func parseSPIFFEBundle(data []byte, defaultDomain string) (*TrustBundle, error) {
	var doc spiffeBundleDoc
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields() // be strict so a typo'd field surfaces loudly...
	if err := dec.Decode(&doc); err != nil {
		// ...but unknown fields are common in real bundles (spiffe_sequence,
		// refresh hints, jwt-svid keys), so retry leniently before giving up.
		doc = spiffeBundleDoc{}
		if err2 := json.Unmarshal(data, &doc); err2 != nil {
			return nil, fmt.Errorf("spiffe: decoding SPIFFE trust bundle: %w", err2)
		}
	}

	byDomain := make(map[string][]*x509.Certificate)
	add := func(domain string, keys []spiffeJWK) error {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" {
			return errors.New("spiffe: SPIFFE trust bundle has a key set with no trust domain (set a default trust domain)")
		}
		certs, err := certsFromJWKs(keys)
		if err != nil {
			return fmt.Errorf("spiffe: trust domain %q: %w", domain, err)
		}
		byDomain[domain] = append(byDomain[domain], certs...)
		return nil
	}

	if len(doc.TrustDomains) > 0 {
		for domain, td := range doc.TrustDomains {
			if err := add(domain, td.Keys); err != nil {
				return nil, err
			}
		}
	}
	if len(doc.Keys) > 0 {
		if err := add(defaultDomain, doc.Keys); err != nil {
			return nil, err
		}
	}
	if len(byDomain) == 0 {
		return nil, errors.New("spiffe: SPIFFE trust bundle contained no x509-svid roots")
	}
	return newBundle(byDomain), nil
}

// certsFromJWKs extracts the DER certificate from every x509-svid JWK.
func certsFromJWKs(keys []spiffeJWK) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, k := range keys {
		// Only X.509 SVID roots are relevant; jwt-svid signing keys are ignored.
		if k.Use != "" && k.Use != "x509-svid" {
			continue
		}
		if len(k.X5c) == 0 {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(k.X5c[0])
		if err != nil {
			return nil, fmt.Errorf("decoding x5c: %w", err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing x5c certificate: %w", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("no x509-svid root certificates present")
	}
	return certs, nil
}

func newBundle(byDomain map[string][]*x509.Certificate) *TrustBundle {
	roots := make(map[string]*x509.CertPool, len(byDomain))
	for domain, certs := range byDomain {
		pool := x509.NewCertPool()
		for _, c := range certs {
			pool.AddCert(c)
		}
		roots[domain] = pool
	}
	return &TrustBundle{roots: roots, certs: byDomain}
}

// BundleSource holds the live trust bundle behind an atomic swap so the
// authenticator always reads a consistent snapshot while a background reload
// (or an admin-triggered Reload) replaces it. It is safe for concurrent use.
type BundleSource struct {
	path          string
	format        BundleFormat
	defaultDomain string

	mu        sync.RWMutex
	bundle    *TrustBundle
	loadedAt  time.Time
	modTime   time.Time
	reloads   uint64
	lastError string
}

// NewBundleSource loads the bundle at path and returns a source that can be
// reloaded. The initial load must succeed (a proxy must not start trusting an
// empty bundle by accident).
func NewBundleSource(path string, format BundleFormat, defaultDomain string) (*BundleSource, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("spiffe: trust bundle path is required")
	}
	s := &BundleSource{path: path, format: format, defaultDomain: defaultDomain}
	if err := s.Reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// Current returns the live trust bundle.
func (s *BundleSource) Current() *TrustBundle {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bundle
}

// Reload re-reads the bundle file and atomically swaps it in. A parse failure
// leaves the previously loaded bundle in place (fail-safe) and is returned so
// the caller can log/alert; the proxy keeps validating against the last known
// good roots.
func (s *BundleSource) Reload() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		s.recordError(err)
		return fmt.Errorf("spiffe: reading trust bundle %q: %w", s.path, err)
	}
	bundle, err := ParseTrustBundle(data, s.format, s.defaultDomain)
	if err != nil {
		s.recordError(err)
		return err
	}
	var modTime time.Time
	if info, statErr := os.Stat(s.path); statErr == nil {
		modTime = info.ModTime()
	}
	s.mu.Lock()
	s.bundle = bundle
	s.loadedAt = time.Now()
	s.modTime = modTime
	s.reloads++
	s.lastError = ""
	s.mu.Unlock()
	return nil
}

func (s *BundleSource) recordError(err error) {
	s.mu.Lock()
	s.lastError = err.Error()
	s.mu.Unlock()
}

// Watch polls the bundle file for modification-time changes every interval and
// reloads when it changes, until ctx is canceled. A non-positive interval
// disables polling (the bundle is then only reloaded on an explicit Reload).
// The done channel argument lets callers run it inline; typically it is started
// as a goroutine.
func (s *BundleSource) Watch(stop <-chan struct{}, interval time.Duration, onReload func(error)) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			info, err := os.Stat(s.path)
			if err != nil {
				if onReload != nil {
					onReload(err)
				}
				continue
			}
			s.mu.RLock()
			unchanged := info.ModTime().Equal(s.modTime)
			s.mu.RUnlock()
			if unchanged {
				continue
			}
			err = s.Reload()
			if onReload != nil {
				onReload(err)
			}
		}
	}
}

// Stats is a point-in-time view of a BundleSource for logging/metrics.
type Stats struct {
	Path        string
	Domains     []string
	Roots       int
	Reloads     uint64
	LoadedAt    time.Time
	SoonestRoot time.Time
	LastError   string
}

// Stats returns a snapshot of the source state.
func (s *BundleSource) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Stats{
		Path:        s.path,
		Domains:     s.bundle.Domains(),
		Roots:       s.bundle.Count(),
		Reloads:     s.reloads,
		LoadedAt:    s.loadedAt,
		SoonestRoot: s.bundle.SoonestExpiry(),
		LastError:   s.lastError,
	}
}
