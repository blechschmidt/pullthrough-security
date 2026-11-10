// Package intercept implements the proxy's TLS-interception (MITM) forward-proxy
// mode, the alternative to explicit package-source configuration.
//
// In explicit mode a client is pointed at the proxy directly (its .npmrc,
// pip.conf, Docker registry mirror, etc. reference "https://proxy/v1/<backend>/")
// and the proxy serves that traffic under the /v1 path space. That mode is
// always available and is the default.
//
// In interception mode the client is instead pointed at the proxy as an ordinary
// HTTP forwarding proxy (HTTP_PROXY / HTTPS_PROXY, or a transparent redirect).
// The client speaks to the real upstream hostname (registry.npmjs.org,
// pypi.org, ...); for HTTPS it issues a CONNECT and the proxy — rather than
// blindly tunneling — terminates TLS itself with an on-the-fly certificate
// minted by a locally-trusted CA, inspects the decrypted request, maps the
// upstream host to a configured backend, and runs it through the full caching +
// admission pipeline. No per-tool reconfiguration is required beyond trusting
// the proxy's CA certificate and setting the proxy environment variables.
//
// This file holds the certificate authority: loading or generating the signing
// CA, and minting (and caching) short-lived leaf certificates per intercepted
// host.
package intercept

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// defaultLeafTTL is the validity window of a minted leaf certificate. Leaves are
// generated on demand and cached only in memory (regenerated on restart), so the
// window is a safety bound rather than an operational lifetime.
const defaultLeafTTL = 90 * 24 * time.Hour

// defaultCertCacheSize bounds the number of distinct host leaf certificates kept
// in memory, so a flood of unique SNI values cannot grow the cache without
// limit. When exceeded the least-recently-minted entries are evicted.
const defaultCertCacheSize = 1024

// CA is the signing certificate authority used to mint leaf certificates for
// intercepted hosts. It is safe for concurrent use.
type CA struct {
	cert    *x509.Certificate
	certDER []byte
	key     *ecdsa.PrivateKey

	leafTTL time.Duration

	mu    sync.Mutex
	leaf  *ecdsa.PrivateKey // shared leaf key, lazily generated
	cache *certCache
}

// CAOptions configures LoadOrGenerateCA.
type CAOptions struct {
	// CertFile and KeyFile are the PEM paths of the signing CA. When both exist
	// they are loaded. When they are absent and Generate is true a fresh CA is
	// generated and written to them (parent directories are created).
	CertFile string
	KeyFile  string
	// Generate permits creating a new CA when the files do not exist. When false,
	// missing files are an error.
	Generate bool
	// Organization is the subject organization of a generated CA (default
	// "Pullthrough Security Proxy").
	Organization string
	// CommonName is the subject common name of a generated CA (default
	// "Pullthrough Security Proxy Intercept CA").
	CommonName string
	// Validity is the lifetime of a generated CA certificate (default 10 years).
	Validity time.Duration
	// LeafTTL is the validity window of minted leaf certificates (default 90d).
	LeafTTL time.Duration
	// CacheSize bounds the in-memory leaf-certificate cache (default 1024).
	CacheSize int
}

// LoadOrGenerateCA loads the CA from opts.CertFile/opts.KeyFile, or, when they
// do not exist and opts.Generate is set, generates a new CA and persists it.
func LoadOrGenerateCA(opts CAOptions) (*CA, error) {
	if opts.CertFile == "" || opts.KeyFile == "" {
		return nil, errors.New("intercept: CA certFile and keyFile are required")
	}
	leafTTL := opts.LeafTTL
	if leafTTL <= 0 {
		leafTTL = defaultLeafTTL
	}
	cacheSize := opts.CacheSize
	if cacheSize <= 0 {
		cacheSize = defaultCertCacheSize
	}

	certExists := fileExists(opts.CertFile)
	keyExists := fileExists(opts.KeyFile)
	switch {
	case certExists && keyExists:
		return loadCA(opts.CertFile, opts.KeyFile, leafTTL, cacheSize)
	case certExists != keyExists:
		return nil, fmt.Errorf("intercept: CA is half-present: certFile exists=%t keyFile exists=%t (provide both or neither)", certExists, keyExists)
	case !opts.Generate:
		return nil, fmt.Errorf("intercept: CA files %q/%q do not exist and generation is disabled", opts.CertFile, opts.KeyFile)
	default:
		return generateCA(opts, leafTTL, cacheSize)
	}
}

// NewCAFromPEM builds a CA from in-memory PEM material (used by tests and by
// callers that manage the CA material themselves).
func NewCAFromPEM(certPEM, keyPEM []byte, leafTTL time.Duration, cacheSize int) (*CA, error) {
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("intercept: parsing CA keypair: %w", err)
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("intercept: parsing CA certificate: %w", err)
	}
	key, ok := tlsCert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("intercept: CA private key must be ECDSA")
	}
	if !leaf.IsCA {
		return nil, errors.New("intercept: CA certificate does not assert the CA basic constraint")
	}
	if leafTTL <= 0 {
		leafTTL = defaultLeafTTL
	}
	if cacheSize <= 0 {
		cacheSize = defaultCertCacheSize
	}
	return &CA{
		cert:    leaf,
		certDER: tlsCert.Certificate[0],
		key:     key,
		leafTTL: leafTTL,
		cache:   newCertCache(cacheSize),
	}, nil
}

func loadCA(certFile, keyFile string, leafTTL time.Duration, cacheSize int) (*CA, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("intercept: reading CA cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("intercept: reading CA key: %w", err)
	}
	return NewCAFromPEM(certPEM, keyPEM, leafTTL, cacheSize)
}

func generateCA(opts CAOptions, leafTTL time.Duration, cacheSize int) (*CA, error) {
	org := opts.Organization
	if org == "" {
		org = "Pullthrough Security Proxy"
	}
	cn := opts.CommonName
	if cn == "" {
		cn = "Pullthrough Security Proxy Intercept CA"
	}
	validity := opts.Validity
	if validity <= 0 {
		validity = 10 * 365 * 24 * time.Hour
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("intercept: generating CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   cn,
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("intercept: creating CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("intercept: parsing generated CA certificate: %w", err)
	}

	if err := persistCA(opts.CertFile, opts.KeyFile, der, key); err != nil {
		return nil, err
	}
	return &CA{
		cert:    cert,
		certDER: der,
		key:     key,
		leafTTL: leafTTL,
		cache:   newCertCache(cacheSize),
	}, nil
}

func persistCA(certFile, keyFile string, der []byte, key *ecdsa.PrivateKey) error {
	for _, dir := range []string{filepath.Dir(certFile), filepath.Dir(keyFile)} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("intercept: creating CA directory: %w", err)
		}
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		return fmt.Errorf("intercept: writing CA cert: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("intercept: marshaling CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	// The private key is secret: owner read/write only.
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return fmt.Errorf("intercept: writing CA key: %w", err)
	}
	return nil
}

// CertPEM returns the PEM-encoded CA certificate, suitable for distributing to
// clients so they trust the intercepted connections.
func (c *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.certDER})
}

// Subject returns the CA certificate subject, for logging/observability.
func (c *CA) Subject() string { return c.cert.Subject.String() }

// LeafForHost returns a leaf certificate valid for host, minting and caching it
// on first use. host may be a DNS name or an IP literal.
func (c *CA) LeafForHost(host string) (*tls.Certificate, error) {
	host = normalizeHost(host)
	if host == "" {
		return nil, errors.New("intercept: empty host")
	}
	if cert, ok := c.cache.get(host); ok {
		return cert, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// Re-check under lock: a concurrent caller may have filled it.
	if cert, ok := c.cache.get(host); ok {
		return cert, nil
	}
	if c.leaf == nil {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("intercept: generating leaf key: %w", err)
		}
		c.leaf = key
	}
	cert, err := c.mintLeaf(host)
	if err != nil {
		return nil, err
	}
	c.cache.put(host, cert)
	return cert, nil
}

func (c *CA) mintLeaf(host string) (*tls.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(c.leafTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &c.leaf.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("intercept: minting leaf for %q: %w", host, err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, c.certDER},
		PrivateKey:  c.leaf,
		Leaf:        mustParse(der),
	}, nil
}

func mustParse(der []byte) *x509.Certificate {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	return cert
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("intercept: generating serial number: %w", err)
	}
	return serial, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// certCache is a size-bounded, LRU-by-insertion leaf-certificate cache.
type certCache struct {
	mu      sync.Mutex
	max     int
	entries map[string]*tls.Certificate
	order   []string
}

func newCertCache(max int) *certCache {
	if max <= 0 {
		max = defaultCertCacheSize
	}
	return &certCache{max: max, entries: make(map[string]*tls.Certificate, max)}
}

func (c *certCache) get(host string) (*tls.Certificate, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cert, ok := c.entries[host]
	return cert, ok
}

func (c *certCache) put(host string, cert *tls.Certificate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[host]; ok {
		c.entries[host] = cert
		return
	}
	if len(c.order) >= c.max {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldest)
	}
	c.entries[host] = cert
	c.order = append(c.order, host)
}

func (c *certCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
