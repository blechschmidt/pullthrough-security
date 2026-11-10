package siem

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"
)

// Sink is a SIEM delivery destination. Implementations must be safe for
// concurrent use (the forwarder delivers to every sink from a single dispatch
// goroutine, but Close may race with in-flight delivery during shutdown).
// DeliverBatch sends a whole batch in one unit of work; returning nil means the
// batch was accepted, a non-nil error means it was not. A *DeliveryError
// signals whether a retry is worthwhile.
type Sink interface {
	// Name is the operator-assigned identifier, unique within a forwarder, used
	// in metrics labels and logs.
	Name() string
	// Kind is the sink implementation type ("splunk_hec" or "syslog").
	Kind() string
	// DeliverBatch sends a batch of events, blocking until the destination
	// responds, ctx is canceled, or the attempt fails.
	DeliverBatch(ctx context.Context, batch []Event) error
	// Close releases any persistent connections or resources.
	Close() error
}

// DeliveryError describes a failed delivery and whether a retry is warranted. A
// transient condition (network error, 429, 5xx) is retryable; a permanent one
// (4xx misconfiguration, auth failure) is not.
type DeliveryError struct {
	Sink      string
	Status    int // HTTP status, or 0 for a transport-level failure
	Retryable bool
	Err       error
}

func (e *DeliveryError) Error() string {
	if e.Status > 0 {
		return fmt.Sprintf("siem: sink %q delivery failed: status %d: %v", e.Sink, e.Status, e.Err)
	}
	return fmt.Sprintf("siem: sink %q delivery failed: %v", e.Sink, e.Err)
}

func (e *DeliveryError) Unwrap() error { return e.Err }

// isRetryable reports whether err is a retryable delivery failure. A non
// *DeliveryError (e.g. a marshaling bug or context cancellation) is treated as
// non-retryable so it surfaces immediately rather than looping.
func isRetryable(err error) bool {
	var de *DeliveryError
	if errors.As(err, &de) {
		return de.Retryable
	}
	return false
}

// TLSConfig is the operator-facing TLS configuration shared by the HEC and
// syslog(+TLS) sinks. The zero value verifies the endpoint against the system
// roots.
type TLSConfig struct {
	// InsecureSkipVerify disables certificate verification. Intended for testing
	// only; a production deployment should pin a CA instead.
	InsecureSkipVerify bool
	// CAFile is a PEM bundle of additional root CAs to trust (e.g. an internal
	// SIEM's private CA). When empty, the system roots are used.
	CAFile string
	// ServerName overrides the SNI / certificate name verified against the
	// endpoint, for deployments that connect by IP or through a load balancer.
	ServerName string
	// MinVersion is the minimum TLS version ("1.2" or "1.3"); empty defaults to
	// 1.2.
	MinVersion string
}

// build constructs a *tls.Config from the operator settings, loading the CA
// bundle from disk when configured.
func (c TLSConfig) build() (*tls.Config, error) {
	cfg := &tls.Config{
		InsecureSkipVerify: c.InsecureSkipVerify, //nolint:gosec // opt-in, documented test-only knob
		ServerName:         c.ServerName,
		MinVersion:         tls.VersionTLS12,
	}
	switch c.MinVersion {
	case "", "1.2":
		cfg.MinVersion = tls.VersionTLS12
	case "1.3":
		cfg.MinVersion = tls.VersionTLS13
	default:
		return nil, fmt.Errorf("siem: unsupported tls minVersion %q (want 1.2 or 1.3)", c.MinVersion)
	}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("siem: reading tls caFile: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("siem: tls caFile %q contained no valid certificates", c.CAFile)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// httpDoer is the HTTP client surface the HEC sink uses so tests can inject a
// transport without a live server.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// newHTTPClient builds the outbound client the HEC sink uses. The timeout
// bounds a single delivery attempt; retries are the forwarder's job.
func newHTTPClient(timeout time.Duration, tlsCfg *tls.Config) *http.Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: timeout,
		TLSClientConfig:     tlsCfg,
	}
	return &http.Client{Timeout: timeout, Transport: tr}
}
