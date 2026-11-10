package spiffe

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
)

// ClientAuthType maps the configured mTLS mode to the tls.ClientAuthType used
// at the listener. Verification of the chain against the SPIFFE trust bundle is
// performed in the application layer (the Authenticator) so the trust bundle
// can be hot-reloaded without restarting the listener; the TLS layer therefore
// only governs whether a client certificate is requested or required.
//
//   - required=false: tls.RequestClientCert — request a cert opportunistically
//     so mTLS composes with token/OIDC auth (either-or). A client that presents
//     none still completes the handshake and is handled by the other
//     authenticators.
//   - required=true: tls.RequireAnyClientCert — the handshake fails unless the
//     client presents a certificate (mTLS-required mode). The certificate is
//     still validated against the trust bundle by the Authenticator.
func ClientAuthType(required bool) tls.ClientAuthType {
	if required {
		return tls.RequireAnyClientCert
	}
	return tls.RequestClientCert
}

// serialString renders a certificate serial number, tolerating a nil serial.
func serialString(cert *x509.Certificate) string {
	if cert == nil || cert.SerialNumber == nil {
		return ""
	}
	return cert.SerialNumber.String()
}

// normalizeDomain lower-cases and trims a trust-domain string for comparison.
func normalizeDomain(d string) string {
	return strings.ToLower(strings.TrimSpace(d))
}
