package admin

import (
	"net/http"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/intercept"
)

// InterceptInspector exposes the TLS-interception listeners (Tasks 100 and
// 172): their addresses, the routing table, and the CA clients must trust.
type InterceptInspector interface {
	Status() intercept.Status
	CACertPEM() []byte
}

// SetIntercept hands the server the interception listeners, which are built
// after it. It must be called before the server serves its first request.
func (s *Server) SetIntercept(insp InterceptInspector) {
	s.opts.Intercept = insp
}

// interceptResponse is the body of GET /api/intercept.
type interceptResponse struct {
	// Enabled is false when interception is not configured; the rest is then
	// empty.
	Enabled bool `json:"enabled"`
	intercept.Status
}

// handleIntercept serves the interception status: the listeners, the routing
// table (which upstream serves which host and path) and the hostnames a
// network has to send to the NAT listeners. With ?format=hosts it answers the
// hostnames one per line — ready for a DNS zone, a dnsmasq configuration or a
// hosts file — and with ?format=hosts&address=<ip> as hosts-file lines that map
// each to that address.
func (s *Server) handleIntercept(w http.ResponseWriter, r *http.Request) {
	insp := s.opts.Intercept
	if insp == nil {
		if strings.EqualFold(r.URL.Query().Get("format"), "hosts") {
			s.writeError(w, http.StatusNotFound, "interception is not enabled")
			return
		}
		s.writeJSON(w, http.StatusOK, interceptResponse{Enabled: false})
		return
	}
	status := insp.Status()
	switch format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format"))); format {
	case "", "json":
		s.writeJSON(w, http.StatusOK, interceptResponse{Enabled: true, Status: status})
	case "hosts":
		address := strings.TrimSpace(r.URL.Query().Get("address"))
		var b strings.Builder
		for _, h := range status.HostNames {
			if address != "" {
				b.WriteString(address)
				b.WriteByte('\t')
			}
			b.WriteString(h)
			b.WriteByte('\n')
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(b.String()))
	default:
		s.writeError(w, http.StatusBadRequest, "format must be json or hosts")
	}
}

// handleInterceptCA serves the PEM certificate of the interception CA: what a
// client has to trust for the proxy's certificates for the upstream hosts to
// be accepted. It is a certificate, not a secret; the key never leaves the
// proxy.
func (s *Server) handleInterceptCA(w http.ResponseWriter, r *http.Request) {
	insp := s.opts.Intercept
	if insp == nil {
		s.writeError(w, http.StatusNotFound, "interception is not enabled")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="pullthrough-intercept-ca.crt"`)
	_, _ = w.Write(insp.CACertPEM())
}
