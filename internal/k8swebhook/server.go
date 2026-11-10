package k8swebhook

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

// Server is the HTTPS ValidatingAdmissionWebhook listener. It wraps the decision
// Handler in an http.Server with a modern TLS floor, mirroring the proxy
// gateway's TLS conventions (internal/proxy/gateway.go). The API server connects
// over HTTPS and verifies the serving certificate against the caBundle wired into
// the ValidatingWebhookConfiguration.
type Server struct {
	cfg     Config
	handler *Handler
	server  *http.Server
	logger  *slog.Logger
}

// NewServer builds the webhook server. It requires a serving certificate
// (TLSCertFile/TLSKeyFile) because the Kubernetes API server only calls webhooks
// over HTTPS. When ClientCAFile is set, the API server's client certificate is
// required and verified against it (mTLS).
func NewServer(cfg Config, source VerdictSource, lock LockdownOracle, logger *slog.Logger) (*Server, error) {
	cfg = cfg.withDefaults()
	if logger == nil {
		logger = slog.Default()
	}
	handler, err := NewHandler(cfg, source, lock, logger)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.TLSCertFile) == "" || strings.TrimSpace(cfg.TLSKeyFile) == "" {
		return nil, errors.New("k8swebhook: tlsCertFile and tlsKeyFile are required (the API server calls webhooks only over HTTPS)")
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if ca := strings.TrimSpace(cfg.ClientCAFile); ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			return nil, fmt.Errorf("k8swebhook: reading clientCaFile: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("k8swebhook: clientCaFile %q contained no certificates", ca)
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler.Mux(),
		TLSConfig:         tlsCfg,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
	return &Server{cfg: cfg, handler: handler, server: srv, logger: logger}, nil
}

// Handler exposes the decision engine (for metrics bridging and tests).
func (s *Server) Handler() *Handler { return s.handler }

// Run serves until ctx is canceled, then shuts down gracefully. It blocks.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("admission webhook listening", "addr", s.cfg.Addr, "path", s.cfg.Path, "mtls", s.cfg.ClientCAFile != "")
		// Certs are passed via TLSConfig would also work; ListenAndServeTLS with the
		// file paths keeps them reloadable on restart and matches the gateway.
		err := s.server.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.server.Shutdown(shutdownCtx); err != nil {
			s.logger.Error("admission webhook shutdown", "error", err)
			return err
		}
		return nil
	case err := <-errCh:
		return err
	}
}
