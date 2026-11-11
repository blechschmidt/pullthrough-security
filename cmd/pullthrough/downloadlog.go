package main

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/blechschmidt/pullthrough-security/internal/clientip"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/downloadlog"
	"github.com/blechschmidt/pullthrough-security/internal/git"
)

// buildDownloadLog constructs the download log (Task 176): the bounded record of
// which package was downloaded from which client address, shown in the admin
// UI's Downloads tab.
//
// It always returns a usable log — a disabled configuration yields one that
// records nothing — so callers need no nil checks. An unusable
// downloadLog.path is a startup error rather than a silent fall-back to memory:
// an operator who asked for a log that survives restarts must not find out
// after the restart that it did not.
//
// The caller closes the log on shutdown, which writes what is still pending.
func buildDownloadLog(cfg *config.Config, logger *slog.Logger) (*downloadlog.Log, error) {
	dc := cfg.DownloadLog
	retention := dc.Retention
	if retention <= 0 {
		// The configuration's "0s" means "no time limit"; the log spells that as
		// a negative retention (its zero value means "use the default").
		retention = -1
	}
	log, err := downloadlog.New(downloadlog.Config{
		Enabled:         dc.Enabled,
		MaxEntries:      dc.MaxEntriesOrDefault(),
		Retention:       retention,
		Path:            dc.Path,
		IncludeMetadata: dc.IncludeMetadata,
		Logger:          logger,
	})
	if err != nil {
		return nil, fmt.Errorf("building the download log (downloadLog.path %q): %w", dc.Path, err)
	}
	if !log.Enabled() {
		logger.Info("download log disabled")
		return log, nil
	}
	st := log.Stats()
	attrs := []any{
		"maxEntries", st.Capacity,
		"persistent", st.Persistent,
		"includeMetadata", st.IncludeMetadata,
		"trustedProxies", len(cfg.Server.TrustedProxies),
	}
	if st.RetentionSeconds > 0 {
		attrs = append(attrs, "retention", dc.Retention.String())
	} else {
		attrs = append(attrs, "retention", "unlimited")
	}
	if st.Persistent {
		attrs = append(attrs, "path", dc.Path, "restored", st.Retained)
	}
	logger.Info("download log enabled", attrs...)
	return log, nil
}

// buildClientIPResolver constructs the resolver that decides which address a
// request is attributed to: the TCP peer, or — for the reverse proxies named in
// server.trustedProxies — the client address they forwarded the request for.
func buildClientIPResolver(cfg *config.Config, logger *slog.Logger) (*clientip.Resolver, error) {
	resolver, err := clientip.New(cfg.Server.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("server.trustedProxies: %w", err)
	}
	if resolver.TrustsAny() {
		logger.Info("client addresses are taken from X-Forwarded-For for trusted proxies",
			"trustedProxies", cfg.Server.TrustedProxies)
	}
	return resolver, nil
}

// sshFetchRecorder returns the Git-over-SSH server's fetch callback: it adds one
// download-log entry per clone or fetch served over SSH, which the HTTP gateway
// never sees. It returns nil — no callback — when the log is disabled.
//
// An SSH session has no HTTP status and no URL. The entry says so (method
// "SSH", status 0) rather than inventing them; the path is the repository as
// the client addressed it, and the identity is the fingerprint of the key the
// client authenticated with. The address is the TCP peer: there is no
// forwarding header to consult on an SSH connection.
func sshFetchRecorder(log *downloadlog.Log, ecosystems map[string]string) func(git.FetchEvent) {
	if !log.Enabled() {
		return nil
	}
	return func(ev git.FetchEvent) {
		ecosystem := ecosystems[ev.Upstream]
		if ecosystem == "" {
			ecosystem = "git"
		}
		entry := downloadlog.Entry{
			ClientIP:   sshClientHost(ev.RemoteAddr),
			Ecosystem:  ecosystem,
			Upstream:   ev.Upstream,
			Package:    ev.Repo,
			Kind:       downloadlog.KindPackage,
			Method:     "SSH",
			Path:       ev.Upstream + "/" + ev.Repo,
			Outcome:    downloadlog.OutcomeServed,
			Bytes:      ev.Bytes,
			DurationMs: ev.Duration.Milliseconds(),
		}
		if ev.Err != nil {
			entry.Outcome = downloadlog.OutcomeError
			entry.Reason = "the upload-pack session did not complete"
			entry.Bytes = 0
		}
		if ev.KeyFingerprint != "" {
			entry.Subject = ev.KeyFingerprint
			entry.AuthMethod = "ssh-key"
		}
		log.Record(entry)
	}
}

// sshClientHost strips the port from an SSH client address.
func sshClientHost(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}
