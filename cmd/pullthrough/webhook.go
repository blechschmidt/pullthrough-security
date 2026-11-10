package main

import (
	"context"
	"flag"
	"fmt"
	"os/signal"
	"strings"
	"syscall"

	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/logging"
)

// runWebhookCommand is the `webhook` subcommand: a standalone Kubernetes
// ValidatingAdmissionWebhook server (Task 111) for the split-deployment topology
// where the webhook runs as its own, independently-scaled workload rather than
// in-process in the proxy pods. It reuses the same configuration file and the
// same admissionWebhook stanza; the verdict source must be the remote dossier
// HTTP endpoint (admissionWebhook.dossier.url), since a standalone webhook has no
// in-process dossier of its own.
//
// The in-process topology — the webhook listening inside the main proxy binary —
// needs no subcommand: just enable admissionWebhook in the normal server config.
func runWebhookCommand(args []string) error {
	fs := flag.NewFlagSet("webhook", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to YAML configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	logger, err := logging.New(logging.Options{
		Level:     cfg.Logging.Level,
		Format:    logging.Format(cfg.Logging.Format),
		AddSource: cfg.Logging.AddSource,
	})
	if err != nil {
		return err
	}

	if !cfg.AdmissionWebhook.Enabled {
		return fmt.Errorf("webhook: admissionWebhook.enabled must be true to run the standalone webhook server")
	}
	if strings.TrimSpace(cfg.AdmissionWebhook.Dossier.URL) == "" {
		return fmt.Errorf("webhook: the standalone webhook requires admissionWebhook.dossier.url (the proxy admin dossier endpoint); " +
			"for the in-process topology, enable admissionWebhook in the normal server config instead")
	}

	// The emergency-lockdown kill-switch (Task 74) is wired from config so a
	// shared state store (lockdown.storePath on shared storage) lets a standalone
	// webhook honor the same targeted blocks the pull path enforces. Audit/notify
	// and HA coordination are the main server's responsibility, so they are nil
	// here (the webhook only reads lockdown state).
	lockdownSvc, err := buildLockdown(cfg, nil, nil, nil, logger)
	if err != nil {
		return err
	}

	// A nil builder is safe: buildAdmissionWebhook takes the HTTP source path
	// because dossier.url is set (checked above).
	srv, err := buildAdmissionWebhook(cfg, nil, lockdownSvc, logger)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger.Info("starting standalone admission webhook", "version", version,
		"dossier", cfg.AdmissionWebhook.Dossier.URL)
	return srv.Run(ctx)
}
