package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/approvals"
	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/gitops"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/simreplay"
)

// buildGitops constructs the GitOps policy & config synchronization subsystem
// (Task 93) from config. It returns nil when disabled. The reconciler patches the
// running config file (configPath) toward the desired-state bundle the source of
// truth declares, verifying the bundle against the audit/attestbundle key
// conventions, validating + previewing it (configcheck + simreplay), and either
// applying it (mode "apply", auto) or surfacing it for dual-control approval (mode
// "suggest"). Apply/rollback are recorded to the Merkle audit log and emitted as
// EventGitOps notifications. The state file defaults to <cache.dir>/gitops.json.
func buildGitops(cfg *config.Config, configPath string, auditLog *audit.Logger, notifier *notify.Notifier, approvalsSvc *approvals.Service, simReplay *simreplay.Recorder, logger *slog.Logger) (*gitops.Service, error) {
	gc := cfg.Gitops
	if !gc.Enabled {
		logger.Info("gitops policy/config synchronization disabled (set gitops.enabled to reconcile from a version-controlled source of truth)")
		return nil, nil
	}

	src, err := buildGitopsSource(cfg)
	if err != nil {
		return nil, err
	}

	verifier, keyDesc, err := buildGitopsVerifier(gc.Verify)
	if err != nil {
		return nil, err
	}

	storePath := strings.TrimSpace(gc.StorePath)
	if storePath == "" && strings.TrimSpace(cfg.Cache.Dir) != "" {
		storePath = filepath.Join(cfg.Cache.Dir, "gitops.json")
	}

	opts := []gitops.Option{}
	if auditLog != nil {
		opts = append(opts, gitops.WithAudit(auditLog))
	}
	if notifier != nil {
		opts = append(opts, gitops.WithNotifier(notifier))
	}
	if approvalsSvc != nil {
		opts = append(opts, gitops.WithApprovals(approvalsSvc))
	}
	if simReplay != nil {
		opts = append(opts, gitops.WithRecords(simReplay.Records))
	}

	svc, err := gitops.New(gitops.Config{
		Enabled:    true,
		Mode:       gitops.Mode(strings.ToLower(strings.TrimSpace(gc.Mode))),
		Interval:   gc.Interval,
		ConfigPath: configPath,
		StorePath:  storePath,
		FailClosed: gc.FailClosed,
	}, cfg, src, verifier, logger, opts...)
	if err != nil {
		return nil, fmt.Errorf("gitops: %w", err)
	}

	logger.Info("gitops policy/config synchronization enabled",
		"mode", svc.Mode(),
		"source", svc.SourceDescription(),
		"interval", gc.Interval,
		"verify", keyDesc,
		"failClosed", gc.FailClosed,
		"configFile", fileOrDefaults(configPath),
		"store", dirOrMemory(storePath))
	if configPath == "" {
		logger.Warn("gitops is enabled but the process runs from defaults with no -config file; apply/rollback will be refused (diff/suggest still work)")
	}
	return svc, nil
}

// buildGitopsSource constructs the desired-state source of truth from config: a
// local pre-fetched bundle (air-gap friendly) or a remote Git repository.
func buildGitopsSource(cfg *config.Config) (gitops.Source, error) {
	sc := cfg.Gitops.Source
	switch strings.ToLower(strings.TrimSpace(sc.Type)) {
	case "", "local":
		return gitops.NewLocalSource(sc.Path), nil
	case "git":
		workDir := strings.TrimSpace(sc.Git.WorkDir)
		if workDir == "" {
			if strings.TrimSpace(cfg.Cache.Dir) != "" {
				workDir = filepath.Join(cfg.Cache.Dir, "gitops-repo")
			} else {
				workDir = filepath.Join(os.TempDir(), "pullthrough-gitops-repo")
			}
		}
		return gitops.NewGitSource(sc.Git.URL, sc.Git.Ref, sc.Path, workDir), nil
	default:
		return nil, fmt.Errorf("gitops: unknown source.type %q (want local|git)", sc.Type)
	}
}

// buildGitopsVerifier constructs the bundle verifier from config: an optional
// trusted public key (inline PEM or file) and an optional pinned content digest.
func buildGitopsVerifier(vc config.GitopsVerifyConfig) (*gitops.Verifier, string, error) {
	var pem []byte
	desc := "none (digest/signature unverified)"
	switch {
	case strings.TrimSpace(vc.PublicKey) != "":
		pem = []byte(vc.PublicKey)
		desc = "trusted key (inline)"
	case strings.TrimSpace(vc.PublicKeyFile) != "":
		data, err := os.ReadFile(vc.PublicKeyFile)
		if err != nil {
			return nil, "", fmt.Errorf("gitops: reading verify.publicKeyFile: %w", err)
		}
		pem = data
		desc = "trusted key (" + vc.PublicKeyFile + ")"
	}
	v, err := gitops.NewVerifier(pem, vc.ExpectedDigest)
	if err != nil {
		return nil, "", err
	}
	if v.HasDigestPin() {
		if v.HasKey() {
			desc += " + pinned digest"
		} else {
			desc = "pinned digest"
		}
	}
	if v.HasKey() && v.KeyID() != "" {
		desc += " keyId=" + v.KeyID()
	}
	return v, desc, nil
}

// fileOrDefaults describes the config file path for logging.
func fileOrDefaults(path string) string {
	if strings.TrimSpace(path) == "" {
		return "(defaults; no file)"
	}
	return path
}
