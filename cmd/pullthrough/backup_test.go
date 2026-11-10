package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/config"
)

func TestBackupMetadataSourcesDerivesConfiguredStores(t *testing.T) {
	cfg := config.Default()
	cfg.Audit.File = "/var/lib/pt/audit.log"
	cfg.Provenance.StoreDir = "/var/lib/pt/provenance"
	cfg.Scanning.Commit.StoreDir = "/var/lib/pt/commitscan"
	cfg.Vulnerabilities.VEX.Dir = "/var/lib/pt/vex"
	cfg.PolicyEngine.Dir = "/var/lib/pt/policy"

	srcs := backupMetadataSources(&cfg)
	byName := map[string]metaSrc{}
	for _, s := range srcs {
		byName[s.name] = s
	}

	// Audit log is a file source; its checkpoints default to "<log>.checkpoints".
	if got := byName["audit-log"]; got.path != "/var/lib/pt/audit.log" || !got.isFile {
		t.Errorf("audit-log source = %+v", got)
	}
	if got := byName["audit-checkpoints"]; got.path != "/var/lib/pt/audit.log.checkpoints" {
		t.Errorf("audit-checkpoints source = %+v", got)
	}
	// Directory stores.
	for _, name := range []string{"provenance", "commit-scan", "vex", "policy-bundles"} {
		s, ok := byName[name]
		if !ok {
			t.Errorf("missing source %q", name)
			continue
		}
		if s.isFile {
			t.Errorf("source %q should be a directory tree", name)
		}
	}
}

func TestBackupMetadataSourcesOmitsUnset(t *testing.T) {
	cfg := config.Default()
	// No audit file, no store dirs set -> no metadata sources.
	if srcs := backupMetadataSources(&cfg); len(srcs) != 0 {
		t.Errorf("expected no sources for empty config, got %d: %+v", len(srcs), srcs)
	}
}

func TestRestoreTargets(t *testing.T) {
	srcs := []metaSrc{
		{name: "audit-log", path: "/var/lib/pt/audit.log", isFile: true},
		{name: "vex", path: "/var/lib/pt/vex", isFile: false},
	}
	targets := restoreTargets(srcs)
	if targets["audit-log"] != "/var/lib/pt" {
		t.Errorf("file source target = %q, want parent dir", targets["audit-log"])
	}
	if targets["vex"] != "/var/lib/pt/vex" {
		t.Errorf("tree source target = %q, want the dir itself", targets["vex"])
	}
}

func TestLoadRawKey(t *testing.T) {
	dir := t.TempDir()
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	hexPath := filepath.Join(dir, "key.hex")
	if err := os.WriteFile(hexPath, []byte(hex.EncodeToString(raw)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadRawKey(hexPath)
	if err != nil {
		t.Fatalf("loadRawKey(hex): %v", err)
	}
	if string(got) != string(raw) {
		t.Error("hex key round-trip mismatch")
	}

	// A wrong-length key must be rejected.
	badPath := filepath.Join(dir, "bad.hex")
	if err := os.WriteFile(badPath, []byte("abcd"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRawKey(badPath); err == nil {
		t.Error("expected rejection of short key")
	}
}

func TestResolveEncryptionKeyDefaults(t *testing.T) {
	cfg := config.Default()
	// No flags, no config -> no encryption.
	k, err := resolveEncryptionKey(&cfg, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if k.IsSet() {
		t.Error("expected no key when encryption is neither requested nor configured")
	}

	// Config-driven passphrase.
	cfg.Backup.Encrypt = true
	cfg.Backup.Passphrase = "from-config"
	k, err = resolveEncryptionKey(&cfg, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if string(k.Passphrase) != "from-config" {
		t.Errorf("expected config passphrase, got %q", k.Passphrase)
	}

	// Explicit flag overrides config.
	k, err = resolveEncryptionKey(&cfg, "from-flag", "", true)
	if err != nil {
		t.Fatal(err)
	}
	if string(k.Passphrase) != "from-flag" {
		t.Errorf("expected flag passphrase to win, got %q", k.Passphrase)
	}
}

func TestPruneOldBackups(t *testing.T) {
	dir := t.TempDir()
	names := []string{
		"pullthrough-backup-20260101T000000Z.tar",
		"pullthrough-backup-20260102T000000Z.tar",
		"pullthrough-backup-20260103T000000Z.tar",
		"pullthrough-backup-20260104T000000Z.tar",
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, n+".sha256"), []byte("d"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pruneOldBackups(dir, 2)

	for _, gone := range names[:2] {
		if _, err := os.Stat(filepath.Join(dir, gone)); !os.IsNotExist(err) {
			t.Errorf("expected %s to be pruned", gone)
		}
		if _, err := os.Stat(filepath.Join(dir, gone+".sha256")); !os.IsNotExist(err) {
			t.Errorf("expected %s.sha256 to be pruned", gone)
		}
	}
	for _, kept := range names[2:] {
		if _, err := os.Stat(filepath.Join(dir, kept)); err != nil {
			t.Errorf("expected %s to be kept: %v", kept, err)
		}
	}

	// retain=0 keeps everything.
	pruneOldBackups(dir, 0)
	if _, err := os.Stat(filepath.Join(dir, names[3])); err != nil {
		t.Errorf("retain=0 should keep all: %v", err)
	}
}
