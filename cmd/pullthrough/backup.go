package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backup"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/config"
)

// runBackupSubcommand dispatches the disaster-recovery subcommands `backup` and
// `restore`. Both load the proxy configuration to locate the cache and the
// sidecar metadata stores, then reuse those stores directly — exactly as the
// air-gapped mirror subcommands do.
func runBackupSubcommand(name string, args []string) error {
	switch name {
	case "backup":
		return runBackup(args)
	case "restore":
		return runRestore(args)
	default:
		return fmt.Errorf("unknown backup command %q", name)
	}
}

// metaSrc is the CLI-level description of one sidecar metadata store: its logical
// name, the on-disk path, and whether that path is a single file (vs a directory
// tree). The distinction determines the restore target root.
type metaSrc struct {
	name   string
	path   string
	isFile bool
}

// backupMetadataSources derives the set of durable sidecar metadata stores to
// snapshot from the proxy configuration. Only stores that persist to disk are
// included (in-memory state — the provenance graph, vulnscan result cache, and
// quarantine set — is rebuilt from these durable stores and from live ingestion
// after a restore, so it need not be captured). Every source is optional: a
// disabled subsystem simply contributes nothing.
func backupMetadataSources(cfg *config.Config) []metaSrc {
	var srcs []metaSrc
	add := func(name, path string, isFile bool) {
		if strings.TrimSpace(path) != "" {
			srcs = append(srcs, metaSrc{name: name, path: path, isFile: isFile})
		}
	}

	// Tamper-evident audit log and its Merkle transparency checkpoints. The
	// checkpoint file defaults to "<log>.checkpoints" when unset, matching the
	// audit subsystem's own default, so consistency proofs survive the round-trip.
	add("audit-log", cfg.Audit.File, true)
	ckpt := cfg.Audit.Transparency.CheckpointFile
	if ckpt == "" && cfg.Audit.File != "" && !cfg.Audit.Transparency.Disabled {
		ckpt = cfg.Audit.File + ".checkpoints"
	}
	add("audit-checkpoints", ckpt, true)

	// Provenance link store (package -> commit associations).
	add("provenance", cfg.Provenance.StoreDir, false)
	// Commit-scan verdict store (LLM scan results persisted to disk).
	add("commit-scan", cfg.Scanning.Commit.StoreDir, false)
	// VEX statement store (air-gapped suppression source).
	add("vex", cfg.Vulnerabilities.VEX.Dir, false)
	// Policy-as-code bundle directory.
	add("policy-bundles", cfg.PolicyEngine.Dir, false)

	return srcs
}

// backupSources projects the CLI sources onto the backup package's generic
// descriptor.
func backupSources(srcs []metaSrc) []backup.MetadataSource {
	out := make([]backup.MetadataSource, 0, len(srcs))
	for _, s := range srcs {
		out = append(out, backup.MetadataSource{Name: s.name, Path: s.path, Optional: true})
	}
	return out
}

// restoreTargets maps each source name to the directory its files are restored
// under: a file source restores into its parent directory (so the file lands at
// its original path), a tree source restores into the directory itself.
func restoreTargets(srcs []metaSrc) map[string]string {
	targets := make(map[string]string, len(srcs))
	for _, s := range srcs {
		if s.isFile {
			targets[s.name] = filepath.Dir(s.path)
		} else {
			targets[s.name] = s.path
		}
	}
	return targets
}

// newBackupCacheStore opens the durable cache store for backup/restore. Both the
// local filesystem and the S3-compatible object store are supported; the
// in-memory backend has no durable state and is rejected.
func newBackupCacheStore(cfg *config.Config) (cache.Store, error) {
	switch cfg.Cache.Backend {
	case "filesystem":
		if cfg.Cache.Dir == "" {
			return nil, errors.New("backup: cache.dir is required for the filesystem backend")
		}
		return cache.NewFilesystemStore(cfg.Cache.Dir)
	case "s3":
		s3 := cfg.Cache.S3
		return cache.NewS3Store(cache.S3Options{
			Endpoint:           s3.Endpoint,
			Region:             s3.Region,
			Bucket:             s3.Bucket,
			Prefix:             s3.Prefix,
			AccessKeyID:        s3.AccessKeyID,
			SecretAccessKey:    s3.SecretAccessKey,
			SessionToken:       s3.SessionToken,
			UsePathStyle:       s3.UsePathStyle,
			InsecureSkipVerify: s3.InsecureSkipVerify,
			MaxRetries:         s3.MaxRetries,
			SpoolDir:           s3.SpoolDir,
		})
	case "memory":
		return nil, errors.New("backup: the in-memory cache backend has no durable state to back up")
	default:
		return nil, fmt.Errorf("backup: unsupported cache backend %q", cfg.Cache.Backend)
	}
}

// resolveEncryptionKey assembles the encryption secret from explicit flag values
// (which override config) or the backup configuration. It returns the zero key
// when encryption is neither requested nor configured.
func resolveEncryptionKey(cfg *config.Config, passphrase, keyFile string, encrypt bool) (backup.EncryptionKey, error) {
	// Explicit flags take precedence over config.
	if passphrase == "" && keyFile == "" && !encrypt {
		// Fall back to config when the operator did not pass flags.
		if !cfg.Backup.Encrypt {
			return backup.EncryptionKey{}, nil
		}
		passphrase = cfg.Backup.Passphrase
		keyFile = cfg.Backup.KeyFile
	}
	if passphrase != "" && keyFile != "" {
		return backup.EncryptionKey{}, errors.New("backup: specify either a passphrase or a key file, not both")
	}
	switch {
	case keyFile != "":
		raw, err := loadRawKey(keyFile)
		if err != nil {
			return backup.EncryptionKey{}, err
		}
		return backup.EncryptionKey{RawKey: raw}, nil
	case passphrase != "":
		return backup.EncryptionKey{Passphrase: []byte(passphrase)}, nil
	default:
		return backup.EncryptionKey{}, nil
	}
}

// loadRawKey reads a 32-byte AES key from a file holding it as hex or base64
// (whitespace-trimmed).
func loadRawKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("backup: reading key file: %w", err)
	}
	s := strings.TrimSpace(string(data))
	if raw, derr := hex.DecodeString(s); derr == nil && len(raw) == 32 {
		return raw, nil
	}
	if raw, derr := base64.StdEncoding.DecodeString(s); derr == nil && len(raw) == 32 {
		return raw, nil
	}
	return nil, fmt.Errorf("backup: key file %q must contain a 32-byte key as hex or base64", path)
}

// runBackup writes a consistent snapshot of the cache and metadata stores.
func runBackup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to YAML configuration file")
	out := fs.String("out", "", "path to write the snapshot (required; use '-' for stdout, e.g. to pipe to tape)")
	noCache := fs.Bool("no-cache", false, "exclude the content-addressable cache (metadata-only snapshot)")
	noMetadata := fs.Bool("no-metadata", false, "exclude sidecar metadata stores (cache-only snapshot)")
	encrypt := fs.Bool("encrypt", false, "encrypt the snapshot (requires -passphrase or -key-file, or backup config)")
	passphrase := fs.String("passphrase", "", "encryption passphrase (overrides config)")
	keyFile := fs.String("key-file", "", "file holding a 32-byte raw AES key as hex/base64 (overrides config)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("backup: -out is required")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	key, err := resolveEncryptionKey(cfg, *passphrase, *keyFile, *encrypt)
	if err != nil {
		return err
	}

	store, err := newBackupCacheStore(cfg)
	if err != nil {
		return err
	}
	defer store.Close()

	var cacheStore cache.Store = store
	if *noCache {
		cacheStore = emptyCacheStore{}
	}
	var sources []backup.MetadataSource
	if !*noMetadata {
		sources = backupSources(backupMetadataSources(cfg))
	}

	ctx, cancel := signalContext()
	defer cancel()

	opts := backup.Options{
		Cache:      cacheStore,
		Sources:    sources,
		AppVersion: version,
		Encryption: key,
	}

	if *out == "-" {
		// Air-gapped streaming: write the snapshot straight to stdout so it can be
		// piped to tape, an SSH transfer, or removable media without staging.
		bw := bufio.NewWriter(os.Stdout)
		result, berr := backup.NewBackuper().Backup(ctx, bw, opts)
		if berr != nil {
			return berr
		}
		if err := bw.Flush(); err != nil {
			return err
		}
		// The manifest digest goes to stderr so stdout stays a clean snapshot.
		fmt.Fprintf(os.Stderr, "manifest digest: %s\n", result.ManifestDigest)
		return nil
	}

	result, err := writeSnapshotFile(ctx, *out, opts)
	if err != nil {
		return err
	}
	printBackupResult(*out, result)
	return nil
}

// writeSnapshotFile stages a snapshot to a temp file and renames it into place so
// an interrupted backup never leaves a partial file that looks complete. It also
// writes the manifest-digest sidecar.
func writeSnapshotFile(ctx context.Context, out string, opts backup.Options) (*backup.Result, error) {
	if dir := filepath.Dir(out); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("backup: creating output directory: %w", err)
		}
	}
	tmp := out + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return nil, fmt.Errorf("backup: creating output: %w", err)
	}
	bw := bufio.NewWriter(f)
	result, err := backup.NewBackuper().Backup(ctx, bw, opts)
	if err != nil {
		f.Close()
		os.Remove(tmp)
		return nil, err
	}
	if err := bw.Flush(); err != nil {
		f.Close()
		os.Remove(tmp)
		return nil, fmt.Errorf("backup: flushing snapshot: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return nil, fmt.Errorf("backup: syncing snapshot: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return nil, fmt.Errorf("backup: closing snapshot: %w", err)
	}
	if err := os.Rename(tmp, out); err != nil {
		os.Remove(tmp)
		return nil, fmt.Errorf("backup: finalizing snapshot: %w", err)
	}
	if err := os.WriteFile(out+".sha256", []byte(result.ManifestDigest+"\n"), 0o644); err != nil {
		return nil, fmt.Errorf("backup: writing digest sidecar: %w", err)
	}
	return result, nil
}

func printBackupResult(out string, result *backup.Result) {
	fmt.Printf("wrote snapshot %s\n", out)
	fmt.Printf("  cache entries:    %d\n", result.CacheEntries)
	fmt.Printf("  metadata files:   %d\n", result.MetadataFiles)
	fmt.Printf("  cache bytes:      %d\n", result.TotalCacheBytes)
	fmt.Printf("  metadata bytes:   %d\n", result.TotalMetaBytes)
	fmt.Printf("  encrypted:        %v\n", result.Encrypted)
	fmt.Printf("  manifest digest:  %s\n", result.ManifestDigest)
	fmt.Printf("  digest written:   %s.sha256\n", out)
}

// runRestore rehydrates a snapshot into the configured cache and metadata stores.
func runRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to YAML configuration file")
	in := fs.String("in", "", "path to the snapshot to restore (required; use '-' for stdin)")
	digest := fs.String("manifest-digest", "", "expected manifest digest (sha256:...) or path to a .sha256 sidecar")
	overwrite := fs.Bool("overwrite", false, "overwrite existing cache entries and metadata files instead of skipping unchanged ones")
	cacheOnly := fs.Bool("cache-only", false, "restore only the cache, leaving metadata stores untouched")
	metadataOnly := fs.Bool("metadata-only", false, "restore only the metadata stores, leaving the cache untouched")
	passphrase := fs.String("passphrase", "", "decryption passphrase (overrides config)")
	keyFile := fs.String("key-file", "", "file holding a 32-byte raw AES key as hex/base64 (overrides config)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return errors.New("restore: -in is required")
	}
	if *cacheOnly && *metadataOnly {
		return errors.New("restore: -cache-only and -metadata-only are mutually exclusive")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	expectedDigest, err := resolveExpectedDigest(*digest)
	if err != nil {
		return err
	}
	key, err := resolveEncryptionKey(cfg, *passphrase, *keyFile, false)
	if err != nil {
		return err
	}

	store, err := newBackupCacheStore(cfg)
	if err != nil {
		return err
	}
	defer store.Close()

	var cacheStore cache.Store = store
	if *metadataOnly {
		cacheStore = emptyCacheStore{}
	}
	targets := map[string]string{}
	if !*cacheOnly {
		srcs := backupMetadataSources(cfg)
		targets = restoreTargets(srcs)
	}

	f, closeFn, err := openSnapshotInput(*in)
	if err != nil {
		return err
	}
	defer closeFn()

	ctx, cancel := signalContext()
	defer cancel()

	result, err := backup.NewRestorer().Restore(ctx, f, backup.RestoreOptions{
		Cache:                  cacheStore,
		Targets:                targets,
		ExpectedManifestDigest: expectedDigest,
		Encryption:             key,
		Overwrite:              *overwrite,
	})
	if err != nil {
		return err
	}

	fmt.Printf("restored snapshot %s\n", *in)
	fmt.Printf("  created:           %s\n", result.CreatedAt)
	fmt.Printf("  manifest digest:   %s\n", result.ManifestDigest)
	fmt.Printf("  cache imported:    %d\n", result.CacheImported)
	fmt.Printf("  cache skipped:     %d\n", result.CacheSkipped)
	fmt.Printf("  metadata written:  %d\n", result.MetadataWritten)
	fmt.Printf("  metadata skipped:  %d\n", result.MetadataSkipped)
	fmt.Printf("  restored bytes:    %d\n", result.TotalBytes)
	fmt.Printf("  encrypted:         %v\n", result.Encrypted)
	return nil
}

// openSnapshotInput opens the snapshot source, supporting "-" for stdin (the
// air-gapped streaming-restore path).
func openSnapshotInput(in string) (reader *bufio.Reader, closeFn func(), err error) {
	if in == "-" {
		return bufio.NewReader(os.Stdin), func() {}, nil
	}
	f, err := os.Open(in)
	if err != nil {
		return nil, nil, fmt.Errorf("restore: opening snapshot: %w", err)
	}
	return bufio.NewReader(f), func() { f.Close() }, nil
}

// emptyCacheStore is a no-op cache.Store used to exclude the cache from a backup
// (List returns nothing) or to skip cache restore (metadata-only). It is never
// written to during those flows.
type emptyCacheStore struct{}

func (emptyCacheStore) Put(context.Context, cache.Record, io.Reader) (cache.Record, error) {
	return cache.Record{}, errors.New("backup: cache excluded")
}

func (emptyCacheStore) Get(context.Context, string) (io.ReadCloser, cache.Record, error) {
	return nil, cache.Record{}, cache.ErrNotFound
}

func (emptyCacheStore) Stat(context.Context, string) (cache.Record, error) {
	return cache.Record{}, cache.ErrNotFound
}

func (emptyCacheStore) SetAccessed(context.Context, string, time.Time) error {
	return cache.ErrNotFound
}

func (emptyCacheStore) Delete(context.Context, string) error { return cache.ErrNotFound }

func (emptyCacheStore) List(context.Context) ([]cache.Record, error) { return nil, nil }

func (emptyCacheStore) Close() error { return nil }

// buildScheduledBackupRun constructs the RunFunc the scheduler invokes: it opens
// fresh stores, writes a timestamped snapshot into the configured directory, and
// prunes old snapshots per the retention policy. Stores are opened per-run so a
// long-lived scheduler never pins file handles between backups.
func buildScheduledBackupRun(cfg *config.Config) backup.RunFunc {
	return func(ctx context.Context) (int64, error) {
		key, err := resolveEncryptionKey(cfg, "", "", false)
		if err != nil {
			return 0, err
		}
		store, err := newBackupCacheStore(cfg)
		if err != nil {
			return 0, err
		}
		defer store.Close()

		var cacheStore cache.Store = store
		if !cfg.Backup.IncludeCacheOrDefault() {
			cacheStore = emptyCacheStore{}
		}

		stamp := nowStamp()
		out := filepath.Join(cfg.Backup.Dir, "pullthrough-backup-"+stamp+".tar")
		result, err := writeSnapshotFile(ctx, out, backup.Options{
			Cache:      cacheStore,
			Sources:    backupSources(backupMetadataSources(cfg)),
			AppVersion: version,
			Encryption: key,
		})
		if err != nil {
			return 0, err
		}
		pruneOldBackups(cfg.Backup.Dir, cfg.Backup.Retain)
		return result.TotalCacheBytes + result.TotalMetaBytes, nil
	}
}

// nowStamp returns a filesystem-safe RFC3339-ish timestamp for snapshot names.
func nowStamp() string {
	return time.Now().UTC().Format("20060102T150405Z")
}

// pruneOldBackups keeps at most `retain` timestamped snapshots in dir (and their
// .sha256 sidecars), deleting the oldest. A non-positive retain keeps all.
func pruneOldBackups(dir string, retain int) {
	if retain <= 0 || dir == "" {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var snaps []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "pullthrough-backup-") && strings.HasSuffix(name, ".tar") {
			snaps = append(snaps, name)
		}
	}
	if len(snaps) <= retain {
		return
	}
	sort.Strings(snaps) // lexical sort == chronological for the timestamp format
	for _, name := range snaps[:len(snaps)-retain] {
		_ = os.Remove(filepath.Join(dir, name))
		_ = os.Remove(filepath.Join(dir, name+".sha256"))
	}
}
