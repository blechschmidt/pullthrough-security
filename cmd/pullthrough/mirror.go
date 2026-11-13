package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/logging"
	"github.com/blechschmidt/pullthrough-security/internal/mirror"
	"github.com/blechschmidt/pullthrough-security/internal/provenance"
	"github.com/blechschmidt/pullthrough-security/internal/repos"
	"github.com/blechschmidt/pullthrough-security/internal/tlspin"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// runMirrorCommand dispatches the air-gapped mirror subcommands: export, import,
// and prewarm. Each loads the proxy configuration to locate the cache and
// provenance stores, then reuses those stores directly.
func runMirrorCommand(name string, args []string) error {
	switch name {
	case "export":
		return runExport(args)
	case "import":
		return runImport(args)
	case "prewarm":
		return runPrewarm(args)
	default:
		return fmt.Errorf("unknown mirror command %q", name)
	}
}

// signalContext returns a context cancelled on SIGINT/SIGTERM so a long bundle
// transfer can be interrupted cleanly (and, for import, resumed later).
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

// requireFilesystemCache validates that the configured cache is the durable
// filesystem backend, which is the only one that can be exported/imported.
func requireFilesystemCache(cfg *config.Config) (string, error) {
	if cfg.Cache.Backend != "filesystem" {
		return "", fmt.Errorf("mirror: cache.backend must be %q to export/import (got %q)", "filesystem", cfg.Cache.Backend)
	}
	if cfg.Cache.Dir == "" {
		return "", errors.New("mirror: cache.dir is required to export/import")
	}
	return cfg.Cache.Dir, nil
}

// openLinkStore opens the durable provenance link store when one is configured.
// It returns (nil, nil) when no store directory is set, in which case provenance
// links are simply omitted from / ignored in the bundle.
func openLinkStore(cfg *config.Config, create bool) (provenance.LinkStore, error) {
	dir := cfg.Provenance.StoreDir
	if dir == "" {
		return nil, nil
	}
	if !create {
		if _, err := os.Stat(dir); err != nil {
			// Nothing to export from a non-existent store; treat as absent.
			return nil, nil
		}
	}
	return provenance.NewFileLinkStore(dir)
}

// llmVerdictBundle adapts the LLM package-scan verdict store to the bundle's
// verdict source and sink, so the verdicts reached on a connected instance are
// carried with the artifacts they are about and enforced on an air-gapped one
// (Task 174).
type llmVerdictBundle struct {
	store llmpkgscan.VerdictStore
}

// openLLMVerdictStore opens the verdict store the LLM package scan persists to
// (llmPackageScan.storeDir). It returns (nil, nil) when none is configured —
// verdicts are then kept in memory only and there is nothing to carry or to
// import into. With create false a directory that does not exist yet is treated
// as "no verdicts".
func openLLMVerdictStore(cfg *config.Config, create bool) (*llmVerdictBundle, error) {
	dir := cfg.LLMPackageScan.StoreDir
	if dir == "" {
		return nil, nil
	}
	if !create {
		if _, err := os.Stat(dir); err != nil {
			return nil, nil
		}
	}
	store, err := llmpkgscan.NewFileStore(dir)
	if err != nil {
		return nil, fmt.Errorf("opening llmPackageScan.storeDir: %w", err)
	}
	return &llmVerdictBundle{store: store}, nil
}

func (b *llmVerdictBundle) Close() error { return b.store.Close() }

// ExportVerdicts implements mirror.VerdictSource.
func (b *llmVerdictBundle) ExportVerdicts(ctx context.Context, digests map[string]bool) ([]mirror.ScanVerdict, error) {
	verdicts, err := llmpkgscan.ExportVerdicts(ctx, b.store, digests)
	if err != nil {
		return nil, err
	}
	out := make([]mirror.ScanVerdict, 0, len(verdicts))
	for _, v := range verdicts {
		out = append(out, mirror.ScanVerdict{Gate: llmpkgscan.BundleGate, Digest: v.Digest, Record: v.Record})
	}
	return out, nil
}

// ImportVerdict implements mirror.VerdictSink. A verdict of another gate is
// left out; one this instance already holds is kept as it is.
func (b *llmVerdictBundle) ImportVerdict(ctx context.Context, v mirror.ScanVerdict) (bool, error) {
	if v.Gate != llmpkgscan.BundleGate {
		return false, nil
	}
	_, err := llmpkgscan.ImportVerdict(ctx, b.store, v.Digest, v.Record)
	if errors.Is(err, llmpkgscan.ErrVerdictPresent) {
		return false, nil
	}
	return err == nil, err
}

// runExport serializes the cache (and provenance links) into a portable bundle.
func runExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to YAML configuration file")
	out := fs.String("out", "", "path to write the bundle tarball (required)")
	noProvenance := fs.Bool("no-provenance", false, "exclude provenance links from the bundle")
	noVerdicts := fs.Bool("no-verdicts", false, "exclude LLM package-scan verdicts from the bundle")
	noReleases := fs.Bool("no-releases", false, "exclude the repository registry's release manifests (and their pins) from the bundle")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("export: -out is required")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	dir, err := requireFilesystemCache(cfg)
	if err != nil {
		return err
	}

	store, err := cache.NewFilesystemStore(dir)
	if err != nil {
		return err
	}
	defer store.Close()

	exporter, err := mirror.NewExporter(store)
	if err != nil {
		return err
	}

	var opts mirror.ExportOptions
	if !*noProvenance {
		links, lerr := openLinkStore(cfg, false)
		if lerr != nil {
			return lerr
		}
		if links != nil {
			defer links.Close()
			opts.Links = links
		}
	}
	if !*noVerdicts {
		// The verdicts the LLM package scan reached on the artifacts being
		// exported travel with them, so the importing instance — which, behind an
		// air gap, cannot reach a provider — enforces them instead of deciding by
		// its fail mode.
		verdicts, verr := openLLMVerdictStore(cfg, false)
		if verr != nil {
			return verr
		}
		if verdicts != nil {
			defer verdicts.Close()
			opts.Verdicts = verdicts
		}
	}

	if !*noReleases {
		// Release manifests (Task 180) travel with the bundle, so the importing
		// instance pins the same objects: an air-gapped copy of a release is as
		// reproducible as the original.
		releases, rerr := openReposOffline(cfg, slog.Default())
		if rerr != nil {
			return rerr
		}
		if releases != nil {
			opts.Releases = releaseBundle{svc: releases}
		}
	}

	ctx, cancel := signalContext()
	defer cancel()

	// Stage to a temporary file and rename into place so an interrupted export
	// never leaves a partial bundle that looks complete.
	tmpPath := *out + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("export: creating output: %w", err)
	}
	bw := bufio.NewWriter(f)

	result, err := exporter.Export(ctx, bw, opts)
	if err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := bw.Flush(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("export: flushing bundle: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("export: syncing bundle: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("export: closing bundle: %w", err)
	}
	if err := os.Rename(tmpPath, *out); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("export: finalizing bundle: %w", err)
	}

	// Write the manifest digest to a sidecar so it can be transferred (and
	// verified) out-of-band alongside the bundle.
	digestPath := *out + ".sha256"
	if err := os.WriteFile(digestPath, []byte(result.ManifestDigest+"\n"), 0o644); err != nil {
		return fmt.Errorf("export: writing digest sidecar: %w", err)
	}

	fmt.Printf("exported bundle %s\n", *out)
	fmt.Printf("  cache entries:   %d\n", result.CacheEntries)
	fmt.Printf("  provenance links: %d\n", result.ProvenanceLinks)
	fmt.Printf("  scan verdicts:    %d\n", result.ScanVerdicts)
	fmt.Printf("  release manifests: %d (pinning %d of the bundle's blobs)\n", result.Releases, result.PinnedKeys)
	fmt.Printf("  total blob bytes: %d\n", result.TotalBlobBytes)
	fmt.Printf("  manifest digest:  %s\n", result.ManifestDigest)
	fmt.Printf("  digest written:   %s\n", digestPath)
	if result.ScanVerdicts > 0 {
		fmt.Printf("  note: the bundle carries LLM package-scan verdicts. They are imported only when the\n")
		fmt.Printf("        import is given this manifest digest (-manifest-digest), transferred out of band.\n")
	}
	return nil
}

// runImport loads a bundle into the (possibly air-gapped) instance's stores,
// verifying integrity.
func runImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to YAML configuration file")
	in := fs.String("in", "", "path to the bundle tarball to import (required)")
	digest := fs.String("manifest-digest", "", "expected bundle manifest digest (sha256:...) to verify; may also be a path to a .sha256 sidecar")
	overwrite := fs.Bool("overwrite", false, "re-import entries that already exist instead of skipping them")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return errors.New("import: -in is required")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	dir, err := requireFilesystemCache(cfg)
	if err != nil {
		return err
	}

	expectedDigest, err := resolveExpectedDigest(*digest)
	if err != nil {
		return err
	}

	store, err := cache.NewFilesystemStore(dir)
	if err != nil {
		return err
	}
	defer store.Close()

	importer, err := mirror.NewImporter(store)
	if err != nil {
		return err
	}

	links, err := openLinkStore(cfg, true)
	if err != nil {
		return err
	}
	if links != nil {
		defer links.Close()
	}

	f, err := os.Open(*in)
	if err != nil {
		return fmt.Errorf("import: opening bundle: %w", err)
	}
	defer f.Close()

	opts := mirror.ImportOptions{
		Links:                  links,
		ExpectedManifestDigest: expectedDigest,
		Overwrite:              *overwrite,
	}
	// LLM package-scan verdicts carried by the bundle are filed in this
	// instance's verdict store — when it has one, and (decided by the importer)
	// only when the manifest digest was verified.
	verdicts, err := openLLMVerdictStore(cfg, true)
	if err != nil {
		return err
	}
	if verdicts != nil {
		defer verdicts.Close()
		opts.Verdicts = verdicts
	}
	// Release manifests (Task 180) are filed in the repository registry — only
	// from a verified bundle — and the objects this instance has pinned are
	// never overwritten by the import.
	releases, err := openReposOffline(cfg, slog.Default())
	if err != nil {
		return err
	}
	if releases != nil {
		opts.Releases = releaseBundle{svc: releases}
		opts.Protected = releases.IsPinned
	}

	ctx, cancel := signalContext()
	defer cancel()

	result, err := importer.Import(ctx, bufio.NewReader(f), opts)
	if err != nil {
		return err
	}

	fmt.Printf("imported bundle %s\n", *in)
	fmt.Printf("  manifest digest:  %s\n", result.ManifestDigest)
	fmt.Printf("  imported entries: %d\n", result.Imported)
	fmt.Printf("  skipped (present): %d\n", result.Skipped)
	fmt.Printf("  provenance links: %d\n", result.ProvenanceLinks)
	fmt.Printf("  scan verdicts:    %d imported, %d already present or not applicable\n", result.ScanVerdicts, result.ScanVerdictsSkipped)
	fmt.Printf("  imported bytes:   %d\n", result.TotalBytes)
	fmt.Printf("  release manifests: %d imported, %d already present\n", result.Releases, result.ReleasesSkipped)
	if result.Protected > 0 {
		fmt.Printf("  pinned blobs kept: %d (a release pins them; the bundle's copy was not written)\n", result.Protected)
	}
	if n := result.ReleasesUntrusted; n > 0 {
		fmt.Printf("  note: %d release manifest(s) were NOT imported: they pin objects, and are accepted only from a\n", n)
		fmt.Printf("        bundle whose manifest digest was verified (-manifest-digest), with repositories.enabled.\n")
	}
	if n := result.ScanVerdictsUntrusted; n > 0 {
		switch {
		case expectedDigest == "":
			fmt.Printf("  note: %d LLM package-scan verdict(s) in the bundle were NOT imported: a verdict is\n", n)
			fmt.Printf("        accepted only from a bundle whose manifest digest was verified. Re-run with\n")
			fmt.Printf("        -manifest-digest <digest or .sha256 file obtained out of band> to import them.\n")
			fmt.Printf("        Until then this instance decides about each artifact itself (scan, or failMode).\n")
		default:
			fmt.Printf("  note: %d LLM package-scan verdict(s) in the bundle were NOT imported: llmPackageScan.storeDir\n", n)
			fmt.Printf("        is not set, so this instance has no persistent verdict store to file them in.\n")
		}
	}
	return nil
}

// resolveExpectedDigest accepts either a literal "sha256:..." digest or the path
// to a sidecar file containing one (as written by export), and returns the
// digest. An empty input yields an empty digest (no manifest-level check).
func resolveExpectedDigest(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	if filepath.IsAbs(v) || fileExists(v) {
		data, err := os.ReadFile(v)
		if err != nil {
			return "", fmt.Errorf("import: reading digest file %q: %w", v, err)
		}
		return trimDigest(string(data)), nil
	}
	return trimDigest(v), nil
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// trimDigest strips surrounding whitespace/newlines from a digest string.
func trimDigest(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			continue
		}
		out = append(out, r)
	}
	return string(out)
}

// runPrewarm pulls the artifacts named in a declarative manifest into the cache
// through the live backend pipeline, so the instance can be sealed afterwards.
func runPrewarm(args []string) error {
	fs := flag.NewFlagSet("prewarm", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to YAML configuration file")
	manifestPath := fs.String("manifest", "", "path to the declarative prewarm manifest (YAML) (required)")
	concurrency := fs.Int("concurrency", 4, "number of artifacts to fetch in parallel")
	continueOnError := fs.Bool("continue-on-error", false, "keep warming after a failure instead of aborting")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" {
		return errors.New("prewarm: -manifest is required")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	logger, err := logging.New(logging.Options{
		Level:  cfg.Logging.Level,
		Format: logging.Format(cfg.Logging.Format),
	})
	if err != nil {
		return err
	}

	mf, err := os.Open(*manifestPath)
	if err != nil {
		return fmt.Errorf("prewarm: opening manifest: %w", err)
	}
	defer mf.Close()
	manifest, err := mirror.ParsePrewarmManifest(mf)
	if err != nil {
		return err
	}

	if cfg.Cache.Sealed {
		logger.Warn("prewarm: cache.sealed is set; building an unsealed cache for warming (warming must reach upstreams)")
	}

	// Warming must fetch from upstream, so it uses the unsealed cache directly.
	// The release pins (Task 180) hold here too: warming must not evict them.
	pinned, err := openReposOffline(cfg, logger)
	if err != nil {
		return err
	}
	cacheImpl, err := newCacheImpl(cfg, logger, pinChecker(pinned))
	if err != nil {
		return err
	}
	defer cacheImpl.Close()

	// Build the backend registry exactly as the server does so warmed entries
	// land under the keys the proxy will later read. Sealed mode is intentionally
	// not applied to these backends (warming reaches upstream).
	warmCfg := *cfg
	warmCfg.Cache.Sealed = false
	// The egress guard applies during prewarm too (it reaches upstream), so the
	// SSRF/private-range floor and allowlist hold while bulk-warming the cache.
	warmEgress, err := buildEgress(&warmCfg, nil, logger)
	if err != nil {
		return err
	}
	// Certificate/CA pinning applies during prewarm too (it reaches upstream), so a
	// mis-pinned upstream fails closed while bulk-warming the cache.
	warmPins := tlspin.New(tlspin.Options{Logger: logger})
	registry, _, _, err := buildBackends(&warmCfg, cacheImpl, nil, warmEgress, warmPins, &upstream.ConnMetrics{}, logger)
	if err != nil {
		return err
	}

	warmer, err := mirror.NewWarmer(registry, cacheImpl, logger)
	if err != nil {
		return err
	}

	ctx, cancel := signalContext()
	defer cancel()

	report, err := warmer.Warm(ctx, manifest, mirror.WarmOptions{
		Concurrency:     *concurrency,
		ContinueOnError: *continueOnError,
	})
	if report != nil {
		printWarmReport(report)
	}
	if err != nil {
		return err
	}
	return nil
}

// printWarmReport writes a human-readable summary of a pre-warm run.
func printWarmReport(report *mirror.WarmReport) {
	for _, r := range report.Results {
		switch r.Status {
		case "fetched":
			fmt.Printf("  [fetched] %s%s (%d bytes)\n", r.Entry.Upstream, r.Entry.Path, r.Bytes)
		case "cached":
			fmt.Printf("  [cached ] %s%s\n", r.Entry.Upstream, r.Entry.Path)
		case "error":
			fmt.Printf("  [error  ] %s%s: %v\n", r.Entry.Upstream, r.Entry.Path, r.Err)
		}
	}
	fmt.Printf("prewarm complete: %d fetched, %d already cached, %d failed, %d bytes\n",
		report.Fetched, report.Cached, report.Failed, report.Bytes)
}

// releaseBundle carries the repository registry's release manifests in an
// air-gap bundle (Task 180).
type releaseBundle struct{ svc *repos.Service }

// ExportReleases implements mirror.ReleaseSource.
func (b releaseBundle) ExportReleases(ctx context.Context) ([]mirror.ReleaseRecord, []string, error) {
	raw, keys, err := b.svc.ExportManifests(ctx)
	if err != nil {
		return nil, nil, err
	}
	out := make([]mirror.ReleaseRecord, 0, len(raw))
	for _, m := range raw {
		out = append(out, mirror.ReleaseRecord{Repo: m.Repo, Commit: m.Commit, Manifest: m.Data})
	}
	return out, keys, nil
}

// ImportRelease implements mirror.ReleaseSink.
func (b releaseBundle) ImportRelease(ctx context.Context, r mirror.ReleaseRecord) (bool, error) {
	return b.svc.ImportManifest(ctx, r.Manifest)
}
