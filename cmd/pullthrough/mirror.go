package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/logging"
	"github.com/blechschmidt/pullthrough-security/internal/mirror"
	"github.com/blechschmidt/pullthrough-security/internal/provenance"
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

// runExport serializes the cache (and provenance links) into a portable bundle.
func runExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to YAML configuration file")
	out := fs.String("out", "", "path to write the bundle tarball (required)")
	noProvenance := fs.Bool("no-provenance", false, "exclude provenance links from the bundle")
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
	fmt.Printf("  total blob bytes: %d\n", result.TotalBlobBytes)
	fmt.Printf("  manifest digest:  %s\n", result.ManifestDigest)
	fmt.Printf("  digest written:   %s\n", digestPath)
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

	ctx, cancel := signalContext()
	defer cancel()

	result, err := importer.Import(ctx, bufio.NewReader(f), mirror.ImportOptions{
		Links:                  links,
		ExpectedManifestDigest: expectedDigest,
		Overwrite:              *overwrite,
	})
	if err != nil {
		return err
	}

	fmt.Printf("imported bundle %s\n", *in)
	fmt.Printf("  manifest digest:  %s\n", result.ManifestDigest)
	fmt.Printf("  imported entries: %d\n", result.Imported)
	fmt.Printf("  skipped (present): %d\n", result.Skipped)
	fmt.Printf("  provenance links: %d\n", result.ProvenanceLinks)
	fmt.Printf("  imported bytes:   %d\n", result.TotalBytes)
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
	cacheImpl, err := newCacheImpl(cfg, logger)
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
