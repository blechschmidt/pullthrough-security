package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/git"
	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

// runLockfiles implements `ptctl lockfiles scan`: the lock files of a Git
// repository, read at a commit, and the exact dependencies they pin (Task 178).
func runLockfiles(args []string) error {
	if len(args) == 0 {
		lockfilesUsage(os.Stderr)
		return fmt.Errorf("an action is required")
	}
	switch args[0] {
	case "scan":
		return lockfilesScan(args[1:], os.Stdout, os.Stderr)
	case "formats":
		return lockfilesFormats(args[1:], os.Stdout)
	case "-h", "--help", "help":
		lockfilesUsage(os.Stdout)
		return nil
	default:
		return fmt.Errorf("unknown lockfiles action %q (try: scan, formats)", args[0])
	}
}

func lockfilesUsage(w io.Writer) {
	fmt.Fprint(w, `ptctl lockfiles <action> [flags]

The lock files of a Git repository and the exact dependencies they pin: name,
version, integrity digests, registry, and the lock file and line each comes
from. The repository's objects are read at a commit — never a working tree, so
uncommitted changes are not seen. See docs/lockfiles.md.

Actions:
  scan <repo-url|path> [--rev REV] [--json]
                          scan a local repository (or a directory in one) or a
                          remote one (fetched one commit deep into a temporary
                          directory, without files larger than --max-file-size)
  formats [--json]        the lock-file formats read, per upstream type, and why
                          the other types have none

Run 'ptctl lockfiles <action> -h' for the action's flags.
`)
}

// parseInterspersed parses flags that may come before and after positional
// arguments ("scan ./repo --json"), returning the positionals.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

// lockfilesScanOutput is the JSON form of a scan.
type lockfilesScanOutput struct {
	Repository string `json:"repository"`
	Revision   string `json:"revision,omitempty"`
	*lockfiles.Report
}

func lockfilesScan(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("lockfiles scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var g globalFlags
	registerGlobals(fs, &g)
	rev := fs.String("rev", "", "the commit, branch or tag to scan (default: HEAD, or the remote's default branch)")
	asJSON := fs.Bool("json", false, "print the full report as JSON")
	subdir := fs.String("path", "", "scan only this directory of the repository (a local path inside a working tree sets it too)")
	var skips, publicURLs multiFlag
	fs.Var(&skips, "skip", "a glob of paths not to scan, in addition to the defaults (repeatable)")
	noDefaultSkip := fs.Bool("no-default-skip", false, "do not skip vendored code and test fixtures (node_modules, vendor, testdata, …)")
	maxDepth := fs.Int("max-depth", lockfiles.DefaultMaxDepth, "how many directories deep to look")
	maxFileSize := fs.Int64("max-file-size", lockfiles.DefaultMaxFileBytes, "the largest lock file read, in bytes")
	maxFiles := fs.Int("max-files", lockfiles.DefaultMaxFiles, "stop after this many lock files")
	configPath := fs.String("config", "", "the proxy's config file: its public URL, personal-link prefix and upstreams map lock files written against it back to the upstreams")
	fs.Var(&publicURLs, "public-url", "a base URL the proxy is reached at, for mapping its URLs back to upstreams (repeatable; --url counts as one)")
	linkPrefix := fs.String("link-prefix", "", "the personal-link path prefix (default /u, or the --config value)")
	discover := fs.Bool("discover", true, "with --url, ask the proxy's admin API which upstreams it has")
	timeout := fs.Duration("scan-timeout", 10*time.Minute, "give up on the whole scan (fetch included) after this long")
	positional, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return fmt.Errorf("lockfiles scan takes one repository URL or path, got %d arguments", len(positional))
	}
	target := positional[0]

	proxy, notes, err := lockfilesProxy(g, *configPath, publicURLs, *linkPrefix, *discover)
	if err != nil {
		return err
	}
	for _, n := range notes {
		fmt.Fprintln(stderr, "note:", n)
	}
	opts := lockfiles.Options{
		Proxy:        proxy,
		Root:         *subdir,
		MaxDepth:     *maxDepth,
		MaxFileBytes: *maxFileSize,
		MaxFiles:     *maxFiles,
	}
	switch {
	case *noDefaultSkip:
		opts.Skip = append([]string{}, skips...)
	default:
		opts.Skip = append(append([]string{}, lockfiles.DefaultSkip...), skips...)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	objs, scanRev, cleanup, err := openLockfilesRepo(ctx, target, *rev, *maxFileSize, &opts, stderr)
	if err != nil {
		return err
	}
	report, err := lockfiles.Scan(ctx, objs, scanRev, opts)
	// The temporary clone goes before anything is printed: a reader that
	// stops early ("| head") ends ptctl with SIGPIPE, and deferred calls do not
	// run then.
	cleanup()
	if err != nil {
		return fmt.Errorf("scanning %s: %w", redactRepo(target, proxy), err)
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(lockfilesScanOutput{Repository: redactRepo(target, proxy), Revision: *rev, Report: report})
	}
	printLockfilesReport(stdout, redactRepo(target, proxy), report)
	return nil
}

// openLockfilesRepo opens target: a local repository (bare, or a working
// tree or a directory in one) or a remote one, fetched into a temporary
// directory. It returns the revision to scan and a cleanup function.
func openLockfilesRepo(ctx context.Context, target, rev string, maxFileSize int64, opts *lockfiles.Options, stderr io.Writer) (*git.ObjectReader, string, func(), error) {
	if fi, err := os.Stat(target); err == nil && fi.IsDir() {
		repo, err := git.LocateRepository(ctx, target, "")
		if err != nil {
			return nil, "", nil, err
		}
		if opts.Root == "" {
			opts.Root = repo.Prefix
		} else if repo.Prefix != "" {
			opts.Root = repo.Prefix + "/" + strings.Trim(opts.Root, "/")
		}
		// A partial clone of the user's own fetches what it lacks, like any
		// git command run in it would.
		objs, err := git.OpenObjectReader(repo.GitDir, git.ObjectReaderOptions{AllowLazyFetch: true})
		if err != nil {
			return nil, "", nil, err
		}
		if rev == "" {
			rev = "HEAD"
		}
		return objs, rev, func() { _ = objs.Close() }, nil
	}
	tmp, err := os.MkdirTemp("", "ptctl-lockfiles-")
	if err != nil {
		return nil, "", nil, err
	}
	removeTmp := func() { _ = os.RemoveAll(tmp) }
	fmt.Fprintf(stderr, "fetching %s%s …\n", redactRepo(target, opts.Proxy), revSuffix(rev))
	commit, err := git.CloneForScan(ctx, git.ScanCloneOptions{URL: target, Dir: tmp + "/repo.git", Rev: rev, MaxBlobBytes: maxFileSize})
	if err != nil {
		removeTmp()
		return nil, "", nil, err
	}
	objs, err := git.OpenObjectReader(tmp+"/repo.git", git.ObjectReaderOptions{})
	if err != nil {
		removeTmp()
		return nil, "", nil, err
	}
	var once sync.Once
	return objs, commit, func() { once.Do(func() { _ = objs.Close(); removeTmp() }) }, nil
}

func revSuffix(rev string) string {
	if rev == "" {
		return ""
	}
	return " at " + rev
}

// redactRepo removes credentials and link tokens from a repository location
// before it is printed.
func redactRepo(target string, proxy *lockfiles.Proxy) string {
	return proxy.Redact(git.RedactURLSecrets(target))
}

// lockfilesProxy builds what the scan knows about the proxy: from --config,
// --public-url, --url and (with --url) the admin API's list of upstreams.
func lockfilesProxy(g globalFlags, configPath string, publicURLs []string, linkPrefix string, discover bool) (*lockfiles.Proxy, []string, error) {
	p := &lockfiles.Proxy{Upstreams: map[string]lockfiles.ProxyUpstream{}}
	var notes []string
	if configPath != "" {
		cfg, err := config.Load(configPath)
		if err != nil {
			return nil, nil, fmt.Errorf("reading the proxy config: %w", err)
		}
		p = proxyFromConfig(cfg)
	}
	p.PublicURLs = append(p.PublicURLs, publicURLs...)
	if linkPrefix != "" {
		p.LinkPrefix = linkPrefix
	}
	if strings.TrimSpace(g.url) != "" {
		p.PublicURLs = append(p.PublicURLs, strings.TrimSpace(g.url))
		if discover {
			c, err := newClient(g)
			if err == nil {
				var backends []backend
				backends, err = discoverBackends(c)
				for _, b := range backends {
					if _, known := p.Upstreams[b.Name]; !known {
						p.Upstreams[b.Name] = lockfiles.ProxyUpstream{Type: b.Type, URL: b.URL}
					}
				}
			}
			if err != nil {
				notes = append(notes, "could not list the proxy's upstreams ("+lockfiles.RedactText(err.Error())+"); URLs through it keep the upstream's name but not its address")
			}
		}
	}
	return p, notes, nil
}

// proxyFromConfig takes what the scan needs from the proxy's configuration.
func proxyFromConfig(cfg *config.Config) *lockfiles.Proxy {
	p := &lockfiles.Proxy{
		LinkPrefix:      cfg.UserLinks.PathPrefix,
		RegistryDefault: cfg.Server.Registry.DefaultUpstream,
		Upstreams:       map[string]lockfiles.ProxyUpstream{},
	}
	if u := strings.TrimSpace(cfg.Server.PublicURL); u != "" {
		p.PublicURLs = append(p.PublicURLs, u)
	}
	for name, up := range cfg.Upstreams {
		if up.Enabled != nil && !*up.Enabled {
			continue
		}
		p.Upstreams[name] = lockfiles.ProxyUpstream{Type: up.Type, URL: up.URL}
	}
	return p
}

// printLockfilesReport prints a scan as a table, then what was not read.
func printLockfilesReport(w io.Writer, repo string, r *lockfiles.Report) {
	fmt.Fprintf(w, "Repository %s, commit %s", repo, r.Commit)
	if r.Root != "" {
		fmt.Fprintf(w, ", directory %s", r.Root)
	}
	fmt.Fprintln(w)
	deps := r.Dependencies()
	if len(deps) > 0 {
		fmt.Fprintln(w)
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "LOCATION\tTYPE\tNAME\tVERSION\tFROM\tDIGEST")
		for _, d := range deps {
			fmt.Fprintf(tw, "%s:%d\t%s\t%s\t%s\t%s\t%s\n", d.File, d.Line, d.Type, d.Name, shorten(d.Version, 40), dependencySource(d), digestSummary(d.Digests))
		}
		_ = tw.Flush()
	}
	fmt.Fprintf(w, "\n%d dependencies in %d lock files.\n", len(deps), len(r.Files))

	var problems []string
	for _, f := range r.Files {
		if f.Error != "" {
			problems = append(problems, fmt.Sprintf("  %s: not read: %s", f.Path, f.Error))
		}
		for _, warn := range f.Warnings {
			problems = append(problems, fmt.Sprintf("  %s: %s", f.Path, warn))
		}
	}
	if len(problems) > 0 {
		fmt.Fprintln(w, "\nWarnings:")
		for _, p := range problems {
			fmt.Fprintln(w, p)
		}
	}
	if len(r.Skipped) > 0 {
		fmt.Fprintln(w, "\nNot read:")
		for _, s := range r.Skipped {
			fmt.Fprintf(w, "  %s: %s\n", s.Path, s.Reason)
		}
		if r.Stats.SkippedDirs > len(r.Skipped) {
			fmt.Fprintf(w, "  … %d directories skipped in all\n", r.Stats.SkippedDirs)
		}
	}
	if len(r.Submodules) > 0 {
		fmt.Fprintln(w, "\nSubmodules:")
		for _, s := range r.Submodules {
			fmt.Fprintf(w, "  %s at %s\n", s.Path, s.Commit)
		}
	}
	if r.Truncated != "" {
		fmt.Fprintf(w, "\nThe scan stopped early: %s.\n", r.Truncated)
	}
}

// dependencySource says where a dependency comes from, in a few words.
func dependencySource(d lockfiles.Dependency) string {
	var s string
	switch d.Source {
	case lockfiles.SourceGit:
		s = "git " + d.Registry
		if d.Revision != "" {
			s += "@" + shorten(d.Revision, 12)
		}
	case lockfiles.SourceURL:
		s = "url " + d.URL
	default:
		s = d.Registry
		if s == "" {
			s = "(default registry)"
		}
	}
	if d.Upstream != "" {
		s = "proxy upstream " + d.Upstream + ": " + s
	}
	return shorten(s, 72)
}

// digestSummary shows the first digest, abbreviated, and how many more.
func digestSummary(ds []lockfiles.Digest) string {
	if len(ds) == 0 {
		return "-"
	}
	sorted := append([]lockfiles.Digest(nil), ds...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Of == "" && sorted[j].Of != "" })
	s := sorted[0].Algorithm + ":" + shorten(sorted[0].Value, 16)
	if len(ds) > 1 {
		s += " (+" + strconv.Itoa(len(ds)-1) + ")"
	}
	return s
}

func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// lockfilesFormats prints the coverage table.
func lockfilesFormats(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("lockfiles formats", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the table as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	table := lockfiles.CoverageTable()
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(table)
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TYPE\tFORMATS READ\tNOTES")
	for _, c := range table {
		formats := strings.Join(c.Formats, ", ")
		if formats == "" {
			formats = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", c.Type, formats, c.Reason)
	}
	return tw.Flush()
}
