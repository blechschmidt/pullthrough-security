package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// runConfig implements `ptctl config`: it generates package-manager
// configuration snippets for the proxy's enabled backends (auto-discovered) or
// for an explicit set of name=type backends. Output goes to stdout (annotated)
// or, with -output, to conventionally-named files in a directory.
func runConfig(args []string) error {
	// `config validate` and `config drift` are sub-actions of the config command
	// (Task 85): preflight a candidate config / the live config, and detect
	// on-disk drift. Everything else is snippet generation.
	if len(args) > 0 {
		switch args[0] {
		case "validate":
			return runConfigValidate(args[1:])
		case "drift":
			return runConfigDrift(args[1:])
		}
	}

	fs := flag.NewFlagSet("config", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	var (
		outDir  = fs.String("output", "", "write snippets to files in this directory instead of stdout")
		manager = fs.String("manager", "", "comma-separated backend names or types to include (default: all)")
		force   = fs.Bool("force", false, "overwrite existing files when writing with -output")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl config [flags] [name=type ...]")
		fmt.Fprintln(os.Stderr, "Generate package-manager config snippets for the proxy's backends.")
		fmt.Fprintln(os.Stderr, "With no positional args, backends are auto-discovered from the proxy.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Sub-actions:")
		fmt.Fprintln(os.Stderr, "  ptctl config validate [file]  validate a candidate config (or the live config)")
		fmt.Fprintln(os.Stderr, "  ptctl config drift            report on-disk vs running config drift")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	c, err := newClient(g)
	if err != nil {
		return err
	}

	backends, err := resolveBackends(c, fs.Args())
	if err != nil {
		return err
	}
	backends = filterBackends(backends, *manager)
	if len(backends) == 0 {
		return fmt.Errorf("no backends matched -manager %q (available: %s)", *manager, "run 'ptctl selftest' to list them")
	}

	host := ""
	if u, perr := url.Parse(c.baseURL); perr == nil {
		host = u.Host
	}
	ctx := snippetContext{
		proxyBase: c.baseURL,
		host:      host,
		tenant:    c.tenant,
		token:     c.token,
	}

	var all []snippet
	for _, b := range backends {
		all = append(all, snippetsFor(ctx, b)...)
	}

	if *outDir != "" {
		return writeSnippets(*outDir, all, *force)
	}
	printSnippets(os.Stdout, ctx, backends, all)
	return nil
}

// filterBackends keeps only backends whose name or type matches one of the
// comma-separated tokens in sel. An empty sel keeps everything.
func filterBackends(in []backend, sel string) []backend {
	sel = strings.TrimSpace(sel)
	if sel == "" {
		return in
	}
	want := map[string]bool{}
	for _, t := range strings.Split(sel, ",") {
		if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
			want[t] = true
		}
	}
	out := make([]backend, 0, len(in))
	for _, b := range in {
		if want[strings.ToLower(b.Name)] || want[strings.ToLower(b.Type)] {
			out = append(out, b)
		}
	}
	return out
}

// printSnippets renders the snippets to w as annotated Markdown-ish text: a
// header noting the tenant/proxy, then each snippet as a titled fenced block
// with notes.
func printSnippets(w *os.File, ctx snippetContext, backends []backend, snippets []snippet) {
	fmt.Fprintf(w, "# Pull-through proxy client configuration\n")
	fmt.Fprintf(w, "# proxy: %s\n", ctx.proxyBase)
	if ctx.tenant != "" {
		fmt.Fprintf(w, "# tenant: %s\n", ctx.tenant)
	}
	fmt.Fprintf(w, "# backends: %s\n\n", backendSummary(backends))
	for _, s := range snippets {
		fmt.Fprintf(w, "## %s\n", s.Title)
		for _, n := range s.Notes {
			fmt.Fprintf(w, "# %s\n", n)
		}
		if s.Body != "" {
			fmt.Fprintf(w, "```%s\n%s", s.Lang, s.Body)
			if !strings.HasSuffix(s.Body, "\n") {
				fmt.Fprintln(w)
			}
			fmt.Fprintln(w, "```")
		}
		fmt.Fprintln(w)
	}
}

// writeSnippets writes each snippet that has both a File and a Body into dir.
// Filenames are prefixed with the backend name to avoid collisions when several
// backends share a conventional filename (e.g. two npm registries).
func writeSnippets(dir string, snippets []snippet, force bool) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}
	written := 0
	for _, s := range snippets {
		if s.File == "" || s.Body == "" {
			continue
		}
		name := sanitizeFilename(s.Title) + "_" + s.File
		path := filepath.Join(dir, name)
		if !force {
			if _, err := os.Stat(path); err == nil {
				return fmt.Errorf("refusing to overwrite %s (pass -force to overwrite)", path)
			}
		}
		// Generated credential files should not be world-readable.
		if err := os.WriteFile(path, []byte(s.Body), 0o600); err != nil {
			return fmt.Errorf("writing %s: %w", path, err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", path)
		written++
	}
	if written == 0 {
		return fmt.Errorf("no file-backed snippets to write for the selected backends")
	}
	return nil
}

// sanitizeFilename turns a snippet title into a filesystem-safe slug.
func sanitizeFilename(title string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(title) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return strings.Trim(collapseDashes(b.String()), "-")
}

func collapseDashes(s string) string {
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	return s
}

// backendSummary renders "name(type), name(type)" for a header line.
func backendSummary(backends []backend) string {
	parts := make([]string, 0, len(backends))
	for _, b := range backends {
		parts = append(parts, fmt.Sprintf("%s(%s)", b.Name, orUnknown(b.Type)))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}
