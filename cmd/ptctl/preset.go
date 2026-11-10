package main

import (
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/blechschmidt/pullthrough-security/internal/presets"
)

// runPreset implements `ptctl preset {list|diff|apply} <name>`: the client
// surface for the curated compliance policy presets (Task 88). It is HTTP-only,
// calling the admin /api/presets* endpoints.
//
// Actions:
//
//	list                 list the available vetted presets
//	diff  <name>         dry-run a preset: show exactly what it would change
//	apply <name>         apply a preset to the proxy's on-disk configuration
//
// `apply` requires the administer capability on the proxy and is recorded in the
// tamper-evident audit log; it previews the change server-side, refuses to apply
// an invalid projection, and snapshots the previous config to a .bak file.
func runPreset(args []string) error {
	if len(args) == 0 {
		return presetUsageErr()
	}
	action := args[0]
	rest := args[1:]
	switch action {
	case "list":
		return presetList(rest)
	case "diff":
		return presetDiff(rest)
	case "apply":
		return presetApply(rest)
	case "-h", "--help", "help":
		presetUsage(os.Stdout)
		return nil
	default:
		return fmt.Errorf("unknown preset action %q (try: list, diff, apply)", action)
	}
}

func presetUsageErr() error {
	presetUsage(os.Stderr)
	return fmt.Errorf("an action is required")
}

func presetUsage(w *os.File) {
	fmt.Fprint(w, `ptctl preset <action> [name] [flags]

Curated compliance policy presets (Task 88): vetted SLSA / NIST SSDF / hardened
baselines applied as one self-contained bundle across the proxy's admission gates.

Actions:
  list           list the available vetted presets and the controls they satisfy
  diff  <name>   dry-run a preset: show exactly what it would change vs the
                 running config, plus the projected-config validation
  apply <name>   apply a preset to the proxy's on-disk configuration (admin-only,
                 audited; previews and validates server-side before writing)

Flags:
  -json          emit machine-readable JSON (list, diff)

Global flags (e.g. -url, -token) follow the action.
`)
}

func presetClient(args []string, name string, extra func(*flag.FlagSet)) (*client, *flag.FlagSet, error) {
	fs := flag.NewFlagSet("preset "+name, flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	if extra != nil {
		extra(fs)
	}
	if err := fs.Parse(args); err != nil {
		return nil, nil, err
	}
	c, err := newClient(g)
	if err != nil {
		return nil, nil, err
	}
	return c, fs, nil
}

func presetList(args []string) error {
	var asJSON *bool
	c, _, err := presetClient(args, "list", func(fs *flag.FlagSet) {
		asJSON = fs.Bool("json", false, "emit the preset list as JSON")
	})
	if err != nil {
		return err
	}
	var resp struct {
		Presets []presets.Summary `json:"presets"`
	}
	if err := c.getJSON(c.adminURL("api/presets", nil), &resp); err != nil {
		return err
	}
	if asJSON != nil && *asJSON {
		return printJSON(resp.Presets)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tVERSION\tSETTINGS\tSTANDARD")
	for _, p := range resp.Presets {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", p.Name, p.Version, p.Settings, p.Standard)
	}
	return tw.Flush()
}

func presetDiff(args []string) error {
	var asJSON *bool
	c, fs, err := presetClient(args, "diff", func(fs *flag.FlagSet) {
		asJSON = fs.Bool("json", false, "emit the diff as JSON")
	})
	if err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("preset diff requires a preset name")
	}
	name := fs.Arg(0)
	var resp struct {
		Diff presets.Diff `json:"diff"`
	}
	if err := c.getJSON(c.adminURL("api/presets/diff", map[string]string{"name": name}), &resp); err != nil {
		return err
	}
	if asJSON != nil && *asJSON {
		return printJSON(resp.Diff)
	}
	printPresetDiffClient(resp.Diff)
	return nil
}

func presetApply(args []string) error {
	c, fs, err := presetClient(args, "apply", nil)
	if err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("preset apply requires a preset name")
	}
	name := fs.Arg(0)
	var result presets.ApplyResult
	body := map[string]any{"name": name, "confirm": true}
	if err := c.postJSON(c.adminURL("api/presets/apply", nil), body, &result); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "applied preset %q v%s: %d setting(s) changed\n", result.Preset, result.Version, result.Changed)
	fmt.Fprintf(os.Stdout, "  config written to %s\n", result.Path)
	if result.BackupPath != "" {
		fmt.Fprintf(os.Stdout, "  previous config backed up to %s\n", result.BackupPath)
	}
	if len(result.Controls) > 0 {
		fmt.Fprintf(os.Stdout, "  compliance controls satisfied: %v\n", result.Controls)
	}
	if result.Note != "" {
		fmt.Fprintf(os.Stdout, "  note: %s\n", result.Note)
	}
	return nil
}

// printPresetDiffClient renders a preset dry-run diff as human-readable text.
func printPresetDiffClient(d presets.Diff) {
	fmt.Fprintf(os.Stdout, "Preset: %s (%s) v%s\n", d.Title, d.Preset, d.Version)
	fmt.Fprintf(os.Stdout, "Standard: %s\n", d.Standard)
	fmt.Fprintf(os.Stdout, "Controls satisfied: %v\n", d.Controls)
	fmt.Fprintf(os.Stdout, "Changes: %d changed, %d unchanged\n\n", d.Changed, d.Unchanged)

	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "  \tSETTING\tCURRENT\tPROPOSED\tCLAUSE")
	for _, s := range d.Settings {
		marker := " "
		if s.Changed {
			marker = "~"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", marker, s.Path, s.Current, s.Proposed, s.Clause)
	}
	tw.Flush()

	if d.Validation != nil && !d.Validation.OK {
		fmt.Fprintf(os.Stdout, "\nWARNING: projected configuration is invalid (%d error(s)):\n", d.Validation.Errors)
		for _, is := range d.Validation.Issues {
			fmt.Fprintf(os.Stdout, "  [%s] %s: %s\n", is.Severity, is.Path, is.Message)
		}
	}
}
