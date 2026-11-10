package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/presets"
)

// runVerifyConfigCommand is the `verify-config` subcommand: the single
// authoritative configuration-validation pass (types, ranges, cross-field
// invariants, unknown/typo'd keys in strict mode, and inter-subsystem
// consistency), run against a candidate config file before it is rolled out. It
// is the server-side twin of `ptctl config validate` and the admin preflight
// endpoint, all sharing internal/config's validation.
//
// It prints every issue with its field path and exits non-zero when any
// error-severity issue is present, so it can be wired into CI or a pre-deploy
// gate. Warnings do not fail the check (use -strict to treat them as failures).
func runVerifyConfigCommand(args []string) error {
	// `verify-config preset ...` is a nested subcommand family: it dry-runs a
	// curated compliance preset against a candidate/running config (Task 88).
	if len(args) > 0 && args[0] == "preset" {
		return runVerifyConfigPresetCommand(args[1:])
	}

	fs := flag.NewFlagSet("verify-config", flag.ContinueOnError)
	var (
		configPath = fs.String("config", "", "path to the candidate YAML configuration file (required)")
		asJSON     = fs.Bool("json", false, "emit the validation report as JSON")
		strict     = fs.Bool("strict", false, "treat warnings as failures (exit non-zero)")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: pullthrough verify-config -config <path> [-json] [-strict]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" && fs.NArg() > 0 {
		*configPath = fs.Arg(0)
	}
	if *configPath == "" {
		fs.Usage()
		return fmt.Errorf("verify-config: -config is required")
	}

	report, err := config.CheckFile(*configPath)
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return err
		}
	} else {
		printConfigReport(os.Stdout, *configPath, report)
	}

	if report.Errors > 0 || (*strict && report.Warnings > 0) {
		return fmt.Errorf("verify-config: %d error(s), %d warning(s)", report.Errors, report.Warnings)
	}
	return nil
}

// runVerifyConfigPresetCommand implements `verify-config preset <action>`:
//
//	verify-config preset list
//	verify-config preset diff <name> [-config <path>] [-json]
//
// `diff` dry-runs the named preset against the configuration loaded from -config
// (or the built-in defaults when omitted), printing exactly what it would change
// and validating the projected configuration — the server-side twin of
// `ptctl preset diff`.
func runVerifyConfigPresetCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("verify-config preset: an action is required (list, diff)")
	}
	action := args[0]
	rest := args[1:]

	switch action {
	case "list":
		fs := flag.NewFlagSet("verify-config preset list", flag.ContinueOnError)
		asJSON := fs.Bool("json", false, "emit the preset list as JSON")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		list := presets.List()
		if *asJSON {
			return json.NewEncoder(os.Stdout).Encode(list)
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tVERSION\tSETTINGS\tSTANDARD")
		for _, p := range list {
			fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", p.Name, p.Version, p.Settings, p.Standard)
		}
		return tw.Flush()

	case "diff":
		fs := flag.NewFlagSet("verify-config preset diff", flag.ContinueOnError)
		configPath := fs.String("config", "", "path to the YAML configuration to diff against (defaults to built-in defaults)")
		asJSON := fs.Bool("json", false, "emit the diff as JSON")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			return fmt.Errorf("verify-config preset diff: a preset name is required (try: %v)", presets.Names())
		}
		name := fs.Arg(0)
		preset, err := presets.Get(name)
		if err != nil {
			return err
		}

		var running *config.Config
		if *configPath != "" {
			running, err = config.Load(*configPath)
			if err != nil {
				return err
			}
		} else {
			def := config.Default()
			running = &def
		}

		diff, err := preset.Diff(running)
		if err != nil {
			return err
		}
		if *asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(diff)
		}
		printPresetDiff(os.Stdout, diff)
		if diff.Validation != nil && !diff.Validation.OK {
			return fmt.Errorf("verify-config preset diff: projected configuration is invalid (%d error(s))", diff.Validation.Errors)
		}
		return nil

	default:
		return fmt.Errorf("verify-config preset: unknown action %q (try: list, diff)", action)
	}
}

// printPresetDiff renders a preset dry-run diff as human-readable text.
func printPresetDiff(w *os.File, d presets.Diff) {
	fmt.Fprintf(w, "Preset: %s (%s) v%s\n", d.Title, d.Preset, d.Version)
	fmt.Fprintf(w, "Standard: %s\n", d.Standard)
	fmt.Fprintf(w, "Controls satisfied: %v\n", d.Controls)
	fmt.Fprintf(w, "Changes: %d changed, %d unchanged\n\n", d.Changed, d.Unchanged)

	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "  \tSETTING\tCURRENT\tPROPOSED\tCLAUSE")
	for _, s := range d.Settings {
		marker := " "
		if s.Changed {
			marker = "~"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", marker, s.Path, s.Current, s.Proposed, s.Clause)
	}
	tw.Flush()

	if d.Validation != nil {
		fmt.Fprintf(w, "\nProjected config validation: %d error(s), %d warning(s)\n", d.Validation.Errors, d.Validation.Warnings)
		for _, is := range d.Validation.Issues {
			fmt.Fprintf(w, "  [%s] %s: %s\n", is.Severity, is.Path, is.Message)
		}
	}
}

// printConfigReport renders a validation report as human-readable text.
func printConfigReport(w *os.File, path string, r *config.Report) {
	if len(r.Issues) == 0 {
		fmt.Fprintf(w, "verify-config: %s is valid (no issues)\n", path)
		return
	}
	for _, is := range r.Issues {
		loc := is.Path
		if loc == "" {
			loc = "(document)"
		}
		fmt.Fprintf(w, "  [%s] %s: %s\n", is.Severity, loc, is.Message)
	}
	fmt.Fprintf(w, "verify-config: %s — %d error(s), %d warning(s)\n", path, r.Errors, r.Warnings)
}
