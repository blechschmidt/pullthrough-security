package main

import (
	"flag"
	"fmt"
	"os"
)

// configIssue mirrors config.Issue for decoding the admin preflight response.
type configIssue struct {
	Path     string `json:"path"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
}

// configReport mirrors config.Report.
type configReport struct {
	OK          bool          `json:"ok"`
	Errors      int           `json:"errors"`
	Warnings    int           `json:"warnings"`
	Issues      []configIssue `json:"issues"`
	Fingerprint string        `json:"fingerprint"`
}

// configDrift mirrors config.DriftStatus.
type configDrift struct {
	Path              string `json:"path"`
	Drifted           bool   `json:"drifted"`
	RunningConfigHash string `json:"runningConfigHash"`
	CurrentConfigHash string `json:"currentConfigHash"`
	RunningFileHash   string `json:"runningFileHash"`
	CurrentFileHash   string `json:"currentFileHash"`
	Error             string `json:"error"`
}

// runConfigValidate implements `ptctl config validate [file]`: it runs the
// proxy's authoritative configuration validation against a candidate file
// (uploaded inline to the admin preflight endpoint) or, with no file, against
// the live running configuration. It prints every issue with its field path and
// exits non-zero on any error (or, with -strict, any warning) so it can gate a
// deploy. The proxy is reached over HTTP only — no shared filesystem needed.
func runConfigValidate(args []string) error {
	fs := flag.NewFlagSet("config validate", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	var (
		strict = fs.Bool("strict", false, "treat warnings as failures (exit non-zero)")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl config validate [flags] [config-file]")
		fmt.Fprintln(os.Stderr, "Validate a candidate config file, or the live config when no file is given.")
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

	var report configReport
	url := c.adminURL("api/config/validate", nil)
	if file := fs.Arg(0); file != "" {
		data, rerr := os.ReadFile(file)
		if rerr != nil {
			return fmt.Errorf("reading %q: %w", file, rerr)
		}
		body := map[string]string{"content": string(data)}
		if err := c.postJSON(url, body, &report); err != nil {
			return err
		}
		printValidateReport(file, &report)
	} else {
		if err := c.getJSON(url, &report); err != nil {
			return err
		}
		printValidateReport("(live config)", &report)
	}

	if report.Errors > 0 || (*strict && report.Warnings > 0) {
		return fmt.Errorf("validation failed: %d error(s), %d warning(s)", report.Errors, report.Warnings)
	}
	return nil
}

func printValidateReport(label string, r *configReport) {
	if len(r.Issues) == 0 {
		fmt.Printf("config validate: %s is valid (no issues)\n", label)
		return
	}
	for _, is := range r.Issues {
		loc := is.Path
		if loc == "" {
			loc = "(document)"
		}
		fmt.Printf("  [%s] %s: %s\n", is.Severity, loc, is.Message)
	}
	fmt.Printf("config validate: %s — %d error(s), %d warning(s)\n", label, r.Errors, r.Warnings)
}

// runConfigDrift implements `ptctl config drift`: it reports whether the proxy's
// on-disk configuration has diverged from what the process is running. Exits
// non-zero when drift is detected, so it can be used as a monitoring probe.
func runConfigDrift(args []string) error {
	fs := flag.NewFlagSet("config drift", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl config drift [flags]")
		fmt.Fprintln(os.Stderr, "Report whether the proxy's on-disk config has drifted from the running process.")
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

	var st configDrift
	if err := c.getJSON(c.adminURL("api/config/drift", nil), &st); err != nil {
		return err
	}

	path := st.Path
	if path == "" {
		path = "(no config file; defaults + environment)"
	}
	if st.Error != "" {
		fmt.Printf("config drift: DRIFTED — on-disk config no longer loads: %s\n", st.Error)
		return fmt.Errorf("configuration drift detected")
	}
	if st.Drifted {
		fmt.Printf("config drift: DRIFTED — %s differs from the running process\n", path)
		fmt.Printf("  running: %s\n  on-disk: %s\n", short(st.RunningConfigHash), short(st.CurrentConfigHash))
		return fmt.Errorf("configuration drift detected")
	}
	fmt.Printf("config drift: in sync — %s matches the running process (%s)\n", path, short(st.RunningConfigHash))
	return nil
}

// short truncates a hex digest for human-readable output.
func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	if h == "" {
		return "(none)"
	}
	return h
}
