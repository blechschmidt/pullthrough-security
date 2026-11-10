package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

// runSbomDiff implements `ptctl sbom-diff [flags] <coordinate> [vA] [vB]`: it asks
// the proxy what changed between two versions of a package — the added/removed/
// version-bumped transitive dependencies, newly-introduced licenses and
// namespaces, and net-new vulnerabilities — together with the derived drift-risk
// score. It answers the self-service question "what changed since the version I
// last approved?". When vA/vB are omitted it diffs the two most recent versions
// the proxy has observed for the coordinate.
//
// It is HTTP-only and read-only: it calls the admin GET /api/sbomdiff/diff
// endpoint and prints the rendered Markdown report (default) or the raw JSON diff
// (-json).
func runSbomDiff(args []string) error {
	fs := flag.NewFlagSet("sbom-diff", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	var (
		ecosystem = fs.String("ecosystem", "", "package ecosystem (npm|pip|cargo|go|nuget|maven|...) — required")
		asJSON    = fs.Bool("json", false, "emit the raw JSON diff instead of the Markdown report")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl sbom-diff [flags] --ecosystem <eco> <coordinate> [fromVersion] [toVersion]")
		fmt.Fprintln(os.Stderr, "Show what changed between two versions of a package (dependency drift).")
		fmt.Fprintln(os.Stderr, "When fromVersion/toVersion are omitted, the two most recent observed versions are diffed.")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	coord := strings.TrimSpace(fs.Arg(0))
	if coord == "" {
		fs.Usage()
		return fmt.Errorf("a coordinate (package name) is required")
	}
	eco := strings.TrimSpace(*ecosystem)
	if eco == "" {
		fs.Usage()
		return fmt.Errorf("--ecosystem is required")
	}
	from := strings.TrimSpace(fs.Arg(1))
	to := strings.TrimSpace(fs.Arg(2))

	c, err := newClient(g)
	if err != nil {
		return err
	}

	query := map[string]string{
		"ecosystem": eco,
		"package":   coord,
		"tenant":    c.tenant,
		"from":      from,
		"to":        to,
	}
	if *asJSON {
		query["format"] = "json"
		var diff json.RawMessage
		u := c.adminURL("api/sbomdiff/diff", query)
		if err := c.getJSON(u, &diff); err != nil {
			return sbomDiffError(err, coord)
		}
		var pretty strings.Builder
		enc := json.NewEncoder(&pretty)
		enc.SetIndent("", "  ")
		if err := enc.Encode(diff); err != nil {
			return err
		}
		fmt.Fprint(os.Stdout, pretty.String())
		return nil
	}

	query["format"] = "md"
	u := c.adminURL("api/sbomdiff/diff", query)
	report, err := c.getText(u)
	if err != nil {
		return sbomDiffError(err, coord)
	}
	fmt.Fprint(os.Stdout, report)
	if !strings.HasSuffix(report, "\n") {
		fmt.Fprintln(os.Stdout)
	}
	return nil
}

// sbomDiffError adds actionable context to the common failure modes (subsystem
// off, or not enough history yet).
func sbomDiffError(err error, coord string) error {
	if ae, ok := err.(*apiError); ok {
		switch ae.Status {
		case 404:
			return fmt.Errorf("no drift available for %q: the SBOM-diff subsystem is disabled or fewer than two versions of this coordinate have been pulled through the proxy", coord)
		}
	}
	return err
}
