package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/remediation"
)

// runRemediate implements `ptctl remediate --ecosystem <eco> <name> [version]`:
// a thin client over the proxy's dependency-remediation advisor (Task 121). For
// a blocked or flagged artifact it asks the proxy for the nearest safe upgrade
// version that clears the failing gate(s), the findings that version resolves,
// and any it introduces. The default output is a human-readable table; --json
// emits the raw structured advice for CI/automation.
//
// It is HTTP-only and read-only: it calls the admin GET /api/remediation/advise
// endpoint, which reuses the live vulnscan/VEX, license, release-cooldown, and
// dependency-firewall gates to score candidate versions.
func runRemediate(args []string) error {
	fs := flag.NewFlagSet("remediate", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	var (
		ecosystem  = fs.String("ecosystem", "", "package ecosystem (npm|pip|cargo|go|nuget|maven|rubygems|composer) — required")
		gates      = fs.String("gates", "", "comma-separated gate restriction (vulnscan,license,maturity,depfirewall); empty = all")
		max        = fs.Int("max", 0, "bound on the number of newer versions evaluated (0 = server default)")
		prerelease = fs.Bool("prerelease", false, "consider prerelease versions as upgrade targets")
		asJSON     = fs.Bool("json", false, "emit the raw JSON advice instead of the table")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl remediate [flags] --ecosystem <eco> <name> [version]")
		fmt.Fprintln(os.Stderr, "       ptctl remediate [flags] --ecosystem <eco> <name@version>")
		fmt.Fprintln(os.Stderr, "\nCompute the nearest safe upgrade for a blocked/flagged artifact.")
		fmt.Fprintln(os.Stderr, "\nFlags:")
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nExamples:")
		fmt.Fprintln(os.Stderr, "  ptctl remediate --ecosystem npm lodash 4.17.4")
		fmt.Fprintln(os.Stderr, "  ptctl remediate --ecosystem pip requests@2.19.0 --json")
		fmt.Fprintln(os.Stderr, "  ptctl remediate --ecosystem npm lodash@4.17.4 --gates vulnscan")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	eco := strings.TrimSpace(*ecosystem)
	if eco == "" {
		fs.Usage()
		return fmt.Errorf("--ecosystem is required")
	}
	name := strings.TrimSpace(fs.Arg(0))
	version := strings.TrimSpace(fs.Arg(1))
	if name == "" {
		fs.Usage()
		return fmt.Errorf("a package name is required")
	}
	// Accept a "name@version" first positional.
	if version == "" {
		if i := strings.LastIndexByte(name, '@'); i > 0 {
			version = name[i+1:]
			name = name[:i]
		}
	}
	if version == "" {
		fs.Usage()
		return fmt.Errorf("a flagged version is required (as a second argument or name@version)")
	}

	c, err := newClient(g)
	if err != nil {
		return err
	}

	query := map[string]string{
		"ecosystem": eco,
		"name":      name,
		"version":   version,
		"tenant":    c.tenant,
	}
	if gs := strings.TrimSpace(*gates); gs != "" {
		query["gates"] = gs
	}
	if *max > 0 {
		query["max"] = fmt.Sprintf("%d", *max)
	}
	if *prerelease {
		query["prerelease"] = "true"
	}

	var advice remediation.Advice
	if err := c.getJSON(c.adminURL("api/remediation/advise", query), &advice); err != nil {
		return remediateError(err, eco, name)
	}
	if *asJSON {
		return emitJSON(advice)
	}
	fmt.Fprint(os.Stdout, advice.Table())
	return nil
}

// remediateError adds actionable context to the common failure modes.
func remediateError(err error, eco, name string) error {
	if ae, ok := err.(*apiError); ok && ae.Status == 404 {
		return fmt.Errorf("remediation advisor is not enabled on the proxy (or no such route) for %s/%s", eco, name)
	}
	return err
}
