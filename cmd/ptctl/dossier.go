package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/dossier"
)

// runDossier implements `ptctl dossier <eco> <coordinate>`: a thin client over
// the proxy's read-only per-coordinate security dossier API (Task 87). It folds
// every wired subsystem's view of one artifact — provenance/source commit,
// risk, findings, vulnerabilities, license, signatures, approvals,
// reproducible-build, SBOM drift, and the correlated timeline — into one triage
// card. The default output is a human summary; --markdown streams the
// server-rendered forensic report and --json emits the raw document.
func runDossier(args []string) error {
	fs := flag.NewFlagSet("dossier", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	var (
		version    = fs.String("version", "", "pin an explicit version (overrides one embedded in the coordinate)")
		asJSON     = fs.Bool("json", false, "emit the raw JSON dossier instead of a summary")
		asMarkdown = fs.Bool("markdown", false, "emit the server-rendered Markdown triage report")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl dossier [flags] <ecosystem> <coordinate>")
		fmt.Fprintln(os.Stderr, "       ptctl dossier [flags] <coordinate>   (ecosystem optional)")
		fmt.Fprintln(os.Stderr, "\nAssemble the complete security story (\"360 view\") for one artifact coordinate.")
		fmt.Fprintln(os.Stderr, "\nFlags:")
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nExamples:")
		fmt.Fprintln(os.Stderr, "  ptctl dossier npm evil@1.0.0")
		fmt.Fprintln(os.Stderr, "  ptctl dossier npm lodash@4.17.21 --markdown")
		fmt.Fprintln(os.Stderr, "  ptctl dossier pypi requests --json")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Accept either "<eco> <coordinate>" or a single "<coordinate>".
	var eco, coord string
	switch fs.NArg() {
	case 0:
		fs.Usage()
		return fmt.Errorf("a coordinate is required")
	case 1:
		coord = strings.TrimSpace(fs.Arg(0))
	default:
		eco = strings.TrimSpace(fs.Arg(0))
		coord = strings.TrimSpace(fs.Arg(1))
	}
	if coord == "" {
		fs.Usage()
		return fmt.Errorf("a coordinate is required")
	}

	c, err := newClient(g)
	if err != nil {
		return err
	}

	query := map[string]string{
		"ecosystem":  eco,
		"coordinate": coord,
		"tenant":     c.tenant,
		"version":    strings.TrimSpace(*version),
	}

	if *asMarkdown {
		query["format"] = "md"
		md, err := c.getText(c.adminURL("api/dossier", query))
		if err != nil {
			return err
		}
		fmt.Fprint(os.Stdout, md)
		return nil
	}

	var d dossier.Dossier
	if err := c.getJSON(c.adminURL("api/dossier", query), &d); err != nil {
		return err
	}
	if *asJSON {
		return emitJSON(d)
	}
	renderDossier(os.Stdout, &d)
	return nil
}

// renderDossier prints a compact, human-first triage summary.
func renderDossier(w io.Writer, d *dossier.Dossier) {
	coord := d.Coordinate
	if d.Ecosystem != "" {
		coord = d.Ecosystem + "/" + coord
	}
	fmt.Fprintf(w, "Dossier: %s\n", coord)
	fmt.Fprintf(w, "Verdict: %s", strings.ToUpper(d.Headline.Verdict))
	if d.Headline.RiskBand != "" {
		fmt.Fprintf(w, "  ·  risk %d (%s)", d.Headline.RiskScore, d.Headline.RiskBand)
	}
	fmt.Fprintln(w)
	if d.Headline.Summary != "" {
		fmt.Fprintf(w, "%s\n", d.Headline.Summary)
	}
	for _, r := range d.Headline.Reasons {
		fmt.Fprintf(w, "  - %s\n", r)
	}
	fmt.Fprintln(w)

	if d.Digest != "" {
		fmt.Fprintf(w, "  digest:    %s\n", d.Digest)
	}
	if d.Provenance != nil {
		p := d.Provenance
		fmt.Fprintf(w, "  source:    %s %s (verified=%v, mismatch=%v)\n",
			dash(shortSha12(p.SourceCommit)), dash(p.RepositoryURL), p.SourceVerified, p.ProvenanceMismatch)
		if p.DownstreamPaths > 0 {
			fmt.Fprintf(w, "  blast:     %d downstream paths (%d direct)\n", p.DownstreamPaths, p.DirectDependents)
		}
	}
	if d.Vulns != nil {
		v := d.Vulns
		fmt.Fprintf(w, "  vulns:     %d (%dC/%dH/%dM/%dL) maxCVSS %.1f%s\n",
			v.Total, v.Critical, v.High, v.Medium, v.Low, v.MaxCVSS, quarantineNote(v.Quarantined))
	}
	if d.License != nil {
		fmt.Fprintf(w, "  license:   %s %s\n", d.License.Disposition, strings.Join(d.License.Licenses, ", "))
	}
	if d.Signature != nil {
		fmt.Fprintf(w, "  signature: %s\n", d.Signature.Status)
	}
	if d.Reproduce != nil {
		fmt.Fprintf(w, "  rebuild:   %s\n", d.Reproduce.Verdict)
	}
	if d.SbomDrift != nil {
		fmt.Fprintf(w, "  sbomDrift: %.1f/100 (%s→%s)\n", d.SbomDrift.DriftScore, dash(d.SbomDrift.FromVersion), dash(d.SbomDrift.ToVersion))
	}
	if d.Findings != nil {
		fmt.Fprintf(w, "  findings:  %d (%d blocking, worst %s)\n", d.Findings.Total, d.Findings.Blocking, dash(d.Findings.Worst))
	}
	if d.Approvals != nil {
		fmt.Fprintf(w, "  approvals: %d active, %d pending\n", d.Approvals.Active, d.Approvals.Pending)
	}
	if d.Timeline != nil {
		fmt.Fprintf(w, "  timeline:  %d events%s\n", d.Timeline.Returned, provableNote(d.Timeline.Provable))
	}
	fmt.Fprintln(w)

	// Source coverage, so the reader can tell "clean" from "not wired".
	on := make([]string, 0, len(d.Sources))
	for _, s := range d.Sources {
		on = append(on, fmt.Sprintf("%s=%s", s.Source, s.Status))
	}
	sort.Strings(on)
	prefix := "sources"
	if d.Partial {
		prefix = "sources (PARTIAL)"
	}
	fmt.Fprintf(w, "%s: %s\n", prefix, strings.Join(on, " "))
}

func quarantineNote(q bool) string {
	if q {
		return " [QUARANTINED]"
	}
	return ""
}

func provableNote(p bool) string {
	if p {
		return " (Merkle-provable)"
	}
	return ""
}

func shortSha12(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
