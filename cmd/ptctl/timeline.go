package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/timeline"
)

// runTimeline implements `ptctl timeline`: a thin client over the proxy's
// read-only forensic incident-timeline API (Task 77). It reconstructs the
// unified, chronologically-ordered, deduplicated event history for a coordinate,
// tenant, identity, or incident ID, rendering it as an aligned table (default),
// raw JSON, or the server's Markdown forensic report (--markdown).
func runTimeline(args []string) error {
	fs := flag.NewFlagSet("timeline", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	var (
		coordinate = fs.String("coordinate", "", "scope to a package coordinate (name[@version]; a bare name matches all versions)")
		identity   = fs.String("identity", "", "scope to an actor/identity")
		incident   = fs.String("incident", "", "scope to a lockdown/approval incident ID")
		since      = fs.String("since", "", "only events at or after this RFC3339 timestamp")
		until      = fs.String("until", "", "only events at or before this RFC3339 timestamp")
		limit      = fs.Int("limit", 0, "maximum events to return (0 = server default)")
		all        = fs.Bool("all", false, "return the whole timeline (no scope selector required)")
		asJSON     = fs.Bool("json", false, "emit the raw JSON result instead of a table")
		asMarkdown = fs.Bool("markdown", false, "emit the server-rendered Markdown forensic report")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl timeline [flags]")
		fmt.Fprintln(os.Stderr, "\nReconstruct the forensic incident timeline for a coordinate, tenant, identity, or incident.")
		fmt.Fprintln(os.Stderr, "\nFlags:")
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nExamples:")
		fmt.Fprintln(os.Stderr, "  # Everything that happened to a package, newest detail first, as a forensic report:")
		fmt.Fprintln(os.Stderr, "  ptctl timeline --coordinate evil@2.0.0 --markdown")
		fmt.Fprintln(os.Stderr, "  # The full chain of an incident (lockdown/approval), as JSON for an evidence bundle:")
		fmt.Fprintln(os.Stderr, "  ptctl timeline --incident INC-42 --json")
		fmt.Fprintln(os.Stderr, "  # An actor's activity within a tenant scope:")
		fmt.Fprintln(os.Stderr, "  ptctl timeline --tenant acme --identity alice@example.com")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *coordinate == "" && g.tenant == "" && *identity == "" && *incident == "" && !*all {
		fs.Usage()
		return fmt.Errorf("a scope is required: one of --coordinate, --tenant, --identity, --incident (or --all)")
	}

	c, err := newClient(g)
	if err != nil {
		return err
	}

	query := map[string]string{
		"coordinate": strings.TrimSpace(*coordinate),
		"tenant":     c.tenant,
		"identity":   strings.TrimSpace(*identity),
		"incident":   strings.TrimSpace(*incident),
		"since":      strings.TrimSpace(*since),
		"until":      strings.TrimSpace(*until),
	}
	if *limit > 0 {
		query["limit"] = strconv.Itoa(*limit)
	}
	if *all {
		query["all"] = "true"
	}

	// Markdown is rendered server-side; stream it straight through.
	if *asMarkdown {
		query["format"] = "md"
		md, err := c.getText(c.adminURL("api/timeline", query))
		if err != nil {
			return err
		}
		fmt.Fprint(os.Stdout, md)
		return nil
	}

	var res timeline.Result
	if err := c.getJSON(c.adminURL("api/timeline", query), &res); err != nil {
		return err
	}
	if *asJSON {
		return emitJSON(res)
	}
	renderTimeline(os.Stdout, res)
	return nil
}

// renderTimeline prints the events as an aligned table followed by a summary.
func renderTimeline(w io.Writer, res timeline.Result) {
	if len(res.Events) == 0 {
		fmt.Fprintln(w, "(no correlated events for this scope)")
	} else {
		cols := []string{"TIME (UTC)", "SOURCE", "CATEGORY", "DECISION", "ACTOR", "COORDINATE", "SUMMARY", "PROOF"}
		rows := make([][]string, 0, len(res.Events))
		for _, ev := range res.Events {
			src := string(ev.Source)
			if len(ev.Corroborated) > 1 {
				src = strings.Join(ev.Corroborated, "+")
			}
			proof := "-"
			if ev.Proof != nil && ev.Proof.AuditSeq != 0 {
				proof = "seq " + strconv.FormatUint(ev.Proof.AuditSeq, 10)
			}
			rows = append(rows, []string{
				ev.Time.UTC().Format("2006-01-02 15:04:05"),
				src,
				string(ev.Category),
				dash(ev.Decision),
				truncate(ev.Actor, 28),
				dash(ev.Coordinate),
				truncate(firstNonEmptyStr(ev.Summary, ev.Kind), 48),
				proof,
			})
		}
		widths := make([]int, len(cols))
		for i, c := range cols {
			widths[i] = len(c)
		}
		for _, r := range rows {
			for i, cell := range r {
				if len(cell) > widths[i] {
					widths[i] = len(cell)
				}
			}
		}
		printRow(w, cols, widths)
		for _, r := range rows {
			printRow(w, r, widths)
		}
	}
	trunc := ""
	if res.Truncated {
		trunc = " (truncated — raise --limit)"
	}
	fmt.Fprintf(w, "\n%d/%d events%s  sources: %s\n", res.Returned, res.Total, trunc, joinEnabledSources(res.Sources))
}

func joinEnabledSources(sources map[string]bool) string {
	on := make([]string, 0, len(sources))
	for k, v := range sources {
		if v {
			on = append(on, k)
		}
	}
	sort.Strings(on)
	if len(on) == 0 {
		return "none"
	}
	return strings.Join(on, ", ")
}

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func firstNonEmptyStr(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
