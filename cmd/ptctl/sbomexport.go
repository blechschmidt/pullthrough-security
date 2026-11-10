package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

// runSBOMExport dispatches the `ptctl sbom-export` subcommands (Task 153): show
// the outbound SBOM/findings federation status, or trigger an immediate export
// sweep on the target node.
func runSBOMExport(args []string) error {
	action := "status"
	if len(args) > 0 {
		action = args[0]
		args = args[1:]
	}
	switch action {
	case "status":
		return sbomExportStatusCmd(args)
	case "run":
		return sbomExportRunCmd(args)
	case "-h", "--help", "help":
		sbomExportUsage(os.Stdout)
		return nil
	default:
		return fmt.Errorf("unknown sbom-export action %q (try: status, run)", action)
	}
}

func sbomExportUsage(w *os.File) {
	fmt.Fprintln(w, "usage: ptctl sbom-export <status|run> [flags]")
	fmt.Fprintln(w, "  status   show configured sinks, sweep interval, leader state, and counters (default)")
	fmt.Fprintln(w, "  run      trigger an immediate export sweep on the target node (bypasses the HA leader gate)")
	fmt.Fprintln(w, "flags: -json (machine-readable), plus the global -url/-token flags")
}

func sbomExportClient(args []string, name string) (*client, bool, error) {
	fs := flag.NewFlagSet("sbom-export "+name, flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	jsonOut := fs.Bool("json", false, "emit machine-readable JSON")
	fs.Usage = func() { sbomExportUsage(os.Stderr) }
	if err := fs.Parse(args); err != nil {
		return nil, false, err
	}
	c, err := newClient(g)
	if err != nil {
		return nil, false, err
	}
	return c, *jsonOut, nil
}

// sbomExport* response shapes mirror the admin JSON (internal/sbomexport.Status /
// RunReport). Only the fields ptctl renders are declared.
type sbomExportRunReport struct {
	Reports  int `json:"reports"`
	Uploaded int `json:"uploaded"`
	Failed   int `json:"failed"`
	Skipped  int `json:"skipped"`
}

type sbomExportMetrics struct {
	Uploads          uint64            `json:"Uploads"`
	Failures         uint64            `json:"Failures"`
	Retries          uint64            `json:"Retries"`
	Skipped          uint64            `json:"Skipped"`
	UploadsByTarget  map[string]uint64 `json:"UploadsByTarget"`
	FailuresByTarget map[string]uint64 `json:"FailuresByTarget"`
}

type sbomExportStatusBody struct {
	Enabled   bool                `json:"enabled"`
	Sinks     []string            `json:"sinks"`
	Interval  string              `json:"interval"`
	Leader    bool                `json:"leader"`
	LastRunAt time.Time           `json:"lastRunAt"`
	LastRun   sbomExportRunReport `json:"lastRun"`
	Metrics   sbomExportMetrics   `json:"metrics"`
}

func sbomExportStatusCmd(args []string) error {
	c, jsonOut, err := sbomExportClient(args, "status")
	if err != nil {
		return err
	}
	var body sbomExportStatusBody
	if err := c.getJSON(c.adminURL("api/sbomexport", nil), &body); err != nil {
		return err
	}
	if jsonOut {
		return printJSON(body)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "Outbound SBOM/findings federation\t")
	fmt.Fprintf(tw, "  Enabled\t%s\n", yesNo(body.Enabled))
	if !body.Enabled {
		return tw.Flush()
	}
	fmt.Fprintf(tw, "  Sinks\t%s\n", strings.Join(sinksOrNone(body.Sinks), ", "))
	fmt.Fprintf(tw, "  Sweep interval\t%s\n", orWord(body.Interval, "manual only"))
	fmt.Fprintf(tw, "  Leader\t%s\n", yesNo(body.Leader))
	if !body.LastRunAt.IsZero() {
		fmt.Fprintf(tw, "  Last sweep\t%s\n", body.LastRunAt.Format(time.RFC3339))
		fmt.Fprintf(tw, "    Reports\t%d\n", body.LastRun.Reports)
		fmt.Fprintf(tw, "    Uploaded\t%d\n", body.LastRun.Uploaded)
		fmt.Fprintf(tw, "    Failed\t%d\n", body.LastRun.Failed)
		fmt.Fprintf(tw, "    Skipped\t%d\n", body.LastRun.Skipped)
	}
	fmt.Fprintf(tw, "  Uploads (total)\t%d\n", body.Metrics.Uploads)
	fmt.Fprintf(tw, "  Failures (total)\t%d\n", body.Metrics.Failures)
	fmt.Fprintf(tw, "  Retries (total)\t%d\n", body.Metrics.Retries)
	for _, target := range sortedKeys(body.Metrics.UploadsByTarget) {
		fmt.Fprintf(tw, "    %s uploads\t%d\n", target, body.Metrics.UploadsByTarget[target])
	}
	return tw.Flush()
}

func sbomExportRunCmd(args []string) error {
	c, jsonOut, err := sbomExportClient(args, "run")
	if err != nil {
		return err
	}
	var r sbomExportRunReport
	if err := c.postJSON(c.adminURL("api/sbomexport/run", nil), map[string]any{}, &r); err != nil {
		return err
	}
	if jsonOut {
		return printJSON(r)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SBOM/findings export sweep complete\t")
	fmt.Fprintf(tw, "  Reports\t%d\n", r.Reports)
	fmt.Fprintf(tw, "  Uploaded\t%d\n", r.Uploaded)
	fmt.Fprintf(tw, "  Failed\t%d\n", r.Failed)
	fmt.Fprintf(tw, "  Skipped\t%d\n", r.Skipped)
	return tw.Flush()
}

func sinksOrNone(s []string) []string {
	if len(s) == 0 {
		return []string{"(none)"}
	}
	return s
}

func orWord(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func sortedKeys(m map[string]uint64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
