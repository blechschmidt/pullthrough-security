package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/metering"
)

// runUsage fetches a per-tenant usage/chargeback report from the admin metering
// endpoint and renders it as a table (default), raw JSON, CSV, or Markdown.
//
// By default the report is scoped to --tenant. Pass --all-tenants to report
// across every tenant (requires an operator/admin-capable token; a tenant-viewer
// is hard-scoped to its own tenant by the portal regardless).
func runUsage(args []string) error {
	fs := flag.NewFlagSet("usage", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	var (
		start      = fs.String("start", "", "report start, RFC3339 or unix seconds (default: earliest retained)")
		end        = fs.String("end", "", "report end, RFC3339 or unix seconds (default: now)")
		gran       = fs.String("granularity", "day", "period granularity: hour|day|total")
		format     = fs.String("format", "table", "output format: table|json|csv|markdown")
		allTenants = fs.Bool("all-tenants", false, "report across all tenants instead of --tenant")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl usage [flags]")
		fmt.Fprintln(os.Stderr, "\nShow the per-tenant usage metering & chargeback report (Task 84).")
		fmt.Fprintln(os.Stderr, "\nFlags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	c, err := newClient(g)
	if err != nil {
		return err
	}

	tenant := c.tenant
	if *allTenants {
		tenant = ""
	}
	query := map[string]string{
		"tenant":      tenant,
		"start":       *start,
		"end":         *end,
		"granularity": *gran,
	}

	switch *format {
	case "csv":
		query["format"] = "csv"
		text, err := c.getText(c.adminURL("api/metering/usage", query))
		if err != nil {
			return err
		}
		fmt.Print(text)
		return nil
	case "markdown", "md":
		query["format"] = "markdown"
		text, err := c.getText(c.adminURL("api/metering/usage", query))
		if err != nil {
			return err
		}
		fmt.Print(text)
		return nil
	case "json":
		var rep metering.UsageReport
		if err := c.getJSON(c.adminURL("api/metering/usage", query), &rep); err != nil {
			return err
		}
		return emitJSON(rep)
	default:
		var rep metering.UsageReport
		if err := c.getJSON(c.adminURL("api/metering/usage", query), &rep); err != nil {
			return err
		}
		renderUsageReport(os.Stdout, rep)
		return nil
	}
}

// renderUsageReport prints the per-tenant totals over the range followed by the
// per-period breakdown, as aligned tables.
func renderUsageReport(w io.Writer, rep metering.UsageReport) {
	scope := "all tenants"
	if rep.Tenant != "" {
		scope = "tenant " + rep.Tenant
	}
	fmt.Fprintf(w, "Usage & chargeback (%s)\n", scope)
	fmt.Fprintf(w, "Range: %s → %s  (granularity: %s)\n\n",
		fmtRangeTime(rep.Start), fmtRangeTime(rep.End), rep.Granularity)

	if len(rep.Totals) == 0 {
		fmt.Fprintln(w, "No usage recorded in the selected range.")
		return
	}

	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "TENANT\tREQUESTS\tBYTES SERVED\tSTORAGE\tSCANS\tSCAN COST\tBLOCKED\tQUARANTINED")
	for _, t := range rep.Totals {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%s\t%d\t%d\n",
			t.Tenant, t.Requests, t.BytesServed(), t.StorageBytes,
			t.ScanInvocations, fmtCost(t.ScanCostMicros), t.Blocked, t.Quarantined)
	}
	fmt.Fprintf(tw, "TOTAL\t%d\t%d\t%d\t%d\t%s\t%d\t%d\n",
		rep.Grand.Requests, rep.Grand.BytesServed(), rep.Grand.StorageBytes,
		rep.Grand.ScanInvocations, fmtCost(rep.Grand.ScanCostMicros), rep.Grand.Blocked, rep.Grand.Quarantined)
	tw.Flush()

	if len(rep.Rows) > 0 {
		fmt.Fprintln(w, "\nBy period:")
		pw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		fmt.Fprintln(pw, "TENANT\tPERIOD START\tREQUESTS\tBYTES SERVED\tSCANS\tSCAN COST\tBLOCKED")
		for _, row := range rep.Rows {
			fmt.Fprintf(pw, "%s\t%s\t%d\t%d\t%d\t%s\t%d\n",
				row.Tenant, fmtRangeTime(row.PeriodStart), row.Requests, row.BytesServed(),
				row.ScanInvocations, fmtCost(row.ScanCostMicros), row.Blocked)
		}
		pw.Flush()
	}
}

func fmtRangeTime(t time.Time) string {
	if t.IsZero() {
		return "(unbounded)"
	}
	return t.UTC().Format(time.RFC3339)
}

func fmtCost(micros int64) string {
	return fmt.Sprintf("%.4f", float64(micros)/1_000_000)
}
