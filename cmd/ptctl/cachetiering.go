package main

import (
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// runCacheTiering reports the proxy's hot/cold tiered storage status or triggers
// an on-demand demotion sweep (Task 154). It is a thin client over the admin
// /api/cache/tiering surface:
//
//	ptctl cache-tiering status   # default
//	ptctl cache-tiering sweep
func runCacheTiering(args []string) error {
	fs := flag.NewFlagSet("cache-tiering", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	format := fs.String("format", "table", "output format: table|json")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl cache-tiering [status|sweep] [flags]")
		fmt.Fprintln(os.Stderr, "\nReport hot/cold tiered cache storage status, or trigger a demotion sweep (Task 154).")
		fmt.Fprintln(os.Stderr, "\nSubcommands:")
		fmt.Fprintln(os.Stderr, "  status   show tiering status and cumulative statistics (default)")
		fmt.Fprintln(os.Stderr, "  sweep    demote idle (and over-capacity LRU) hot artifacts to the cold tier now")
		fmt.Fprintln(os.Stderr, "\nFlags:")
		fs.PrintDefaults()
	}

	// Accept an optional leading subcommand before the flags (status|sweep).
	sub := "status"
	if len(args) > 0 && (args[0] == "status" || args[0] == "sweep") {
		sub = args[0]
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *format != "table" && *format != "json" {
		return fmt.Errorf("unknown --format %q (want table or json)", *format)
	}

	c, err := newClient(g)
	if err != nil {
		return err
	}

	switch sub {
	case "status":
		return tieringStatus(c, *format)
	case "sweep":
		return tieringSweep(c, *format)
	default:
		fs.Usage()
		return fmt.Errorf("unknown subcommand %q", sub)
	}
}

func tieringStatus(c *client, format string) error {
	var st cache.TieredStats
	if err := c.getJSON(c.adminURL("api/cache/tiering", nil), &st); err != nil {
		return err
	}
	if format == "json" {
		return printJSON(st)
	}
	if !st.Enabled {
		fmt.Println("Tiered cache storage: disabled")
		fmt.Println("Enable it with cache.tiering.enabled: true (configure a cold backend under cache.tiering.cold).")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "Tiered cache storage\t")
	fmt.Fprintf(tw, "  Promote on read\t%s\n", enabledWord(st.PromoteOnRead))
	if st.DemoteAfterIdle != "" {
		fmt.Fprintf(tw, "  Demote after idle\t%s\n", st.DemoteAfterIdle)
	} else {
		fmt.Fprintln(tw, "  Demote after idle\tdisabled")
	}
	if st.HotMaxBytes > 0 {
		fmt.Fprintf(tw, "  Hot tier cap\t%s\n", humanBytes(st.HotMaxBytes))
	} else {
		fmt.Fprintln(tw, "  Hot tier cap\tunbounded")
	}
	if st.MinAccessesToStayHot > 0 {
		fmt.Fprintf(tw, "  Min accesses to stay hot\t%d\n", st.MinAccessesToStayHot)
	}
	if st.SweepInterval != "" {
		fmt.Fprintf(tw, "  Sweep interval\t%s\n", st.SweepInterval)
	} else {
		fmt.Fprintln(tw, "  Sweep interval\tmanual only")
	}
	fmt.Fprintln(tw, "\t")
	fmt.Fprintf(tw, "  Hot tier\t%d objects, %s\n", st.HotObjects, humanBytes(st.HotBytes))
	fmt.Fprintf(tw, "  Cold tier\t%d objects, %s\n", st.ColdObjects, humanBytes(st.ColdBytes))
	fmt.Fprintln(tw, "\t")
	fmt.Fprintf(tw, "  Hot hits\t%d\n", st.HotHits)
	fmt.Fprintf(tw, "  Cold hits\t%d\n", st.ColdHits)
	fmt.Fprintf(tw, "  Hot hit ratio\t%.1f%%\n", 100*st.HotTierHitRatio)
	fmt.Fprintln(tw, "\t")
	fmt.Fprintf(tw, "  Promotions\t%d\n", st.Promotions)
	fmt.Fprintf(tw, "  Demotions\t%d\n", st.Demotions)
	fmt.Fprintf(tw, "  Promote failures\t%d\n", st.PromoteFailures)
	fmt.Fprintf(tw, "  Demote failures\t%d\n", st.DemoteFailures)
	fmt.Fprintf(tw, "  Sweeps\t%d\n", st.Sweeps)
	if !st.LastSweep.IsZero() {
		fmt.Fprintf(tw, "  Last sweep\t%s\n", st.LastSweep.Format("2006-01-02 15:04:05 MST"))
	}
	return tw.Flush()
}

func tieringSweep(c *client, format string) error {
	var rep cache.TierSweepReport
	if err := c.postJSON(c.adminURL("api/cache/tiering/sweep", nil), struct{}{}, &rep); err != nil {
		return err
	}
	if format == "json" {
		return printJSON(rep)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "Tier demotion sweep complete\t")
	fmt.Fprintf(tw, "  Duration\t%s\n", rep.Duration)
	fmt.Fprintf(tw, "  Hot objects before\t%d\n", rep.HotObjectsBefore)
	fmt.Fprintf(tw, "  Candidates\t%d\n", rep.Candidates)
	fmt.Fprintf(tw, "  Demoted\t%d\n", rep.Demoted)
	fmt.Fprintf(tw, "  Skipped\t%d\n", rep.Skipped)
	fmt.Fprintf(tw, "  Errors\t%d\n", rep.Errors)
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(rep.SampleErrors) > 0 {
		fmt.Println("\nSample errors:")
		for _, e := range rep.SampleErrors {
			fmt.Printf("  - %s\n", e)
		}
	}
	return nil
}
