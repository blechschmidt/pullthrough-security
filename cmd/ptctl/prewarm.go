package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"
	"time"
)

// runPrewarm dispatches the `ptctl prewarm` subcommands (Task 134): show the
// predictive cache pre-warming status, or trigger an immediate cycle on demand.
func runPrewarm(args []string) error {
	action := "status"
	if len(args) > 0 {
		action = args[0]
		args = args[1:]
	}
	switch action {
	case "status":
		return prewarmStatusCmd(args)
	case "run":
		return prewarmRunCmd(args)
	case "-h", "--help", "help":
		prewarmUsage(os.Stdout)
		return nil
	default:
		return fmt.Errorf("unknown prewarm action %q (try: status, run)", action)
	}
}

func prewarmUsage(w *os.File) {
	fmt.Fprintln(w, "usage: ptctl prewarm <status|run> [flags]")
	fmt.Fprintln(w, "  status   show predictor status, learned-history size, and counters (default)")
	fmt.Fprintln(w, "  run      trigger an immediate prediction + pre-warm cycle on the target node")
	fmt.Fprintln(w, "flags: -json (machine-readable), plus the global -url/-token flags")
}

func prewarmClient(args []string, name string) (*client, bool, error) {
	fs := flag.NewFlagSet("prewarm "+name, flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	jsonOut := fs.Bool("json", false, "emit machine-readable JSON")
	fs.Usage = func() { prewarmUsage(os.Stderr) }
	if err := fs.Parse(args); err != nil {
		return nil, false, err
	}
	c, err := newClient(g)
	if err != nil {
		return nil, false, err
	}
	return c, *jsonOut, nil
}

// prewarm* response shapes mirror the admin JSON (internal/prewarm.Status /
// RunReport). Only the fields ptctl renders are declared.
type prewarmRunReport struct {
	StartedAt     time.Time `json:"startedAt"`
	FinishedAt    time.Time `json:"finishedAt"`
	Predicted     int       `json:"predicted"`
	Fetched       int       `json:"fetched"`
	AlreadyCached int       `json:"alreadyCached"`
	GateBlocked   int       `json:"gateBlocked"`
	Errors        int       `json:"errors"`
	Skipped       string    `json:"skipped"`
}

type prewarmMetrics struct {
	Predicted     uint64            `json:"predicted"`
	Fetched       uint64            `json:"fetched"`
	AlreadyCached uint64            `json:"alreadyCached"`
	GateBlocked   uint64            `json:"gateBlocked"`
	Errors        uint64            `json:"errors"`
	HitAttributed uint64            `json:"hitAttributed"`
	CyclesRun     uint64            `json:"cyclesRun"`
	SkippedCycles map[string]uint64 `json:"skippedCycles"`
}

type prewarmStatusBody struct {
	Enabled            bool             `json:"enabled"`
	Running            bool             `json:"running"`
	Leader             bool             `json:"leader"`
	KillSwitchActive   bool             `json:"killSwitchActive"`
	InOffPeakWindow    bool             `json:"inOffPeakWindow"`
	Interval           string           `json:"interval"`
	OffPeakWindow      string           `json:"offPeakWindow"`
	MaxConcurrency     int              `json:"maxConcurrency"`
	MaxPerCycle        int              `json:"maxPerCycle"`
	RatePerMinute      int              `json:"ratePerMinute"`
	TransitiveDeps     bool             `json:"transitiveDeps"`
	HistoryCoordinates int              `json:"historyCoordinates"`
	PrewarmedTracked   int              `json:"prewarmedTracked"`
	LastRun            prewarmRunReport `json:"lastRun"`
	Metrics            prewarmMetrics   `json:"metrics"`
}

func prewarmStatusCmd(args []string) error {
	c, jsonOut, err := prewarmClient(args, "status")
	if err != nil {
		return err
	}
	var st prewarmStatusBody
	if err := c.getJSON(c.adminURL("api/prewarm", nil), &st); err != nil {
		return err
	}
	if jsonOut {
		return printJSON(st)
	}
	printPrewarmStatus(st)
	return nil
}

func printPrewarmStatus(st prewarmStatusBody) {
	if !st.Enabled {
		fmt.Println("Predictive cache pre-warming: disabled")
		fmt.Println("Enable it with prewarm.enabled: true to forecast and pre-fetch likely pulls during off-peak windows.")
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "Predictive cache pre-warming\t")
	fmt.Fprintf(tw, "  Running\t%s\n", yesNo(st.Running))
	fmt.Fprintf(tw, "  Leader (this node)\t%s\n", yesNo(st.Leader))
	fmt.Fprintf(tw, "  Kill-switch engaged\t%s\n", yesNo(st.KillSwitchActive))
	fmt.Fprintf(tw, "  In off-peak window\t%s\n", yesNo(st.InOffPeakWindow))
	fmt.Fprintf(tw, "  Interval\t%s\n", st.Interval)
	fmt.Fprintf(tw, "  Off-peak window\t%s\n", st.OffPeakWindow)
	fmt.Fprintf(tw, "  Max concurrency\t%d\n", st.MaxConcurrency)
	fmt.Fprintf(tw, "  Max per cycle\t%d\n", st.MaxPerCycle)
	fmt.Fprintf(tw, "  Rate per minute\t%s\n", rateWord(st.RatePerMinute))
	fmt.Fprintf(tw, "  Transitive deps\t%s\n", yesNo(st.TransitiveDeps))
	fmt.Fprintf(tw, "  History coordinates\t%d\n", st.HistoryCoordinates)
	fmt.Fprintf(tw, "  Pre-warmed tracked\t%d\n", st.PrewarmedTracked)
	fmt.Fprintln(tw, "\t")
	fmt.Fprintln(tw, "Cumulative counters\t")
	fmt.Fprintf(tw, "  Predicted\t%d\n", st.Metrics.Predicted)
	fmt.Fprintf(tw, "  Fetched\t%d\n", st.Metrics.Fetched)
	fmt.Fprintf(tw, "  Already cached\t%d\n", st.Metrics.AlreadyCached)
	fmt.Fprintf(tw, "  Gate-blocked\t%d\n", st.Metrics.GateBlocked)
	fmt.Fprintf(tw, "  Errors\t%d\n", st.Metrics.Errors)
	fmt.Fprintf(tw, "  Hit-attributed\t%d\n", st.Metrics.HitAttributed)
	fmt.Fprintf(tw, "  Cycles run\t%d\n", st.Metrics.CyclesRun)
	if len(st.Metrics.SkippedCycles) > 0 {
		reasons := make([]string, 0, len(st.Metrics.SkippedCycles))
		for r := range st.Metrics.SkippedCycles {
			reasons = append(reasons, r)
		}
		sort.Strings(reasons)
		for _, r := range reasons {
			fmt.Fprintf(tw, "  Skipped (%s)\t%d\n", r, st.Metrics.SkippedCycles[r])
		}
	}
	if !st.LastRun.StartedAt.IsZero() {
		fmt.Fprintln(tw, "\t")
		fmt.Fprintln(tw, "Last cycle\t")
		printPrewarmRun(tw, st.LastRun)
	}
	_ = tw.Flush()
}

func printPrewarmRun(tw *tabwriter.Writer, r prewarmRunReport) {
	if r.Skipped != "" {
		fmt.Fprintf(tw, "  Skipped\t%s\n", r.Skipped)
		return
	}
	fmt.Fprintf(tw, "  Started\t%s\n", r.StartedAt.Format(time.RFC3339))
	fmt.Fprintf(tw, "  Predicted\t%d\n", r.Predicted)
	fmt.Fprintf(tw, "  Fetched\t%d\n", r.Fetched)
	fmt.Fprintf(tw, "  Already cached\t%d\n", r.AlreadyCached)
	fmt.Fprintf(tw, "  Gate-blocked\t%d\n", r.GateBlocked)
	fmt.Fprintf(tw, "  Errors\t%d\n", r.Errors)
}

func prewarmRunCmd(args []string) error {
	c, jsonOut, err := prewarmClient(args, "run")
	if err != nil {
		return err
	}
	var r prewarmRunReport
	if err := c.postJSON(c.adminURL("api/prewarm/run", nil), map[string]any{}, &r); err != nil {
		return err
	}
	if jsonOut {
		return printJSON(r)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "Pre-warm cycle complete\t")
	printPrewarmRun(tw, r)
	return tw.Flush()
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func rateWord(n int) string {
	if n <= 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%d", n)
}
