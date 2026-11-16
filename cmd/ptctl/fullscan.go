package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/fullscan"
)

// runFullScan dispatches `ptctl fullscan` (Task 192): the full scan's status,
// and the operators' controls — pause, resume, rescan.
func runFullScan(args []string) error {
	action := "status"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		action, args = args[0], args[1:]
	}
	switch action {
	case "status":
		return fullScanStatus(args, os.Stdout)
	case "pause":
		return fullScanPause(args, os.Stdout)
	case "resume":
		return fullScanResume(args, os.Stdout)
	case "rescan":
		return fullScanRescan(args, os.Stdout)
	case "-h", "--help", "help":
		fullScanUsage(os.Stdout)
		return nil
	}
	return fmt.Errorf("unknown fullscan action %q (try: status, pause, resume, rescan)", action)
}

func fullScanUsage(w io.Writer) {
	fmt.Fprint(w, `ptctl fullscan <action> [flags]

The full scan (Task 192) keeps every cached artifact of the upstreams that set
fullMirror.fullScan (or, with fullScan.enabled, of every upstream the LLM
package scan covers) under a current LLM package-scan verdict, within a cost
budget per day and month.

Actions:
  status  [--upstream NAME] [--json]   the full scan overall, or one upstream in detail
  pause   [--upstream NAME] [--reason TEXT]
                                       start no scan (every upstream when none is named)
  resume  [--upstream NAME]            lift a pause (without a name: the global pause and every upstream's)
  rescan  [--upstream NAME] [--filter F] [--path P]
                                       scan again with a model call, though the bytes have a
                                       verdict: F is all (default), malicious, suspicious, benign,
                                       flagged, unscannable, refused, not-applicable or error;
                                       --path (with --upstream) re-scans one artifact, first

Pause and resume need the operate capability, rescan administer. With
webauthn.enforce, all three need a fresh passkey step-up: run them from the
admin console, or pass --stepup-token (env PULLTHROUGH_STEPUP_TOKEN).
Global flags (--url, --token, ...) follow the action.
`)
}

type fullScanFlags struct {
	upstream string
	reason   string
	filter   string
	path     string
	jsonOut  bool
}

func fullScanClient(name string, args []string, withReason, withJSON, withRescan bool) (*client, fullScanFlags, error) {
	fs := flag.NewFlagSet("fullscan "+name, flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	var f fullScanFlags
	fs.StringVar(&f.upstream, "upstream", "", "the upstream (a key of upstreams)")
	if withReason {
		fs.StringVar(&f.reason, "reason", "", "why, for the status and the audit log")
	}
	if withJSON {
		fs.BoolVar(&f.jsonOut, "json", false, "emit machine-readable JSON")
	}
	if withRescan {
		fs.StringVar(&f.filter, "filter", "all", "which artifacts, by their last reading")
		fs.StringVar(&f.path, "path", "", "one artifact: its request path under the upstream's mount")
	}
	stepUp := fs.String("stepup-token", os.Getenv("PULLTHROUGH_STEPUP_TOKEN"), "a fresh WebAuthn step-up token for a protected action (env PULLTHROUGH_STEPUP_TOKEN)")
	fs.Usage = func() { fullScanUsage(os.Stderr) }
	if err := fs.Parse(args); err != nil {
		return nil, f, err
	}
	if fs.NArg() > 0 {
		return nil, f, fmt.Errorf("unexpected argument %q (name the upstream with --upstream)", fs.Arg(0))
	}
	c, err := newClient(g)
	if err != nil {
		return nil, f, err
	}
	c.stepUp = strings.TrimSpace(*stepUp)
	return c, f, nil
}

func fullScanStatus(args []string, out io.Writer) error {
	c, f, err := fullScanClient("status", args, false, true, false)
	if err != nil {
		return err
	}
	if f.upstream != "" {
		var us fullscan.UpstreamStatus
		if err := c.getJSON(c.adminURL("api/fullscan/status", map[string]string{"upstream": f.upstream}), &us); err != nil {
			return err
		}
		if f.jsonOut {
			return writeJSONTo(out, us)
		}
		printFullScanUpstream(out, us)
		return nil
	}
	var st fullscan.Status
	if err := c.getJSON(c.adminURL("api/fullscan/status", nil), &st); err != nil {
		return err
	}
	if f.jsonOut {
		return writeJSONTo(out, st)
	}
	printFullScanStatus(out, st)
	return nil
}

func printFullScanStatus(out io.Writer, st fullscan.Status) {
	if !st.Enabled {
		fmt.Fprintln(out, "Full scan: not enabled (fullScan.enabled, or upstreams.<name>.fullMirror.fullScan; see docs/full-mirroring.md#full-scan)")
		return
	}
	scope := "the upstreams that set fullMirror.fullScan"
	if st.All {
		scope = "every upstream the LLM package scan covers"
	}
	fmt.Fprintf(out, "Full scan: %d upstream(s) (%s); this replica %s\n", len(st.Upstreams), scope, scanLeadWord(st.Leader))
	state := st.State
	if st.Detail != "" {
		state += ": " + printable(st.Detail)
	}
	fmt.Fprintf(out, "State: %s\n", state)
	if st.Paused {
		fmt.Fprintf(out, "PAUSED for every upstream%s%s\n", byWord(st.PausedBy), reasonWord(st.PauseReason))
	}
	if st.Lockdown != "" {
		fmt.Fprintf(out, "HELD by the emergency lockdown (%s)\n", st.Lockdown)
	}
	fmt.Fprintf(out, "Signature: %s; %d scan(s) at a time\n", dash(st.Signature), st.Concurrency)
	b := st.Budget
	fmt.Fprintf(out, "Budget: %s today, %s this month, $%.2f in total%s\n",
		usdWindow(b.Daily), usdWindow(b.Monthly), b.TotalSpentUSD, map[bool]string{true: " — SPENT, the queue waits", false: ""}[b.Exhausted])
	q := st.Queue
	fmt.Fprintf(out, "Queue: %d client, %d mirror, %d backfill (%d waiting out a retry, %d of paused upstreams), %d running\n",
		q.Client, q.Mirror, q.Backfill, q.Delayed, q.Parked, q.InFlight)
	sw := st.Sweep
	if sw.Inventory {
		fmt.Fprintf(out, "Sweep: every %s; last finished %s%s\n", sw.Interval, timeWord(sw.LastFinished), errWord(sw.LastError))
	} else {
		fmt.Fprintln(out, "Sweep: the cache cannot be listed; the mirror's and the clients' readings fill the inventory")
	}
	tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "UPSTREAM\tCACHED\tSCANNED\tPENDING\tMALICIOUS\tSUSPICIOUS\tREFUSED\tUNSCANNABLE\tERRORS\tQUARANTINED\tOLDEST UNSCANNED\tSPENT")
	for _, u := range st.Upstreams {
		name := u.Upstream
		if u.Paused {
			name += " (paused)"
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t$%.2f\n", name, u.Cached, u.Scanned, u.Pending, u.Malicious, u.Suspicious,
			u.Refused, u.Unscannable, u.Errors, u.Quarantined, oldestWord(u.OldestUnscanned), u.SpentUSD)
	}
	_ = tw.Flush()
	t := st.Totals
	fmt.Fprintf(out, "Total: %d cached, %d scanned (%d benign, %d suspicious, %d malicious), %d pending, %d refused, %d unscannable, %d errors, %d quarantined\n",
		t.Cached, t.Scanned, t.Benign, t.Suspicious, t.Malicious, t.Pending, t.Refused, t.Unscannable, t.Errors, t.Quarantined)
	if st.Untracked > 0 {
		fmt.Fprintf(out, "Untracked: %d cached object(s) of no upstream in scope, or cached before fill metadata existed\n", st.Untracked)
	}
}

func printFullScanUpstream(out io.Writer, u fullscan.UpstreamStatus) {
	tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
	row := func(k, v string) { fmt.Fprintf(tw, "%s\t%s\n", k, v) }
	row("Upstream", u.Upstream)
	if u.Paused {
		row("Paused", "yes"+byWord(u.PausedBy)+reasonWord(u.PauseReason))
	}
	row("Cached", fmt.Sprintf("%d tracked (%d untracked)", u.Cached, u.Untracked))
	row("Scanned", fmt.Sprintf("%d (%d benign, %d suspicious, %d malicious)", u.Scanned, u.Benign, u.Suspicious, u.Malicious))
	row("Pending", fmt.Sprintf("%d", u.Pending))
	row("Refused by the model", fmt.Sprintf("%d", u.Refused))
	row("Unscannable", fmt.Sprintf("%d", u.Unscannable))
	row("Not applicable", fmt.Sprintf("%d", u.NotApplicable))
	row("Errors", fmt.Sprintf("%d", u.Errors))
	row("Quarantined", fmt.Sprintf("%d evicted by the action ladder, %d refused in the cache", u.Quarantined, u.RefusedByAction))
	row("Oldest unscanned", oldestWord(u.OldestUnscanned))
	if o := u.OldestUnscanned; o != nil && o.Path != "" {
		// A request path a client chose: no terminal control sequences.
		row("", printable(o.Path))
	}
	c := u.Counters
	row("Readings", fmt.Sprintf("%d with a model call, %d from the verdict cache, %d from the mirror, %d from client pulls", c.Scans, c.CachedVerdicts, c.Mirrored, c.ClientPulls))
	row("Verdicts", strings.TrimPrefix(countsWord(c.Verdicts), " "))
	if len(c.Unscanned) > 0 {
		row("Unscanned", strings.TrimPrefix(countsWord(c.Unscanned), " "))
	}
	row("Enforced", fmt.Sprintf("%d refused, %d evicted", c.Refused, c.Evicted))
	if len(c.Rescans) > 0 {
		row("Re-scans", strings.TrimPrefix(countsWord(c.Rescans), " "))
	}
	row("Attempts", fmt.Sprintf("%d retried, %d failed, %d left the cache", c.Retries, c.Errors, c.Gone))
	row("Spent", fmt.Sprintf("$%.4f", u.SpentUSD))
	_ = tw.Flush()
}

func fullScanPause(args []string, out io.Writer) error {
	c, f, err := fullScanClient("pause", args, true, false, false)
	if err != nil {
		return err
	}
	if err := c.postJSON(c.adminURL("api/fullscan/pause", nil), map[string]string{"upstream": f.upstream, "reason": f.reason}, nil); err != nil {
		return err
	}
	fmt.Fprintf(out, "full scan paused: %s\n", firstNonEmpty(f.upstream, "every upstream"))
	return nil
}

func fullScanResume(args []string, out io.Writer) error {
	c, f, err := fullScanClient("resume", args, false, false, false)
	if err != nil {
		return err
	}
	if err := c.postJSON(c.adminURL("api/fullscan/resume", nil), map[string]string{"upstream": f.upstream}, nil); err != nil {
		return err
	}
	fmt.Fprintf(out, "full scan resumed: %s\n", firstNonEmpty(f.upstream, "every upstream"))
	return nil
}

func fullScanRescan(args []string, out io.Writer) error {
	c, f, err := fullScanClient("rescan", args, false, false, true)
	if err != nil {
		return err
	}
	if f.path != "" && f.upstream == "" {
		return fmt.Errorf("a re-scan by --path names the upstream too (--upstream)")
	}
	var resp struct {
		Request fullscan.RescanRequest `json:"request"`
	}
	body := map[string]string{"upstream": f.upstream, "filter": f.filter, "path": f.path}
	if err := c.postJSON(c.adminURL("api/fullscan/rescan", nil), body, &resp); err != nil {
		return err
	}
	what := firstNonEmpty(f.upstream, "every upstream")
	if f.path != "" {
		what += " " + f.path
	}
	fmt.Fprintf(out, "full scan re-scan requested (#%d): %s, %s artifacts — each is scanned again with a model call, paid from fullScan.budget\n",
		resp.Request.Seq, what, firstNonEmpty(resp.Request.Filter, "all"))
	return nil
}

func scanLeadWord(leader bool) string {
	if leader {
		return "leads (scans)"
	}
	return "stands by (another replica leads)"
}

func usdWindow(w fullscan.WindowStatus) string {
	if w.CeilingUSD <= 0 {
		return fmt.Sprintf("$%.2f (no ceiling)", w.SpentUSD)
	}
	return fmt.Sprintf("$%.2f of $%.2f", w.SpentUSD, w.CeilingUSD)
}

func oldestWord(o *fullscan.Oldest) string {
	if o == nil {
		return "-"
	}
	return fmt.Sprintf("%s (%s, cached %s)", time.Duration(o.AgeSeconds*float64(time.Second)).Round(time.Second), o.State, timeWord(o.Cached))
}

func errWord(msg string) string {
	if msg == "" {
		return ""
	}
	return " (last error: " + printable(msg) + ")"
}
