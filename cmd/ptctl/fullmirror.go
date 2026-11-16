package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

// runFullMirror dispatches `ptctl fullmirror` (Task 189): the full mirror's
// status, and the operators' controls — pause, resume, resync.
func runFullMirror(args []string) error {
	action := "status"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		action, args = args[0], args[1:]
	}
	switch action {
	case "status":
		return fullMirrorStatus(args, os.Stdout)
	case "pause":
		return fullMirrorPause(args, os.Stdout)
	case "resume":
		return fullMirrorResume(args, os.Stdout)
	case "resync":
		return fullMirrorResync(args, os.Stdout)
	case "-h", "--help", "help":
		fullMirrorUsage(os.Stdout)
		return nil
	}
	return fmt.Errorf("unknown fullmirror action %q (try: status, pause, resume, resync)", action)
}

func fullMirrorUsage(w io.Writer) {
	fmt.Fprint(w, `ptctl fullmirror <action> [flags]

The full mirror (Task 189) follows the registries of the upstreams that enable
upstreams.<name>.fullMirror and fetches every new file through the gated
pipeline before any client asks for it.

Actions:
  status  [--upstream NAME] [--json]   the mirror overall, or one upstream in detail
  pause   [--upstream NAME] [--reason TEXT]
                                       stop fetching (every upstream when none is named);
                                       a batch is resumed where it stopped
  resume  [--upstream NAME]            lift a pause (without a name: the global pause and every upstream's)
  resync  --upstream NAME              forget the cursor and enumerate the registry again
                                       (the cache spares what is already mirrored)

Pause and resume need the operate capability, resync administer. With
webauthn.enforce, all three need a fresh passkey step-up: run them from the
admin console, or pass --stepup-token (env PULLTHROUGH_STEPUP_TOKEN).
Global flags (--url, --token, ...) follow the action.
`)
}

// fullMirrorFlags parses an action's flags.
type fullMirrorFlags struct {
	upstream string
	reason   string
	jsonOut  bool
}

func fullMirrorClient(name string, args []string, withReason, withJSON bool) (*client, fullMirrorFlags, error) {
	fs := flag.NewFlagSet("fullmirror "+name, flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	var f fullMirrorFlags
	fs.StringVar(&f.upstream, "upstream", "", "the upstream (a key of upstreams)")
	if withReason {
		fs.StringVar(&f.reason, "reason", "", "why, for the status and the audit log")
	}
	if withJSON {
		fs.BoolVar(&f.jsonOut, "json", false, "emit machine-readable JSON")
	}
	stepUp := fs.String("stepup-token", os.Getenv("PULLTHROUGH_STEPUP_TOKEN"), "a fresh WebAuthn step-up token for a protected action (env PULLTHROUGH_STEPUP_TOKEN)")
	fs.Usage = func() { fullMirrorUsage(os.Stderr) }
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

// The response shapes mirror internal/fullmirror's Status and UpstreamStatus;
// only the fields ptctl renders are declared.
type fmCounters struct {
	Polls         uint64            `json:"polls"`
	PollErrors    uint64            `json:"pollErrors"`
	Batches       uint64            `json:"batches"`
	Packages      uint64            `json:"packages"`
	Excluded      uint64            `json:"excluded"`
	Deleted       uint64            `json:"deleted"`
	PackageErrors uint64            `json:"packageErrors"`
	Fetched       uint64            `json:"fetched"`
	FetchedBytes  uint64            `json:"fetchedBytes"`
	Refused       uint64            `json:"refused"`
	RefusedBy     map[string]uint64 `json:"refusedBy"`
	Failed        uint64            `json:"failed"`
	Deferred      uint64            `json:"deferred"`
	Skipped       map[string]uint64 `json:"skipped"`
	Retries       uint64            `json:"retries"`
}

func (c fmCounters) skipped() uint64 {
	var n uint64
	for _, v := range c.Skipped {
		n += v
	}
	return n
}

type fmUpstream struct {
	Upstream      string     `json:"upstream"`
	Type          string     `json:"type"`
	Tier          string     `json:"tier"`
	State         string     `json:"state"`
	Detail        string     `json:"detail"`
	Phase         string     `json:"phase"`
	Cursor        string     `json:"cursor"`
	DryRun        bool       `json:"dryRun"`
	Paused        bool       `json:"paused"`
	PausedBy      string     `json:"pausedBy"`
	PauseReason   string     `json:"pauseReason"`
	ResyncPending bool       `json:"resyncPending"`
	LastPoll      time.Time  `json:"lastPoll"`
	LastChange    time.Time  `json:"lastChange"`
	NextPoll      time.Time  `json:"nextPoll"`
	BackoffUntil  time.Time  `json:"backoffUntil"`
	FeedHead      string     `json:"feedHead"`
	Lag           *int64     `json:"lag"`
	LagSeconds    *float64   `json:"lagSeconds"`
	Queued        int        `json:"queued"`
	InFlight      int        `json:"inFlight"`
	Deferred      int        `json:"deferred"`
	NextDeferred  time.Time  `json:"nextDeferred"`
	Batch         uint64     `json:"batch"`
	Counters      fmCounters `json:"counters"`
	Budget        struct {
		Limit     int64 `json:"limit"`
		Used      int64 `json:"used"`
		Exhausted bool  `json:"exhausted"`
	} `json:"budget"`
	Policy struct {
		Versions          string   `json:"versions"`
		Include           []string `json:"include"`
		Exclude           []string `json:"exclude"`
		MaxArtifactBytes  int64    `json:"maxArtifactBytes"`
		Concurrency       int      `json:"concurrency"`
		RequestsPerSecond float64  `json:"requestsPerSecond"`
		PollInterval      string   `json:"pollInterval"`
		Window            string   `json:"window"`
	} `json:"policy"`
	RecentErrors []struct {
		Time    time.Time `json:"time"`
		Package string    `json:"package"`
		Path    string    `json:"path"`
		Message string    `json:"message"`
	} `json:"recentErrors"`
}

type fmStatus struct {
	Enabled     bool   `json:"enabled"`
	Running     bool   `json:"running"`
	Attached    bool   `json:"attached"`
	Leader      bool   `json:"leader"`
	StateDir    string `json:"stateDir"`
	Tenant      string `json:"tenant"`
	Subject     string `json:"subject"`
	Paused      bool   `json:"paused"`
	PausedBy    string `json:"pausedBy"`
	PauseReason string `json:"pauseReason"`
	Lockdown    string `json:"lockdown"`
	Totals      struct {
		Upstreams     int    `json:"upstreams"`
		Queued        int    `json:"queued"`
		Packages      uint64 `json:"packages"`
		PackageErrors uint64 `json:"packageErrors"`
		Fetched       uint64 `json:"fetched"`
		FetchedBytes  uint64 `json:"fetchedBytes"`
		Refused       uint64 `json:"refused"`
		Failed        uint64 `json:"failed"`
		Skipped       uint64 `json:"skipped"`
		Deferred      int    `json:"deferred"`
		BudgetBytes   int64  `json:"budgetBytes"`
		BudgetUsed    int64  `json:"budgetUsedBytes"`
	} `json:"totals"`
	Upstreams []fmUpstream `json:"upstreams"`
}

func fullMirrorStatus(args []string, out io.Writer) error {
	c, f, err := fullMirrorClient("status", args, false, true)
	if err != nil {
		return err
	}
	if f.upstream != "" {
		var us fmUpstream
		if err := c.getJSON(c.adminURL("api/fullmirror/status", map[string]string{"upstream": f.upstream}), &us); err != nil {
			return err
		}
		if f.jsonOut {
			return writeJSONTo(out, us)
		}
		printFullMirrorUpstream(out, us)
		return nil
	}
	var st fmStatus
	if err := c.getJSON(c.adminURL("api/fullmirror/status", nil), &st); err != nil {
		return err
	}
	if f.jsonOut {
		return writeJSONTo(out, st)
	}
	printFullMirrorStatus(out, st)
	return nil
}

func printFullMirrorStatus(out io.Writer, st fmStatus) {
	if !st.Enabled {
		fmt.Fprintln(out, "Full mirroring: not enabled for any upstream (upstreams.<name>.fullMirror; see docs/full-mirroring.md)")
		return
	}
	fmt.Fprintf(out, "Full mirroring: %d upstream(s); this replica %s; fetching as %s", st.Totals.Upstreams, leadWord(st.Leader), st.Subject)
	if st.Tenant != "" {
		fmt.Fprintf(out, " (tenant %s)", st.Tenant)
	}
	fmt.Fprintln(out)
	if st.Paused {
		fmt.Fprintf(out, "PAUSED for every upstream%s%s\n", byWord(st.PausedBy), reasonWord(st.PauseReason))
	}
	if st.Lockdown != "" {
		fmt.Fprintf(out, "HELD by the emergency lockdown (%s)\n", st.Lockdown)
	}
	tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "UPSTREAM\tTYPE\tTIER\tSTATE\tPHASE\tQUEUED\tDEFERRED\tFETCHED\tREFUSED\tFAILED\tSKIPPED\tBUDGET USED\tLAST POLL\tLAG")
	for _, u := range st.Upstreams {
		state := u.State
		if u.DryRun {
			state += " (dry run)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%s\t%s\n",
			u.Upstream, u.Type, dash(u.Tier), state, dash(u.Phase), u.Queued, u.Deferred, u.Counters.Fetched, u.Counters.Refused,
			u.Counters.Failed, u.Counters.skipped(), budgetWord(u.Budget.Used, u.Budget.Limit), timeWord(u.LastPoll), lagWord(u.Lag, u.LagSeconds))
	}
	_ = tw.Flush()
	t := st.Totals
	fmt.Fprintf(out, "Total: %d fetched (%s), %d refused, %d failed, %d skipped, %d queued, %d deferred\n",
		t.Fetched, bytesWord(int64(t.FetchedBytes)), t.Refused, t.Failed, t.Skipped, t.Queued, t.Deferred)
}

func printFullMirrorUpstream(out io.Writer, u fmUpstream) {
	tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
	row := func(k, v string) { fmt.Fprintf(tw, "%s\t%s\n", k, v) }
	row("Upstream", u.Upstream+" ("+u.Type+", tier "+dash(u.Tier)+")")
	state := u.State
	if u.Detail != "" {
		state += ": " + u.Detail
	}
	row("State", state)
	if u.Paused {
		row("Paused", "yes"+byWord(u.PausedBy)+reasonWord(u.PauseReason))
	}
	if u.ResyncPending {
		row("Resync", "requested")
	}
	row("Dry run", yesNo(u.DryRun))
	row("Phase", dash(u.Phase))
	row("Cursor", dash(u.Cursor))
	row("Feed head", dash(u.FeedHead))
	row("Lag", lagWord(u.Lag, u.LagSeconds))
	row("Last poll", timeWord(u.LastPoll))
	row("Last change", timeWord(u.LastChange))
	if !u.NextPoll.IsZero() {
		row("Next poll", timeWord(u.NextPoll))
	}
	if !u.BackoffUntil.IsZero() {
		row("Backing off until", timeWord(u.BackoffUntil))
	}
	row("Queued", fmt.Sprintf("%d (batch %d), %d file(s) in flight", u.Queued, u.Batch, u.InFlight))
	deferred := fmt.Sprintf("%d file(s)", u.Deferred)
	if !u.NextDeferred.IsZero() {
		deferred += ", next due " + timeWord(u.NextDeferred)
	}
	row("Deferred", deferred+fmt.Sprintf(" (%d deferral(s) so far)", u.Counters.Deferred))
	exhausted := ""
	if u.Budget.Exhausted {
		exhausted = " — SPENT"
	}
	row("Budget", budgetWord(u.Budget.Used, u.Budget.Limit)+exhausted)
	p := u.Policy
	row("Versions", p.Versions)
	if len(p.Include) > 0 {
		row("Include", strings.Join(p.Include, ", "))
	}
	if len(p.Exclude) > 0 {
		row("Exclude", strings.Join(p.Exclude, ", "))
	}
	if p.MaxArtifactBytes > 0 {
		row("Max file size", bytesWord(p.MaxArtifactBytes))
	}
	row("Pacing", fmt.Sprintf("%d at a time, %g requests/s, poll every %s, window %s", p.Concurrency, p.RequestsPerSecond, p.PollInterval, p.Window))
	c := u.Counters
	row("Polls", fmt.Sprintf("%d (%d failed)", c.Polls, c.PollErrors))
	row("Changes", fmt.Sprintf("%d mirrored, %d excluded, %d deleted, %d without a version list", c.Packages, c.Excluded, c.Deleted, c.PackageErrors))
	row("Files fetched", fmt.Sprintf("%d (%s)", c.Fetched, bytesWord(int64(c.FetchedBytes))))
	row("Files refused", fmt.Sprintf("%d%s", c.Refused, countsWord(c.RefusedBy)))
	row("Files failed", fmt.Sprintf("%d (%d retries)", c.Failed, c.Retries))
	row("Files skipped", fmt.Sprintf("%d%s", c.skipped(), countsWord(c.Skipped)))
	_ = tw.Flush()
	if len(u.RecentErrors) > 0 {
		fmt.Fprintln(out, "Recent errors:")
		for _, e := range u.RecentErrors {
			what := e.Package
			if e.Path != "" {
				what = strings.TrimSpace(what + " " + e.Path)
			}
			if what != "" {
				what += ": "
			}
			fmt.Fprintf(out, "  %s  %s%s\n", e.Time.UTC().Format(time.RFC3339), what, e.Message)
		}
	}
}

func fullMirrorPause(args []string, out io.Writer) error {
	c, f, err := fullMirrorClient("pause", args, true, false)
	if err != nil {
		return err
	}
	if err := c.postJSON(c.adminURL("api/fullmirror/pause", nil), map[string]string{"upstream": f.upstream, "reason": f.reason}, nil); err != nil {
		return err
	}
	fmt.Fprintf(out, "full mirror paused: %s\n", firstNonEmpty(f.upstream, "every upstream"))
	return nil
}

func fullMirrorResume(args []string, out io.Writer) error {
	c, f, err := fullMirrorClient("resume", args, false, false)
	if err != nil {
		return err
	}
	if err := c.postJSON(c.adminURL("api/fullmirror/resume", nil), map[string]string{"upstream": f.upstream}, nil); err != nil {
		return err
	}
	fmt.Fprintf(out, "full mirror resumed: %s\n", firstNonEmpty(f.upstream, "every upstream"))
	return nil
}

func fullMirrorResync(args []string, out io.Writer) error {
	c, f, err := fullMirrorClient("resync", args, false, false)
	if err != nil {
		return err
	}
	if strings.TrimSpace(f.upstream) == "" {
		return fmt.Errorf("name the upstream to resync with --upstream: it enumerates the whole registry again")
	}
	if err := c.postJSON(c.adminURL("api/fullmirror/resync", nil), map[string]string{"upstream": f.upstream}, nil); err != nil {
		return err
	}
	fmt.Fprintf(out, "full mirror resync requested: %s (the registry is enumerated again; cached files are not fetched again)\n", f.upstream)
	return nil
}

func leadWord(leader bool) string {
	if leader {
		return "leads (polls and fetches)"
	}
	return "stands by (another replica leads)"
}

func byWord(by string) string {
	if by == "" {
		return ""
	}
	return " by " + by
}

func reasonWord(reason string) string {
	if reason == "" {
		return ""
	}
	return ": " + reason
}

func timeWord(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

func lagWord(lag *int64, secs *float64) string {
	var parts []string
	if lag != nil {
		parts = append(parts, fmt.Sprintf("%d change(s)", *lag))
	}
	if secs != nil {
		parts = append(parts, time.Duration(*secs*float64(time.Second)).Round(time.Second).String())
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

func budgetWord(used, limit int64) string {
	if limit <= 0 {
		return bytesWord(used)
	}
	return fmt.Sprintf("%s of %s (%.0f%%)", bytesWord(used), bytesWord(limit), 100*float64(used)/float64(limit))
}

func bytesWord(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func countsWord(m map[string]uint64) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", k, m[k]))
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

// writeJSONTo writes v as indented JSON.
func writeJSONTo(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
