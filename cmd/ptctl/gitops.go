package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// runGitops dispatches the `ptctl gitops` subcommands (Task 93): show the GitOps
// reconciliation status, force an immediate sync, or roll back to the last-known-
// good applied revision.
func runGitops(args []string) error {
	if len(args) == 0 {
		return gitopsUsageErr()
	}
	action := args[0]
	rest := args[1:]
	switch action {
	case "status":
		return gitopsStatus(rest)
	case "sync":
		return gitopsSync(rest)
	case "rollback":
		return gitopsRollback(rest)
	case "-h", "--help", "help":
		gitopsUsage(os.Stdout)
		return nil
	default:
		return fmt.Errorf("unknown gitops action %q (try: status, sync, rollback)", action)
	}
}

func gitopsUsage(w *os.File) {
	fmt.Fprintln(w, "usage: ptctl gitops <status|sync|rollback> [flags]")
	fmt.Fprintln(w, "  status            show sync status, last revision, drift, and pending change")
	fmt.Fprintln(w, "  sync              force an immediate reconcile against the source of truth")
	fmt.Fprintln(w, "  rollback          revert the last apply to the last-known-good config")
	fmt.Fprintln(w, "flags: -json (machine-readable), -reason (rollback), plus the global -url/-token flags")
}

func gitopsUsageErr() error {
	gitopsUsage(os.Stderr)
	return fmt.Errorf("gitops requires an action")
}

// gitops* response shapes mirror the admin JSON (internal/admin/gitops.go). Only
// the fields ptctl renders are declared.
type gitopsSettingChange struct {
	Path     string `json:"path"`
	Current  string `json:"current"`
	Proposed string `json:"proposed"`
	Changed  bool   `json:"changed"`
}

type gitopsPreview struct {
	Revision    string                `json:"revision"`
	Changed     int                   `json:"changed"`
	Settings    []gitopsSettingChange `json:"settings"`
	Valid       bool                  `json:"valid"`
	BlastRadius *struct {
		Total       int `json:"total"`
		Changed     int `json:"changed"`
		Flips       int `json:"flips"`
		NowBlocked  int `json:"nowBlocked"`
		NowAdmitted int `json:"nowAdmitted"`
	} `json:"blastRadius,omitempty"`
}

type gitopsAppliedEntry struct {
	Revision  string    `json:"revision"`
	Changed   int       `json:"changed"`
	By        string    `json:"by"`
	AppliedAt time.Time `json:"appliedAt"`
	Approved  bool      `json:"approved"`
}

type gitopsPending struct {
	Revision  string `json:"revision"`
	Changed   int    `json:"changed"`
	RequestID string `json:"requestId"`
	Reason    string `json:"reason"`
}

type gitopsStatusBody struct {
	Enabled       bool                `json:"enabled"`
	Mode          string              `json:"mode"`
	Source        string              `json:"source"`
	Interval      string              `json:"interval"`
	InSync        bool                `json:"inSync"`
	DriftDetected bool                `json:"driftDetected"`
	LastSyncAt    time.Time           `json:"lastSyncAt"`
	LastRevision  string              `json:"lastRevision"`
	LastOutcome   string              `json:"lastOutcome"`
	LastError     string              `json:"lastError"`
	KeyID         string              `json:"keyId"`
	LastApplied   *gitopsAppliedEntry `json:"lastApplied"`
	Pending       *gitopsPending      `json:"pending"`
	Preview       *gitopsPreview      `json:"preview"`
}

type gitopsStatusResponse struct {
	Status gitopsStatusBody `json:"status"`
}

type gitopsOutcome struct {
	Result    string `json:"result"`
	Revision  string `json:"revision"`
	Changed   int    `json:"changed"`
	Applied   bool   `json:"applied"`
	Pending   bool   `json:"pending"`
	InSync    bool   `json:"inSync"`
	Verified  bool   `json:"verified"`
	RequestID string `json:"requestId"`
	Error     string `json:"error"`
}

type gitopsSyncResponse struct {
	Outcome gitopsOutcome    `json:"outcome"`
	Status  gitopsStatusBody `json:"status"`
}

type gitopsRollbackResponse struct {
	Rollback struct {
		RolledBackFrom string `json:"rolledBackFrom"`
		RestoredTo     string `json:"restoredTo"`
	} `json:"rollback"`
}

func gitopsClient(args []string, name string, extra func(*flag.FlagSet)) (*client, bool, error) {
	fs := flag.NewFlagSet("gitops "+name, flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	jsonOut := fs.Bool("json", false, "emit machine-readable JSON")
	if extra != nil {
		extra(fs)
	}
	if err := fs.Parse(args); err != nil {
		return nil, false, err
	}
	c, err := newClient(g)
	if err != nil {
		return nil, false, err
	}
	return c, *jsonOut, nil
}

func gitopsStatus(args []string) error {
	c, jsonOut, err := gitopsClient(args, "status", nil)
	if err != nil {
		return err
	}
	var resp gitopsStatusResponse
	if err := c.getJSON(c.adminURL("api/gitops", nil), &resp); err != nil {
		return err
	}
	if jsonOut {
		return printJSON(resp.Status)
	}
	printGitopsStatus(resp.Status)
	return nil
}

func printGitopsStatus(st gitopsStatusBody) {
	state := "IN SYNC"
	if st.DriftDetected {
		state = "DRIFT"
	}
	if !st.InSync && !st.DriftDetected {
		state = "UNKNOWN"
	}
	fmt.Fprintf(os.Stdout, "GitOps: %s (mode=%s)\n", state, st.Mode)
	fmt.Fprintf(os.Stdout, "  source:    %s\n", st.Source)
	fmt.Fprintf(os.Stdout, "  interval:  %s\n", st.Interval)
	if st.KeyID != "" {
		fmt.Fprintf(os.Stdout, "  verifyKey: %s\n", st.KeyID)
	}
	if !st.LastSyncAt.IsZero() {
		fmt.Fprintf(os.Stdout, "  lastSync:  %s (%s)\n", st.LastSyncAt.Format(time.RFC3339), st.LastOutcome)
	}
	if st.LastRevision != "" {
		fmt.Fprintf(os.Stdout, "  revision:  %s\n", st.LastRevision)
	}
	if st.LastError != "" {
		fmt.Fprintf(os.Stdout, "  error:     %s\n", st.LastError)
	}
	if st.LastApplied != nil {
		fmt.Fprintf(os.Stdout, "  applied:   %s (%d change(s)) by %s at %s\n",
			st.LastApplied.Revision, st.LastApplied.Changed, st.LastApplied.By,
			st.LastApplied.AppliedAt.Format(time.RFC3339))
	}
	if st.Pending != nil {
		fmt.Fprintf(os.Stdout, "  PENDING APPROVAL: %s (%d change(s)) request=%s\n",
			st.Pending.Revision, st.Pending.Changed, st.Pending.RequestID)
	}
	if st.Preview != nil && st.Preview.Changed > 0 {
		fmt.Fprintf(os.Stdout, "  pending changes (%d):\n", st.Preview.Changed)
		for _, s := range st.Preview.Settings {
			if s.Changed {
				fmt.Fprintf(os.Stdout, "    - %s: %s -> %s\n", s.Path, s.Current, s.Proposed)
			}
		}
		if b := st.Preview.BlastRadius; b != nil {
			fmt.Fprintf(os.Stdout, "  blast radius: %d/%d pulls change (%d now-blocked, %d now-admitted)\n",
				b.Changed, b.Total, b.NowBlocked, b.NowAdmitted)
		}
	}
}

func gitopsSync(args []string) error {
	c, jsonOut, err := gitopsClient(args, "sync", nil)
	if err != nil {
		return err
	}
	var resp gitopsSyncResponse
	if err := c.postJSON(c.adminURL("api/gitops/sync", nil), map[string]any{}, &resp); err != nil {
		return err
	}
	if jsonOut {
		return printJSON(resp)
	}
	o := resp.Outcome
	fmt.Fprintf(os.Stdout, "sync: %s\n", o.Result)
	if o.Revision != "" {
		fmt.Fprintf(os.Stdout, "  revision:  %s\n", o.Revision)
	}
	fmt.Fprintf(os.Stdout, "  verified:  %t\n", o.Verified)
	fmt.Fprintf(os.Stdout, "  changed:   %d\n", o.Changed)
	switch {
	case o.Applied:
		fmt.Fprintln(os.Stdout, "  applied to the on-disk config (takes effect on next reload/restart)")
	case o.Pending:
		fmt.Fprintf(os.Stdout, "  pending dual-control approval (request=%s)\n", o.RequestID)
	case o.InSync:
		fmt.Fprintln(os.Stdout, "  already in sync with the source of truth")
	}
	if o.Error != "" {
		fmt.Fprintf(os.Stdout, "  note:      %s\n", o.Error)
	}
	return nil
}

func gitopsRollback(args []string) error {
	var reason string
	c, jsonOut, err := gitopsClient(args, "rollback", func(fs *flag.FlagSet) {
		fs.StringVar(&reason, "reason", "", "operator reason recorded to the audit log")
	})
	if err != nil {
		return err
	}
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("rollback requires -reason")
	}
	var resp gitopsRollbackResponse
	if err := c.postJSON(c.adminURL("api/gitops/rollback", nil), map[string]any{"reason": reason}, &resp); err != nil {
		return err
	}
	if jsonOut {
		return printJSON(resp)
	}
	fmt.Fprintf(os.Stdout, "rolled back %s -> %s\n", resp.Rollback.RolledBackFrom, resp.Rollback.RestoredTo)
	fmt.Fprintln(os.Stdout, "  the last-known-good config is restored (takes effect on next reload/restart)")
	return nil
}
