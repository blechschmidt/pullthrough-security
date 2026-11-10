package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// runSnapshot implements `ptctl snapshot <action> [flags] [args]`: the client
// surface for the organization-wide dependency snapshot, freeze & instant-rollback
// subsystem (Task 70). It is HTTP-only, calling the admin /api/snapshots/*
// endpoints.
//
// Actions:
//
//	list                       list snapshots and the active freeze
//	get <id>                   print one snapshot manifest (JSON)
//	diff <fromID> <toID>       print the drift report between two snapshots
//	create [name]              capture a snapshot of the served-state live set
//	freeze <id>                freeze the org to a snapshot (admin-only)
//	unfreeze                   lift the active freeze (admin-only)
//	rollback                   pin the org back to the last-known-good snapshot
//	markgood <id> [false]      (un)mark a snapshot as a known-good rollback target
func runSnapshot(args []string) error {
	if len(args) == 0 {
		return snapshotUsageErr()
	}
	action := args[0]
	rest := args[1:]
	switch action {
	case "list":
		return snapshotList(rest)
	case "get":
		return snapshotGet(rest)
	case "diff":
		return snapshotDiff(rest)
	case "create":
		return snapshotCreate(rest)
	case "freeze":
		return snapshotFreeze(rest)
	case "unfreeze":
		return snapshotUnfreeze(rest)
	case "rollback":
		return snapshotRollback(rest)
	case "markgood":
		return snapshotMarkGood(rest)
	case "-h", "--help", "help":
		snapshotUsage(os.Stdout)
		return nil
	default:
		return fmt.Errorf("unknown snapshot action %q (try: list, get, diff, create, freeze, unfreeze, rollback, markgood)", action)
	}
}

func snapshotUsageErr() error {
	snapshotUsage(os.Stderr)
	return fmt.Errorf("an action is required")
}

func snapshotUsage(w *os.File) {
	fmt.Fprint(w, `ptctl snapshot <action> [flags] [args]

Actions:
  list                     list snapshots and the active freeze state
  get <id>                 print one snapshot manifest (JSON)
  diff <fromID> <toID>     print the drift report between two snapshots
  create [name]            capture a snapshot of the served dependency state
  freeze <id>              freeze the organization to a snapshot (admin-only)
  unfreeze                 lift the active freeze (admin-only)
  rollback                 pin the org to the last-known-good snapshot (admin-only)
  markgood <id> [false]    (un)mark a snapshot as a known-good rollback target

Global flags (e.g. -url, -token, -tenant) follow the action.
`)
}

// snapshotListResponse mirrors the admin /api/snapshots payload.
type snapshotListResponse struct {
	Snapshots []struct {
		ID         string    `json:"id"`
		Name       string    `json:"name"`
		CreatedAt  time.Time `json:"createdAt"`
		EntryCount int       `json:"entryCount"`
		Good       bool      `json:"good"`
		Signed     bool      `json:"signed"`
		Frozen     bool      `json:"frozen"`
		Scheduled  bool      `json:"scheduled"`
	} `json:"snapshots"`
	Freeze struct {
		Active       bool   `json:"active"`
		SnapshotID   string `json:"snapshotId"`
		SnapshotName string `json:"snapshotName"`
		Mode         string `json:"mode"`
		Rollback     bool   `json:"rollback"`
		SetSize      int    `json:"setSize"`
	} `json:"freeze"`
}

func snapshotClient(args []string, name string) (*client, *flag.FlagSet, error) {
	fs := flag.NewFlagSet("snapshot "+name, flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	if err := fs.Parse(args); err != nil {
		return nil, nil, err
	}
	c, err := newClient(g)
	if err != nil {
		return nil, nil, err
	}
	return c, fs, nil
}

func snapshotList(args []string) error {
	c, _, err := snapshotClient(args, "list")
	if err != nil {
		return err
	}
	var resp snapshotListResponse
	if err := c.getJSON(c.adminURL("api/snapshots", nil), &resp); err != nil {
		return err
	}
	if resp.Freeze.Active {
		fmt.Fprintf(os.Stdout, "FREEZE ACTIVE: %s (%s%s) — %d coordinates\n\n",
			shortSnapID(resp.Freeze.SnapshotID), orValue(resp.Freeze.Mode, "block"),
			rollbackTag(resp.Freeze.Rollback), resp.Freeze.SetSize)
	} else {
		fmt.Fprint(os.Stdout, "no active freeze\n\n")
	}
	if len(resp.Snapshots) == 0 {
		fmt.Fprintln(os.Stdout, "no snapshots captured yet")
		return nil
	}
	fmt.Fprintf(os.Stdout, "%-14s  %-20s  %-20s  %7s  %-5s  %-7s  %s\n",
		"ID", "NAME", "CREATED", "ENTRIES", "GOOD", "SIGNED", "STATE")
	for _, s := range resp.Snapshots {
		state := ""
		if s.Frozen {
			state = "FROZEN"
		} else if s.Scheduled {
			state = "scheduled"
		}
		fmt.Fprintf(os.Stdout, "%-14s  %-20s  %-20s  %7d  %-5v  %-7v  %s\n",
			shortSnapID(s.ID), truncate(s.Name, 20), s.CreatedAt.Format("2006-01-02 15:04:05"),
			s.EntryCount, s.Good, s.Signed, state)
	}
	return nil
}

func snapshotGet(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("get requires a snapshot id")
	}
	id := args[0]
	c, _, err := snapshotClient(args[1:], "get")
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := c.getJSON(c.adminURL("api/snapshots/get", map[string]string{"id": id}), &raw); err != nil {
		return err
	}
	return printJSON(raw)
}

func snapshotDiff(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("diff requires a fromID and a toID")
	}
	from, to := args[0], args[1]
	c, _, err := snapshotClient(args[2:], "diff")
	if err != nil {
		return err
	}
	report, err := c.getText(c.adminURL("api/snapshots/diff", map[string]string{"from": from, "to": to, "format": "md"}))
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stdout, report)
	if !strings.HasSuffix(report, "\n") {
		fmt.Fprintln(os.Stdout)
	}
	return nil
}

func snapshotCreate(args []string) error {
	name := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name = args[0]
		args = args[1:]
	}
	c, _, err := snapshotClient(args, "create")
	if err != nil {
		return err
	}
	var resp map[string]any
	if err := c.postJSON(c.adminURL("api/snapshots/create", nil), map[string]string{"name": name}, &resp); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "captured snapshot %v (%v entries)\n", resp["id"], resp["entryCount"])
	return nil
}

func snapshotFreeze(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("freeze requires a snapshot id")
	}
	id := args[0]
	fs := flag.NewFlagSet("snapshot freeze", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	mode := fs.String("mode", "block", "freeze mode: block|quarantine")
	reason := fs.String("reason", "frozen via ptctl", "reason recorded in the audit log")
	enforceDigest := fs.Bool("enforce-digest", true, "block a frozen coordinate served with a different digest")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	c, err := newClient(g)
	if err != nil {
		return err
	}
	var resp map[string]any
	if err := c.postJSON(c.adminURL("api/snapshots/freeze", nil), map[string]any{
		"id": id, "mode": *mode, "reason": *reason, "enforceDigest": *enforceDigest,
	}, &resp); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "organization frozen to %s (%v coordinates)\n", shortSnapID(id), resp["setSize"])
	return nil
}

func snapshotUnfreeze(args []string) error {
	c, _, err := snapshotClient(args, "unfreeze")
	if err != nil {
		return err
	}
	if err := c.postJSON(c.adminURL("api/snapshots/unfreeze", nil), map[string]any{}, nil); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "freeze lifted")
	return nil
}

func snapshotRollback(args []string) error {
	fs := flag.NewFlagSet("snapshot rollback", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	reason := fs.String("reason", "instant rollback via ptctl", "reason recorded in the audit log")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := newClient(g)
	if err != nil {
		return err
	}
	var resp map[string]any
	if err := c.postJSON(c.adminURL("api/snapshots/rollback", nil), map[string]string{"reason": *reason}, &resp); err != nil {
		return err
	}
	if fr, ok := resp["freeze"].(map[string]any); ok {
		fmt.Fprintf(os.Stdout, "rolled back: organization pinned to last-known-good snapshot %v\n", fr["snapshotId"])
	} else {
		fmt.Fprintln(os.Stdout, "rolled back to last-known-good snapshot")
	}
	return nil
}

func snapshotMarkGood(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("markgood requires a snapshot id")
	}
	id := args[0]
	good := true
	rest := args[1:]
	if len(rest) > 0 && (rest[0] == "false" || rest[0] == "true") {
		good = rest[0] == "true"
		rest = rest[1:]
	}
	c, _, err := snapshotClient(rest, "markgood")
	if err != nil {
		return err
	}
	if err := c.postJSON(c.adminURL("api/snapshots/markgood", nil), map[string]any{"id": id, "good": good}, nil); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "snapshot %s marked good=%v\n", shortSnapID(id), good)
	return nil
}

// --- small local helpers ----------------------------------------------------

func shortSnapID(id string) string {
	h := strings.TrimPrefix(id, "sha256:")
	if len(h) > 12 {
		return h[:12]
	}
	if h == "" {
		return "—"
	}
	return h
}

func rollbackTag(b bool) string {
	if b {
		return ", rollback"
	}
	return ""
}

func orValue(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func truncate(s string, n int) string {
	if s == "" {
		return "—"
	}
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
