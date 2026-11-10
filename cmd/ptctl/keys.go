package main

import (
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"
)

// runKeys dispatches the `ptctl keys` subcommands (Task 148): report the expiry
// standings of the proxy's long-lived signing keys / credentials / certificates,
// or drive a supported in-place rotation.
func runKeys(args []string) error {
	action := "status"
	if len(args) > 0 {
		action = args[0]
		args = args[1:]
	}
	switch action {
	case "status":
		return keysStatusCmd(args)
	case "rotate":
		return keysRotateCmd(args)
	case "-h", "--help", "help":
		keysUsage(os.Stdout)
		return nil
	default:
		return fmt.Errorf("unknown keys action %q (try: status, rotate)", action)
	}
}

func keysUsage(w *os.File) {
	fmt.Fprintln(w, "usage: ptctl keys <status|rotate> [flags]")
	fmt.Fprintln(w, "  status   show every monitored key/credential/certificate and its remaining lifetime (default)")
	fmt.Fprintln(w, "  rotate   rotate a supported material in place: ptctl keys rotate -material <id> [-force]")
	fmt.Fprintln(w, "flags: -json (machine-readable), plus the global -url/-token flags")
}

// keys* response shapes mirror the admin JSON (internal/keyrotation.ScanResult /
// RotationOutcome). Only the fields ptctl renders are declared.
type keysMaterial struct {
	ID                string    `json:"id"`
	Kind              string    `json:"kind"`
	KeyID             string    `json:"keyId"`
	Description       string    `json:"description"`
	Status            string    `json:"status"`
	HasExpiry         bool      `json:"hasExpiry"`
	EffectiveExpiry   time.Time `json:"effectiveExpiry"`
	ExpirySource      string    `json:"expirySource"`
	SecondsRemaining  float64   `json:"secondsRemaining"`
	Overlap           bool      `json:"overlap"`
	RotationSupported bool      `json:"rotationSupported"`
	Note              string    `json:"note"`
}

type keysStatusBody struct {
	Enabled           bool           `json:"enabled"`
	GeneratedAt       time.Time      `json:"generatedAt"`
	WarnThreshold     string         `json:"warnThreshold"`
	CriticalThreshold string         `json:"criticalThreshold"`
	Counts            keysCounts     `json:"counts"`
	Materials         []keysMaterial `json:"materials"`
}

type keysCounts struct {
	Total    int `json:"total"`
	OK       int `json:"ok"`
	Warning  int `json:"warning"`
	Critical int `json:"critical"`
	Expired  int `json:"expired"`
	Unknown  int `json:"unknown"`
}

type keysRotateOutcome struct {
	MaterialID      string    `json:"materialId"`
	Supported       bool      `json:"supported"`
	Performed       bool      `json:"performed"`
	NewPrimaryKeyID string    `json:"newPrimaryKeyId"`
	StartedAt       time.Time `json:"startedAt"`
	Duration        string    `json:"duration"`
	Scanned         int       `json:"scanned"`
	Rewrapped       int       `json:"rewrapped"`
	Detail          string    `json:"detail"`
}

func keysStatusCmd(args []string) error {
	fs := flag.NewFlagSet("keys status", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	jsonOut := fs.Bool("json", false, "emit machine-readable JSON")
	fs.Usage = func() { keysUsage(os.Stderr) }
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := newClient(g)
	if err != nil {
		return err
	}
	var st keysStatusBody
	if err := c.getJSON(c.adminURL("api/keys/status", nil), &st); err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(st)
	}
	printKeysStatus(st)
	return nil
}

func printKeysStatus(st keysStatusBody) {
	if !st.Enabled {
		fmt.Println("Key-rotation / expiry monitoring: disabled")
		fmt.Println("Enable it with keyRotation.enabled: true to monitor signing keys, the cache KEK, upstream credentials, and pinned certificates for expiry.")
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintf(tw, "Key-rotation / expiry monitoring\t\n")
	fmt.Fprintf(tw, "  Warn / critical thresholds\t%s / %s\n", st.WarnThreshold, st.CriticalThreshold)
	fmt.Fprintf(tw, "  Materials\t%d (ok %d, warning %d, critical %d, expired %d, unknown %d)\n",
		st.Counts.Total, st.Counts.OK, st.Counts.Warning, st.Counts.Critical, st.Counts.Expired, st.Counts.Unknown)
	fmt.Fprintln(tw, "\t")
	fmt.Fprintln(tw, "MATERIAL\tKIND\tSTATUS\tEXPIRES\tROTATE")
	for _, m := range st.Materials {
		expires := "—"
		if m.HasExpiry {
			expires = humanizeRemaining(m.SecondsRemaining)
		} else if m.Note != "" {
			expires = "no expiry"
		}
		rotate := "manual"
		if m.RotationSupported {
			rotate = "in-place"
		}
		if m.Overlap {
			rotate += " (overlap)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", m.ID, m.Kind, m.Status, expires, rotate)
	}
	_ = tw.Flush()
}

// humanizeRemaining renders a signed seconds-remaining as a coarse human string.
func humanizeRemaining(secs float64) string {
	if secs <= 0 {
		days := int(-secs / 86400)
		if days <= 0 {
			return "EXPIRED"
		}
		return fmt.Sprintf("expired %dd ago", days)
	}
	days := secs / 86400
	if days >= 2 {
		return fmt.Sprintf("in %.0fd", days)
	}
	hours := secs / 3600
	return fmt.Sprintf("in %.0fh", hours)
}

func keysRotateCmd(args []string) error {
	fs := flag.NewFlagSet("keys rotate", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	material := fs.String("material", "", "id of the key/credential to rotate (e.g. cache.kek)")
	force := fs.Bool("force", false, "override the single-in-flight overlap guard")
	jsonOut := fs.Bool("json", false, "emit machine-readable JSON")
	fs.Usage = func() { keysUsage(os.Stderr) }
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *material == "" {
		return fmt.Errorf("keys rotate: -material is required")
	}
	c, err := newClient(g)
	if err != nil {
		return err
	}
	var out keysRotateOutcome
	body := map[string]any{"material": *material, "force": *force}
	if err := c.postJSON(c.adminURL("api/keys/rotate", nil), body, &out); err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(out)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	if !out.Supported {
		fmt.Fprintf(tw, "Material %s: no automated in-place rotation\t\n", out.MaterialID)
		if out.Detail != "" {
			fmt.Fprintf(tw, "  %s\n", out.Detail)
		}
		return tw.Flush()
	}
	fmt.Fprintf(tw, "Rotation of %s\t\n", out.MaterialID)
	fmt.Fprintf(tw, "  Performed\t%s\n", yesNo(out.Performed))
	if out.NewPrimaryKeyID != "" {
		fmt.Fprintf(tw, "  New primary key id\t%s\n", out.NewPrimaryKeyID)
	}
	if out.Scanned > 0 || out.Rewrapped > 0 {
		fmt.Fprintf(tw, "  Scanned / re-wrapped\t%d / %d\n", out.Scanned, out.Rewrapped)
	}
	if out.Duration != "" {
		fmt.Fprintf(tw, "  Duration\t%s\n", out.Duration)
	}
	if out.Detail != "" {
		fmt.Fprintf(tw, "  Detail\t%s\n", out.Detail)
	}
	return tw.Flush()
}
