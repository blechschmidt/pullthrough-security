package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// runLockdown implements `ptctl lockdown {freeze|strict|block|status|clear}`: the
// client surface for the emergency-lockdown / global kill-switch incident-response
// control (Task 74). It is HTTP-only, calling the admin /api/lockdown* endpoints.
//
// Actions:
//
//	status                                 print the current lockdown posture
//	freeze   -incident ID -reason R        serve only cached artifacts; block fetches
//	strict   -incident ID -reason R        flip every observe-mode gate to enforce
//	block    -incident ID -reason R <coord...>  deny specific coordinate(s) everywhere
//	clear    -reason R                     lift the active lockdown
//
// A block coordinate is "[ecosystem:]name[@version]" (an omitted version blocks
// the whole package). Engage/clear are administrator-only on the proxy side.
func runLockdown(args []string) error {
	if len(args) == 0 {
		return lockdownUsageErr()
	}
	action := args[0]
	rest := args[1:]
	switch action {
	case "status":
		return lockdownStatus(rest)
	case "freeze", "strict":
		return lockdownEngage(action, rest)
	case "block":
		return lockdownBlock(rest)
	case "clear":
		return lockdownClear(rest)
	case "-h", "--help", "help":
		lockdownUsage(os.Stdout)
		return nil
	default:
		return fmt.Errorf("unknown lockdown action %q (try: status, freeze, strict, block, clear)", action)
	}
}

func lockdownUsageErr() error {
	lockdownUsage(os.Stderr)
	return fmt.Errorf("an action is required")
}

func lockdownUsage(w *os.File) {
	fmt.Fprint(w, `ptctl lockdown <action> [flags] [args]

Emergency lockdown / global kill-switch (Task 74). All transitions require a
reason and an incident ID and carry a TTL with auto-expiry.

Actions:
  status                          print the current lockdown posture
  freeze  -incident ID -reason R  serve only already-cached artifacts; block all new fetches
  strict  -incident ID -reason R  flip every observe-mode gate to enforce + harden thresholds
  block   -incident ID -reason R <coord...>
                                  deny specific coordinate(s) everywhere, ahead of the feed
  clear   -reason R               lift the active lockdown

Engage/block/strict flags:
  -incident   incident ID recorded to the audit log (required)
  -reason     operator reason recorded to the audit log (required)
  -ttl        auto-expiry duration, e.g. 30m, 2h (default: server default)

A block coordinate is "[ecosystem:]name[@version]"; an omitted version blocks the
whole package. Global flags (e.g. -url, -token) follow the action.
`)
}

// lockdownStatusResponse mirrors the admin /api/lockdown payload (the fields the
// CLI renders).
type lockdownStatusResponse struct {
	Status struct {
		Active           bool      `json:"active"`
		Mode             string    `json:"mode"`
		Reason           string    `json:"reason"`
		IncidentID       string    `json:"incidentId"`
		Operator         string    `json:"operator"`
		EngagedAt        time.Time `json:"engagedAt"`
		ExpiresAt        time.Time `json:"expiresAt"`
		SecondsRemaining float64   `json:"secondsRemaining"`
		Targets          []struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
			Version   string `json:"version"`
		} `json:"targets"`
	} `json:"status"`
}

func lockdownClient(args []string, name string) (*client, error) {
	fs := flag.NewFlagSet("lockdown "+name, flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return newClient(g)
}

func lockdownStatus(args []string) error {
	c, err := lockdownClient(args, "status")
	if err != nil {
		return err
	}
	var resp lockdownStatusResponse
	if err := c.getJSON(c.adminURL("api/lockdown", nil), &resp); err != nil {
		return err
	}
	st := resp.Status
	if !st.Active {
		fmt.Fprintln(os.Stdout, "no active lockdown")
		return nil
	}
	fmt.Fprintf(os.Stdout, "LOCKDOWN ACTIVE: %s\n", strings.ToUpper(st.Mode))
	fmt.Fprintf(os.Stdout, "  incident:  %s\n", st.IncidentID)
	fmt.Fprintf(os.Stdout, "  reason:    %s\n", st.Reason)
	if st.Operator != "" {
		fmt.Fprintf(os.Stdout, "  operator:  %s\n", st.Operator)
	}
	if !st.ExpiresAt.IsZero() {
		fmt.Fprintf(os.Stdout, "  expires:   %s (%s remaining)\n",
			st.ExpiresAt.Format(time.RFC3339), fmtDurationSecs(st.SecondsRemaining))
	}
	if len(st.Targets) > 0 {
		fmt.Fprintln(os.Stdout, "  targets:")
		for _, t := range st.Targets {
			fmt.Fprintf(os.Stdout, "    - %s\n", lockdownCoordString(t.Ecosystem, t.Name, t.Version))
		}
	}
	return nil
}

func lockdownEngage(mode string, args []string) error {
	fs := flag.NewFlagSet("lockdown "+mode, flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	incident := fs.String("incident", "", "incident ID recorded to the audit log (required)")
	reason := fs.String("reason", "", "operator reason recorded to the audit log (required)")
	ttl := fs.String("ttl", "", "auto-expiry duration, e.g. 30m, 2h (default: server default)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*incident) == "" || strings.TrimSpace(*reason) == "" {
		return fmt.Errorf("%s requires -incident and -reason", mode)
	}
	c, err := newClient(g)
	if err != nil {
		return err
	}
	return lockdownPostEngage(c, map[string]any{
		"mode":       mode,
		"incidentId": *incident,
		"reason":     *reason,
		"ttl":        *ttl,
	})
}

func lockdownBlock(args []string) error {
	fs := flag.NewFlagSet("lockdown block", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	incident := fs.String("incident", "", "incident ID recorded to the audit log (required)")
	reason := fs.String("reason", "", "operator reason recorded to the audit log (required)")
	ttl := fs.String("ttl", "", "auto-expiry duration, e.g. 30m, 2h (default: server default)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	coords := fs.Args()
	if strings.TrimSpace(*incident) == "" || strings.TrimSpace(*reason) == "" {
		return fmt.Errorf("block requires -incident and -reason")
	}
	if len(coords) == 0 {
		return fmt.Errorf("block requires at least one coordinate, e.g. npm:left-pad@1.3.0")
	}
	targets := make([]map[string]string, 0, len(coords))
	for _, raw := range coords {
		eco, name, version := parseLockdownCoord(raw)
		if name == "" {
			return fmt.Errorf("invalid coordinate %q (want [ecosystem:]name[@version])", raw)
		}
		targets = append(targets, map[string]string{"ecosystem": eco, "name": name, "version": version})
	}
	c, err := newClient(g)
	if err != nil {
		return err
	}
	return lockdownPostEngage(c, map[string]any{
		"mode":       "block",
		"incidentId": *incident,
		"reason":     *reason,
		"ttl":        *ttl,
		"targets":    targets,
	})
}

func lockdownPostEngage(c *client, body map[string]any) error {
	var resp lockdownStatusResponse
	if err := c.postJSON(c.adminURL("api/lockdown/engage", nil), body, &resp); err != nil {
		return err
	}
	st := resp.Status
	fmt.Fprintf(os.Stdout, "lockdown engaged: %s (incident %s)\n", strings.ToUpper(st.Mode), st.IncidentID)
	if !st.ExpiresAt.IsZero() {
		fmt.Fprintf(os.Stdout, "  auto-expires at %s\n", st.ExpiresAt.Format(time.RFC3339))
	}
	if len(st.Targets) > 0 {
		fmt.Fprintf(os.Stdout, "  %d coordinate(s) denied everywhere\n", len(st.Targets))
	}
	return nil
}

func lockdownClear(args []string) error {
	fs := flag.NewFlagSet("lockdown clear", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	reason := fs.String("reason", "", "operator reason recorded to the audit log (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*reason) == "" {
		return fmt.Errorf("clear requires -reason")
	}
	c, err := newClient(g)
	if err != nil {
		return err
	}
	if err := c.postJSON(c.adminURL("api/lockdown/clear", nil), map[string]any{"reason": *reason}, nil); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "lockdown cleared")
	return nil
}

// --- small local helpers ----------------------------------------------------

// parseLockdownCoord splits "[ecosystem:]name[@version]" into its parts.
func parseLockdownCoord(raw string) (eco, name, version string) {
	s := strings.TrimSpace(raw)
	if i := strings.Index(s, ":"); i >= 0 {
		eco = strings.TrimSpace(s[:i])
		s = s[i+1:]
	}
	if i := strings.LastIndex(s, "@"); i > 0 {
		version = strings.TrimSpace(s[i+1:])
		s = s[:i]
	}
	name = strings.TrimSpace(s)
	return eco, name, version
}

func lockdownCoordString(eco, name, version string) string {
	out := name
	if version != "" {
		out += "@" + version
	}
	if eco != "" {
		out = eco + ":" + out
	}
	return out
}

func fmtDurationSecs(secs float64) string {
	if secs < 0 {
		return "no expiry"
	}
	return (time.Duration(secs) * time.Second).Truncate(time.Second).String()
}
