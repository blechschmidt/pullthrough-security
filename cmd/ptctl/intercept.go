package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/blechschmidt/pullthrough-security/internal/intercept"
)

// runIntercept implements `ptctl intercept {status|ca|hosts}`: the operator's
// view of TLS interception and NAT mode (Task 172).
//
//	status         the listeners, the routing table and the counters
//	ca             the CA certificate intercepted clients must trust
//	hosts          the hostnames to send to the NAT listeners (DNS zone, hosts file)
func runIntercept(args []string) error {
	if len(args) == 0 {
		interceptUsage(os.Stderr)
		return fmt.Errorf("an action is required")
	}
	switch args[0] {
	case "status":
		return interceptStatus(args[1:])
	case "ca":
		return interceptCA(args[1:])
	case "hosts":
		return interceptHosts(args[1:])
	case "-h", "--help", "help":
		interceptUsage(os.Stdout)
		return nil
	default:
		return fmt.Errorf("unknown intercept action %q (try: status, ca, hosts)", args[0])
	}
}

func interceptUsage(w *os.File) {
	fmt.Fprint(w, `ptctl intercept <action> [flags]

TLS interception and NAT mode (Task 172): clients that keep their registries'
addresses, and either use the proxy as HTTPS_PROXY or are sent to it by the
network. See docs/intercept-mode.md.

Actions:
  status                  listeners, routing table (host/path -> upstream), counters
  ca [--out FILE]         the CA certificate intercepted clients must trust (PEM)
  hosts [--address IP]    the hostnames to send to the NAT listeners, one per line;
                          with --address, as hosts-file lines mapping each to IP

Run 'ptctl intercept <action> -h' for the action's flags. Global flags (--url,
--token, …) follow the action.
`)
}

// interceptListing mirrors the admin API's GET /api/intercept response.
type interceptListing struct {
	Enabled bool `json:"enabled"`
	intercept.Status
}

func interceptStatus(args []string) error {
	fs := flag.NewFlagSet("intercept status", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	format := fs.String("format", "table", "output format: table|json")
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
	var listing interceptListing
	if err := c.getJSON(c.adminURL("api/intercept", nil), &listing); err != nil {
		return err
	}
	if *format == "json" {
		return emitJSON(listing)
	}
	renderInterceptStatus(os.Stdout, listing)
	return nil
}

// renderInterceptStatus prints the status as text.
func renderInterceptStatus(w io.Writer, l interceptListing) {
	if !l.Enabled {
		fmt.Fprintln(w, "TLS interception is disabled on this proxy (server.intercept.enabled).")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintf(tw, "Forward proxy (HTTPS_PROXY)\t%s\n", orNotRun(l.ForwardProxy))
	fmt.Fprintf(tw, "NAT listener, TLS (port 443)\t%s\n", orNotRun(l.NATHTTPS))
	fmt.Fprintf(tw, "NAT listener, plain HTTP (port 80)\t%s\n", orNotRun(l.NATHTTP))
	fmt.Fprintf(tw, "CA\t%s\n", l.CASubject)
	passthrough := "refused"
	if l.PassthroughUnmatched {
		passthrough = "passed on undecrypted"
	}
	fmt.Fprintf(tw, "Unconfigured hosts\t%s\n", passthrough)
	tw.Flush()

	fmt.Fprintln(w)
	tw = tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST/PATH\tUPSTREAM")
	for _, r := range l.Routes {
		fmt.Fprintf(tw, "%s\t%s\n", r.Rule, r.Upstream)
	}
	tw.Flush()

	modes := []intercept.Mode{intercept.ModeForward, intercept.ModeNAT}
	fmt.Fprintln(w)
	tw = tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "MODE\tCONNECTIONS\tTLS INTERCEPTED\tREQUESTS\tUNROUTED\tPASSED THROUGH\tREFUSED")
	for _, m := range modes {
		refused := map[string]uint64{}
		var total uint64
		for _, r := range l.Counters.Refused {
			if r.Mode == m {
				refused[r.Reason] += r.Count
				total += r.Count
			}
		}
		detail := ""
		if total > 0 {
			reasons := make([]string, 0, len(refused))
			for reason, n := range refused {
				reasons = append(reasons, fmt.Sprintf("%s %d", reason, n))
			}
			sort.Strings(reasons)
			detail = " (" + strings.Join(reasons, ", ") + ")"
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%d\t%d%s\n", m,
			l.Counters.Connections[m], l.Counters.Intercepted[m], l.Counters.Requests[m],
			l.Counters.Unrouted[m], l.Counters.Passthrough[m], total, detail)
	}
	tw.Flush()
}

func orNotRun(addr string) string {
	if addr == "" {
		return "not run"
	}
	return addr
}

func interceptCA(args []string) error {
	fs := flag.NewFlagSet("intercept ca", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	out := fs.String("out", "", "write the certificate to this file instead of standard output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := newClient(g)
	if err != nil {
		return err
	}
	pem, _, err := c.getRaw(c.adminURL("api/intercept/ca.crt", nil))
	if err != nil {
		return err
	}
	if *out == "" {
		_, err = os.Stdout.Write(pem)
		return err
	}
	if err := os.WriteFile(*out, pem, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote the interception CA certificate to %s\n", *out)
	return nil
}

func interceptHosts(args []string) error {
	fs := flag.NewFlagSet("intercept hosts", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	address := fs.String("address", "", "print hosts-file lines mapping every hostname to this address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := newClient(g)
	if err != nil {
		return err
	}
	query := map[string]string{"format": "hosts"}
	if *address != "" {
		query["address"] = *address
	}
	text, err := c.getText(c.adminURL("api/intercept", query))
	if err != nil {
		return err
	}
	fmt.Print(text)
	return nil
}
