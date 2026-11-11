package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/downloadlog"
)

// downloadsPage mirrors the admin API's download-log response.
type downloadsPage struct {
	Enabled    bool                `json:"enabled"`
	Total      int                 `json:"total"`
	Returned   int                 `json:"returned"`
	NextBefore uint64              `json:"nextBefore"`
	Entries    []downloadlog.Entry `json:"entries"`
	Log        downloadlog.Stats   `json:"log"`
}

// downloadsSummary mirrors the admin API's download-log summary response.
type downloadsSummary struct {
	Enabled bool `json:"enabled"`
	downloadlog.Summary
	Log downloadlog.Stats `json:"log"`
}

// runDownloads queries the proxy's download log (Task 176): which package was
// downloaded from which client address. It is the command-line view of the
// admin console's Downloads tab, for the two questions an incident starts with:
//
//	ptctl downloads --package left-pad        # who pulled left-pad?
//	ptctl downloads --ip 10.0.0.7             # what did 10.0.0.7 pull?
//
// and for exporting the answer (--format csv|json).
func runDownloads(args []string) error {
	fs := flag.NewFlagSet("downloads", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	var (
		ip        = fs.String("ip", "", "client address or CIDR prefix (10.0.0.7, 10.0.0.0/8, 2001:db8::/32)")
		pkg       = fs.String("package", "", "package, as name or name@version; * is a wildcard (\"@acme/*\", \"left-pad@1.*\")")
		ecosystem = fs.String("ecosystem", "", "ecosystem (cargo, go, npm, pip, docker, git, …)")
		upstream  = fs.String("upstream", "", "configured upstream name")
		outcome   = fs.String("outcome", "", "served | not_modified | blocked | not_found | error")
		subject   = fs.String("subject", "", "authenticated subject (user, token name, key fingerprint)")
		search    = fs.String("search", "", "free-text search across address, package, path, client tool, reason")
		since     = fs.String("since", "", "only entries newer than this: an age (15m, 24h, 7d), RFC 3339, or unix seconds")
		until     = fs.String("until", "", "only entries older than this (same forms as --since)")
		limit     = fs.Int("limit", 50, "maximum number of entries to show")
		all       = fs.Bool("all", false, "show every matching entry (pages through the log; overrides --limit)")
		summary   = fs.Bool("summary", false, "show totals and the busiest client addresses and packages instead of entries")
		top       = fs.Int("top", 10, "with --summary: how many clients and packages to list")
		format    = fs.String("format", "table", "output format: table|json|csv")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl downloads [flags]")
		fmt.Fprintln(os.Stderr, "\nShow the proxy's download log: which package was downloaded from which client")
		fmt.Fprintln(os.Stderr, "address (Task 176). Filters are ANDed. Examples:")
		fmt.Fprintln(os.Stderr, "\n  ptctl downloads --package left-pad            who pulled left-pad?")
		fmt.Fprintln(os.Stderr, "  ptctl downloads --ip 10.0.0.7                 what did 10.0.0.7 pull?")
		fmt.Fprintln(os.Stderr, "  ptctl downloads --outcome blocked --since 24h refused attempts of the last day")
		fmt.Fprintln(os.Stderr, "  ptctl downloads --summary --ecosystem cargo   busiest addresses and crates")
		fmt.Fprintln(os.Stderr, "  ptctl downloads --all --format csv > log.csv  export everything")
		fmt.Fprintln(os.Stderr, "\nFlags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch *format {
	case "table", "json", "csv":
	default:
		return fmt.Errorf("unknown --format %q (want table, json or csv)", *format)
	}
	if *limit < 1 {
		return fmt.Errorf("--limit must be positive")
	}
	if *summary && *format == "csv" {
		return fmt.Errorf("--summary has no CSV form; use --format json")
	}

	c, err := newClient(g)
	if err != nil {
		return err
	}

	query := map[string]string{
		"ip": *ip,
		// The text is passed on as given. Whether "openssl@3" is a package of
		// that name (it is, in Homebrew) or version 3 of "openssl" is not
		// something the text says; the API matches the filter against both the
		// name and the name@version coordinate.
		"package":   *pkg,
		"ecosystem": *ecosystem,
		"upstream":  *upstream,
		"outcome":   *outcome,
		"subject":   *subject,
		"q":         *search,
		"since":     *since,
		"until":     *until,
	}
	// --tenant is a global flag that also defaults from the environment; it
	// narrows the log only when given on this command line, so an exported
	// PULLTHROUGH_TENANT does not silently hide other tenants' downloads from an
	// operator.
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "tenant" {
			query["tenant"] = g.tenant
		}
	})

	if *summary {
		query["top"] = strconv.Itoa(*top)
		var sum downloadsSummary
		if err := c.getJSON(c.adminURL("api/downloads/summary", query), &sum); err != nil {
			return err
		}
		if *format == "json" {
			return emitJSON(sum)
		}
		renderDownloadsSummary(os.Stdout, sum)
		return nil
	}

	if *format == "csv" {
		text, err := fetchDownloadsCSV(c, query, *limit, *all)
		if err != nil {
			return err
		}
		fmt.Print(text)
		return nil
	}

	page, err := fetchDownloads(c, query, *limit, *all)
	if err != nil {
		return err
	}
	if *format == "json" {
		return emitJSON(page)
	}
	renderDownloads(os.Stdout, page)
	return nil
}

// downloadsPageSize is the page size used when paging through the whole log.
const downloadsPageSize = 1000

// fetchDownloads reads up to limit entries (every entry with all), following the
// API's pagination cursor.
func fetchDownloads(c *client, query map[string]string, limit int, all bool) (downloadsPage, error) {
	var out downloadsPage
	before := ""
	for {
		want := downloadsPageSize
		if !all && limit-len(out.Entries) < want {
			want = limit - len(out.Entries)
		}
		q := map[string]string{"limit": strconv.Itoa(want), "before": before}
		for k, v := range query {
			q[k] = v
		}
		var page downloadsPage
		if err := c.getJSON(c.adminURL("api/downloads", q), &page); err != nil {
			return out, err
		}
		if before == "" {
			out.Enabled, out.Total, out.Log = page.Enabled, page.Total, page.Log
		}
		out.Entries = append(out.Entries, page.Entries...)
		out.NextBefore = page.NextBefore
		if page.NextBefore == 0 || len(page.Entries) == 0 || (!all && len(out.Entries) >= limit) {
			break
		}
		before = strconv.FormatUint(page.NextBefore, 10)
	}
	out.Returned = len(out.Entries)
	return out, nil
}

// fetchDownloadsCSV returns the server's CSV export of the selection: every
// matching entry with all, the newest limit otherwise. There is no paging to
// do: the server writes an export as one response and bounds it by limit
// exactly, however large the limit is.
func fetchDownloadsCSV(c *client, query map[string]string, limit int, all bool) (string, error) {
	q := map[string]string{"format": "csv"}
	for k, v := range query {
		q[k] = v
	}
	if !all {
		q["limit"] = strconv.Itoa(limit)
	}
	return c.getText(c.adminURL("api/downloads", q))
}

// renderDownloads prints the entries as an aligned table, newest first.
func renderDownloads(w io.Writer, page downloadsPage) {
	if !page.Enabled {
		fmt.Fprintln(w, "The download log is disabled on this proxy (downloadLog.enabled).")
		return
	}
	if len(page.Entries) == 0 {
		fmt.Fprintln(w, "No downloads match.")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tCLIENT IP\tECOSYSTEM\tPACKAGE\tVERSION\tOUTCOME\tCACHE\tBYTES\tIDENTITY")
	for _, e := range page.Entries {
		client := e.ClientIP
		if e.ForwardedBy != "" {
			client += " (via " + e.ForwardedBy + ")"
		}
		outcome := string(e.Outcome)
		cache := e.Cache
		if e.Outcome == downloadlog.OutcomeBlocked {
			if e.Gate != "" {
				outcome += ":" + e.Gate
			}
			cache = ""
		}
		name := e.Package
		if name == "" {
			name = e.Path
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
			e.Time.UTC().Format(time.RFC3339), client, dash(e.Ecosystem), name, dash(e.Version),
			outcome, dash(cache), e.Bytes, dash(downloadIdentity(e)))
	}
	tw.Flush()
	if page.Returned < page.Total {
		fmt.Fprintf(w, "\n%d of %d matching entries shown (newest first); use --limit or --all for more.\n", page.Returned, page.Total)
	} else {
		fmt.Fprintf(w, "\n%d matching entries.\n", page.Total)
	}
}

// renderDownloadsSummary prints the totals and the busiest clients and packages.
func renderDownloadsSummary(w io.Writer, sum downloadsSummary) {
	if !sum.Enabled {
		fmt.Fprintln(w, "The download log is disabled on this proxy (downloadLog.enabled).")
		return
	}
	fmt.Fprintf(w, "Downloads: %d  (served %d, blocked %d, not modified %d, not found %d, errors %d)\n",
		sum.Total, sum.Served, sum.Blocked, sum.NotModified, sum.NotFound, sum.Errors)
	fmt.Fprintf(w, "Client addresses: %d   Packages: %d   Bytes sent: %d\n", sum.Clients, sum.Packages, sum.Bytes)
	if sum.First != nil && sum.Last != nil {
		fmt.Fprintf(w, "Period: %s → %s\n", sum.First.UTC().Format(time.RFC3339), sum.Last.UTC().Format(time.RFC3339))
	}
	if sum.Total == 0 {
		return
	}

	fmt.Fprintln(w, "\nClient addresses (most pulls first):")
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "CLIENT IP\tPULLS\tSERVED\tBLOCKED\tPACKAGES\tBYTES\tLAST SEEN\tIDENTITIES")
	for _, cs := range sum.ByClient {
		ids := "-"
		if len(cs.Identities) > 0 {
			ids = joinComma(cs.Identities)
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%d\t%s\t%s\n", cs.ClientIP, cs.Downloads, cs.Served, cs.Blocked,
			cs.Packages, cs.Bytes, cs.LastSeen.UTC().Format(time.RFC3339), ids)
	}
	tw.Flush()

	fmt.Fprintln(w, "\nPackages (most pulls first):")
	pw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(pw, "ECOSYSTEM\tPACKAGE\tPULLS\tSERVED\tBLOCKED\tCLIENTS\tLAST SEEN\tVERSIONS")
	for _, ps := range sum.ByPackage {
		versions := "-"
		if len(ps.Versions) > 0 {
			versions = joinComma(ps.Versions)
		}
		fmt.Fprintf(pw, "%s\t%s\t%d\t%d\t%d\t%d\t%s\t%s\n", ps.Ecosystem, ps.Package, ps.Downloads, ps.Served, ps.Blocked,
			ps.Clients, ps.LastSeen.UTC().Format(time.RFC3339), versions)
	}
	pw.Flush()
}

func downloadIdentity(e downloadlog.Entry) string {
	switch {
	case e.Subject != "" && e.Tenant != "":
		return e.Subject + " (" + e.Tenant + ")"
	case e.Subject != "":
		return e.Subject
	default:
		return e.Tenant
	}
}

func joinComma(items []string) string {
	out := ""
	for i, s := range items {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}
