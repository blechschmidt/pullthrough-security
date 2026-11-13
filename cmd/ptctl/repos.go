package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/repos"
)

// runRepos implements `ptctl repos`: the repository registry of Task 180 —
// repositories whose tags the proxy tracks and whose releases it pins.
func runRepos(args []string) error {
	if len(args) == 0 {
		reposUsage(os.Stderr)
		return fmt.Errorf("an action is required")
	}
	actions := map[string]func([]string, io.Writer) error{
		"add":      reposAdd,
		"list":     reposList,
		"show":     reposShow,
		"tags":     reposTags,
		"releases": reposReleases,
		"commit":   reposCommit,
		"lookup":   reposLookup,
		"sync":     reposSync,
		"pin":      reposPin,
		"remove":   reposRemove,
		"verify":   reposVerify,
		"scan":     reposScan,
		"report":   reposReport,
		"update":   reposUpdate,
		"updates":  reposUpdates,
	}
	switch args[0] {
	case "-h", "--help", "help":
		reposUsage(os.Stdout)
		return nil
	}
	fn, ok := actions[args[0]]
	if !ok {
		return fmt.Errorf("unknown repos action %q (try: add, list, show, tags, releases, commit, lookup, sync, pin, remove, verify, scan, report, update, updates)", args[0])
	}
	return fn(args[1:], os.Stdout)
}

func reposUsage(w io.Writer) {
	fmt.Fprint(w, `ptctl repos <action> [flags]

The repository registry (Task 180): repositories whose tags the proxy tracks.
When a tag appears or moves, the lock files at its commit are read and every
dependency they pin is fetched through the proxy's gates and pinned in its
cache, so the release stays reproducible. Every tag-to-commit association ever
seen is kept; a commit no tag points at any more is "historical" and keeps its
pins.

Actions:
  add <name> <url> [--tenant T] [--credentials-ref env://VAR] [--username U]
                   [--lockfile GLOB]... [--tag GLOB]... [--upstream type=name]...
                   [--role ROLE]... [--full-name owner/repo] [--backfill N]
                              register a repository (administer capability)
  list                        the registered repositories
  show <name>                 a repository and its current tags, with the
                              state of the release each names
  tags <name> [--tag T]       the tag history: every commit each tag pointed
                              at, first/last seen, and what superseded it
  releases <name> [--tag T] [--commit C] [--full]
                              releases by tag (current and historical commits)
                              or by commit
  commit <sha>                the releases of a commit, in every repository
  lookup <type/name[@version]> | --digest sha256:…
                              which releases contain a dependency or object
  sync <name>                 fetch the repository's tags now
  pin <name> <commit>         pin (or retry pinning) a release now
  remove <name>               stop tracking an API registration; its history,
                              releases and pins are kept (administer)
  verify <name>               verify the hash chain of the tag history
  scan <name> [--rev REV] [--wait] [--wait-timeout D]
                              scan every dependency the lock files pin with the
                              LLM package-content scan (Task 181): the revision
                              named (tag, branch, commit; default the default
                              branch's head). A release is scanned through its
                              pinned objects. --wait waits for the report.
  report <name> [--rev REV] [--verdict all|flagged|unscanned|not-benign]
                [--sarif FILE]
                              the scan report: each dependency's verdict, model,
                              time and the lock-file lines that pin it; --sarif
                              writes SARIF located at those lines ("-" stdout)
  update <name> [--dry-run] [--no-wait] [--wait-timeout D] [--run ID]
                              run the maintenance updater (Task 182): the newest
                              compatible version of each dependency that passes
                              every gate and the LLM package scan is written to
                              the lock files on the maintenance branch, which is
                              pushed (--dry-run: computed, not pushed); prints
                              each update and each skipped candidate with its
                              reason. --run ID prints a past run's report.
  updates <name>              the maintenance branch's state, the newest runs,
                              and how each lock-file format is updated

Global flags (--url, --token, --tenant, …) follow the action. --format json
prints the API's answer.
`)
}

// reposFlags parses an action's flags (interspersed with positionals).
func reposFlags(name string, args []string, setup func(fs *flag.FlagSet)) (*client, []string, string, error) {
	fs := flag.NewFlagSet("repos "+name, flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	format := fs.String("format", "table", "output format: table|json")
	if setup != nil {
		setup(fs)
	}
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return nil, nil, "", err
	}
	if *format != "table" && *format != "json" {
		return nil, nil, "", fmt.Errorf("unknown --format %q (want table or json)", *format)
	}
	// --tenant narrows the answer only when given on this command line, so
	// that an exported PULLTHROUGH_TENANT does not silently hide other
	// tenants' repositories from an operator (as with ptctl downloads).
	explicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "tenant" {
			explicit = true
		}
	})
	if !explicit {
		g.tenant = ""
	}
	c, err := newClient(g)
	if err != nil {
		return nil, nil, "", err
	}
	return c, pos, *format, nil
}

// tenantQuery passes --tenant on when it was given on the command line.
func tenantQuery(c *client, q map[string]string) map[string]string {
	if c.tenant != "" {
		q["tenant"] = c.tenant
	}
	return q
}

func reposAdd(args []string, w io.Writer) error {
	var (
		tenant, credRef, user, fullName string
		backfill                        int
		lockfiles, tags, upstreams      multiFlag
		roles                           multiFlag
	)
	c, pos, format, err := reposFlags("add", args, func(fs *flag.FlagSet) {
		fs.StringVar(&tenant, "owner", "", "the tenant that owns the repository (defaults to --tenant)")
		fs.StringVar(&credRef, "credentials-ref", "", "secret reference of the HTTPS token: env://VAR, file:///path, vault://mount/path#key")
		fs.StringVar(&user, "username", "", "HTTPS user name sent with the token (default x-access-token)")
		fs.StringVar(&fullName, "full-name", "", "owner/repo, for routing push webhooks")
		fs.IntVar(&backfill, "backfill", -2, "how many existing tags to pin at the first sync (-1 all, 0 none; default: the server's)")
		fs.Var(&lockfiles, "lockfile", "glob of the lock files that make up a release (repeatable; default every lock file)")
		fs.Var(&tags, "tag", "glob of the tags tracked (repeatable; default every tag)")
		fs.Var(&upstreams, "upstream", "type=upstream: fetch this type's dependencies through that upstream (repeatable)")
		fs.Var(&roles, "role", "access-control role the release pinner fetches the dependencies with (repeatable; default repositories.roles; a tenant-bound identity cannot set it)")
	})
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf("repos add takes a name and a URL")
	}
	r := repos.Repo{Name: pos[0], URL: pos[1], CredentialsRef: credRef, Username: user, FullName: fullName,
		Tenant: firstNonEmpty(tenant, c.tenant), Lockfiles: lockfiles, Tags: tags, Roles: roles}
	if backfill >= -1 {
		r.BackfillTags = &backfill
	}
	for _, kv := range upstreams {
		t, up, ok := strings.Cut(kv, "=")
		if !ok || t == "" || up == "" {
			return fmt.Errorf("--upstream %q is not type=upstream", kv)
		}
		if r.Upstreams == nil {
			r.Upstreams = map[string]string{}
		}
		r.Upstreams[t] = up
	}
	var added repos.Repo
	if err := c.postJSON(c.adminURL("api/repos", nil), r, &added); err != nil {
		return err
	}
	if format == "json" {
		return emitJSON(added)
	}
	fmt.Fprintf(w, "registered %s (%s)", added.Name, added.URL)
	if added.Tenant != "" {
		fmt.Fprintf(w, " for tenant %s", added.Tenant)
	}
	fmt.Fprintln(w, "; its tags are being fetched")
	return nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

type reposListResponse struct {
	Repositories []repos.RepoView `json:"repositories"`
	Stats        repos.Stats      `json:"stats"`
}

func reposList(args []string, w io.Writer) error {
	c, _, format, err := reposFlags("list", args, nil)
	if err != nil {
		return err
	}
	var out reposListResponse
	if err := c.getJSON(c.adminURL("api/repos", tenantQuery(c, map[string]string{})), &out); err != nil {
		return err
	}
	if format == "json" {
		return emitJSON(out)
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tTENANT\tSTATE\tTAGS\tRELEASES\tPINNED\tLAST SYNC\tURL")
	for _, r := range out.Repositories {
		state := r.State
		if r.LastError != "" || r.HistoryError != "" {
			state += " (error)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%d\t%s\t%s\n", r.Name, dash(r.Tenant), state, r.Tags, r.Releases, r.FullyPinned,
			ago(&r.LastSuccess, time.Now()), r.URL)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(w, "\n%d repositories · %d pinned objects (%s) · %d releases queued\n", out.Stats.Repositories,
		out.Stats.PinnedObjects, humanBytes(out.Stats.PinnedBytes), out.Stats.Queued)
	return nil
}

func reposShow(args []string, w io.Writer) error {
	c, pos, format, err := reposFlags("show", args, nil)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("repos show takes a repository name")
	}
	var d repos.RepoDetail
	if err := c.getJSON(c.adminURL("api/repos/show", tenantQuery(c, map[string]string{"name": pos[0]})), &d); err != nil {
		return err
	}
	if format == "json" {
		return emitJSON(d)
	}
	fmt.Fprintf(w, "%s  %s\n", d.Name, d.URL)
	fmt.Fprintf(w, "  tenant: %s · source: %s · state: %s\n", dash(d.Tenant), d.Source, d.State)
	if len(d.Lockfiles) > 0 {
		fmt.Fprintf(w, "  lock files: %s\n", strings.Join(d.Lockfiles, ", "))
	}
	if len(d.Repo.Tags) > 0 {
		fmt.Fprintf(w, "  tags tracked: %s\n", strings.Join(d.Repo.Tags, ", "))
	}
	if d.CredentialsRef != "" {
		fmt.Fprintf(w, "  credentials: %s\n", d.CredentialsRef)
	}
	fmt.Fprintf(w, "  last sync: %s", ago(&d.LastSuccess, time.Now()))
	if d.LastError != "" {
		fmt.Fprintf(w, " · last error: %s", d.LastError)
	}
	fmt.Fprintln(w)
	if d.HistoryError != "" {
		fmt.Fprintf(w, "  HISTORY DOES NOT VERIFY: %s\n", d.HistoryError)
	}
	fmt.Fprintf(w, "  releases: %d (%d fully pinned)\n\n", d.Releases, d.FullyPinned)
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "TAG\tCOMMIT\tFIRST SEEN\tLAST SEEN\tRELEASE")
	for _, t := range d.CurrentTags {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", t.Tag, shortSHA(t.Commit), stamp(t.FirstSeen), stamp(t.LastSeen), t.Release)
	}
	return tw.Flush()
}

type reposTagsResponse struct {
	Repo         string                 `json:"repo"`
	Verified     bool                   `json:"verified"`
	Error        string                 `json:"error,omitempty"`
	Associations []repos.TagAssociation `json:"associations"`
}

func reposTags(args []string, w io.Writer) error {
	var tag string
	c, pos, format, err := reposFlags("tags", args, func(fs *flag.FlagSet) {
		fs.StringVar(&tag, "tag", "", "only this tag")
	})
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("repos tags takes a repository name")
	}
	var out reposTagsResponse
	if err := c.getJSON(c.adminURL("api/repos/tags", tenantQuery(c, map[string]string{"name": pos[0], "tag": tag})), &out); err != nil {
		return err
	}
	if format == "json" {
		return emitJSON(out)
	}
	if !out.Verified {
		fmt.Fprintf(w, "WARNING: the tag history does not verify: %s\n\n", out.Error)
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "TAG\tCOMMIT\tSTATE\tFIRST SEEN\tLAST SEEN\tSUPERSEDED")
	for _, a := range out.Associations {
		sup := "—"
		switch a.State {
		case repos.AssocMoved:
			sup = fmt.Sprintf("#%d %s → %s", a.SupersededBy, stamp(a.SupersededAt), shortSHA(a.NextCommit))
		case repos.AssocDeleted:
			sup = fmt.Sprintf("#%d %s (deleted)", a.SupersededBy, stamp(a.SupersededAt))
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", a.Tag, shortSHA(a.Commit), a.State, stamp(a.FirstSeen), stamp(a.LastSeen), sup)
	}
	return tw.Flush()
}

type reposReleasesResponse struct {
	Releases []repos.ReleaseView `json:"releases"`
}

func reposReleases(args []string, w io.Writer) error {
	var tag, commit string
	var full bool
	c, pos, format, err := reposFlags("releases", args, func(fs *flag.FlagSet) {
		fs.StringVar(&tag, "tag", "", "the releases a tag named: its current commit and every one it pointed at before")
		fs.StringVar(&commit, "commit", "", "the release of a commit (7+ hex digits)")
		fs.BoolVar(&full, "full", false, "include the manifests (lock files, dependencies, objects); implies --format json")
	})
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("repos releases takes a repository name")
	}
	q := map[string]string{"name": pos[0], "tag": tag, "commit": commit}
	if full {
		q["full"] = "1"
		format = "json"
	}
	var out reposReleasesResponse
	if err := c.getJSON(c.adminURL("api/repos/releases", tenantQuery(c, q)), &out); err != nil {
		return err
	}
	if format == "json" {
		return emitJSON(out)
	}
	return renderReleases(w, out.Releases)
}

func reposCommit(args []string, w io.Writer) error {
	c, pos, format, err := reposFlags("commit", args, nil)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("repos commit takes a commit ID")
	}
	var out reposReleasesResponse
	if err := c.getJSON(c.adminURL("api/repos/releases", tenantQuery(c, map[string]string{"commit": pos[0]})), &out); err != nil {
		return err
	}
	if format == "json" {
		return emitJSON(out)
	}
	return renderReleases(w, out.Releases)
}

func reposLookup(args []string, w io.Writer) error {
	var digest string
	c, pos, format, err := reposFlags("lookup", args, func(fs *flag.FlagSet) {
		fs.StringVar(&digest, "digest", "", "an object or lock-file digest (sha256:…, sha512:…)")
	})
	if err != nil {
		return err
	}
	q := map[string]string{"digest": digest}
	switch {
	case digest != "" && len(pos) == 0:
	case digest == "" && len(pos) == 1:
		q["coordinate"] = pos[0]
	default:
		return fmt.Errorf("repos lookup takes a coordinate (type/name[@version]) or --digest")
	}
	var out reposReleasesResponse
	if err := c.getJSON(c.adminURL("api/repos/lookup", tenantQuery(c, q)), &out); err != nil {
		return err
	}
	if format == "json" {
		return emitJSON(out)
	}
	if len(out.Releases) == 0 {
		fmt.Fprintln(w, "no release contains it")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "REPO\tCOMMIT\tSTATE\tTAGS\tDEPENDENCY\tSTATUS")
	for _, r := range out.Releases {
		for _, m := range r.Matches {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Repo, shortSHA(r.Commit), r.State, releaseTags(r), m.Coordinate(), m.Status)
		}
	}
	return tw.Flush()
}

func renderReleases(w io.Writer, rel []repos.ReleaseView) error {
	if len(rel) == 0 {
		fmt.Fprintln(w, "no releases")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "REPO\tCOMMIT\tSTATE\tTAGS\tSTATUS\tDEPS\tPINNED\tOBJECTS\tBYTES\tUPDATED")
	for _, r := range rel {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%s\t%s\n", r.Repo, shortSHA(r.Commit), r.State, releaseTags(r), r.Status,
			r.Summary.Dependencies, r.Summary.Pinned, r.Summary.PinnedObjects, humanBytes(r.Summary.PinnedBytes), stamp(r.UpdatedAt))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	for _, r := range rel {
		if r.Reason != "" {
			fmt.Fprintf(w, "\n%s@%s: %s", r.Repo, shortSHA(r.Commit), r.Reason)
		}
	}
	fmt.Fprintln(w)
	return nil
}

func releaseTags(r repos.ReleaseView) string {
	if len(r.CurrentTags) > 0 {
		return strings.Join(r.CurrentTags, ",")
	}
	if len(r.FormerTags) > 0 {
		return "(was " + strings.Join(r.FormerTags, ",") + ")"
	}
	return "—"
}

func reposSync(args []string, w io.Writer) error {
	c, pos, format, err := reposFlags("sync", args, nil)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("repos sync takes a repository name")
	}
	var res repos.SyncResult
	if err := c.postJSON(c.adminURL("api/repos/sync", tenantQuery(c, map[string]string{"name": pos[0]})), struct{}{}, &res); err != nil {
		return err
	}
	if format == "json" {
		return emitJSON(res)
	}
	fmt.Fprintf(w, "%s: %d tags · %d created · %d moved · %d deleted · %d releases queued for pinning\n",
		res.Repo, res.Tags, res.Created, res.Moved, res.Deleted, res.Queued)
	return nil
}

func reposPin(args []string, w io.Writer) error {
	c, pos, _, err := reposFlags("pin", args, nil)
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf("repos pin takes a repository name and a commit")
	}
	if err := c.postJSON(c.adminURL("api/repos/pin", tenantQuery(c, map[string]string{"name": pos[0], "commit": pos[1]})), struct{}{}, nil); err != nil {
		return err
	}
	fmt.Fprintf(w, "%s@%s queued for pinning; follow it with: ptctl repos releases %s --commit %s\n", pos[0], shortSHA(pos[1]), pos[0], shortSHA(pos[1]))
	return nil
}

func reposRemove(args []string, w io.Writer) error {
	c, pos, _, err := reposFlags("remove", args, nil)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("repos remove takes a repository name")
	}
	if err := c.postJSON(c.adminURL("api/repos/remove", tenantQuery(c, map[string]string{"name": pos[0]})), struct{}{}, nil); err != nil {
		return err
	}
	fmt.Fprintf(w, "%s is no longer tracked; its tag history, releases and pins are kept\n", pos[0])
	return nil
}

func reposVerify(args []string, w io.Writer) error {
	c, pos, format, err := reposFlags("verify", args, nil)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("repos verify takes a repository name")
	}
	var out struct {
		Repo     string `json:"repo"`
		Records  int    `json:"records"`
		Verified bool   `json:"verified"`
		Error    string `json:"error,omitempty"`
	}
	if err := c.getJSON(c.adminURL("api/repos/verify", tenantQuery(c, map[string]string{"name": pos[0]})), &out); err != nil {
		return err
	}
	if format == "json" {
		return emitJSON(out)
	}
	if !out.Verified {
		return fmt.Errorf("the tag history of %s does not verify: %s", out.Repo, out.Error)
	}
	fmt.Fprintf(w, "the tag history of %s verifies: %d records, each chained to the one before\n", out.Repo, out.Records)
	return nil
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04")
}

// shortSHA abbreviates a commit ID.
func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// verdictFilter maps a --verdict choice onto the API's filter.
func verdictFilter(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "all":
		return "", nil
	case "flagged":
		return "malicious,suspicious", nil
	case "unscanned":
		return "unscanned", nil
	case "not-benign":
		return "malicious,suspicious,unscanned", nil
	}
	return "", fmt.Errorf("--verdict %q: want all, flagged, unscanned or not-benign", v)
}

// reposScan queues a dependency scan and, with --wait, waits for its report.
func reposScan(args []string, w io.Writer) error {
	var (
		rev     string
		wait    bool
		timeout time.Duration
	)
	c, pos, format, err := reposFlags("scan", args, func(fs *flag.FlagSet) {
		fs.StringVar(&rev, "rev", "", "tag, branch or commit to scan (default: the default branch's head)")
		fs.BoolVar(&wait, "wait", false, "wait for the scan's report")
		fs.DurationVar(&timeout, "wait-timeout", 30*time.Minute, "how long --wait waits")
	})
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("repos scan takes a repository name")
	}
	before := time.Now().UTC()
	var ticket repos.ScanTicket
	if err := c.postJSON(c.adminURL("api/repos/scan", tenantQuery(c, map[string]string{"name": pos[0], "rev": rev})), struct{}{}, &ticket); err != nil {
		return err
	}
	if !wait {
		if format == "json" {
			return emitJSON(ticket)
		}
		fmt.Fprintf(w, "%s %s %s@%s (%s); read it with: ptctl repos report %s --rev %s\n",
			ticket.Status, ticket.Kind, ticket.Repo, shortSHA(ticket.Commit), firstNonEmpty(ticket.Ref, "—"), ticket.Repo, ticket.Commit)
		return nil
	}
	deadline := time.Now().Add(timeout)
	for {
		var rep repos.ScanReportView
		err := c.getJSON(c.adminURL("api/repos/scan", tenantQuery(c, map[string]string{"name": pos[0], "rev": ticket.Commit})), &rep)
		if err == nil && !rep.FinishedAt.Before(before) {
			if format == "json" {
				return emitJSON(rep)
			}
			return renderScanReport(w, &rep)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no report of %s@%s within %s (the scan is %s); read it later with: ptctl repos report %s --rev %s",
				ticket.Repo, shortSHA(ticket.Commit), timeout, ticket.Status, ticket.Repo, ticket.Commit)
		}
		time.Sleep(2 * time.Second)
	}
}

// reposReport prints a scan report, or writes it as SARIF.
func reposReport(args []string, w io.Writer) error {
	var rev, verdict, sarif string
	c, pos, format, err := reposFlags("report", args, func(fs *flag.FlagSet) {
		fs.StringVar(&rev, "rev", "", "tag, branch or commit (default: the default branch's head)")
		fs.StringVar(&verdict, "verdict", "all", "which dependencies: all, flagged, unscanned, not-benign")
		fs.StringVar(&sarif, "sarif", "", "write the report as SARIF 2.1.0 to this file (\"-\" for stdout)")
	})
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("repos report takes a repository name")
	}
	filter, err := verdictFilter(verdict)
	if err != nil {
		return err
	}
	q := map[string]string{"name": pos[0], "rev": rev}
	if sarif != "" {
		body, _, err := c.getRaw(c.adminURL("api/repos/scan/sarif", tenantQuery(c, q)))
		if err != nil {
			return err
		}
		if sarif == "-" {
			_, err = w.Write(body)
			return err
		}
		if err := os.WriteFile(sarif, body, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(w, "wrote %s\n", sarif)
		return nil
	}
	q["verdict"] = filter
	var rep repos.ScanReportView
	if err := c.getJSON(c.adminURL("api/repos/scan", tenantQuery(c, q)), &rep); err != nil {
		return err
	}
	if format == "json" {
		return emitJSON(rep)
	}
	return renderScanReport(w, &rep)
}

// renderScanReport prints a report: a header, then one row per dependency.
// The model's reasons and excerpts are not printed (they are package text);
// --format json carries them.
func renderScanReport(w io.Writer, rep *repos.ScanReportView) error {
	where := rep.Kind
	if rep.Ref != "" {
		where += " " + rep.Ref
	}
	if len(rep.Tags) > 0 {
		where += " (" + strings.Join(rep.Tags, ", ") + ")"
	}
	fmt.Fprintf(w, "%s @ %s · %s · %s %s", rep.Repo, shortSHA(rep.Commit), where, rep.Status, rep.Result)
	if rep.ContainsMaliciousDependency {
		fmt.Fprint(w, " · CONTAINS MALICIOUS DEPENDENCY")
	}
	fmt.Fprintf(w, "\n%s / %s (prompt v%d) · action %s · %s · finished %s\n",
		firstNonEmpty(rep.Gate.Provider, "—"), firstNonEmpty(rep.Gate.Model, "—"), rep.Gate.PromptVersion,
		firstNonEmpty(rep.Gate.Action, "—"), rep.Trigger, stamp(rep.FinishedAt))
	s := rep.Summary
	fmt.Fprintf(w, "%d dependencies: %d malicious, %d suspicious, %d benign, %d unscanned · %d verdicts from the cache, %d scanned\n",
		s.Dependencies, s.Malicious, s.Suspicious, s.Benign, s.Unscanned, s.Cached, s.Scanned)
	if rep.Reason != "" {
		fmt.Fprintln(w, rep.Reason)
	}
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "VERDICT\tDEPENDENCY\tLOCK FILE\tMODEL\tSCANNED\tNOTE")
	for _, d := range rep.Dependencies {
		model, scanned := "—", "—"
		if v := d.Detail; v != nil {
			model = firstNonEmpty(v.Model, "—")
			if v.Confidence > 0 {
				model += fmt.Sprintf(" (%.2f)", v.Confidence)
			}
			scanned = stamp(v.ScannedAt)
		}
		note := ""
		switch {
		case d.Unscanned != nil:
			note = d.Unscanned.Code + ": " + d.Unscanned.Reason
		case d.Released != "":
			note = "released by break-glass " + d.Released
		case d.Refused:
			note = "refused to clients"
		}
		if d.Pinned && d.Verdict == repos.VerdictMalicious {
			note = strings.TrimPrefix(note+"; pinned bytes kept for forensics", "; ")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", d.Verdict, d.Coordinate(), strings.Join(d.Files, ","), model, scanned, note)
	}
	return tw.Flush()
}

// reposUpdate starts a maintenance run and waits for its report (Task 182).
func reposUpdate(args []string, w io.Writer) error {
	var (
		dryRun  bool
		noWait  bool
		runID   string
		timeout time.Duration
	)
	c, pos, format, err := reposFlags("update", args, func(fs *flag.FlagSet) {
		fs.BoolVar(&dryRun, "dry-run", false, "compute the updates and the commit, push nothing")
		fs.BoolVar(&noWait, "no-wait", false, "start the run and return")
		fs.StringVar(&runID, "run", "", "print the report of this run instead of starting one")
		fs.DurationVar(&timeout, "wait-timeout", 2*time.Hour, "how long to wait for the run")
	})
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("repos update takes a repository name")
	}
	if runID != "" {
		var run repos.UpdateRun
		if err := c.getJSON(c.adminURL("api/repos/update", tenantQuery(c, map[string]string{"name": pos[0], "run": runID})), &run); err != nil {
			return err
		}
		if format == "json" {
			return emitJSON(run)
		}
		return renderUpdateRun(w, &run)
	}
	q := map[string]string{"name": pos[0]}
	if dryRun {
		q["dryRun"] = "1"
	}
	var run repos.UpdateRun
	if err := c.postJSON(c.adminURL("api/repos/update", tenantQuery(c, q)), struct{}{}, &run); err != nil {
		return err
	}
	if noWait {
		if format == "json" {
			return emitJSON(run)
		}
		fmt.Fprintf(w, "%s: run %s started; read it with: ptctl repos update %s --run %s\n", run.Repo, run.ID, run.Repo, run.ID)
		return nil
	}
	deadline := time.Now().Add(timeout)
	for run.Status == repos.UpdateRunning {
		if time.Now().After(deadline) {
			return fmt.Errorf("run %s did not finish within %s; read it later with: ptctl repos update %s --run %s", run.ID, timeout, run.Repo, run.ID)
		}
		time.Sleep(2 * time.Second)
		var next repos.UpdateRun
		if err := c.getJSON(c.adminURL("api/repos/update", tenantQuery(c, map[string]string{"name": pos[0], "run": run.ID})), &next); err != nil {
			continue // stored once it ends; a replica restart in between is retried
		}
		run = next
	}
	if format == "json" {
		return emitJSON(run)
	}
	if err := renderUpdateRun(w, &run); err != nil {
		return err
	}
	if run.Status == repos.UpdateFailed || run.Status == repos.UpdateConflict {
		return fmt.Errorf("the maintenance run ended %s", run.Status)
	}
	return nil
}

// renderUpdateRun prints a maintenance run: a header, the updates, the skipped
// candidates.
func renderUpdateRun(w io.Writer, run *repos.UpdateRun) error {
	fmt.Fprintf(w, "%s · %s · %s on %s@%s · run %s\n", run.Repo, run.Status, run.Branch, firstNonEmpty(run.BaseBranch, "—"), shortSHA(run.Base), run.ID)
	if run.Reason != "" {
		fmt.Fprintln(w, run.Reason)
	}
	if run.Commit != "" {
		fmt.Fprintf(w, "commit %s", shortSHA(run.Commit))
		if run.Previous != "" {
			fmt.Fprintf(w, " (branch was at %s)", shortSHA(run.Previous))
		}
		fmt.Fprintln(w)
	}
	if run.PullRequest != nil {
		fmt.Fprintf(w, "pull request #%d %s\n", run.PullRequest.Number, run.PullRequest.URL)
	} else if run.PullRequestError != "" {
		fmt.Fprintf(w, "pull request not opened: %s\n", run.PullRequestError)
	}
	fmt.Fprintf(w, "%d dependencies examined · %d updates · %d skipped\n\n", run.Dependencies, len(run.Updates), len(run.Skipped))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if len(run.Updates) > 0 {
		fmt.Fprintln(tw, "UPDATE\tFROM\tTO\tBUMP\tMETHOD\tVERDICT\tSCAN\tFILES")
		for _, u := range run.Updates {
			fmt.Fprintf(tw, "%s/%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", u.Type, u.Name, u.From, u.To, u.Bump, u.Method, u.Verdict,
				strings.Join(u.ScanIDs, ","), strings.Join(u.Files, ","))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		fmt.Fprintln(w)
	}
	if len(run.Skipped) > 0 {
		tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "SKIPPED\tFROM\tCANDIDATE\tREASON")
		for _, sk := range run.Skipped {
			fmt.Fprintf(tw, "%s/%s\t%s\t%s\t%s: %s\n", sk.Type, sk.Name, sk.From, firstNonEmpty(sk.To, "—"), sk.Code, sk.Reason)
		}
		return tw.Flush()
	}
	return nil
}

// reposUpdates prints a repository's maintenance state (Task 182).
func reposUpdates(args []string, w io.Writer) error {
	c, pos, format, err := reposFlags("updates", args, nil)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("repos updates takes a repository name")
	}
	var ov repos.UpdateOverview
	if err := c.getJSON(c.adminURL("api/repos/updates", tenantQuery(c, map[string]string{"name": pos[0]})), &ov); err != nil {
		return err
	}
	if format == "json" {
		return emitJSON(ov)
	}
	state := "enabled"
	if !ov.Enabled {
		state = "disabled"
	}
	fmt.Fprintf(w, "%s · maintenance %s · branch %s · last pushed %s", ov.Repo, state, ov.Branch, firstNonEmpty(shortSHA(ov.State.LastPushed), "—"))
	if ov.State.LastStatus != "" {
		fmt.Fprintf(w, " · last run %s %s", ov.State.LastStatus, stamp(ov.State.LastRunAt))
	}
	fmt.Fprintln(w)
	if ov.State.Conflict != "" {
		fmt.Fprintf(w, "CONFLICT: %s\n", ov.State.Conflict)
	}
	if ov.Running != nil {
		fmt.Fprintf(w, "running: %s (started %s)\n", ov.Running.ID, stamp(ov.Running.StartedAt))
	}
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "RUN\tSTATUS\tBASE\tCOMMIT\tUPDATES\tSKIPPED\tTRIGGER")
	for _, r := range ov.Runs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%d\t%s\n", r.ID, r.Status, shortSHA(r.Base), firstNonEmpty(shortSHA(r.Commit), "—"), len(r.Updates), len(r.Skipped), r.Trigger)
	}
	return tw.Flush()
}
