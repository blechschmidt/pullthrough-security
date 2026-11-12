package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/userlinks"
)

// runUserLinks implements `ptctl userlinks {list|revoke|issue}`: the operator's
// command-line view of personal cache links (Task 177) — the links cache users
// create after signing in through the identity provider, so that their
// downloads are recorded under their name.
//
//	list                         who holds which link, its state, when and from where it was last used
//	revoke --id ID               end one link
//	revoke --user SUBJECT        end everything issued to a user (and their sign-in session)
//	issue  --user SUBJECT        create a link for a service account; prints its token, once
func runUserLinks(args []string) error {
	if len(args) == 0 {
		userLinksUsage(os.Stderr)
		return fmt.Errorf("an action is required")
	}
	switch args[0] {
	case "list":
		return userLinksList(args[1:])
	case "revoke":
		return userLinksRevoke(args[1:])
	case "issue":
		return userLinksIssue(args[1:])
	case "-h", "--help", "help":
		userLinksUsage(os.Stdout)
		return nil
	default:
		return fmt.Errorf("unknown userlinks action %q (try: list, revoke, issue)", args[0])
	}
}

func userLinksUsage(w *os.File) {
	fmt.Fprint(w, `ptctl userlinks <action> [flags]

Personal cache links (Task 177): cache users sign in through the identity
provider and get their own address for every package source, so that downloads
are recorded per user. The proxy keeps no link tokens — a link cannot be shown
again, only revoked.

Actions:
  list                    list links: user, name, state, expiry, last use
  revoke --id ID          revoke one link
  revoke --user SUBJECT   revoke everything issued to a user, and end their
                          session on the links page (they may sign in again)
  issue  --user SUBJECT   issue a link for a service account, or where no
                          identity provider is configured; prints the link once

Run 'ptctl userlinks <action> -h' for the action's flags. Global flags (--url,
--token, …) follow the action.
`)
}

// clientTool reduces a User-Agent to the tool it names: its first product token
// ("docker/29.1.3" of the Docker Engine's hundred-odd characters). The table is
// for telling tools apart at a glance; --format json has the whole string.
func clientTool(agent string) string {
	agent = strings.TrimSpace(agent)
	if i := strings.IndexAny(agent, " \t"); i > 0 {
		agent = agent[:i]
	}
	if len(agent) > 40 {
		agent = agent[:40] + "…"
	}
	return agent
}

// userLinksListing mirrors the admin API's GET /api/userlinks response.
type userLinksListing struct {
	Enabled    bool             `json:"enabled"`
	SignIn     bool             `json:"signIn"`
	PageURL    string           `json:"pageUrl"`
	PathPrefix string           `json:"pathPrefix"`
	Registry   userlinks.Stats  `json:"registry"`
	Total      int              `json:"total"`
	Links      []userlinks.Info `json:"links"`
	Users      []struct {
		Subject    string     `json:"subject"`
		Name       string     `json:"name"`
		Team       string     `json:"team"`
		Links      int        `json:"links"`
		Active     int        `json:"active"`
		LastUsedAt *time.Time `json:"lastUsedAt"`
		LastAddr   string     `json:"lastAddr"`
	} `json:"users"`
}

func userLinksList(args []string) error {
	fs := flag.NewFlagSet("userlinks list", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	var (
		user   = fs.String("user", "", "only this user's links (the subject, exactly)")
		state  = fs.String("state", "", "only links in this state: active | expired | revoked")
		search = fs.String("search", "", "free-text search across user, name, team, link name, link id and last address")
		limit  = fs.Int("limit", 200, "maximum number of links to show")
		byUser = fs.Bool("users", false, "summarize per user instead of listing links")
		format = fs.String("format", "table", "output format: table|json")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl userlinks list [flags]")
		fmt.Fprintln(os.Stderr, "\nList personal cache links. Examples:")
		fmt.Fprintln(os.Stderr, "\n  ptctl userlinks list                          every link, newest first")
		fmt.Fprintln(os.Stderr, "  ptctl userlinks list --users                  one line per user")
		fmt.Fprintln(os.Stderr, "  ptctl userlinks list --user alice@example.com --state active")
		fmt.Fprintln(os.Stderr, "\nFlags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *format != "table" && *format != "json" {
		return fmt.Errorf("unknown --format %q (want table or json)", *format)
	}
	if *limit < 1 {
		return fmt.Errorf("--limit must be positive")
	}
	c, err := newClient(g)
	if err != nil {
		return err
	}
	var listing userLinksListing
	query := map[string]string{"subject": *user, "state": *state, "q": *search, "limit": strconv.Itoa(*limit)}
	if err := c.getJSON(c.adminURL("api/userlinks", query), &listing); err != nil {
		return err
	}
	if *format == "json" {
		return emitJSON(listing)
	}
	renderUserLinks(os.Stdout, listing, *byUser, time.Now())
	return nil
}

// renderUserLinks prints the listing as a table: one line per link, or — with
// byUser — one per user.
func renderUserLinks(w io.Writer, l userLinksListing, byUser bool, now time.Time) {
	if !l.Enabled {
		fmt.Fprintln(w, "Personal cache links are disabled on this proxy (userLinks.enabled).")
		return
	}
	if !l.Registry.Synced || l.Registry.LastSyncError != "" {
		fmt.Fprintf(w, "WARNING: the link registry cannot reach its store (%s); links this replica does not know are refused until it can.\n\n",
			orDash(l.Registry.LastSyncError))
	}
	if l.Total == 0 {
		fmt.Fprintln(w, "No links match.")
		if l.SignIn {
			fmt.Fprintf(w, "Users create links at %s\n", l.PageURL)
		}
		return
	}

	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	if byUser {
		fmt.Fprintln(tw, "USER\tTEAM\tWORKING\tLINKS\tLAST USED\tFROM")
		for _, u := range l.Users {
			fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\t%s\n", u.Subject, dash(u.Team), u.Active, u.Links, ago(u.LastUsedAt, now), dash(u.LastAddr))
		}
	} else {
		fmt.Fprintln(tw, "ID\tUSER\tTEAM\tNAME\tSTATE\tCREATED\tEXPIRES\tLAST USED\tFROM\tCLIENT")
		for _, info := range l.Links {
			state := string(info.State)
			if info.State == userlinks.StateRevoked && info.RevokedBy != "" {
				state += " by " + info.RevokedBy
			}
			expires := "never"
			if info.ExpiresAt != nil {
				expires = info.ExpiresAt.UTC().Format("2006-01-02")
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				info.ID, info.Subject, dash(info.Team), dash(info.Label), state,
				info.CreatedAt.UTC().Format("2006-01-02"), expires, ago(info.LastUsedAt, now), dash(info.LastAddr), dash(clientTool(info.LastAgent)))
		}
	}
	tw.Flush()

	fmt.Fprintf(w, "\n%d working, %d expired, %d revoked; %d users with a working link.\n",
		l.Registry.Active, l.Registry.Expired, l.Registry.Revoked, l.Registry.Users)
	if !byUser && len(l.Links) < l.Total {
		fmt.Fprintf(w, "%d of %d matching links shown (newest first); use --limit for more.\n", len(l.Links), l.Total)
	}
}

// ago renders how long ago t was, coarsely: this is a column to scan for links
// nobody uses any more, and for one that was used a minute ago.
func ago(t *time.Time, now time.Time) string {
	if t == nil || t.IsZero() {
		return "never"
	}
	d := now.Sub(*t)
	switch {
	case d < 0:
		return t.UTC().Format(time.RFC3339)
	case d < 90*time.Second:
		return "just now"
	case d < 90*time.Minute:
		return strconv.Itoa(int(d.Minutes()+0.5)) + "m ago"
	case d < 36*time.Hour:
		return strconv.Itoa(int(d.Hours()+0.5)) + "h ago"
	default:
		return strconv.Itoa(int(d.Hours()/24+0.5)) + "d ago"
	}
}

func userLinksRevoke(args []string) error {
	fs := flag.NewFlagSet("userlinks revoke", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	var (
		id     = fs.String("id", "", "revoke the link with this identifier (see `ptctl userlinks list`)")
		user   = fs.String("user", "", "revoke everything issued to this user: every link, and their session on the links page")
		reason = fs.String("reason", "", "why; recorded with the revocation and in the audit log")
		format = fs.String("format", "table", "output format: table|json")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl userlinks revoke (--id ID | --user SUBJECT) [--reason R] [flags]")
		fmt.Fprintln(os.Stderr, "\nRevoke one personal cache link, or everything issued to a user. A revoked link")
		fmt.Fprintln(os.Stderr, "is refused at once on the replica that performed the revocation and within the")
		fmt.Fprintln(os.Stderr, "registry's refresh interval (userLinks.syncInterval) on the others.")
		fmt.Fprintln(os.Stderr, "\nFlags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	*id, *user = strings.TrimSpace(*id), strings.TrimSpace(*user)
	if (*id == "") == (*user == "") {
		return fmt.Errorf("give exactly one of --id (one link) or --user (everything issued to a user)")
	}
	if *format != "table" && *format != "json" {
		return fmt.Errorf("unknown --format %q (want table or json)", *format)
	}
	c, err := newClient(g)
	if err != nil {
		return err
	}
	body := map[string]string{"reason": *reason}
	if *id != "" {
		body["id"] = *id
	} else {
		body["subject"] = *user
	}
	var resp struct {
		OK        bool            `json:"ok"`
		Link      *userlinks.Info `json:"link,omitempty"`
		Subject   string          `json:"subject,omitempty"`
		Revoked   int             `json:"revoked"`
		NotBefore *time.Time      `json:"notBefore,omitempty"`
	}
	if err := c.postJSON(c.adminURL("api/userlinks/revoke", nil), body, &resp); err != nil {
		return err
	}
	if *format == "json" {
		return emitJSON(resp)
	}
	if resp.Link != nil {
		fmt.Printf("Revoked link %s (%s) of %s.\n", resp.Link.ID, orDash(resp.Link.Label), resp.Link.Subject)
		return nil
	}
	fmt.Printf("Revoked everything issued to %s: %d working link(s) ended, and their session on the links page with them.\n", resp.Subject, resp.Revoked)
	fmt.Println("They can sign in again and create new links; to keep them out, disable the account at the identity provider.")
	return nil
}

func userLinksIssue(args []string) error {
	fs := flag.NewFlagSet("userlinks issue", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	var (
		user    = fs.String("user", "", "who the link's downloads are recorded as (required), e.g. ci-bot or build@example.com")
		name    = fs.String("name", "", "display name of the identity")
		email   = fs.String("email", "", "e-mail address of the identity")
		team    = fs.String("team", "", "team (tenant) the identity belongs to")
		roles   = fs.String("roles", "", "comma-separated RBAC roles (auth.roles) the identity holds")
		label   = fs.String("label", "", "name of the link, e.g. where it will be used")
		ttlDays = fs.Int("ttl-days", 0, "lifetime in days (0: the proxy's userLinks.linkTtl; a longer one is cut to it)")
		format  = fs.String("format", "table", "output format: table|json")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl userlinks issue --user SUBJECT [flags]")
		fmt.Fprintln(os.Stderr, "\nIssue a personal cache link for an identity you name: a service account that")
		fmt.Fprintln(os.Stderr, "cannot sign in, or any user where no identity provider is configured. The link")
		fmt.Fprintln(os.Stderr, "is printed once — the proxy does not keep it. Needs the administer capability,")
		fmt.Fprintln(os.Stderr, "and an admin surface that authenticates its callers.")
		fmt.Fprintln(os.Stderr, "\nFlags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*user) == "" {
		return fmt.Errorf("--user is required: who the link's downloads are recorded as")
	}
	if *ttlDays < 0 {
		return fmt.Errorf("--ttl-days must not be negative")
	}
	if *format != "table" && *format != "json" {
		return fmt.Errorf("unknown --format %q (want table or json)", *format)
	}
	c, err := newClient(g)
	if err != nil {
		return err
	}
	body := map[string]any{
		"subject": strings.TrimSpace(*user), "name": *name, "email": *email, "team": *team,
		"label": *label, "ttlDays": *ttlDays,
	}
	var roleList []string
	for _, r := range strings.Split(*roles, ",") {
		if r = strings.TrimSpace(r); r != "" {
			roleList = append(roleList, r)
		}
	}
	if len(roleList) > 0 {
		body["roles"] = roleList
	}
	var resp struct {
		OK      bool           `json:"ok"`
		Token   string         `json:"token"`
		BaseURL string         `json:"baseUrl"`
		Link    userlinks.Info `json:"link"`
	}
	if err := c.postJSON(c.adminURL("api/userlinks/issue", nil), body, &resp); err != nil {
		return err
	}
	if *format == "json" {
		return emitJSON(resp)
	}
	renderIssuedLink(os.Stdout, resp.Token, resp.BaseURL, resp.Link)
	return nil
}

// renderIssuedLink prints a new link. This is the only time it can be shown.
func renderIssuedLink(w io.Writer, token, base string, link userlinks.Info) {
	fmt.Fprintf(w, "Issued link %s for %s", link.ID, link.Subject)
	if link.Label != "" {
		fmt.Fprintf(w, " (%s)", link.Label)
	}
	if link.ExpiresAt != nil {
		fmt.Fprintf(w, ", expires %s", link.ExpiresAt.UTC().Format("2006-01-02"))
	} else {
		fmt.Fprint(w, ", does not expire")
	}
	fmt.Fprintln(w, ".")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  Personal base address:  %s\n", base)
	fmt.Fprintf(w, "  e.g. an npm registry:   %s/v1/<upstream>/\n", base)
	fmt.Fprintf(w, "  As a credential:        %s   (the password; any user name)\n", token)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "This is the only time the link is shown: the proxy keeps a hash of it, not the link.")
	fmt.Fprintln(w, "Treat it like a password. Client configuration for it:")
	fmt.Fprintf(w, "  ptctl config --personal-link %s\n", base)
}
