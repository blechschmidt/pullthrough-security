//go:build integration
// +build integration

package userlinks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	dl "github.com/blechschmidt/pullthrough-security/internal/downloadlog"
	"github.com/blechschmidt/pullthrough-security/internal/userlinks"
	"github.com/blechschmidt/pullthrough-security/internal/userlinks/oidctest"
)

// ecosystem is one package ecosystem under test.
type ecosystem struct {
	// id is the name of the ecosystem's upstream in the proxy configuration.
	id string
	// logName is what the download log calls the ecosystem.
	logName string
	find    func(*stub) (installer, error)
	pkg     func(*stub) pkg
	// artifact is the path of the package's artifact under the upstream's mount,
	// for the checks that fetch it without a package manager.
	artifact func(*stub) string
	// narrow selects, among the downloads of one install, the entry of the
	// artifact itself — for an ecosystem where one install is several downloads
	// (a container image is a manifest, a configuration and a layer).
	narrow func(*stub) url.Values
	// passThrough marks an ecosystem whose downloads the proxy forwards without
	// caching them (a Git fetch is a negotiation, not a file).
	passThrough bool
}

var ecosystems = []ecosystem{
	{
		id: "npm", logName: "npm", find: func(*stub) (installer, error) { return findNpm() },
		pkg:      func(s *stub) pkg { return s.npm },
		artifact: func(s *stub) string { return "/" + s.npm.Name + "/-/" + s.npm.Name + "-" + s.npm.Version + ".tgz" },
	},
	{
		id: "pypi", logName: "pip", find: func(*stub) (installer, error) { return findPip() },
		pkg: func(s *stub) pkg { return s.pypi },
		artifact: func(s *stub) string {
			return "/files/http/" + s.host() + s.pypi.upstreamPath
		},
	},
	{
		id: "cargo", logName: "cargo", find: func(*stub) (installer, error) { return findCargo() },
		pkg:      func(s *stub) pkg { return s.crate },
		artifact: func(s *stub) string { return "/api/v1/crates/" + s.crate.Name + "/" + s.crate.Version + "/download" },
	},
	{
		id: "go", logName: "go", find: func(*stub) (installer, error) { return findGo() },
		pkg:      func(s *stub) pkg { return s.module },
		artifact: func(s *stub) string { return "/" + s.module.Name + "/@v/" + s.module.Version + ".zip" },
	},
	{
		// A container image, pulled by the Docker Engine. The link is the leading
		// part of the repository name: the one place a container client can put it.
		id: "dockerhub", logName: "docker", find: func(*stub) (installer, error) { return findDocker() },
		pkg:    func(s *stub) pkg { return s.image },
		narrow: func(s *stub) url.Values { return url.Values{"q": {s.image.digest}} },
	},
	{
		// A Git repository, cloned by git. The clone names the forge; the page's
		// insteadOf rule sends it through the link.
		id: "git", logName: "git", find: findGit,
		pkg:         func(s *stub) pkg { return s.repo },
		passThrough: true,
	},
}

// goArtifact is the path of the Go fixture's zip under its mount: what the
// checks that need no package manager fetch.
func goArtifact(s *stub) string {
	for _, eco := range ecosystems {
		if eco.id == "go" {
			return eco.artifact(s)
		}
	}
	panic("the suite has no go ecosystem")
}

// suite is the shared state of one run.
type suite struct {
	t      *testing.T
	stub   *stub
	idp    *oidctest.Provider
	bin    string
	work   string
	report *report
	// proxies are every proxy process started, stopped at the end.
	proxies []*proxyProc
	// tokens are the tokens of every link created, for the final check that
	// none of them is anywhere it must not be.
	tokens []string
	// realClients makes a missing package manager a failure.
	realClients bool
	clientSeq   int
}

// check runs one assertion and records its outcome in the report. A failed
// check fails the test without stopping it: the matrix should show everything
// that is wrong, not only the first thing.
func (s *suite) check(ecosystem, name string, fn func() error) bool {
	s.t.Helper()
	if err := fn(); err != nil {
		s.report.set(ecosystem, name, statusFail, err.Error())
		where := name
		if ecosystem != "" {
			where = ecosystem + "/" + name
		}
		s.t.Errorf("%s: %v", where, err)
		return false
	}
	s.report.set(ecosystem, name, statusPass, "")
	return true
}

func (s *suite) start(o proxyOptions, listen string) *proxyProc {
	s.t.Helper()
	p, err := startProxy(s.bin, s.work, s.stub, s.idp, o, listen)
	if err != nil {
		s.t.Fatalf("starting proxy %s: %v", o.name, err)
	}
	s.proxies = append(s.proxies, p)
	return p
}

// newLink has a signed-in user create a link, and remembers its token.
func (s *suite) newLink(u *user, label string) link {
	s.t.Helper()
	l := u.createLink(label)
	s.tokens = append(s.tokens, l.Token)
	return l
}

// clientDir returns a fresh scratch directory for one run of a package manager.
func (s *suite) clientDir(name string) string {
	s.t.Helper()
	s.clientSeq++
	dir := filepath.Join(s.work, "clients", strconv.Itoa(s.clientSeq)+"-"+name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		s.t.Fatal(err)
	}
	return dir
}

// fetch requests a URL the way a script would: no cookies, no redirects
// followed. It returns the status, the body and the response headers.
func fetch(rawURL string, header ...string) (int, string, http.Header, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, "", nil, err
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	return resp.StatusCode, string(body), resp.Header, err
}

// TestMain removes the proxy binary the suite built for itself.
func TestMain(m *testing.M) {
	code := m.Run()
	if proxyBinTemp != "" {
		_ = os.RemoveAll(proxyBinTemp)
	}
	os.Exit(code)
}

func TestPersonalLinks(t *testing.T) {
	bin := proxyBinary(t)

	work := os.Getenv(envWorkDir)
	if work == "" {
		var err error
		if work, err = os.MkdirTemp("", "userlinks-e2e-"); err != nil {
			t.Fatal(err)
		}
	}
	work, err := filepath.Abs(work)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}

	st, err := newStub()
	if err != nil {
		t.Fatalf("building the stub registries: %v", err)
	}
	defer st.close()
	idp, err := oidctest.Start(oidcClientID, oidcSecret)
	if err != nil {
		t.Fatalf("starting the identity provider: %v", err)
	}
	defer idp.Close()

	s := &suite{
		t: t, stub: st, idp: idp, bin: bin, work: work, report: newReport(),
		realClients: strings.EqualFold(os.Getenv(envClients), "real"),
	}
	defer func() {
		for _, p := range s.proxies {
			p.stop()
		}
		s.report.Passed = !t.Failed()
		for _, dir := range []string{os.Getenv(envReportDir), os.Getenv(envAttachments)} {
			if dir != "" {
				if err := s.report.write(dir); err != nil {
					t.Errorf("writing the report to %s: %v", dir, err)
				}
				break
			}
		}
		if t.Failed() || os.Getenv(envKeep) != "" {
			t.Logf("the work directory is kept: %s", work)
			return
		}
		removeAll(work)
	}()

	// One deployment, two replicas: both keep the link registry in the same
	// directory. Clients talk to the first.
	registry := filepath.Join(work, "registry")
	a := s.start(proxyOptions{name: "replica-a", registryDir: registry}, "")

	alice := newUser(t, a, idp, oidctest.User{
		Subject: "idp-0001", Email: "Alice@Example.com", Name: "Alice Example", Team: "platform", Groups: []string{"cache-readers"},
	})
	bob := newUser(t, a, idp, oidctest.User{
		Subject: "idp-0002", Email: "bob@example.com", Name: "Bob Example", Team: "payments", Groups: []string{"npm-team"},
	})
	const aliceSubject, bobSubject = "alice@example.com", "bob@example.com"

	// --- signing in ---------------------------------------------------------
	var aliceLink, bobLink link
	signedIn := s.check("", checkSignIn, func() error {
		if status, session := alice.page(http.MethodGet, "api/session", nil); status != 200 || session["authenticated"] != false {
			return fmt.Errorf("before signing in the page reports %d %v", status, session)
		}
		if status, _ := alice.page(http.MethodPost, "api/links", map[string]any{"label": "x"}); status != http.StatusUnauthorized {
			return fmt.Errorf("creating a link without signing in: status %d, want 401", status)
		}
		for _, u := range []*user{alice, bob} {
			if status, page := u.signIn(); status != 200 || !strings.Contains(page, "Personal cache links") {
				return fmt.Errorf("signing in as %s ended on status %d: %s", u.who.Email, status, firstLine([]byte(page)))
			}
		}
		status, session := alice.page(http.MethodGet, "api/session", nil)
		who, _ := session["user"].(map[string]any)
		if status != 200 || session["authenticated"] != true || who == nil {
			return fmt.Errorf("after signing in the page reports %d %v", status, session)
		}
		// The e-mail address — lower-cased — is what the user is called; the
		// team came from the ID token.
		if who["subject"] != aliceSubject || who["team"] != "platform" || who["name"] != "Alice Example" {
			return fmt.Errorf("the page knows the user as %v", who)
		}
		aliceLink, bobLink = s.newLink(alice, "laptop"), s.newLink(bob, "laptop")
		if !userlinks.WellFormed(aliceLink.Token) || aliceLink.Base != a.url+"/u/"+aliceLink.Token {
			return fmt.Errorf("the page handed out the link %q", aliceLink.Base)
		}
		if aliceLink.Token == bobLink.Token || aliceLink.ID == bobLink.ID {
			return errors.New("two users were handed the same link")
		}
		return nil
	})
	if !signedIn {
		t.Fatalf("nobody could sign in; the rest of the suite cannot run\n%s", tailFile(a.logPath, 40))
	}

	// --- the package managers ------------------------------------------------
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	for _, eco := range ecosystems {
		s.runEcosystem(ctx, eco, a, alice, aliceLink, bobLink, aliceSubject, bobSubject)
	}

	// --- without a link -------------------------------------------------------
	goZip := goArtifact(st)
	s.check("", checkAnonymous, func() error {
		status, body, _, err := fetch(a.url + "/v1/go" + goZip)
		if err != nil || status != 200 || body != string(st.module.Body) {
			return fmt.Errorf("fetching a module without a link: status %d, %v", status, err)
		}
		entries, err := a.awaitDownloads(url.Values{"subject": {dl.NoSubject}, "ecosystem": {"go"}}, 1)
		if err != nil {
			return err
		}
		if len(entries) != 1 || entries[0].Subject != "" || entries[0].Link != "" || entries[0].AuthMethod == userlinks.MethodPersonalLink {
			return fmt.Errorf("the download without a link is logged as %+v", entries)
		}
		// The index documents a client without a link reads name the mount, and
		// nobody's personal address.
		_, packument, hdr, err := fetch(a.url + "/v1/npm/" + st.npm.Name)
		if err != nil || strings.Contains(packument, "/u/") || !strings.Contains(packument, a.url+"/v1/npm/"+st.npm.Name+"/-/") {
			return fmt.Errorf("a packument fetched without a link: %v: %s", err, firstLine([]byte(packument)))
		}
		if strings.Contains(hdr.Get("Cache-Control"), "private") {
			return fmt.Errorf("a response to a request without a link was made private: %q", hdr.Get("Cache-Control"))
		}
		return nil
	})

	// --- what the user sees ---------------------------------------------------
	s.check("", checkLastUse, func() error {
		status, listing := alice.page(http.MethodGet, "api/links", nil)
		links, _ := listing["links"].([]any)
		if status != 200 || len(links) == 0 {
			return fmt.Errorf("the page lists %d %v", status, listing)
		}
		for _, raw := range links {
			l, _ := raw.(map[string]any)
			if l["subject"] != aliceSubject {
				return fmt.Errorf("the page shows %s a link of %v", aliceSubject, l["subject"])
			}
			if l["id"] != aliceLink.ID {
				continue
			}
			if l["state"] != "active" || l["lastUsedAt"] == nil || l["lastAddr"] != "127.0.0.1" || l["lastAgent"] == nil || l["label"] != "laptop" {
				return fmt.Errorf("the page shows the link as %v", l)
			}
			return nil
		}
		return fmt.Errorf("the page does not list the link %s", aliceLink.ID)
	})

	// --- what the operator sees -----------------------------------------------
	s.check("", checkAdmin, func() error {
		var listing struct {
			Enabled bool `json:"enabled"`
			SignIn  bool `json:"signIn"`
			PageURL string
			Total   int              `json:"total"`
			Links   []userlinks.Info `json:"links"`
			Users   []struct {
				Subject string `json:"subject"`
				Active  int    `json:"active"`
			} `json:"users"`
		}
		if status, err := a.admin(http.MethodGet, "userlinks", nil, &listing); err != nil || status != 200 {
			return fmt.Errorf("GET userlinks: %d, %v", status, err)
		}
		if !listing.Enabled || !listing.SignIn || len(listing.Users) != 2 {
			return fmt.Errorf("the admin API lists %+v", listing)
		}
		var filtered struct {
			Total int `json:"total"`
		}
		if status, err := a.admin(http.MethodGet, "userlinks?state=active&subject="+url.QueryEscape(bobSubject), nil, &filtered); err != nil || status != 200 || filtered.Total != 1 {
			return fmt.Errorf("bob's working links: %d (status %d, %v), want 1", filtered.Total, status, err)
		}
		if status, _, _, _ := fetch(a.url + "/admin/api/userlinks"); status != http.StatusUnauthorized {
			return fmt.Errorf("the link list without the admin credential: status %d, want 401", status)
		}

		// Downloads, per user.
		var sum logSummary
		if status, err := a.admin(http.MethodGet, "downloads/summary?top=50", nil, &sum); err != nil || status != 200 {
			return fmt.Errorf("GET downloads/summary: %d, %v", status, err)
		}
		if sum.Users != 2 || sum.Unattributed < 1 || sum.Clients != 1 {
			return fmt.Errorf("the summary counts %d users, %d downloads without an identity and %d client addresses; want 2 users, at least 1, and one address", sum.Users, sum.Unattributed, sum.Clients)
		}
		byUser := map[string]dl.UserSummary{}
		for _, u := range sum.ByUser {
			byUser[u.Subject] = u
		}
		if byUser[aliceSubject].Downloads == 0 || byUser[bobSubject].Downloads == 0 || byUser[aliceSubject].Tenant != "platform" || byUser[bobSubject].Tenant != "payments" {
			return fmt.Errorf("the per-user summary is %+v", sum.ByUser)
		}
		if got := byUser[aliceSubject].Links; len(got) != 1 || got[0] != aliceLink.ID {
			return fmt.Errorf("alice's downloads are attributed to the links %v, want %s", got, aliceLink.ID)
		}
		// "What did alice pull" as a pattern, the way an operator would type it.
		entries, err := a.downloads(url.Values{"subject": {"alice@*"}})
		if err != nil || len(entries) != byUser[aliceSubject].Downloads {
			return fmt.Errorf("the filter alice@* returns %d entries, the summary counts %d (%v)", len(entries), byUser[aliceSubject].Downloads, err)
		}
		return nil
	})

	// --- links that are not good ----------------------------------------------
	s.check("", checkRefused, func() error {
		unknown, _ := userlinks.NewToken()
		before := st.requests()
		for name, tc := range map[string]struct {
			url    string
			status int
			says   string
		}{
			"a link nobody issued": {a.url + "/u/" + unknown + "/v1/go" + goZip, 403, "not valid"},
			"a link cut short":     {a.url + "/u/" + aliceLink.Token[:30] + "/v1/go" + goZip, 403, "cut short"},
			"a link to the admin":  {aliceLink.Base + "/admin/api/userlinks", 404, ""},
			"a link to the page":   {aliceLink.Base + "/links/", 404, ""},
			"a link as credential": {a.url + "/v1/go" + goZip, 401, "not valid"},
		} {
			var header []string
			if name == "a link as credential" {
				header = []string{"Authorization", "Bearer " + unknown}
			}
			status, body, _, err := fetch(tc.url, header...)
			if err != nil || status != tc.status || !strings.Contains(body, tc.says) {
				return fmt.Errorf("%s: status %d (want %d), %v: %s", name, status, tc.status, err, firstLine([]byte(body)))
			}
			if strings.Contains(body, unknown) || strings.Contains(body, aliceLink.Token) {
				return fmt.Errorf("%s: the answer repeats the link: %s", name, firstLine([]byte(body)))
			}
		}
		if st.requests() != before {
			return errors.New("a request with a refused link reached an upstream")
		}
		return nil
	})

	// --- a second replica -------------------------------------------------------
	b := s.start(proxyOptions{name: "replica-b", registryDir: registry}, "")
	s.check("", checkReplica, func() error {
		// A link created on the first replica before the second existed.
		if status, _, _, err := fetch(b.url + "/u/" + aliceLink.Token + "/v1/go" + goZip); err != nil || status != 200 {
			return fmt.Errorf("replica B with a link it loaded at start: status %d, %v", status, err)
		}
		entries, err := b.awaitDownloads(url.Values{"subject": {aliceSubject}}, 1)
		if err != nil || len(entries) != 1 || entries[0].Link != aliceLink.ID {
			return fmt.Errorf("replica B logged %+v (%v)", entries, err)
		}
		// A link created on the first replica just now: the second has not
		// refreshed, and honours it all the same.
		fresh := s.newLink(alice, "created while replica B was running")
		if status, _, _, err := fetch(b.url + "/u/" + fresh.Token + "/v1/go" + goZip); err != nil || status != 200 {
			return fmt.Errorf("replica B with a link created on replica A a moment ago: status %d, %v", status, err)
		}
		// Revoked on the first replica: gone there at once, and on the second
		// within its refresh interval (one second in this suite).
		if status, resp := alice.page(http.MethodPost, "api/links/revoke", map[string]any{"id": fresh.ID}); status != 200 {
			return fmt.Errorf("revoking on replica A: %d %v", status, resp)
		}
		if status, _, _, _ := fetch(a.url + "/u/" + fresh.Token + "/v1/go" + goZip); status != 403 {
			return fmt.Errorf("replica A after the revocation: status %d, want 403 at once", status)
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			status, body, _, _ := fetch(b.url + "/u/" + fresh.Token + "/v1/go" + goZip)
			if status == 403 && strings.Contains(body, "revoked") {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("replica B still answers %d ten seconds after the link was revoked on replica A", status)
			}
			time.Sleep(100 * time.Millisecond)
		}
		// What replica B saw of a link shows on the user's page, served by A.
		deadline = time.Now().Add(45 * time.Second)
		for {
			_, listing := alice.page(http.MethodGet, "api/links", nil)
			links, _ := listing["links"].([]any)
			for _, raw := range links {
				if l, _ := raw.(map[string]any); l["id"] == fresh.ID && l["lastUsedAt"] != nil {
					return nil
				}
			}
			if time.Now().After(deadline) {
				return errors.New("the use replica B saw of a link never showed on the page served by replica A")
			}
			time.Sleep(500 * time.Millisecond)
		}
	})

	// --- a restart ----------------------------------------------------------------
	s.check("", checkRestart, func() error {
		a.stop()
		if err := a.start(); err != nil {
			return fmt.Errorf("restarting replica A: %w", err)
		}
		if status, _, _, err := fetch(aliceLink.mount("go") + goZip); err != nil || status != 200 {
			return fmt.Errorf("a link after the restart: status %d, %v", status, err)
		}
		// The session is a signed cookie: it needs no memory of the proxy's.
		if status, session := alice.page(http.MethodGet, "api/session", nil); status != 200 || session["authenticated"] != true {
			return fmt.Errorf("the sign-in session after the restart: %d %v", status, session)
		}
		// The download log was written to its file and read back.
		entries, err := a.downloads(url.Values{"subject": {bobSubject}})
		if err != nil || len(entries) == 0 || entries[0].Link != bobLink.ID {
			return fmt.Errorf("the download log after the restart holds %d entries of bob (%v)", len(entries), err)
		}
		return nil
	})

	// --- everything of one user ---------------------------------------------------
	s.check("", checkRevokeUser, func() error {
		// Sessions are dated to the second: let one pass.
		time.Sleep(1100 * time.Millisecond)
		var resp struct {
			OK      bool `json:"ok"`
			Revoked int  `json:"revoked"`
		}
		status, err := a.admin(http.MethodPost, "userlinks/revoke", map[string]any{"subject": bobSubject, "reason": "left the company"}, &resp)
		if err != nil || status != 200 || !resp.OK || resp.Revoked != 1 {
			return fmt.Errorf("revoking everything of bob: status %d, %+v, %v", status, resp, err)
		}
		if status, body, _, _ := fetch(bobLink.mount("go") + goZip); status != 403 || !strings.Contains(body, "revoked") {
			return fmt.Errorf("bob's link on replica A after the revocation: status %d", status)
		}
		if status, session := bob.page(http.MethodGet, "api/session", nil); status != 200 || session["authenticated"] != false {
			return fmt.Errorf("bob's session after the revocation: %v", session)
		}
		if status, _ := bob.page(http.MethodPost, "api/links", map[string]any{"label": "again"}); status != http.StatusUnauthorized {
			return fmt.Errorf("bob created a link with his old session: status %d", status)
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			status, _, _, _ := fetch(b.url + "/u/" + bobLink.Token + "/v1/go" + goZip)
			if status == 403 {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("replica B still answers %d ten seconds after everything of bob was revoked on replica A", status)
			}
			time.Sleep(100 * time.Millisecond)
		}
		// Alice is not bob.
		if status, _, _, _ := fetch(aliceLink.mount("go") + goZip); status != 200 {
			return fmt.Errorf("alice's link after bob's revocation: status %d", status)
		}
		// It is a watermark, not a ban: bob signs in again and starts over.
		time.Sleep(1100 * time.Millisecond)
		if status, _ := bob.signIn(); status != 200 {
			return fmt.Errorf("bob signing in again: status %d", status)
		}
		again := s.newLink(bob, "after the revocation")
		if status, _, _, _ := fetch(again.mount("go") + goZip); status != 200 {
			return fmt.Errorf("bob's new link: status %d", status)
		}
		return nil
	})

	// --- with client authentication on ----------------------------------------------
	c := s.start(proxyOptions{name: "with-auth", registryDir: filepath.Join(work, "registry-auth"), auth: true}, "")
	reader := newUser(t, c, idp, alice.who) // in "cache-readers": may pull everything
	npmOnly := newUser(t, c, idp, bob.who)  // in "npm-team": may pull npm
	nobody := newUser(t, c, idp, oidctest.User{Subject: "idp-0003", Email: "dave@example.com", Groups: []string{"interns"}})
	var readerLink link
	s.check("", checkAccess, func() error {
		for _, u := range []*user{reader, npmOnly, nobody} {
			if status, _ := u.signIn(); status != 200 {
				return fmt.Errorf("signing in as %s on the proxy with access control: status %d", u.who.Email, status)
			}
		}
		readerLink = s.newLink(reader, "laptop")
		npmLink, nobodyLink := s.newLink(npmOnly, "laptop"), s.newLink(nobody, "laptop")
		packument := "/v1/npm/" + st.npm.Name
		for name, tc := range map[string]struct {
			url    string
			status int
			says   string
		}{
			"no credential":                       {c.url + packument, 401, ""},
			"a reader, npm":                       {readerLink.Base + packument, 200, readerLink.Base + "/v1/npm/"},
			"a reader, go":                        {readerLink.mount("go") + goZip, 200, ""},
			"npm only, npm":                       {npmLink.Base + packument, 200, ""},
			"npm only, go":                        {npmLink.mount("go") + goZip, 403, "no role"},
			"a user in no group that maps":        {nobodyLink.Base + packument, 403, "no roles"},
			"a link of the other deployment here": {c.url + "/u/" + aliceLink.Token + packument, 403, "not valid"},
		} {
			status, body, _, err := fetch(tc.url)
			if err != nil || status != tc.status || !strings.Contains(body, tc.says) {
				return fmt.Errorf("%s: status %d (want %d), %v: %s", name, status, tc.status, err, firstLine([]byte(body)))
			}
		}
		// The denials are in the audit trail, with who was denied.
		audit, err := os.ReadFile(filepath.Join(c.stateDir, "audit.log"))
		if err != nil {
			return err
		}
		if !strings.Contains(string(audit), `"subject":"dave@example.com"`) || !strings.Contains(string(audit), `"decision":"deny"`) {
			return errors.New("the audit log does not record the denial of the user without a role")
		}
		return nil
	})

	// The link as a credential, with the real npm: the registry URL stays the
	// mount's, the token goes where npm keeps passwords.
	s.check("", checkCredential, func() error {
		npm, err := findNpm()
		if err != nil {
			if s.realClients {
				return fmt.Errorf("npm is not installed (%v), and %s=real requires it", err, envClients)
			}
			s.t.Logf("npm is not installed (%v): the link is presented as a credential by a scripted request instead", err)
			status, body, _, ferr := fetch(c.url+"/v1/npm/"+st.npm.Name, "Authorization", "Bearer "+readerLink.Token)
			if ferr != nil || status != 200 || strings.Contains(body, "/u/") {
				return fmt.Errorf("the link as a bearer token: status %d, %v", status, ferr)
			}
			return nil
		}
		snippet := readerLink.tokenSnippets["npm"]
		if !strings.Contains(snippet, "registry="+c.url+"/v1/npm/") || !strings.Contains(snippet, ":_authToken="+readerLink.Token) {
			return fmt.Errorf("the page's npm configuration for the link as a credential is:\n%s", strings.ReplaceAll(snippet, readerLink.Token, "<token>"))
		}
		dir := s.clientDir("npm-credential")
		if ok, out := npm.install(ctx, snippet, st.npm, dir); !ok {
			return fmt.Errorf("npm with the link as a credential failed:\n%s", strings.ReplaceAll(out, readerLink.Token, "<token>"))
		}
		entries, err := c.awaitDownloads(url.Values{"ecosystem": {"npm"}, "subject": {"alice@example.com"}}, 1)
		if err != nil || len(entries) != 1 || entries[0].Link != readerLink.ID || entries[0].AuthMethod != userlinks.MethodPersonalLink {
			return fmt.Errorf("the download is logged as %+v (%v)", entries, err)
		}
		// No URL npm wrote down carries the link — and none had to be rewritten.
		lock, err := os.ReadFile(filepath.Join(dir, "app", "package-lock.json"))
		if err != nil {
			return err
		}
		if strings.Contains(string(lock), readerLink.Token) || strings.Contains(string(lock), "/u/") {
			return errors.New("package-lock.json contains the link although it was presented as a credential")
		}
		if !strings.Contains(string(lock), c.url+"/v1/npm/"+st.npm.Name+"/-/") {
			return fmt.Errorf("package-lock.json does not name the mount's own tarball URL:\n%s", lock)
		}
		return nil
	})

	// A link in the path needs no credential from the client: every request
	// carries it. So with client authentication on it lets in a package manager
	// that cannot present a token — cargo sends none for crate downloads
	// (docs/clients.md, "Clients that cannot present a token").
	s.check("", checkPathAuth, func() error {
		crate := "/api/v1/crates/" + st.crate.Name + "/" + st.crate.Version + "/download"
		if status, _, _, err := fetch(c.url + "/v1/cargo" + crate); err != nil || status != http.StatusUnauthorized {
			return fmt.Errorf("a crate download without a link or a token: status %d (want 401), %v", status, err)
		}
		cargo, err := findCargo()
		if err != nil {
			if s.realClients {
				return fmt.Errorf("cargo is not installed (%v), and %s=real requires it", err, envClients)
			}
			s.t.Logf("cargo is not installed (%v): the link in the path is used by a scripted request instead", err)
			if status, _, _, ferr := fetch(readerLink.mount("cargo") + crate); ferr != nil || status != 200 {
				return fmt.Errorf("a crate download through the link: status %d, %v", status, ferr)
			}
			return nil
		}
		dir := s.clientDir("cargo-with-auth")
		if ok, out := cargo.install(ctx, readerLink.snippets["cargo"], st.crate, dir); !ok {
			return fmt.Errorf("cargo through a personal link, with access control on, failed:\n%s", strings.ReplaceAll(out, readerLink.Token, "<token>"))
		}
		entries, err := c.awaitDownloads(url.Values{"ecosystem": {"cargo"}, "subject": {"alice@example.com"}}, 1)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.Link != readerLink.ID || e.AuthMethod != userlinks.MethodPersonalLink || e.Outcome != "served" {
				return fmt.Errorf("a download of the cargo run is logged as %+v", e)
			}
		}
		// Every request cargo made was its user's: none came in without the link.
		if anon, err := c.downloads(url.Values{"ecosystem": {"cargo"}, "subject": {"-"}}); err != nil || len(anon) != 0 {
			return fmt.Errorf("downloads of the cargo run without an identity: %+v (%v)", anon, err)
		}
		return nil
	})

	// The same with the Docker Engine: `docker login`, and the image is pulled
	// under its ordinary name.
	if inst, err := findDocker(); err != nil {
		if s.realClients {
			s.check("", checkDockerLogin, func() error {
				return fmt.Errorf("the Docker Engine is not available (%v), and %s=real requires it", err, envClients)
			})
		} else {
			t.Logf("the Docker Engine is not available (%v); the docker-login check is skipped", err)
		}
	} else {
		docker := inst.(realDocker)
		s.check("", checkDockerLogin, func() error {
			dir := s.clientDir("docker-login")
			if err := os.MkdirAll(filepath.Join(dir, "docker-config"), 0o700); err != nil {
				return err
			}
			registry := c.listen
			ref := registry + "/dockerhub/" + st.image.Name + ":" + st.image.Version
			hide := func(out string) string { return strings.ReplaceAll(out, readerLink.Token, "<token>") }

			// Nobody pulls without a credential.
			if ok, out := docker.pull(ctx, ref, dir); ok {
				return fmt.Errorf("the image was pulled without a credential although client authentication is on:\n%s", out)
			}
			// The link's token is the password; the user name is whatever the
			// user likes to see in `docker info`.
			out, err := docker.runWithInput(ctx, dir, readerLink.Token+"\n", "login", "--username", "alice", "--password-stdin", registry)
			if err != nil {
				return fmt.Errorf("docker login with the link's token as the password failed:\n%s", hide(out))
			}
			defer func() { _, _ = docker.run(context.Background(), dir, "logout", registry) }()
			if ok, out := docker.pull(ctx, ref, dir); !ok {
				return fmt.Errorf("docker pull after docker login failed:\n%s\n--- proxy log ---\n%s", hide(out), hide(tailFile(c.logPath, 12)))
			}
			entries, err := c.awaitDownloads(url.Values{"ecosystem": {"docker"}, "subject": {"alice@example.com"}, "q": {st.image.digest}}, 1)
			if err != nil {
				return err
			}
			if len(entries) != 1 || entries[0].Link != readerLink.ID || entries[0].AuthMethod != userlinks.MethodPersonalLink {
				return fmt.Errorf("the pull is logged as %+v", entries)
			}
			// A password that is no link is refused, not let through as nobody.
			unknown, _ := userlinks.NewToken()
			if out, err := docker.runWithInput(ctx, dir, unknown+"\n", "login", "--username", "alice", "--password-stdin", registry); err == nil {
				if ok, pullOut := docker.pull(ctx, ref, dir); ok {
					return fmt.Errorf("the image was pulled with a token nobody issued:\n%s\n%s", out, pullOut)
				}
			}
			return nil
		})
	}

	// And with git: the page's configuration for the link as a credential puts
	// the token into the user's global Git configuration, scoped to the proxy.
	if inst, err := findGit(st); err != nil {
		if s.realClients {
			s.check("", checkGitHeader, func() error {
				return fmt.Errorf("git is not available (%v), and %s=real requires it", err, envClients)
			})
		} else {
			t.Logf("git is not available (%v); the git-credential check is skipped", err)
		}
	} else {
		git := inst.(realGit)
		s.check("", checkGitHeader, func() error {
			hide := func(out string) string { return strings.ReplaceAll(out, readerLink.Token, "<token>") }
			repoURL := c.url + "/v1/git/" + st.repo.Name
			snippet := readerLink.tokenSnippets["git"]
			m := extraHeaderInSnippet.FindStringSubmatch(snippet)
			if m == nil || m[2] != "Authorization: Bearer "+readerLink.Token {
				return fmt.Errorf("the page's Git configuration for the link as a credential sets no header:\n%s", hide(snippet))
			}

			// Nobody clones without a credential — and git, challenged, does not
			// hang at a prompt.
			dir := s.clientDir("git-credential")
			if out, err := git.run(ctx, dir, "clone", "--quiet", repoURL, filepath.Join(dir, "anonymous")); err == nil {
				return fmt.Errorf("the repository was cloned without a credential although client authentication is on:\n%s", out)
			}
			// The page's configuration, then a clone under the ordinary URL.
			if out, err := git.run(ctx, dir, "config", "--global", m[1], m[2]); err != nil {
				return fmt.Errorf("applying the page's Git configuration failed:\n%s", hide(out))
			}
			if out, err := git.run(ctx, dir, "clone", "--quiet", repoURL, filepath.Join(dir, "app")); err != nil {
				return fmt.Errorf("git clone with the page's credential configuration failed:\n%s\n--- proxy log ---\n%s", hide(out), hide(tailFile(c.logPath, 12)))
			}
			entries, err := c.awaitDownloads(url.Values{"ecosystem": {"git"}, "subject": {"alice@example.com"}}, 1)
			if err != nil {
				return err
			}
			if len(entries) != 1 || entries[0].Link != readerLink.ID || entries[0].AuthMethod != userlinks.MethodPersonalLink {
				return fmt.Errorf("the clone is logged as %+v", entries)
			}
			// The checkout knows where it came from, and not as whom.
			config, err := os.ReadFile(filepath.Join(dir, "app", ".git", "config"))
			if err != nil {
				return err
			}
			if strings.Contains(string(config), readerLink.Token) || !strings.Contains(string(config), repoURL) {
				return fmt.Errorf("the checkout's .git/config is:\n%s", hide(string(config)))
			}

			// The other way a Git user presents a token: as the password in the
			// URL (or from a credential helper), which git sends once the proxy
			// challenges it with Basic.
			basic := s.clientDir("git-basic")
			withPassword := "http://alice:" + readerLink.Token + "@" + c.listen + "/v1/git/" + st.repo.Name
			if out, err := git.run(ctx, basic, "clone", "--quiet", withPassword, filepath.Join(basic, "app")); err != nil {
				return fmt.Errorf("git clone with the token as the HTTP Basic password failed:\n%s", hide(out))
			}
			if entries, _ := c.awaitDownloads(url.Values{"ecosystem": {"git"}, "subject": {"alice@example.com"}}, 2); len(entries) != 2 {
				return fmt.Errorf("the second clone is not in the log: %+v", entries)
			}
			// A password that is no link is refused.
			unknown, _ := userlinks.NewToken()
			wrong := "http://alice:" + unknown + "@" + c.listen + "/v1/git/" + st.repo.Name
			if out, err := git.run(ctx, basic, "clone", "--quiet", wrong, filepath.Join(basic, "wrong")); err == nil {
				return fmt.Errorf("the repository was cloned with a token nobody issued:\n%s", out)
			}
			return nil
		})
	}

	// --- the metrics ---------------------------------------------------------------
	s.check("", checkMetrics, func() error {
		// One more index document through a link, so the counters of this
		// process — restarted above — have a rewritten document to count.
		_, packument, hdr, err := fetch(aliceLink.Base + "/v1/npm/" + st.npm.Name)
		if err != nil || !strings.Contains(packument, aliceLink.Base+"/v1/npm/"+st.npm.Name+"/-/") {
			return fmt.Errorf("a packument fetched through a link does not name the link's own tarball address (%v)", err)
		}
		if cc := hdr.Get("Cache-Control"); !strings.Contains(cc, "private") {
			return fmt.Errorf("a document that names a personal address is served with Cache-Control %q, want private", cc)
		}
		_, text, _, err := fetch(a.url + "/metrics")
		if err != nil {
			return err
		}
		for name, atLeast := range map[string]float64{
			`pullthrough_userlinks_links{state="active"}`:                          1,
			`pullthrough_userlinks_links{state="revoked"}`:                         1,
			`pullthrough_userlinks_users`:                                          1,
			`pullthrough_userlinks_requests_total{via="path",outcome="ok"}`:        1,
			`pullthrough_userlinks_requests_total{via="path",outcome="revoked"}`:   1,
			`pullthrough_userlinks_requests_total{via="path",outcome="unknown"}`:   0,
			`pullthrough_userlinks_requests_total{via="path",outcome="malformed"}`: 0,
			`pullthrough_userlinks_signins_total{result="completed"}`:              1,
			`pullthrough_userlinks_registry_synced`:                                1,
			`pullthrough_userlinks_user_revocations_total`:                         1,
			`pullthrough_userlinks_personal_responses_total`:                       1,
			`pullthrough_userlinks_rewritten_responses_total`:                      1,
			`pullthrough_userlinks_rewritten_links_total`:                          1,
			`pullthrough_downloadlog_entries_total{outcome="served"}`:              1,
		} {
			value, ok := metricValue(text, name)
			if !ok {
				return fmt.Errorf("the metric %s is not exported", name)
			}
			if value < atLeast {
				return fmt.Errorf("%s = %v, want at least %v", name, value, atLeast)
			}
		}
		for _, name := range []string{"pullthrough_userlinks_store_errors_total", "pullthrough_userlinks_sync_errors_total"} {
			if value, ok := metricValue(text, name); !ok || value != 0 {
				return fmt.Errorf("%s = %v (exported: %v), want 0", name, value, ok)
			}
		}
		return nil
	})

	// --- the token is nowhere --------------------------------------------------------
	// Record the log for the report before the proxies stop.
	if entries, err := a.downloads(nil); err == nil {
		s.report.setLog(entries)
	}
	for _, p := range s.proxies {
		p.stop() // writes what is still in memory: the download log, the link usage
	}
	s.check("", checkTokenSecret, func() error {
		if len(s.tokens) < 6 {
			return fmt.Errorf("only %d links were created; the check would prove little", len(s.tokens))
		}
		// Everything the proxies wrote: their logs (at debug level), their state
		// — audit log, download log, cache — and the link registries. The
		// clients' own directories are left out: a client's configuration holds
		// its link, that is what it is for.
		var searched int
		err := filepath.WalkDir(work, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if path == filepath.Join(work, "clients") {
					return filepath.SkipDir
				}
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			searched++
			for _, token := range s.tokens {
				if i := strings.Index(string(data), token); i >= 0 {
					rel, _ := filepath.Rel(work, path)
					return fmt.Errorf("%s contains a link's token: …%s…", rel, redactAround(string(data), i, token))
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		if searched < 10 {
			return fmt.Errorf("only %d files were searched", searched)
		}
		// And everything the proxies sent on.
		upstream := st.requests()
		for _, token := range s.tokens {
			if i := strings.Index(upstream, token); i >= 0 {
				return fmt.Errorf("an upstream was sent a link's token: …%s…", redactAround(upstream, i, token))
			}
		}
		// The registry itself: there are records for the links, by hash.
		entries, err := os.ReadDir(filepath.Join(registry, "link"))
		if err != nil || len(entries) < 4 {
			return fmt.Errorf("the registry holds %d link records (%v)", len(entries), err)
		}
		// The request log does show personal requests — with the link taken out.
		log, err := os.ReadFile(a.logPath)
		if err != nil {
			return err
		}
		if !strings.Contains(string(log), "/u/<link>/v1/") {
			return errors.New("the proxy's request log shows no redacted personal path: was debug logging on?")
		}
		return nil
	})
}

// runEcosystem runs the per-ecosystem checks with the ecosystem's real package
// manager.
func (s *suite) runEcosystem(ctx context.Context, eco ecosystem, a *proxyProc, alice *user, aliceLink, bobLink link, aliceSubject, bobSubject string) {
	t := s.t
	inst, err := eco.find(s.stub)
	if err != nil {
		if s.realClients {
			s.report.addEcosystem(eco.id, "not installed")
			s.report.set(eco.id, checkInstall, statusFail, err.Error())
			t.Errorf("%s: the package manager is not installed (%v), and %s=real requires it", eco.id, err, envClients)
			return
		}
		s.report.addEcosystem(eco.id, "not installed — skipped")
		t.Logf("%s: the package manager is not installed (%v); its checks are skipped", eco.id, err)
		return
	}
	s.report.addEcosystem(eco.id, inst.describe())
	p := eco.pkg(s.stub)
	redact := func(out string) string {
		for _, token := range s.tokens {
			out = strings.ReplaceAll(out, token, "<token>")
		}
		return out
	}
	runClient := func(l link, name string) (bool, string, string) {
		dir := s.clientDir(eco.id + "-" + name)
		cctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
		defer cancel()
		snippet := l.snippets[eco.id]
		if snippet == "" {
			return false, "the page handed out no configuration for " + eco.id, dir
		}
		ok, out := inst.install(cctx, snippet, p, dir)
		return ok, redact(out), dir
	}

	// install
	var aliceDir string
	installed := s.check(eco.id, checkInstall, func() error {
		ok, out, dir := runClient(aliceLink, "alice")
		aliceDir = dir
		if !ok {
			return fmt.Errorf("%s could not install %s through the personal link:\n%s\n--- proxy log ---\n%s", inst.describe(), p, out, redact(tailFile(a.logPath, 15)))
		}
		return nil
	})
	if !installed {
		return
	}

	// served is the query for the downloads of one user's install that were
	// served; artifact narrows it to the entry of the artifact itself.
	served := func(subject string) url.Values {
		return url.Values{"ecosystem": {eco.logName}, "subject": {subject}, "outcome": {"served"}}
	}
	artifact := func(subject string) url.Values {
		q := served(subject)
		if eco.narrow != nil {
			for k, v := range eco.narrow(s.stub) {
				q[k] = v
			}
		}
		return q
	}
	wantCache := func(first bool) string {
		switch {
		case eco.passThrough:
			return "" // nothing was looked up in the cache
		case first:
			return "MISS"
		}
		return "HIT"
	}

	// attributed
	s.check(eco.id, checkAttributed, func() error {
		entries, err := a.awaitDownloads(artifact(aliceSubject), 1)
		if err != nil {
			return err
		}
		if len(entries) != 1 {
			return fmt.Errorf("the log holds %d served %s downloads of the artifact by %s, want 1: %+v", len(entries), eco.logName, aliceSubject, entries)
		}
		e := entries[0]
		if e.ClientIP != "127.0.0.1" || !strings.HasPrefix(e.UserAgent, inst.userAgent()) || e.Cache != wantCache(true) {
			return fmt.Errorf("the entry is %+v, want it from 127.0.0.1, by %s…, cache %q", e, inst.userAgent(), wantCache(true))
		}
		if e.Package != p.Name {
			return fmt.Errorf("the entry names the package %q, want %q", e.Package, p.Name)
		}
		// Everything the install downloaded — for a container image that is more
		// than the layer — is the user's, and none of it shows the user's address.
		all, err := a.downloads(served(aliceSubject))
		if err != nil {
			return err
		}
		for _, e := range all {
			if e.Link != aliceLink.ID || e.AuthMethod != userlinks.MethodPersonalLink || e.Tenant != "platform" {
				return fmt.Errorf("a download is not attributed to the user's link: %+v", e)
			}
			// The path is the resource's, not the user's personal address of it.
			if strings.Contains(e.Path, "/u/") || !strings.HasPrefix(e.Path, "/v1/"+eco.id+"/") {
				return fmt.Errorf("an entry's path is %q", e.Path)
			}
		}
		// Had the client followed a link out of its personal address, the
		// artifact would have been downloaded by nobody.
		stray, err := a.downloads(url.Values{"ecosystem": {eco.logName}, "subject": {dl.NoSubject}})
		if err != nil {
			return err
		}
		if len(stray) != 0 {
			return fmt.Errorf("%d %s downloads were made without a link: the client left its personal address: %+v", len(stray), eco.logName, stray)
		}
		return nil
	})

	// two-users
	s.check(eco.id, checkTwoUsers, func() error {
		ok, out, _ := runClient(bobLink, "bob")
		if !ok {
			return fmt.Errorf("the second user's install failed:\n%s", out)
		}
		entries, err := a.awaitDownloads(artifact(bobSubject), 1)
		if err != nil {
			return err
		}
		if len(entries) != 1 || entries[0].Link != bobLink.ID || entries[0].Tenant != "payments" {
			return fmt.Errorf("the second user's download is logged as %+v", entries)
		}
		// Same machine, same address — and, where the proxy caches, served from
		// the cache: what tells the two downloads apart is the user.
		if entries[0].ClientIP != "127.0.0.1" || entries[0].Cache != wantCache(false) {
			return fmt.Errorf("the second download is %+v, want it from 127.0.0.1 and cache %q", entries[0], wantCache(false))
		}
		if n := s.stub.fetches(p); !eco.passThrough && n != 1 {
			return fmt.Errorf("the artifact was fetched from the upstream %d times, want once", n)
		}
		var sum logSummary
		if status, err := a.admin(http.MethodGet, "downloads/summary?ecosystem="+eco.logName+"&outcome=served", nil, &sum); err != nil || status != 200 {
			return fmt.Errorf("GET downloads/summary: %d, %v", status, err)
		}
		if sum.Users != 2 || sum.Clients != 1 || sum.Unattributed != 0 {
			return fmt.Errorf("the summary of %s counts %d users on %d addresses, %d unattributed; want 2, 1 and 0", eco.logName, sum.Users, sum.Clients, sum.Unattributed)
		}
		return nil
	})

	// no-leak
	s.check(eco.id, checkNoLeak, func() error {
		found := 0
		for _, path := range inst.written(aliceDir) {
			data, err := os.ReadFile(path)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			found++
			if strings.Contains(string(data), aliceLink.Token) {
				return fmt.Errorf("%s contains the link", filepath.Base(path))
			}
		}
		if want := len(inst.written(aliceDir)); found != want {
			return fmt.Errorf("%d of the %d files the client is expected to write exist", found, want)
		}
		return nil
	})

	// revoked
	s.check(eco.id, checkRevoked, func() error {
		doomed := s.newLink(alice, eco.id+", to be revoked")
		if status, resp := alice.page(http.MethodPost, "api/links/revoke", map[string]any{"id": doomed.ID}); status != 200 {
			return fmt.Errorf("revoking a link on the page: %d %v", status, resp)
		}
		before := s.stub.requestsNaming(p)
		ok, out, _ := runClient(doomed, "revoked")
		if ok {
			return fmt.Errorf("%s installed %s through a revoked link:\n%s", inst.describe(), p, out)
		}
		if n := s.stub.requestsNaming(p) - before; n != 0 {
			return fmt.Errorf("%d requests for the package reached the upstream through the revoked link", n)
		}
		entries, err := a.downloads(url.Values{"link": {doomed.ID}})
		if err != nil {
			return err
		}
		if len(entries) != 0 {
			return fmt.Errorf("the download log holds entries for the revoked link: %+v", entries)
		}
		// The refusals are in the audit trail, naming the link and its owner.
		audit, err := os.ReadFile(filepath.Join(a.stateDir, "audit.log"))
		if err != nil {
			return err
		}
		denied := false
		for _, line := range strings.Split(string(audit), "\n") {
			if strings.Contains(line, `"link":"`+doomed.ID+`"`) && strings.Contains(line, `"decision":"deny"`) && strings.Contains(line, `"subject":"`+aliceSubject+`"`) {
				denied = true
			}
		}
		if !denied {
			return errors.New("the audit log does not record that the revoked link was refused")
		}
		return nil
	})
}

// extraHeaderInSnippet finds the page's `git config --global http.<proxy>/.extraHeader "…"`.
var extraHeaderInSnippet = regexp.MustCompile(`(?m)^git config --global (http\.\S+\.extraHeader) "([^"]+)"$`)

// metricValue returns the value of a metric line in a Prometheus exposition.
func metricValue(text, name string) (float64, bool) {
	for _, line := range strings.Split(text, "\n") {
		rest, ok := strings.CutPrefix(line, name+" ")
		if !ok {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(rest), 64)
		return v, err == nil
	}
	return 0, false
}

// redactAround returns what stands around a token found at index i, with the
// token itself taken out — a failure message must not leak what the check is
// there to protect.
func redactAround(s string, i int, token string) string {
	from, to := max(0, i-120), min(len(s), i+len(token)+60)
	return strings.ReplaceAll(strings.ReplaceAll(s[from:to], token, "<token>"), "\n", " ")
}

// removeAll removes a work directory. The Go module cache in it is read-only.
func removeAll(dir string) {
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(path, 0o755)
		}
		return nil
	})
	_ = os.RemoveAll(dir)
}
