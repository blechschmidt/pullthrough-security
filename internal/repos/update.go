package repos

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
	"github.com/blechschmidt/pullthrough-security/internal/repos/forge"
	"github.com/blechschmidt/pullthrough-security/internal/repos/sandbox"
	"github.com/blechschmidt/pullthrough-security/internal/repos/update"
	"github.com/blechschmidt/pullthrough-security/internal/secrets"
	"github.com/blechschmidt/pullthrough-security/internal/versions"
)

// Maintenance updates (Task 182).
//
// The updater keeps a maintenance branch of each registered repository with
// the dependency updates that are both compatible and vetted: for each
// dependency the default branch's lock files pin it lists the newer versions
// the dependency's registry offers through the proxy, keeps those the
// project's declared constraint allows (or, without one, those within the same
// major version — configurable to patch-only), and vets each candidate the way
// a client's pull would be judged and more: every admission gate, the
// dependency firewall and the maturity cooldown, and a benign verdict of the
// LLM package-content scan for the exact bytes, scanned on demand. Anything
// unscanned, pending or refused is skipped and reported.
//
// The chosen versions are written into the lock files — natively, from the
// digests of the bytes the proxy fetched, verified and cached, or by the real
// package manager in a network-less sandbox whose only registry is the proxy —
// re-parsed and held to what was intended, committed on top of the default
// branch's head and pushed to the maintenance branch with a lease on the
// commit the updater pushed last. Nothing is pushed when nothing changed.

// Statuses of a maintenance run (UpdateRun.Status).
const (
	UpdateRunning   = "running"
	UpdatePushed    = "pushed"     // the branch was created or moved
	UpdateUnchanged = "unchanged"  // the branch already holds these updates on this head
	UpdateNone      = "no-updates" // no dependency has a vetted, compatible update
	UpdateDryRun    = "dry-run"    // computed, not pushed
	UpdateConflict  = "conflict"   // the branch was moved by someone else: not overwritten
	UpdateRetired   = "retired"    // no vetted update is left: the updater's branch was deleted
	UpdateFailed    = "failed"
)

// Reasons a candidate version is skipped (SkippedCandidate.Code).
const (
	SkipIncompatible  = "incompatible"       // outside the declared constraint (or the default policy)
	SkipUnknownConstr = "constraint-unknown" // a requirement on it could not be read
	SkipPrerelease    = "prerelease"         // a pre-release, and the pinned version is not one
	SkipYanked        = "yanked"             // the registry withdrew it
	SkipIgnored       = "ignored"            // the repository's ignore list names it
	SkipFirewall      = "firewall"           // the dependency firewall refuses it
	SkipCooldown      = "cooldown"           // still within the maturity cooldown
	SkipRefused       = "refused"            // an admission gate refused it
	SkipFetchFailed   = "fetch-failed"       // it could not be fetched
	SkipMalicious     = "malicious"          // the LLM package scan judges it malicious
	SkipSuspicious    = "suspicious"         // the LLM package scan judges it suspicious
	SkipUnscanned     = "unscanned"          // no verdict (pending, failed, out of scope, …)
	SkipDigest        = "digest"             // the bytes are not those the registry metadata states
	SkipNotWritable   = "not-writable"       // its lock file cannot be updated (format, sandbox)
	SkipVerify        = "verify-failed"      // the rewritten lock file is not what was intended
	SkipResolution    = "resolution"         // the re-resolution brought in something that is not vetted
	SkipLimit         = "limit"              // beyond updates.maxCandidates or maxUpdates
	SkipUnsupported   = "unsupported"        // its versions cannot be listed through the proxy
	SkipListingFailed = "listing-failed"     // the registry's version list could not be read
	SkipRedirected    = "redirected"         // the repository builds something else for it (a replace, patch or override)
)

// UpdateConfig tunes the maintenance updater.
type UpdateConfig struct {
	// Enabled turns it on: scheduled runs, and runs on request.
	Enabled bool
	// Interval is the period between scheduled runs of each repository
	// (default 24h); negative runs on request only.
	Interval time.Duration
	// Branch is the maintenance branch (default "pullthrough/maintenance").
	Branch string
	// MaxBump bounds updates when no constraint is declared: versions.LevelMinor
	// (the default: within the same major) or versions.LevelPatch.
	MaxBump versions.Level
	// IncludeDev updates development dependencies too (default true).
	IncludeDev *bool
	// MaxCandidates is how many compatible newer versions of one dependency
	// are vetted, newest first, before it is given up (default 3).
	MaxCandidates int
	// MaxUpdates bounds the updates of one run (default 50).
	MaxUpdates int
	// Concurrency is how many dependencies are examined at a time (default 2).
	Concurrency int
	// Subject is the system principal the updater fetches as (default
	// "system:repository-updater").
	Subject string
	// AuthorName and AuthorEmail sign the commits' author and committer lines.
	AuthorName  string
	AuthorEmail string
	// Signer signs the commits; nil leaves them unsigned.
	Signer CommitSigner
	// PullRequests opens or updates a pull/merge request per repository
	// whose registration names a forge and whose token resolves.
	PullRequests PullRequestConfig
	// KeepRuns is how many run reports are kept per repository (default 20).
	KeepRuns int
	// RunTimeout bounds one run (default 2h).
	RunTimeout time.Duration
	// PublicURLPrefix is the proxy's public URL followed by "/v1/": links to
	// it in registry metadata are pointed at the sandbox's own address.
	PublicURLPrefix string
}

// PullRequestConfig configures the pull/merge requests.
type PullRequestConfig struct {
	// Enabled opens them for repositories with a forge and a token.
	Enabled bool
	// Labels are added to each; Draft opens them as drafts.
	Labels []string
	Draft  bool
}

func (c UpdateConfig) withDefaults() UpdateConfig {
	if c.Interval == 0 {
		c.Interval = 24 * time.Hour
	}
	if strings.TrimSpace(c.Branch) == "" {
		c.Branch = "pullthrough/maintenance"
	}
	if c.MaxBump != versions.LevelPatch {
		c.MaxBump = versions.LevelMinor
	}
	if c.IncludeDev == nil {
		t := true
		c.IncludeDev = &t
	}
	if c.MaxCandidates <= 0 {
		c.MaxCandidates = 3
	}
	if c.MaxUpdates <= 0 {
		c.MaxUpdates = 50
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 2
	}
	if c.Subject == "" {
		c.Subject = "system:repository-updater"
	}
	if c.AuthorName == "" {
		c.AuthorName = "pullthrough-security"
	}
	if c.AuthorEmail == "" {
		c.AuthorEmail = "pullthrough@localhost"
	}
	if c.KeepRuns <= 0 {
		c.KeepRuns = 20
	}
	if c.RunTimeout <= 0 {
		c.RunTimeout = 2 * time.Hour
	}
	return c
}

// RepoUpdate is a repository's own maintenance settings.
type RepoUpdate struct {
	// Disabled turns the updater off for the repository.
	Disabled bool `json:"disabled,omitempty"`
	// Branch overrides the maintenance branch's name.
	Branch string `json:"branch,omitempty"`
	// MaxBump overrides the default policy: "minor" or "patch".
	MaxBump string `json:"maxBump,omitempty"`
	// Ignore lists what is never proposed: "type/name" (every version),
	// "type/name@version" (one version), "type/name@<constraint>" (versions
	// the constraint allows, in the ecosystem's syntax); "*" matches any
	// type, and a name may end in "*".
	Ignore []string `json:"ignore,omitempty"`
	// Forge opens pull/merge requests: "github" or "gitlab".
	Forge string `json:"forge,omitempty"`
	// ForgeAPI is the API base URL (default: the public one).
	ForgeAPI string `json:"forgeApi,omitempty"`
	// ForgeRepo is "owner/name" or the GitLab project path; default: read
	// from the repository's URL.
	ForgeRepo string `json:"forgeRepo,omitempty"`
	// ForgeTokenRef is the secret reference of the forge API token.
	ForgeTokenRef string `json:"forgeTokenRef,omitempty"`
}

// CommitSigner signs a commit's payload; the result is the armored signature
// git keeps in the commit's "gpgsig" header.
type CommitSigner interface {
	SignCommit(payload []byte) ([]byte, error)
}

// CommitSpec is a commit the updater builds.
type CommitSpec struct {
	Base    string
	Files   map[string][]byte
	Message string
	Author  string
	Email   string
	When    time.Time
	Signer  CommitSigner
}

// BranchSource is the Git side of the updater: the files of a commit of the
// repository's mirror, the commit it builds there, and the remote branch.
type BranchSource interface {
	// ReadFiles returns the content of the named files at commit, at most
	// maxBytes of them together (ErrTooLarge beyond); a path that is not a
	// regular file there is absent from the result.
	ReadFiles(ctx context.Context, repo Repo, commit string, paths []string, maxBytes int64) (map[string][]byte, error)
	// ListFiles returns the paths of the regular files at commit below dir
	// ("" the whole tree) that match, skipping vendored and installed trees;
	// at most max of them.
	ListFiles(ctx context.Context, repo Repo, commit, dir string, match func(path string) bool, max int) ([]string, error)
	// BuildCommit writes the commit (objects only) and returns its ID and tree.
	BuildCommit(ctx context.Context, repo Repo, spec CommitSpec) (commit, tree string, err error)
	// CommitInfo returns a commit's tree and parents, when the mirror has it.
	CommitInfo(ctx context.Context, repo Repo, commit string) (tree string, parents []string, err error)
	// CommitObject returns a commit object of the mirror as git stores it.
	CommitObject(ctx context.Context, repo Repo, commit string) ([]byte, error)
	// RemoteBranch returns the commit of the remote's branch, "" when absent.
	RemoteBranch(ctx context.Context, repo Repo, cred Credential, branch string) (string, error)
	// PushBranch pushes commit to the remote's branch with a lease: the
	// remote branch must be at expect ("" = must not exist). A lost lease
	// wraps ErrLeaseRejected.
	PushBranch(ctx context.Context, repo Repo, cred Credential, branch, commit, expect string) error
	// DeleteBranch deletes the remote's branch with a lease: it must be at
	// expect. A branch already gone is not an error; a lost lease wraps
	// ErrLeaseRejected.
	DeleteBranch(ctx context.Context, repo Repo, cred Credential, branch, expect string) error
}

// ErrLeaseRejected is a push whose lease the remote no longer matches.
var ErrLeaseRejected = errors.New("repos: the remote branch moved since the lease was taken")

// CandidatePolicy holds a candidate to the policies that judge a version by its
// coordinate before it is fetched: the dependency firewall and the maturity
// cooldown. The gates apply the same policies when the candidate is fetched;
// asking first spares the fetch and the scan of a version they would refuse.
type CandidatePolicy interface {
	// CheckCandidate returns ok, or the code (SkipFirewall, SkipCooldown) and
	// the reason a version is not to be proposed.
	CheckCandidate(tenant, ecosystem, name, version string) (ok bool, code, reason string)
}

// SandboxRunner runs a package manager in a network-less sandbox.
type SandboxRunner interface {
	// Tool reports whether the sandbox runs the tool ("npm", "cargo", "go"),
	// and why not.
	Tool(tool string) (bool, string)
	// Run runs the job and returns the files it collects.
	Run(ctx context.Context, job sandbox.Job) (*sandbox.Result, error)
}

// --- reports -------------------------------------------------------------------

// UpdateRun is the report of one maintenance run.
type UpdateRun struct {
	ID     string `json:"id"`
	Repo   string `json:"repo"`
	Tenant string `json:"tenant,omitempty"`
	// Branch is the maintenance branch; BaseBranch and Base the default
	// branch and the commit the run built on.
	Branch     string `json:"branch"`
	BaseBranch string `json:"baseBranch,omitempty"`
	Base       string `json:"base,omitempty"`
	// Trigger is "schedule" or "manual"; RequestedBy who asked.
	Trigger     string    `json:"trigger"`
	RequestedBy string    `json:"requestedBy,omitempty"`
	DryRun      bool      `json:"dryRun,omitempty"`
	StartedAt   time.Time `json:"startedAt"`
	FinishedAt  time.Time `json:"finishedAt,omitzero"`
	// Status is one of the Update* statuses; Reason explains it.
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	// Commit is the commit built; Previous the remote branch's commit before
	// the run (the lease); Pushed reports that the branch was moved.
	Commit   string `json:"commit,omitempty"`
	Tree     string `json:"tree,omitempty"`
	Previous string `json:"previous,omitempty"`
	Pushed   bool   `json:"pushed,omitempty"`
	// Attempts counts the starts over a default branch that moved meanwhile.
	Attempts int `json:"attempts"`
	// PullRequest is the pull/merge request opened or updated.
	PullRequest      *forge.PullRequest `json:"pullRequest,omitempty"`
	PullRequestError string             `json:"pullRequestError,omitempty"`
	// Updates are the updates on the branch; Skipped the candidates (and
	// dependencies) passed over, with the reasons.
	Updates []AppliedUpdate    `json:"updates"`
	Skipped []SkippedCandidate `json:"skipped"`
	// LockFiles say how each lock file with an update was written.
	LockFiles []LockFileUpdate `json:"lockFiles,omitempty"`
	// Dependencies counts the dependencies examined.
	Dependencies int `json:"dependencies"`
	// Message is the commit message.
	Message string `json:"message,omitempty"`

	// syncErr is the error of the last attempt's refresh of the mirror.
	syncErr error
}

// AppliedUpdate is one dependency update on the maintenance branch.
type AppliedUpdate struct {
	Type string `json:"type"`
	Name string `json:"name"`
	From string `json:"from"`
	To   string `json:"to"`
	Bump string `json:"bump"`
	// Constraint is the declared constraint the new version satisfies ("" when
	// none is declared and the default policy applied).
	Constraint string `json:"constraint,omitempty"`
	// Files are the lock files (and manifests) changed for it.
	Files []string `json:"files"`
	// Method is native or sandbox.
	Method string `json:"method"`
	// Verdict is the LLM package scan's (benign); ScanIDs the verdicts' IDs,
	// one per scanned object; Digest the package's sha256.
	Verdict string   `json:"verdict"`
	ScanIDs []string `json:"scanIds"`
	Digest  string   `json:"digest"`
	Model   string   `json:"model,omitempty"`
	// Upstream is the upstream it was fetched through.
	Upstream string `json:"upstream,omitempty"`
}

// Coordinate returns "type/name@to".
func (u AppliedUpdate) Coordinate() string { return u.Type + "/" + u.Name + "@" + u.To }

// SkippedCandidate is a newer version — or a whole dependency — the updater
// passed over.
type SkippedCandidate struct {
	Type string `json:"type"`
	Name string `json:"name"`
	From string `json:"from"`
	// To is the candidate version; empty when the whole dependency was
	// passed over (its versions could not be listed).
	To     string `json:"to,omitempty"`
	Code   string `json:"code"`
	Reason string `json:"reason"`
	// Verdict, ScanID and Digest are the LLM package scan's reading, when
	// one was made.
	Verdict string `json:"verdict,omitempty"`
	ScanID  string `json:"scanId,omitempty"`
	Digest  string `json:"digest,omitempty"`
}

// LockFileUpdate says how one lock file was written.
type LockFileUpdate struct {
	Path   string `json:"path"`
	Format string `json:"format"`
	// Method is native or sandbox; Tool the sandboxed package manager.
	Method string `json:"method"`
	Tool   string `json:"tool,omitempty"`
	// Changed lists the files written (the lock file, its manifest).
	Changed []string `json:"changed,omitempty"`
	// Updates counts the updates written; Error is why none could be.
	Updates int    `json:"updates"`
	Error   string `json:"error,omitempty"`
}

// UpdateState is the updater's durable state of a repository.
type UpdateState struct {
	Repo string `json:"repo"`
	// Branch is the maintenance branch; LastPushed the commit the updater
	// pushed to it last — the lease of the next push.
	Branch     string    `json:"branch"`
	LastPushed string    `json:"lastPushed,omitempty"`
	PushedAt   time.Time `json:"pushedAt,omitzero"`
	// LastRun is the newest run's ID, status and time.
	LastRun    string    `json:"lastRun,omitempty"`
	LastStatus string    `json:"lastStatus,omitempty"`
	LastRunAt  time.Time `json:"lastRunAt,omitzero"`
	// Conflict is set while the branch holds commits the updater did not push.
	Conflict string `json:"conflict,omitempty"`
}

// UpdateOverview is a repository's maintenance state at a glance.
type UpdateOverview struct {
	Repo    string                 `json:"repo"`
	Enabled bool                   `json:"enabled"`
	Branch  string                 `json:"branch"`
	State   UpdateState            `json:"state"`
	Running *UpdateRun             `json:"running,omitempty"`
	Runs    []UpdateRun            `json:"runs"`
	Formats []update.FormatSupport `json:"formats"`
}

func updateStateObject(repo string) string { return "updatestate/" + repo }
func updateLock(repo string) string        { return "update\x00" + repo }

// updateRunObject is where a run's report is kept: dry runs apart from the
// rest, so that asking what a run would do never evicts the record of a push.
func updateRunObject(repo, id string, dry bool) string {
	if dry {
		return "updatedry/" + repo + "/" + id
	}
	return "updates/" + repo + "/" + id
}

// keptDryRuns is how many dry-run reports are kept per repository.
const keptDryRuns = 5

// UpdateDisabledError is a run asked for while the updater is off.
type UpdateDisabledError struct{ Msg string }

func (e *UpdateDisabledError) Error() string { return e.Msg }

// UpdateOptions are what a run is asked with.
type UpdateOptions struct {
	DryRun  bool
	By      string
	Trigger string
}

// updatesEnabled reports whether the updater runs at all.
func (s *Service) updatesEnabled() bool { return s.cfg.Update.Enabled }

// branchFor returns a repository's maintenance branch.
func (s *Service) branchFor(r Repo) string {
	if r.Update != nil && strings.TrimSpace(r.Update.Branch) != "" {
		return strings.TrimSpace(r.Update.Branch)
	}
	return s.cfg.Update.Branch
}

// updateRunning tracks the runs in progress, by repository.
type updateRunning struct {
	mu   sync.Mutex
	runs map[string]*UpdateRun
}

func (u *updateRunning) get(repo string) *UpdateRun {
	u.mu.Lock()
	defer u.mu.Unlock()
	if r := u.runs[repo]; r != nil {
		cp := *r
		return &cp
	}
	return nil
}

// claim registers r as the repository's run unless one is registered already,
// which it then returns.
func (u *updateRunning) claim(repo string, r *UpdateRun) (*UpdateRun, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if cur := u.runs[repo]; cur != nil {
		cp := *cur
		return &cp, false
	}
	if u.runs == nil {
		u.runs = map[string]*UpdateRun{}
	}
	cp := *r
	u.runs[repo] = &cp
	return nil, true
}

func (u *updateRunning) set(repo string, r *UpdateRun) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.runs == nil {
		u.runs = map[string]*UpdateRun{}
	}
	if r == nil {
		delete(u.runs, repo)
		return
	}
	cp := *r
	u.runs[repo] = &cp
}

// StartUpdate begins a maintenance run in the background and returns its
// report so far (status "running"); UpdateReport reads it once done. A run of
// the repository already in progress is returned instead of a second one.
func (s *Service) StartUpdate(ctx context.Context, tenant, name string, opts UpdateOptions) (*UpdateRun, error) {
	reg, ok := s.registration(tenant, name)
	if !ok || reg.Removed {
		return nil, ErrNotFound
	}
	if err := s.updateAllowed(reg.Repo); err != nil {
		return nil, err
	}
	run := s.newRun(reg.Repo, opts)
	if cur, ok := s.upRunning.claim(name, run); !ok {
		if cur.DryRun != opts.DryRun {
			// Answering with the other kind of run would drop this request.
			return nil, &ConflictError{Msg: "a maintenance run of " + name + " is in progress (" + cur.ID + "); ask again once it ends"}
		}
		return cur, nil // a run of the same kind is in progress: that one is the answer
	}
	// The caller is answered with a copy: the run itself belongs to the
	// goroutine that runs it.
	answer := *run
	started := s.spawn(func() {
		if _, err := s.runUpdate(s.runCtx, reg.Repo, run); err != nil {
			s.log.Warn("maintenance run failed", "repo", name, "error", err)
		}
	})
	if !started {
		s.upRunning.set(name, nil)
		return nil, errors.New("repos: shutting down")
	}
	return &answer, nil
}

// RunUpdate runs a maintenance run to its end and returns its report.
func (s *Service) RunUpdate(ctx context.Context, tenant, name string, opts UpdateOptions) (*UpdateRun, error) {
	reg, ok := s.registration(tenant, name)
	if !ok || reg.Removed {
		return nil, ErrNotFound
	}
	if err := s.updateAllowed(reg.Repo); err != nil {
		return nil, err
	}
	run := s.newRun(reg.Repo, opts)
	if cur, ok := s.upRunning.claim(name, run); !ok {
		return nil, &ConflictError{Msg: "a maintenance run of " + name + " is in progress (" + cur.ID + ")"}
	}
	return s.runUpdate(ctx, reg.Repo, run)
}

func (s *Service) updateAllowed(r Repo) error {
	if !s.updatesEnabled() {
		return &UpdateDisabledError{Msg: "the maintenance updater is off (repositories.updates.enabled)"}
	}
	if r.Update != nil && r.Update.Disabled {
		return &UpdateDisabledError{Msg: "the maintenance updater is off for " + r.Name + " (its updates.disabled)"}
	}
	if s.opts.Branches == nil {
		return &UpdateDisabledError{Msg: "the maintenance updater has no Git access configured"}
	}
	return nil
}

func (s *Service) newRun(r Repo, opts UpdateOptions) *UpdateRun {
	trigger := opts.Trigger
	if trigger == "" {
		trigger = TriggerManual
	}
	return &UpdateRun{
		ID: newRunID(s.now()), Repo: r.Name, Tenant: r.Tenant, Branch: s.branchFor(r),
		Trigger: trigger, RequestedBy: opts.By, DryRun: opts.DryRun, StartedAt: s.now().UTC(),
		Status: UpdateRunning, Updates: []AppliedUpdate{}, Skipped: []SkippedCandidate{},
	}
}

// newRunID is a sortable, unique run ID: the start time and random bits, in
// the lower case the state store's object names are made of
// ("20261113t061715.081z-c8cd2238").
func newRunID(now time.Time) string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return strings.ToLower(now.UTC().Format("20060102T150405.000Z")) + "-" + hex.EncodeToString(b[:])
}

// validRunID reports whether s is a run ID.
func validRunID(id string) bool {
	if len(id) != 29 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c == 't' || c == 'z' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// --- state ---------------------------------------------------------------------

func (s *Service) readUpdateState(ctx context.Context, repo string) UpdateState {
	st := UpdateState{Repo: repo}
	if data, err := s.st.Get(ctx, updateStateObject(repo)); err == nil {
		var stored UpdateState
		if json.Unmarshal(data, &stored) == nil && stored.Repo == repo {
			st = stored
		}
	}
	return st
}

func (s *Service) writeUpdateState(ctx context.Context, st UpdateState) error {
	data, err := json.MarshalIndent(&st, "", "  ")
	if err != nil {
		return err
	}
	return s.st.Put(ctx, updateStateObject(st.Repo), data)
}

func (s *Service) writeUpdateRun(ctx context.Context, run *UpdateRun) error {
	data, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		return err
	}
	if err := s.st.Put(ctx, updateRunObject(run.Repo, run.ID, run.DryRun), data); err != nil {
		return err
	}
	// Keep the newest reports of each kind.
	prefix, keep := "updates/"+run.Repo+"/", s.cfg.Update.KeepRuns
	if run.DryRun {
		prefix, keep = "updatedry/"+run.Repo+"/", keptDryRuns
	}
	names, err := s.st.List(ctx, prefix)
	if err != nil {
		return nil
	}
	sort.Strings(names)
	for len(names) > keep {
		_ = s.st.Delete(ctx, names[0])
		names = names[1:]
	}
	return nil
}

// UpdateReport returns a run's report: the run of that ID, or the newest one
// (a run in progress first).
func (s *Service) UpdateReport(ctx context.Context, tenant, name, id string) (*UpdateRun, error) {
	reg, ok := s.registration(tenant, name)
	if !ok {
		return nil, ErrNotFound
	}
	if r := s.upRunning.get(reg.Name); r != nil && (id == "" || r.ID == id) {
		return r, nil
	}
	if id == "" {
		runs := s.updateRuns(ctx, reg.Name, 1)
		if len(runs) == 0 {
			return nil, ErrNotFound
		}
		return &runs[0], nil
	}
	if !validRunID(id) {
		return nil, &ValidationError{Err: fmt.Errorf("%q is not a run ID", id)}
	}
	data, err := s.st.Get(ctx, updateRunObject(reg.Name, id, false))
	if errors.Is(err, ErrNotFound) {
		data, err = s.st.Get(ctx, updateRunObject(reg.Name, id, true))
	}
	if err != nil {
		return nil, err
	}
	var run UpdateRun
	if err := json.Unmarshal(data, &run); err != nil {
		return nil, err
	}
	return &run, nil
}

// updateRuns returns a repository's newest stored run reports, newest first.
func (s *Service) updateRuns(ctx context.Context, repo string, max int) []UpdateRun {
	names, err := s.st.List(ctx, "updates/"+repo+"/")
	if err != nil {
		return nil
	}
	if dry, err := s.st.List(ctx, "updatedry/"+repo+"/"); err == nil {
		names = append(names, dry...)
	}
	// Run IDs begin with their start time: the last segment orders them.
	sort.Slice(names, func(i, j int) bool { return path.Base(names[i]) > path.Base(names[j]) })
	var out []UpdateRun
	for _, n := range names {
		if len(out) >= max {
			break
		}
		data, err := s.st.Get(ctx, n)
		if err != nil {
			continue
		}
		var run UpdateRun
		if json.Unmarshal(data, &run) == nil && run.Repo == repo {
			out = append(out, run)
		}
	}
	return out
}

// UpdateOverview returns a repository's maintenance state, its run in
// progress and its newest runs.
func (s *Service) UpdateOverview(ctx context.Context, tenant, name string) (*UpdateOverview, error) {
	reg, ok := s.registration(tenant, name)
	if !ok {
		return nil, ErrNotFound
	}
	ov := &UpdateOverview{
		Repo: reg.Name, Enabled: s.updateAllowed(reg.Repo) == nil, Branch: s.branchFor(reg.Repo),
		State: s.readUpdateState(ctx, reg.Name), Running: s.upRunning.get(reg.Name),
		Runs: s.updateRuns(ctx, reg.Name, s.cfg.Update.KeepRuns),
	}
	for _, f := range update.Formats() {
		ov.Formats = append(ov.Formats, f)
	}
	if ov.Runs == nil {
		ov.Runs = []UpdateRun{}
	}
	return ov, nil
}

// sweepUpdates starts the scheduled runs that are due (leader only).
func (s *Service) sweepUpdates(ctx context.Context) {
	if !s.updatesEnabled() || s.cfg.Update.Interval < 0 || s.opts.Branches == nil {
		return
	}
	now := s.now()
	for _, r := range s.tracked() {
		if ctx.Err() != nil {
			return
		}
		if r.Update != nil && r.Update.Disabled {
			continue
		}
		st := s.readUpdateState(ctx, r.Name)
		if !st.LastRunAt.IsZero() && now.Sub(st.LastRunAt) < s.cfg.Update.Interval {
			continue
		}
		if s.upRunning.get(r.Name) != nil {
			continue
		}
		// One scheduled run at a time across repositories: each may hold the
		// LLM gate's slots for a while.
		if _, err := s.RunUpdate(ctx, "", r.Name, UpdateOptions{Trigger: TriggerSchedule}); err != nil {
			s.log.Warn("scheduled maintenance run failed", "repo", r.Name, "error", err)
		}
	}
}

// --- validation --------------------------------------------------------------------

// maxIgnores bounds a repository's ignore list.
const maxIgnores = 256

// validateUpdate checks a registration's maintenance settings.
func (r *Repo) validateUpdate() error {
	u := r.Update
	if u == nil {
		return nil
	}
	u.Branch = strings.TrimSpace(u.Branch)
	if u.Branch != "" && !ValidBranch(u.Branch) {
		return fmt.Errorf("repository %q: updates.branch %q is not a valid branch name", r.Name, u.Branch)
	}
	if u.Branch != "" && u.Branch == r.Branch {
		return fmt.Errorf("repository %q: updates.branch must not be the branch the repository follows", r.Name)
	}
	switch u.MaxBump = strings.TrimSpace(u.MaxBump); u.MaxBump {
	case "", "minor", "patch":
	default:
		return fmt.Errorf("repository %q: updates.maxBump must be minor or patch, got %q", r.Name, u.MaxBump)
	}
	if len(u.Ignore) > maxIgnores {
		return fmt.Errorf("repository %q: at most %d updates.ignore entries", r.Name, maxIgnores)
	}
	for _, ig := range u.Ignore {
		if _, err := parseIgnore(ig); err != nil {
			return fmt.Errorf("repository %q: updates.ignore: %w", r.Name, err)
		}
	}
	switch u.Forge = strings.ToLower(strings.TrimSpace(u.Forge)); u.Forge {
	case "", "github", "gitlab":
	default:
		return fmt.Errorf("repository %q: updates.forge must be github or gitlab, got %q", r.Name, u.Forge)
	}
	if u.ForgeTokenRef = strings.TrimSpace(u.ForgeTokenRef); u.ForgeTokenRef != "" {
		ref, err := secrets.ParseRef(u.ForgeTokenRef)
		if err != nil || ref.Scheme == secrets.SchemeLiteral {
			return fmt.Errorf("repository %q: updates.forgeTokenRef must be a secret reference (env://, file://, vault://…#key), never the token itself", r.Name)
		}
	}
	if u.ForgeAPI = strings.TrimSpace(u.ForgeAPI); u.ForgeAPI != "" {
		pu, err := url.Parse(u.ForgeAPI)
		if err != nil || (pu.Scheme != "https" && pu.Scheme != "http") || pu.Host == "" || pu.User != nil {
			return fmt.Errorf("repository %q: updates.forgeApi must be an http(s) URL without credentials", r.Name)
		}
	}
	if u.ForgeRepo = strings.TrimSpace(u.ForgeRepo); len(u.ForgeRepo) > 256 || strings.ContainsAny(u.ForgeRepo, " \t\r\n\x00?#") {
		return fmt.Errorf("repository %q: updates.forgeRepo %q is not a project path", r.Name, u.ForgeRepo)
	}
	if u.Forge != "" && u.ForgeAPI == "" {
		if _, err := forgeAPIFor(u.Forge, r.URL); err != nil {
			return fmt.Errorf("repository %q: %w", r.Name, err)
		}
	}
	return nil
}

// forgeAPIFor is the API of a forge when none is configured: the public one —
// only for a repository the public forge hosts. A self-hosted forge needs its
// API named: the token must never go to github.com or gitlab.com for it.
func forgeAPIFor(kind, cloneURL string) (string, error) {
	host := cloneHost(cloneURL)
	switch {
	case kind == "github" && host == "github.com":
		return forge.DefaultGitHubAPIURL, nil
	case kind == "gitlab" && host == "gitlab.com":
		return forge.DefaultGitLabAPIURL, nil
	}
	return "", fmt.Errorf("the repository is not hosted on the public %s; name its API (updates.forgeApi)", kind)
}

// cloneHost returns the lower-cased host of a clone URL (https://host/…,
// ssh://user@host/…, user@host:path).
func cloneHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "://"); i > 0 {
		if u, err := url.Parse(raw); err == nil {
			return strings.ToLower(u.Hostname())
		}
		return ""
	}
	if at := strings.Index(raw, "@"); at >= 0 {
		raw = raw[at+1:]
	}
	if colon := strings.Index(raw, ":"); colon > 0 {
		return strings.ToLower(raw[:colon])
	}
	return ""
}

// --- helpers ---------------------------------------------------------------------

// lockfileKey is the format key of a lock file ("npm/package-lock.json").
func lockfileKey(lf LockFile) string { return lockfiles.CanonicalType(lf.Type) + "/" + lf.Format }
