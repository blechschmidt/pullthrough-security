package repos

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/git"
	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
	"github.com/blechschmidt/pullthrough-security/internal/repos/locate"
	"github.com/blechschmidt/pullthrough-security/internal/secrets"
)

// Where a registration came from (Repo.Source).
const (
	SourceConfig = "config"
	SourceAPI    = "api"
)

// Repo is a registered repository.
type Repo struct {
	// Name identifies the repository in the API, the state store and the
	// metrics: lower-case letters, digits, ".", "_" and "-".
	Name string `json:"name"`
	// URL is the clone URL (https://…, ssh://… or user@host:path).
	URL string `json:"url"`
	// Username is the HTTPS user name sent with the credential; empty sends
	// "x-access-token" (GitHub's convention for tokens).
	Username string `json:"username,omitempty"`
	// CredentialsRef is a secret reference (env://, file://, vault://…#key)
	// resolved through the secrets provider each time the repository is
	// fetched; never the secret itself.
	CredentialsRef string `json:"credentialsRef,omitempty"`
	// Tenant owns the repository: its releases are visible to that tenant
	// only, and its dependencies are fetched as that tenant (cache namespace,
	// tenant policies).
	Tenant string `json:"tenant,omitempty"`
	// Lockfiles are globs of the lock files whose dependencies make up a
	// release (lockfiles.Options.Include); empty takes every lock file.
	Lockfiles []string `json:"lockfiles,omitempty"`
	// Tags are globs of the tags tracked ("v*"); empty tracks every tag.
	Tags []string `json:"tags,omitempty"`
	// Upstreams maps an upstream type to the upstream this repository's
	// dependencies of the type are fetched through, when the registry the
	// lock file names is not enough to choose.
	Upstreams map[string]string `json:"upstreams,omitempty"`
	// FullName ("owner/repo") routes push webhooks to the repository in
	// addition to its URL.
	FullName string `json:"fullName,omitempty"`
	// BackfillTags is how many of the tags found at the first sync are pinned
	// (the most recently committed first); nil takes the service default, -1
	// is all, 0 none. Every tag is recorded in the history either way.
	BackfillTags *int `json:"backfillTags,omitempty"`
	// Roles are the access-control roles (auth.roles) the release pinner
	// holds when it fetches this repository's dependencies; empty takes the
	// service default. With access control on, a dependency from an upstream
	// no role grants is refused like a client's pull would be: the lock files
	// name the registries, and they must not reach an upstream the operator
	// has not granted.
	Roles []string `json:"roles,omitempty"`
	// Branch is the branch whose head the dependency scan follows (Task 181);
	// empty follows the repository's default branch (its remote HEAD).
	Branch string `json:"branch,omitempty"`

	// Source says whether the registration comes from the configuration or
	// the admin API; only the latter can be removed through the API.
	Source string `json:"source"`
	// CreatedAt and CreatedBy say when and by whom it was registered.
	CreatedAt time.Time `json:"createdAt,omitzero"`
	CreatedBy string    `json:"createdBy,omitempty"`
}

// repoNameRE is the shape of a repository name.
var repoNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,99}$`)

// ValidName reports whether name is a valid repository name.
func ValidName(name string) bool {
	return repoNameRE.MatchString(name) && !strings.Contains(name, "..")
}

// maxGlobs bounds the globs of one registration.
const maxGlobs = 64

// Validate checks a registration. allowedSchemes are the URL schemes accepted
// ("https", "ssh"); scp-like "user@host:path" counts as ssh.
func (r *Repo) Validate(allowedSchemes []string) error {
	r.Name = strings.TrimSpace(r.Name)
	r.URL = strings.TrimSpace(r.URL)
	r.Tenant = strings.TrimSpace(r.Tenant)
	r.Username = strings.TrimSpace(r.Username)
	r.CredentialsRef = strings.TrimSpace(r.CredentialsRef)
	r.FullName = strings.TrimSpace(r.FullName)
	if !ValidName(r.Name) {
		return fmt.Errorf("repository name %q must be 1-100 lower-case letters, digits, '.', '_' or '-', starting with a letter or digit", r.Name)
	}
	scheme, err := urlScheme(r.URL)
	if err != nil {
		return fmt.Errorf("repository %q: %w", r.Name, err)
	}
	allowed := false
	for _, s := range allowedSchemes {
		if strings.EqualFold(s, scheme) {
			allowed = true
		}
	}
	if !allowed {
		return fmt.Errorf("repository %q: %s URLs are not accepted (allowed: %s)", r.Name, scheme, strings.Join(allowedSchemes, ", "))
	}
	if r.CredentialsRef != "" {
		ref, err := secrets.ParseRef(r.CredentialsRef)
		if err != nil {
			return fmt.Errorf("repository %q: credentialsRef must be a secret reference (env://NAME, file:///path, vault://mount/path#key), never the secret itself", r.Name)
		}
		if ref.Scheme == secrets.SchemeLiteral {
			return fmt.Errorf("repository %q: credentialsRef must name where the secret is kept; literal:// would put it in the registration", r.Name)
		}
		if scheme != "https" && scheme != "http" {
			return fmt.Errorf("repository %q: credentialsRef applies to HTTPS URLs; an SSH URL authenticates with the proxy host's SSH configuration", r.Name)
		}
	}
	if strings.ContainsAny(r.Username, ":\r\n\x00") || len(r.Username) > 256 {
		return fmt.Errorf("repository %q: invalid username", r.Name)
	}
	if strings.ContainsAny(r.Tenant, "\r\n\x00/") || len(r.Tenant) > 128 {
		return fmt.Errorf("repository %q: invalid tenant %q", r.Name, r.Tenant)
	}
	if len(r.FullName) > 256 || strings.ContainsAny(r.FullName, "\r\n\x00 ") {
		return fmt.Errorf("repository %q: invalid fullName", r.Name)
	}
	if len(r.Lockfiles) > maxGlobs || len(r.Tags) > maxGlobs {
		return fmt.Errorf("repository %q: at most %d lock-file globs and %d tag globs", r.Name, maxGlobs, maxGlobs)
	}
	if err := lockfiles.ValidateGlobs(r.Lockfiles); err != nil {
		return fmt.Errorf("repository %q: lock-file globs: %w", r.Name, err)
	}
	for _, g := range r.Tags {
		if strings.TrimSpace(g) == "" {
			return fmt.Errorf("repository %q: empty tag glob", r.Name)
		}
		if _, err := path.Match(g, ""); err != nil {
			return fmt.Errorf("repository %q: tag glob %q: %w", r.Name, g, err)
		}
	}
	for t, up := range r.Upstreams {
		if strings.TrimSpace(t) == "" || strings.TrimSpace(up) == "" {
			return fmt.Errorf("repository %q: upstreams entries need a type and an upstream name", r.Name)
		}
	}
	if r.BackfillTags != nil && *r.BackfillTags < -1 {
		return fmt.Errorf("repository %q: backfillTags must be -1 (all), 0 (none) or a positive count", r.Name)
	}
	r.Branch = strings.TrimSpace(r.Branch)
	if r.Branch != "" && !ValidBranch(r.Branch) {
		return fmt.Errorf("repository %q: branch %q is not a valid branch name", r.Name, r.Branch)
	}
	if len(r.Roles) > maxGlobs {
		return fmt.Errorf("repository %q: at most %d roles", r.Name, maxGlobs)
	}
	seenRole := map[string]bool{}
	for i, role := range r.Roles {
		role = strings.TrimSpace(role)
		if role == "" || len(role) > 128 || strings.ContainsAny(role, "\r\n\x00") {
			return fmt.Errorf("repository %q: invalid role %q", r.Name, role)
		}
		if seenRole[role] {
			return fmt.Errorf("repository %q: role %q is listed twice", r.Name, role)
		}
		seenRole[role] = true
		r.Roles[i] = role
	}
	return nil
}

// branchRE is the shape of a branch name the registry accepts: the
// characters Git branch names are made of in practice, nothing a command
// line could read as an option or a revision expression.
var branchRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/+-]{0,199}$`)

// ValidBranch reports whether b is a branch name the registry accepts.
func ValidBranch(b string) bool {
	return branchRE.MatchString(b) && !strings.Contains(b, "..") && !strings.Contains(b, "//") &&
		!strings.HasSuffix(b, "/") && !strings.HasSuffix(b, ".lock") && !strings.HasSuffix(b, ".")
}

// urlScheme returns the scheme of a clone URL ("ssh" for scp-like), refusing
// what git would read as an option or a remote helper, and credentials in the
// URL itself.
func urlScheme(raw string) (string, error) {
	if err := git.ValidateCloneURL(raw); err != nil {
		return "", err
	}
	lower := strings.ToLower(raw)
	if i := strings.Index(lower, "://"); i > 0 {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" && lower[:i] != "file" {
			return "", fmt.Errorf("invalid repository URL")
		}
		if _, hasPassword := u.User.Password(); hasPassword || (u.User != nil && lower[:i] != "ssh") {
			return "", errors.New("the URL carries credentials; use credentialsRef")
		}
		return lower[:i], nil
	}
	return "ssh", nil // user@host:path
}

// tagSelected reports whether a tag is tracked.
func (r *Repo) tagSelected(tag string) bool {
	if len(r.Tags) == 0 {
		return true
	}
	for _, g := range r.Tags {
		if ok, _ := path.Match(g, tag); ok {
			return true
		}
	}
	return false
}

// clone returns a deep copy.
func (r Repo) clone() Repo {
	out := r
	out.Lockfiles = append([]string(nil), r.Lockfiles...)
	out.Tags = append([]string(nil), r.Tags...)
	if r.Upstreams != nil {
		out.Upstreams = make(map[string]string, len(r.Upstreams))
		for k, v := range r.Upstreams {
			out.Upstreams[k] = v
		}
	}
	if r.BackfillTags != nil {
		n := *r.BackfillTags
		out.BackfillTags = &n
	}
	out.Roles = append([]string(nil), r.Roles...)
	return out
}

// cloneScan returns a deep copy of a release's scan summary.
func (rs *ReleaseScan) clone() *ReleaseScan {
	if rs == nil {
		return nil
	}
	out := *rs
	out.Flagged = append([]string(nil), rs.Flagged...)
	return &out
}

// --- tag history ------------------------------------------------------------

// Kinds of tag history records (TagRecord.Kind).
const (
	TagCreated = "created"
	TagMoved   = "moved"
	TagDeleted = "deleted"
)

// TagRecord is one entry of a repository's append-only tag history: a tag
// seen pointing at a commit (created, or moved from another commit), or a tag
// gone. A record is written once and never rewritten: when a tag moves or is
// deleted, a new record supersedes the old one. Records are hash-chained per
// repository, so a rewritten or removed record is detected (VerifyHistory).
type TagRecord struct {
	// Seq numbers the repository's records from 1.
	Seq uint64 `json:"seq"`
	// Repo and Tag (the short name, "v1.2.0") say what the record is about.
	Repo string `json:"repo"`
	Tag  string `json:"tag"`
	// Kind is TagCreated, TagMoved or TagDeleted.
	Kind string `json:"kind"`
	// Commit is the commit the tag points at; empty for a deletion.
	Commit string `json:"commit,omitempty"`
	// Object is the tag object of an annotated tag.
	Object string `json:"object,omitempty"`
	// At is when the association was first seen (or the tag seen gone).
	At time.Time `json:"at"`
	// Supersedes is the record this one replaces, for a move or a deletion;
	// PreviousLastSeen is when that record's association was last seen.
	Supersedes       uint64    `json:"supersedes,omitempty"`
	PreviousCommit   string    `json:"previousCommit,omitempty"`
	PreviousLastSeen time.Time `json:"previousLastSeen,omitzero"`
	// Initial marks a tag found at the repository's first sync.
	Initial bool `json:"initial,omitempty"`
	// Trigger is what made the tracker look: "poll", "webhook" or "manual".
	Trigger string `json:"trigger,omitempty"`
	// Prev is the previous record's Hash ("" for the first); Hash is this
	// record's: SHA-256 over Prev and the record without Hash.
	Prev string `json:"prev"`
	Hash string `json:"hash"`
}

// States of a tag association (TagAssociation.State).
const (
	AssocCurrent = "current"
	AssocMoved   = "moved"
	AssocDeleted = "deleted"
)

// TagAssociation is one tag-to-commit association of the history, as the API
// shows it: when it was first and last seen, and what superseded it.
type TagAssociation struct {
	Tag       string    `json:"tag"`
	Commit    string    `json:"commit"`
	Object    string    `json:"object,omitempty"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
	// State is AssocCurrent while the tag still points at the commit,
	// AssocMoved once it points elsewhere, AssocDeleted once it is gone.
	State string `json:"state"`
	// SupersededBy is the Seq of the record that ended the association;
	// SupersededAt when; NextCommit where the tag went (empty when deleted).
	SupersededBy uint64    `json:"supersededBy,omitempty"`
	SupersededAt time.Time `json:"supersededAt,omitzero"`
	NextCommit   string    `json:"nextCommit,omitempty"`
	Seq          uint64    `json:"seq"`
	Initial      bool      `json:"initial,omitempty"`
}

// --- release manifests -----------------------------------------------------

// Statuses of a release manifest (Manifest.Status).
const (
	// ReleasePending: the release is queued for pinning or being pinned.
	ReleasePending = "pending"
	// ReleasePinned: every dependency's objects are pinned.
	ReleasePinned = "pinned"
	// ReleasePartial: some dependencies are pinned, others were refused,
	// failed, or cannot be fetched through the proxy.
	ReleasePartial = "partial"
	// ReleaseFailed: nothing could be pinned (the lock files could not be
	// read, or every dependency failed).
	ReleaseFailed = "failed"
)

// Statuses of a dependency and of an object (Dependency.Status, Object.Status).
const (
	StatusPinned      = "pinned"
	StatusRefused     = "refused"
	StatusFailed      = "failed"
	StatusMismatch    = "mismatch"
	StatusUnsupported = "unsupported"
	StatusSkipped     = "skipped"
	StatusUncached    = "uncached"
)

// Manifest is the release manifest of one commit of a repository: the lock
// files read at the commit, the dependencies they pin, and for each the cache
// objects fetched for it — digest, gate verdicts — and whether they are pinned.
type Manifest struct {
	Repo   string `json:"repo"`
	Tenant string `json:"tenant,omitempty"`
	Commit string `json:"commit"`
	// Tags are the tags seen pointing at the commit when it was pinned.
	Tags []string `json:"tags"`
	// Status is ReleasePending, ReleasePinned, ReleasePartial or
	// ReleaseFailed.
	Status string `json:"status"`
	// FullyPinned is Status == ReleasePinned.
	FullyPinned bool `json:"fullyPinned"`
	// Reason says why a release is not fully pinned.
	Reason    string    `json:"reason,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	// Attempts counts the pinning runs; NextAttempt is when the next retry
	// of what is not pinned is due.
	Attempts    int       `json:"attempts"`
	NextAttempt time.Time `json:"nextAttempt,omitzero"`
	// LockFiles are the lock files read; Skipped those the walk passed over;
	// Truncated says why the walk ended early.
	LockFiles []LockFile            `json:"lockFiles"`
	Skipped   []lockfiles.Skipped   `json:"skipped,omitempty"`
	Truncated string                `json:"truncated,omitempty"`
	Submodule []lockfiles.Submodule `json:"submodules,omitempty"`
	// Dependencies are the distinct dependencies of the lock files.
	Dependencies []Dependency `json:"dependencies"`
	Summary      Summary      `json:"summary"`
	// Scan is the latest LLM dependency scan of the release (Task 181). Only
	// the scanner writes it; the pinner keeps it as it finds it.
	Scan *ReleaseScan `json:"scan,omitempty"`
}

// ReleaseScan summarizes a release's latest dependency scan in its manifest.
type ReleaseScan struct {
	// Status is ScanComplete, ScanIncomplete or ScanFailed; Result is
	// ResultMalicious, ResultSuspicious, ResultIncomplete or ResultClean.
	Status string `json:"status"`
	Result string `json:"result"`
	// ContainsMaliciousDependency marks the release "contains malicious
	// dependency": the scan judged at least one of its dependencies
	// malicious. Its bytes stay pinned, for forensics.
	ContainsMaliciousDependency bool `json:"containsMaliciousDependency"`
	// Flagged are the coordinates judged malicious, and suspicious ones the
	// quarantine action holds.
	Flagged    []string `json:"flagged,omitempty"`
	Malicious  int      `json:"malicious"`
	Suspicious int      `json:"suspicious"`
	Unscanned  int      `json:"unscanned"`
	Benign     int      `json:"benign"`
	// Model and PromptVersion are the gate's when the scan ran; Action its
	// action; ScannedAt when the scan finished.
	Model         string    `json:"model,omitempty"`
	PromptVersion int       `json:"promptVersion,omitempty"`
	Action        string    `json:"action,omitempty"`
	ScannedAt     time.Time `json:"scannedAt"`
}

// LockFile is one lock file read for a release.
type LockFile struct {
	Path          string `json:"path"`
	Type          string `json:"type"`
	Format        string `json:"format"`
	FormatVersion string `json:"formatVersion,omitempty"`
	Dependencies  int    `json:"dependencies"`
	Warnings      int    `json:"warnings,omitempty"`
	Error         string `json:"error,omitempty"`
}

// Dependency is one dependency of a release and what became of it.
type Dependency struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	ID       string `json:"id,omitempty"`
	Source   string `json:"source,omitempty"`
	Registry string `json:"registry,omitempty"`
	Revision string `json:"revision,omitempty"`
	Dev      bool   `json:"dev,omitempty"`
	// Files are the lock-file locations ("path:line") that pin it.
	Files []string `json:"files"`
	// LockDigests are the digests the lock files record for it.
	LockDigests []lockfiles.Digest `json:"lockDigests,omitempty"`
	// Unverified: nothing in the lock file pins the content; it is pinned as
	// served (trust on first use).
	Unverified       bool   `json:"unverified,omitempty"`
	UnverifiedReason string `json:"unverifiedReason,omitempty"`
	// Upstream is the upstream it was fetched through.
	Upstream string `json:"upstream,omitempty"`
	// Status is StatusPinned, StatusRefused, StatusFailed, StatusMismatch or
	// StatusUnsupported; Reason explains anything but StatusPinned.
	Status string   `json:"status"`
	Reason string   `json:"reason,omitempty"`
	Notes  []string `json:"notes,omitempty"`
	// Objects are the cache objects fetched for it.
	Objects []Object `json:"objects,omitempty"`

	// lock is the lock file's record of the dependency, which locating
	// reads; it is not stored (a stored dependency that is pinned is never
	// located again).
	lock lockfiles.Dependency
}

// Coordinate returns "type/name@version".
func (d Dependency) Coordinate() string {
	return lockfiles.CanonicalType(d.Type) + "/" + d.Name + "@" + d.Version
}

// key identifies the dependency within a manifest.
func (d Dependency) key() string {
	return strings.Join([]string{lockfiles.CanonicalType(d.Type), d.Name, d.Version, d.ID, d.Source, d.Registry, d.Revision}, "\x00")
}

// Object is one cache object fetched for a dependency.
type Object struct {
	Role     string `json:"role"`
	File     string `json:"file,omitempty"`
	Upstream string `json:"upstream,omitempty"`
	// Path is the request path, "/v1/<upstream>/…".
	Path string `json:"path"`
	// Status is StatusPinned, StatusRefused, StatusFailed, StatusMismatch,
	// StatusUncached or StatusSkipped (an optional object not fetched).
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	// Optional objects do not count against the dependency.
	Optional bool `json:"optional,omitempty"`
	// CacheKey is the key the object is stored (and pinned) under; Digest
	// the cache's content digest ("sha256:…"); Size its length.
	CacheKey string `json:"cacheKey,omitempty"`
	Digest   string `json:"digest,omitempty"`
	Size     int64  `json:"size,omitempty"`
	// Cache is how the proxy obtained it (HIT, MISS, COALESCED-HIT, BYPASS);
	// HTTPStatus what it answered.
	Cache      string `json:"cache,omitempty"`
	HTTPStatus int    `json:"httpStatus,omitempty"`
	// Gate, Code and Reason explain a refusal.
	Gate string `json:"gate,omitempty"`
	Code string `json:"code,omitempty"`
	// Verdicts are the admission gates that judged the object.
	Verdicts []GateVerdict `json:"verdicts,omitempty"`
	// Check compares the bytes with the lock file's digests.
	Check     *locate.CheckResult `json:"check,omitempty"`
	FetchedAt time.Time           `json:"fetchedAt,omitzero"`
	// Repairs counts integrity repairs (re-fetches after the cached bytes
	// were found corrupted).
	Repairs int `json:"repairs,omitempty"`
	// LLM is the LLM package-content scan's reading of the bytes of an object
	// another gate refused (Task 181): the release does not pin them, but its
	// dependency scan reports what the LLM gate read in them.
	LLM *LLMReading `json:"llm,omitempty"`
}

// LLMReading is the LLM package-content scan gate's reading of an object, as
// a manifest keeps it: the gate's disposition and where it came from. The
// model's own words are not kept here.
type LLMReading struct {
	Verdict       string    `json:"verdict"`
	Reason        string    `json:"reason,omitempty"`
	Digest        string    `json:"digest,omitempty"`
	ModelVerdict  string    `json:"modelVerdict,omitempty"`
	Confidence    float64   `json:"confidence,omitempty"`
	Provider      string    `json:"provider,omitempty"`
	Model         string    `json:"model,omitempty"`
	PromptVersion int       `json:"promptVersion,omitempty"`
	ScannedAt     time.Time `json:"scannedAt,omitzero"`
	BreakGlass    string    `json:"breakGlass,omitempty"`
}

// GateVerdict is one admission gate's judgement of an object.
type GateVerdict struct {
	Gate string `json:"gate"`
	// Outcome is "pass" or "refuse".
	Outcome string `json:"outcome"`
	Detail  string `json:"detail,omitempty"`
}

// Summary counts a manifest's dependencies and objects.
type Summary struct {
	Dependencies  int   `json:"dependencies"`
	Pinned        int   `json:"pinned"`
	Refused       int   `json:"refused"`
	Failed        int   `json:"failed"`
	Mismatched    int   `json:"mismatched"`
	Unsupported   int   `json:"unsupported"`
	Unverified    int   `json:"unverified"`
	Objects       int   `json:"objects"`
	PinnedObjects int   `json:"pinnedObjects"`
	PinnedBytes   int64 `json:"pinnedBytes"`
}

// summarize recomputes s from the dependencies.
func (m *Manifest) summarize() {
	var s Summary
	for _, d := range m.Dependencies {
		s.Dependencies++
		switch d.Status {
		case StatusPinned:
			s.Pinned++
			if d.Unverified {
				s.Unverified++
			}
		case StatusRefused:
			s.Refused++
		case StatusMismatch:
			s.Mismatched++
		case StatusUnsupported:
			s.Unsupported++
		default:
			s.Failed++
		}
		for _, o := range d.Objects {
			s.Objects++
			if o.Status == StatusPinned {
				s.PinnedObjects++
				s.PinnedBytes += o.Size
			}
		}
	}
	m.Summary = s
}

// settle derives the manifest's status from its dependencies.
func (m *Manifest) settle() {
	m.summarize()
	s := m.Summary
	var reasons []string
	if m.Truncated != "" {
		reasons = append(reasons, "the lock-file scan stopped early: "+m.Truncated)
	}
	for _, lf := range m.LockFiles {
		if lf.Error != "" {
			reasons = append(reasons, "lock file "+lf.Path+" could not be read: "+lf.Error)
			break
		}
	}
	// A lock file the walk found but did not read (over the size limit, a
	// symbolic link, content missing) pins dependencies nobody looked at. A
	// directory it passed over ("…/") was skipped on purpose (vendored code,
	// test fixtures, the depth limit).
	unread := 0
	for _, sk := range m.Skipped {
		if !strings.HasSuffix(sk.Path, "/") {
			unread++
		}
	}
	if unread > 0 {
		reasons = append(reasons, fmt.Sprintf("%d lock file(s) were not read (see skipped)", unread))
	}
	notPinned := s.Dependencies - s.Pinned
	if notPinned > 0 {
		var parts []string
		for _, kv := range []struct {
			n    int
			what string
		}{{s.Refused, "refused by an admission gate"}, {s.Mismatched, "did not match the lock file's digest"},
			{s.Failed, "could not be fetched"}, {s.Unsupported, "cannot be fetched through the proxy"}} {
			if kv.n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", kv.n, kv.what))
			}
		}
		reasons = append(reasons, fmt.Sprintf("%d of %d dependencies are not pinned (%s)", notPinned, s.Dependencies, strings.Join(parts, ", ")))
	}
	switch {
	case len(reasons) == 0:
		m.Status, m.Reason = ReleasePinned, ""
	case s.Pinned == 0 && s.Dependencies > 0, s.Dependencies == 0 && len(reasons) > 0:
		m.Status, m.Reason = ReleaseFailed, strings.Join(reasons, "; ")
	default:
		m.Status, m.Reason = ReleasePartial, strings.Join(reasons, "; ")
	}
	m.FullyPinned = m.Status == ReleasePinned
}

// pinnedObjects returns the objects of the manifest that are pinned.
func (m *Manifest) pinnedObjects() []Object {
	var out []Object
	for _, d := range m.Dependencies {
		for _, o := range d.Objects {
			if o.Status == StatusPinned && o.CacheKey != "" {
				out = append(out, o)
			}
		}
	}
	return out
}

// addTag records that tag pointed at the manifest's commit.
func (m *Manifest) addTag(tag string) {
	for _, t := range m.Tags {
		if t == tag {
			return
		}
	}
	m.Tags = append(m.Tags, tag)
	sort.Strings(m.Tags)
}

// commitRE is the shape of a commit ID (SHA-1 or SHA-256).
var commitRE = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// validCommit reports whether c is a full commit ID.
func validCommit(c string) bool { return commitRE.MatchString(c) }
