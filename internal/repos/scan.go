package repos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

// Dependency scans (Task 181).
//
// Every dependency a repository's lock files pin is put before the sandboxed
// LLM package-content scan gate (internal/llmpkgscan): the dependencies of each
// release manifest once it is pinned, those of the default branch's head when
// it moves (a push) and on a schedule, and those of any revision on request.
// The gate's verdict cache is reused — bytes that already have a verdict under
// the current model and prompt version cost no model call — and every scan is
// held to the gate's cost budget, concurrency limits and per-tenant share.
//
// A dependency the scan cannot cover — it cannot be fetched through the proxy,
// a gate refused it, it was served without a digest, its ecosystem is outside
// the gate's scope, the scan itself failed — is reported "unscanned" with the
// reason: unscanned is never benign. A malicious verdict on a release's pinned
// dependency raises a finding and a notification and marks the release
// manifest "contains malicious dependency"; the pinned bytes are kept, for
// forensics, and are never served while the gate refuses them.
//
// The per-repository report — each dependency's verdict, model, time and
// evidence — is stored under scans/<repo>/<commit> and feeds the admin API and
// UI, the dossier, SARIF (located at the lock file's line), the findings layer
// (dedup, suppression trail, store, SIEM) and the query and MCP APIs.

// Kinds of scan (ScanReport.Kind).
const (
	// ScanRelease scans a release manifest: its pinned objects.
	ScanRelease = "release"
	// ScanHead scans the default branch's head commit.
	ScanHead = "head"
	// ScanRevision scans another revision, on request.
	ScanRevision = "revision"
)

// What started a scan (ScanReport.Trigger).
const (
	TriggerRelease     = "release"
	TriggerPush        = "push"
	TriggerSchedule    = "schedule"
	TriggerManual      = "manual"
	TriggerRetry       = "retry"
	TriggerModelChange = "model-change"
)

// Statuses of a scan (ScanReport.Status).
const (
	// ScanComplete: every dependency has a verdict.
	ScanComplete = "complete"
	// ScanIncomplete: some dependencies are unscanned.
	ScanIncomplete = "incomplete"
	// ScanFailed: nothing could be scanned (the lock files could not be read,
	// there is no release manifest).
	ScanFailed = "failed"
)

// Results of a scan (ScanReport.Result).
const (
	ResultMalicious  = "malicious"
	ResultSuspicious = "suspicious"
	// ResultIncomplete: nothing flagged, but some dependencies are unscanned —
	// which is not clean.
	ResultIncomplete = "incomplete"
	// ResultClean: every dependency was scanned and judged benign.
	ResultClean = "clean"
	// ResultEmpty: no lock file pins a dependency.
	ResultEmpty = "empty"
)

// Verdicts of a dependency (DependencyScan.Verdict): how the gate reads it.
const (
	VerdictMalicious  = "malicious"
	VerdictSuspicious = "suspicious"
	VerdictBenign     = "benign"
	VerdictUnscanned  = "unscanned"
)

// Reasons a dependency is unscanned that the repository scan itself finds
// (UnscannedInfo.Code); the gate's own reason codes ("oversized",
// "unsupported-format", "budget-exhausted", …) pass through as they are.
const (
	UnscannedUnsupported  = "unsupported"        // it cannot be fetched through the proxy
	UnscannedFetchRefused = "fetch-refused"      // an admission gate refused it
	UnscannedFetchFailed  = "fetch-failed"       // it could not be fetched
	UnscannedNoDigest     = "no-digest"          // served without caching: no digest to bind a verdict to
	UnscannedLockMismatch = "lockfile-mismatch"  // the bytes are not the ones the lock file pins
	UnscannedOutOfScope   = "out-of-scope"       // the gate does not scan its ecosystem or upstream
	UnscannedNoContent    = "no-package-content" // none of its objects is package content
	UnscannedNotPinned    = "not-pinned"         // a release dependency whose objects are not pinned
	UnscannedScanFailed   = "scan-failed"        // the object could not be put before the gate
	UnscannedScanDisabled = "scan-disabled"      // the gate was switched off
)

// ScanConfig tunes the dependency scans.
type ScanConfig struct {
	// Enabled turns them on; they also need an ObjectScanner whose gate is
	// enabled.
	Enabled bool
	// Releases scans each release manifest once it is pinned (default true);
	// DefaultBranch the default branch's head (default true).
	Releases      *bool
	DefaultBranch *bool
	// Interval is how often the default branch's head is scanned again when
	// it has not moved (default 24h; negative only scans it when it moves).
	Interval time.Duration
	// Workers is how many revisions are scanned at a time (default 1);
	// Concurrency how many dependencies of one revision (default 2).
	Workers     int
	Concurrency int
	// RetryInterval is the wait before dependencies left unscanned for a
	// passing reason (a provider failure, a busy scanner, a spent budget) are
	// tried again, doubling per attempt (default 1h); MaxAttempts bounds the
	// attempts (default 5).
	RetryInterval time.Duration
	MaxAttempts   int
	// Subject is the system principal scans run as (default
	// "system:repository-scanner").
	Subject string
}

func (c ScanConfig) withDefaults() ScanConfig {
	t := true
	if c.Releases == nil {
		c.Releases = &t
	}
	if c.DefaultBranch == nil {
		c.DefaultBranch = &t
	}
	if c.Interval == 0 {
		c.Interval = 24 * time.Hour
	}
	if c.Workers <= 0 {
		c.Workers = 1
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 2
	}
	if c.RetryInterval <= 0 {
		c.RetryInterval = time.Hour
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 5
	}
	if c.Subject == "" {
		c.Subject = "system:repository-scanner"
	}
	return c
}

// ScannerStatus describes the LLM package-content scan gate as configured.
type ScannerStatus struct {
	Enabled       bool   `json:"enabled"`
	Provider      string `json:"provider,omitempty"`
	Model         string `json:"model,omitempty"`
	PromptVersion int    `json:"promptVersion,omitempty"`
	// Action is annotate, block or quarantine; FailMode open or closed.
	Action   string `json:"action,omitempty"`
	FailMode string `json:"failMode,omitempty"`
}

// ObjectScanRequest asks for the gate's reading of one cached object.
type ObjectScanRequest struct {
	// Upstream and Path (backend-relative) name the object; Accept is the
	// Accept header it was fetched with.
	Upstream string
	Path     string
	Accept   string
	// CacheKey and Digest are where the cache holds it and what it is.
	CacheKey string
	Digest   string
	// Tenant, Subject and Roles are the system principal the scan runs as.
	Tenant  string
	Subject string
	Roles   []string
}

// ObjectScanner puts objects before the LLM package-content scan gate
// (the gateway's SystemScan, in production).
type ObjectScanner interface {
	// Status describes the gate.
	Status() ScannerStatus
	// Scope reports whether the gate scans artifacts of an ecosystem fetched
	// through an upstream, and why not when it does not.
	Scope(ecosystem, upstream string) (bool, string)
	// ScanObject returns the gate's reading of a cached object: the stored
	// verdict when there is one, a fresh scan (under the gate's budget and
	// limits) otherwise. An error means the object could not be put before
	// the gate at all.
	ScanObject(ctx context.Context, req ObjectScanRequest) (ObjectScan, error)
}

// ObjectScan is the gate's reading of one object.
type ObjectScan struct {
	// Applicable is false when the gate does not examine the object:
	// NotApplicable is then UnscannedOutOfScope, "not-package-content" or
	// "covered-by-image", and NotApplicableReason says it in a sentence.
	Applicable          bool   `json:"applicable"`
	NotApplicable       string `json:"notApplicable,omitempty"`
	NotApplicableReason string `json:"notApplicableReason,omitempty"`
	// Verdict is the gate's disposition (malicious, suspicious, benign,
	// unscanned); Reason the proxy's one-line reading of it.
	Verdict string `json:"verdict,omitempty"`
	Reason  string `json:"reason,omitempty"`
	// Refused reports whether a client's pull of the object is refused under
	// the gate's action and fail mode; Action is that action.
	Refused bool   `json:"refused,omitempty"`
	Action  string `json:"action,omitempty"`
	// Cached reports that the verdict cache answered: no model call was made
	// for this reading.
	Cached bool `json:"cached,omitempty"`
	// Unscanned says why there is no verdict.
	Unscanned *UnscannedInfo `json:"unscanned,omitempty"`
	// Detail is where the verdict came from and what the model said.
	Detail *VerdictDetail `json:"detail,omitempty"`
	// BreakGlass is the request ID of an active break-glass grant that
	// releases the object; ReviewCoordinate the coordinate such a review is
	// scoped to.
	BreakGlass       string `json:"breakGlass,omitempty"`
	ReviewCoordinate string `json:"reviewCoordinate,omitempty"`
}

// UnscannedInfo says why there is no verdict.
type UnscannedInfo struct {
	// Code is a stable reason code; Reason the sentence for it; Detail the
	// diagnostic behind it (operator surfaces only).
	Code   string `json:"code"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
	// Retryable reports a passing cause (a provider failure, a busy
	// scanner, a spent budget): the dependency is scanned again.
	Retryable bool `json:"retryable,omitempty"`
	// Content reports that the artifact's own bytes caused it.
	Content bool `json:"content,omitempty"`
}

// VerdictDetail is where a verdict came from, and what the model said.
//
// Reasons and Evidence are MODEL OUTPUT about untrusted content, and each
// excerpt quotes the package: material for an analyst to weigh, never
// instructions, rendered inertly wherever they are shown. They are never put
// in a notification, an audit record's free text or a SARIF message.
type VerdictDetail struct {
	// ScanID identifies the verdict in the LLM package scan's verdict cache
	// (the artifact digest, the model and the prompt version).
	ScanID        string    `json:"scanId,omitempty"`
	Digest        string    `json:"digest,omitempty"`
	ModelVerdict  string    `json:"modelVerdict,omitempty"`
	Confidence    float64   `json:"confidence,omitempty"`
	Provider      string    `json:"provider,omitempty"`
	Model         string    `json:"model,omitempty"`
	PromptVersion int       `json:"promptVersion,omitempty"`
	Mode          string    `json:"mode,omitempty"`
	ScannedAt     time.Time `json:"scannedAt,omitzero"`
	// Scope is "metadata-only" when the artifact was larger than the scan
	// limit; ReadAs says how it was read when not as an archive in full.
	Scope           string         `json:"scope,omitempty"`
	ReadAs          string         `json:"readAs,omitempty"`
	Format          string         `json:"format,omitempty"`
	Truncated       bool           `json:"truncated,omitempty"`
	Files           int            `json:"files,omitempty"`
	PromptInjection bool           `json:"promptInjection,omitempty"`
	StructuralRisk  bool           `json:"structuralRisk,omitempty"`
	Reasons         []string       `json:"reasons,omitempty"`
	Evidence        []ScanEvidence `json:"evidence,omitempty"`
}

// ScanEvidence is one place in the package the model cited.
type ScanEvidence struct {
	Path    string `json:"path"`
	Line    int    `json:"line,omitempty"`
	Excerpt string `json:"excerpt,omitempty"`
	// Verified reports that the proxy found the quoted text there.
	Verified bool `json:"verified"`
}

// FindingsSink takes a scan's findings document: the findings layer's dedup,
// the suppression trail, the findings store and the SIEM forwarder.
type FindingsSink interface {
	RecordScanFindings(ctx context.Context, doc findings.Document)
}

// HeadSource is the half of a RefSource that knows branches: the head of the
// default branch, and any revision of the mirror.
type HeadSource interface {
	// DefaultHead returns the branch whose head is scanned — the
	// repository's Branch, or its remote's default branch — and the commit
	// that head is at in the mirror (refreshed by the last Tags).
	DefaultHead(ctx context.Context, repo Repo, cred Credential) (Head, error)
	// ResolveRevision returns the commit a revision (a tag, a branch, a
	// commit ID or prefix) names in the mirror.
	ResolveRevision(ctx context.Context, repo Repo, rev string) (string, error)
}

// Head is a branch and the commit at its head.
type Head struct {
	Branch string `json:"branch"`
	Commit string `json:"commit"`
}

// --- reports -----------------------------------------------------------------

// ScanReport is the per-repository report of one scan of one commit.
type ScanReport struct {
	Repo   string `json:"repo"`
	Tenant string `json:"tenant,omitempty"`
	Commit string `json:"commit"`
	// Kind is ScanRelease, ScanHead or ScanRevision; Ref the branch of a head
	// scan or the revision asked for; Tags the tags at the commit.
	Kind string   `json:"kind"`
	Ref  string   `json:"ref,omitempty"`
	Tags []string `json:"tags,omitempty"`
	// Branch is set when the commit was the head of the default branch when
	// it was scanned (a release can be the head too: it is then scanned
	// through its pins, and its report is the head's).
	Branch string `json:"branch,omitempty"`
	// Trigger is what started the scan; RequestedBy who asked, for a manual
	// scan.
	Trigger     string `json:"trigger"`
	RequestedBy string `json:"requestedBy,omitempty"`
	// Status is ScanComplete, ScanIncomplete or ScanFailed; Result
	// ResultMalicious, ResultSuspicious, ResultIncomplete, ResultClean or
	// ResultEmpty; Reason explains anything short of clean.
	Status string `json:"status"`
	Result string `json:"result"`
	Reason string `json:"reason,omitempty"`
	// ContainsMaliciousDependency: a dependency is judged malicious (and no
	// break-glass grant releases it).
	ContainsMaliciousDependency bool      `json:"containsMaliciousDependency"`
	StartedAt                   time.Time `json:"startedAt"`
	FinishedAt                  time.Time `json:"finishedAt"`
	// Attempts counts the runs of this scan; NextAttempt is when the
	// dependencies left unscanned for a passing reason are tried again.
	Attempts    int       `json:"attempts"`
	NextAttempt time.Time `json:"nextAttempt,omitzero"`
	// Gate is the LLM package-content scan gate the scan ran against.
	Gate ScannerStatus `json:"gate"`
	// URL is the repository's URL (no credentials), for SARIF.
	URL string `json:"url,omitempty"`
	// LockFiles are the lock files read; Truncated says why the read ended
	// early.
	LockFiles []LockFile `json:"lockFiles"`
	// Skipped are the lock files the walk found and did not read (over the
	// size limit, a symbolic link): the dependencies they pin are unscanned.
	Skipped      []lockfiles.Skipped `json:"skipped,omitempty"`
	Truncated    string              `json:"truncated,omitempty"`
	Dependencies []DependencyScan    `json:"dependencies"`
	Summary      ScanSummary         `json:"summary"`
}

// ScanSummary counts a scan's dependencies by verdict.
type ScanSummary struct {
	Dependencies int `json:"dependencies"`
	Malicious    int `json:"malicious"`
	Suspicious   int `json:"suspicious"`
	Benign       int `json:"benign"`
	Unscanned    int `json:"unscanned"`
	// Retryable counts the unscanned ones a later attempt may scan.
	Retryable int `json:"retryable,omitempty"`
	// Released counts flagged dependencies a break-glass grant releases;
	// MaliciousUnreleased the malicious ones none releases (those mark a
	// release "contains malicious dependency").
	Released            int `json:"released,omitempty"`
	MaliciousUnreleased int `json:"maliciousUnreleased,omitempty"`
	// Cached counts dependencies whose verdicts all came from the verdict
	// cache; Scanned those that needed at least one model call.
	Cached  int `json:"cached"`
	Scanned int `json:"scanned"`
	// UnscannedByCode counts the unscanned dependencies by reason.
	UnscannedByCode map[string]int `json:"unscannedByCode,omitempty"`
	// UnreadLockFiles counts the lock files that could not be read or were
	// skipped: whatever they pin is unscanned too.
	UnreadLockFiles int `json:"unreadLockFiles,omitempty"`
}

// DependencyScan is one dependency's result.
type DependencyScan struct {
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
	// Upstream is the upstream it was fetched through; Pinned reports a
	// release dependency whose pinned objects were scanned.
	Upstream string `json:"upstream,omitempty"`
	Pinned   bool   `json:"pinned,omitempty"`
	// Verdict is VerdictMalicious, VerdictSuspicious, VerdictBenign or
	// VerdictUnscanned: the worst reading of its objects. Reason is the
	// proxy's sentence for it.
	Verdict string `json:"verdict"`
	Reason  string `json:"reason,omitempty"`
	// Refused reports that a client's pull of it is refused under the gate's
	// action and fail mode.
	Refused bool `json:"refused,omitempty"`
	// Unscanned says why there is no verdict.
	Unscanned *UnscannedInfo `json:"unscanned,omitempty"`
	// Detail is the verdict's provenance and what the model said (the worst
	// object's).
	Detail *VerdictDetail `json:"detail,omitempty"`
	// Cached reports that every verdict came from the verdict cache.
	Cached bool `json:"cached,omitempty"`
	// Released is the request ID of an active break-glass grant that
	// releases the flagged dependency: its finding is suppressed and it does
	// not mark the release.
	Released string `json:"released,omitempty"`
	// Artifacts are its objects and what the gate read in each.
	Artifacts []ArtifactScan `json:"artifacts,omitempty"`
}

// ArtifactScan is one object of a dependency and the gate's reading of it.
type ArtifactScan struct {
	Role     string `json:"role,omitempty"`
	File     string `json:"file,omitempty"`
	Upstream string `json:"upstream,omitempty"`
	Path     string `json:"path,omitempty"`
	CacheKey string `json:"cacheKey,omitempty"`
	Digest   string `json:"digest,omitempty"`
	Size     int64  `json:"size,omitempty"`
	ObjectScan
	// fresh marks a reading that needed a model call.
	fresh bool
}

// Coordinate returns "type/name@version".
func (d DependencyScan) Coordinate() string {
	return d.Type + "/" + d.Name + "@" + d.Version
}

// flagged reports whether the gate flags the dependency.
func (d DependencyScan) flagged() bool {
	return d.Verdict == VerdictMalicious || d.Verdict == VerdictSuspicious
}

// HeadState is what the scanner knows of a repository's default branch.
type HeadState struct {
	Repo      string    `json:"repo"`
	Branch    string    `json:"branch,omitempty"`
	Commit    string    `json:"commit,omitempty"`
	CheckedAt time.Time `json:"checkedAt,omitzero"`
	LastError string    `json:"lastError,omitempty"`
	// ScannedCommit is the head commit last scanned, ScannedAt when.
	ScannedCommit string    `json:"scannedCommit,omitempty"`
	ScannedAt     time.Time `json:"scannedAt,omitzero"`
	// Notified are the flagged dependencies of the head already announced
	// ("verdict|coordinate|digest"): a malicious dependency that stays in the
	// branch is announced once, not at every push.
	Notified []string `json:"notified,omitempty"`
}

// ScanTicket is the answer to a scan request.
type ScanTicket struct {
	Repo   string `json:"repo"`
	Commit string `json:"commit"`
	Kind   string `json:"kind"`
	Ref    string `json:"ref,omitempty"`
	// Status is "queued", "running" (already being scanned) or "deferred"
	// (a release still being pinned: it is scanned once pinned).
	Status string `json:"status"`
}

// --- objects ---------------------------------------------------------------

func scanObject(repo, commit string) string        { return "scans/" + repo + "/" + commit }
func scanRequestObject(repo, commit string) string { return "scanreqs/" + repo + "/" + commit }
func headObject(repo string) string                { return "heads/" + repo }

// scanRequest is a durable request for a scan: written by whichever replica
// asked, run by the leader, removed once the scan ran.
type scanRequest struct {
	Repo    string    `json:"repo"`
	Commit  string    `json:"commit"`
	Kind    string    `json:"kind"`
	Ref     string    `json:"ref,omitempty"`
	Trigger string    `json:"trigger"`
	By      string    `json:"by,omitempty"`
	At      time.Time `json:"at"`
}

// scanJob is one queued scan.
type scanJob struct {
	repo, commit, kind, ref, trigger, by string
}

func (j scanJob) key() string { return j.repo + "/" + j.commit }

func scanJobLock(repo, commit string) string { return "scanjob\x00" + repo + "\x00" + commit }
func headLock(repo string) string            { return "head\x00" + repo }

// --- switches ----------------------------------------------------------------

// scansEnabled reports whether dependency scans run at all.
func (s *Service) scansEnabled() bool {
	return s.cfg.Scan.Enabled && s.opts.Scans != nil && s.opts.Scans.Status().Enabled
}

func (s *Service) releaseScans() bool { return s.scansEnabled() && *s.cfg.Scan.Releases }

func (s *Service) headScans() bool { return s.scansEnabled() && *s.cfg.Scan.DefaultBranch }

// defersLLM reports whether the release pinner leaves the LLM gate's refusals
// to the release scan: it then pins the bytes of a dependency the gate refuses
// (they are kept for forensics, never served while the gate refuses them) and
// the scan marks the release and reports it.
func (s *Service) defersLLM() bool { return s.releaseScans() }

// ScanStatus describes the dependency scans' gate, and whether they run.
func (s *Service) ScanStatus() (ScannerStatus, bool) {
	if s.opts.Scans == nil {
		return ScannerStatus{}, false
	}
	return s.opts.Scans.Status(), s.scansEnabled()
}

// --- queue -------------------------------------------------------------------

// enqueueScan records a scan request durably and, on the leader, queues it.
// It reports whether the scan was queued here (a scan of the commit already
// queued, a full queue or another replica leading leave it to the next sweep).
func (s *Service) enqueueScan(ctx context.Context, j scanJob) bool {
	req := scanRequest{Repo: j.repo, Commit: j.commit, Kind: j.kind, Ref: j.ref, Trigger: j.trigger, By: j.by, At: s.now().UTC()}
	if data, err := json.Marshal(req); err == nil {
		if err := s.st.Put(ctx, scanRequestObject(j.repo, j.commit), data); err != nil {
			s.log.Warn("recording a scan request failed", "repo", j.repo, "commit", j.commit, "error", err)
		}
	}
	if !s.isLeader() {
		return false
	}
	return s.pushScan(j)
}

func (s *Service) pushScan(j scanJob) bool {
	s.scanQMu.Lock()
	defer s.scanQMu.Unlock()
	if s.scanRunning[j.key()] {
		// Asked again while being scanned (a re-pin pinned more, a push):
		// scanned once more when the running scan ends — it may have read
		// what this request is about too late.
		s.scanAgain[j.key()] = j
		return true
	}
	if s.scanQueued[j.key()] {
		return false
	}
	select {
	case s.scanQ <- j:
		s.scanQueued[j.key()] = true
		s.metrics().setScanQueue(len(s.scanQueued))
		return true
	default:
		return false
	}
}

// pushScanIdle queues a scan unless the commit is queued or being scanned
// already: the sweep's way, which must not have a running scan run again just
// because its request is still recorded.
func (s *Service) pushScanIdle(j scanJob) bool {
	s.scanQMu.Lock()
	running := s.scanRunning[j.key()]
	s.scanQMu.Unlock()
	if running {
		return false
	}
	return s.pushScan(j)
}

func (s *Service) scanDequeued(j scanJob) {
	s.scanQMu.Lock()
	delete(s.scanQueued, j.key())
	n := len(s.scanQueued)
	s.scanQMu.Unlock()
	s.metrics().setScanQueue(n)
}

func (s *Service) scanQueuedOrRunning(repo, commit string) (queued, running bool) {
	k := repo + "/" + commit
	s.scanQMu.Lock()
	defer s.scanQMu.Unlock()
	return s.scanQueued[k], s.scanRunning[k]
}

func (s *Service) scanWorker() {
	for {
		select {
		case <-s.runCtx.Done():
			return
		case j := <-s.scanQ:
			if !s.isLeader() {
				// Another replica scans; the request is in the shared state.
				s.scanDequeued(j)
				continue
			}
			s.scanQMu.Lock()
			s.scanRunning[j.key()] = true
			s.scanQMu.Unlock()
			started := s.now().UTC()
			err := s.runScan(s.runCtx, j)
			s.scanQMu.Lock()
			delete(s.scanRunning, j.key())
			again, rerun := s.scanAgain[j.key()]
			delete(s.scanAgain, j.key())
			s.scanQMu.Unlock()
			switch {
			case errors.Is(err, errNotLeader), errors.Is(err, context.Canceled), errors.Is(err, errScanDeferred):
				// Resumed by whoever leads next, or once the release is
				// pinned: the request stays recorded, the sweep queues it.
			case err != nil:
				s.log.Error("scanning a repository's dependencies failed", "repo", j.repo, "commit", j.commit, "error", err)
				s.dropScanRequest(j, started)
			default:
				s.dropScanRequest(j, started)
			}
			s.scanDequeued(j)
			if rerun && s.runCtx.Err() == nil {
				s.pushScan(again)
			}
		}
	}
}

// errScanDeferred is a scan of a release that is still being pinned: it runs
// once the release is pinned.
var errScanDeferred = errors.New("repos: the release is being pinned; it is scanned once pinned")

// dropScanRequest removes a request once a scan that started after it ran. A
// request made while the scan ran (by another replica, say) stays: the sweep
// queues the commit once more.
func (s *Service) dropScanRequest(j scanJob, started time.Time) {
	ctx := context.WithoutCancel(s.runCtx)
	data, err := s.st.Get(ctx, scanRequestObject(j.repo, j.commit))
	if err != nil {
		return
	}
	var req scanRequest
	if json.Unmarshal(data, &req) == nil && req.At.After(started) {
		return
	}
	_ = s.st.Delete(ctx, scanRequestObject(j.repo, j.commit))
}

// queueReleaseScan queues the scan of a release.
func (s *Service) queueReleaseScan(ctx context.Context, repo Repo, commit, trigger, by string) bool {
	if !s.releaseScans() && trigger != TriggerManual {
		return false
	}
	return s.enqueueScan(ctx, scanJob{repo: repo.Name, commit: commit, kind: ScanRelease, trigger: trigger, by: by})
}

// sweepScans queues what is due: recorded requests not queued yet (another
// replica's, or a previous run's), retries of incomplete scans, releases never
// scanned (or scanned under another model or prompt), and the default
// branch's scheduled scan.
func (s *Service) sweepScans(ctx context.Context) {
	if !s.scansEnabled() {
		return
	}
	// Recorded requests.
	if names, err := s.st.List(ctx, "scanreqs/"); err == nil {
		for _, n := range names {
			data, err := s.st.Get(ctx, n)
			if err != nil {
				continue
			}
			var req scanRequest
			if json.Unmarshal(data, &req) != nil || !ValidName(req.Repo) || !validCommit(req.Commit) || scanRequestObject(req.Repo, req.Commit) != n {
				_ = s.st.Delete(ctx, n)
				continue
			}
			if reg, ok := s.registration("", req.Repo); !ok || reg.Removed {
				continue
			}
			s.pushScanIdle(scanJob{repo: req.Repo, commit: req.Commit, kind: req.Kind, ref: req.Ref, trigger: req.Trigger, by: req.By})
		}
	}
	now := s.now()
	st := s.opts.Scans.Status()
	reports := s.scanHeaders("")
	byCommit := map[string]ScanReport{}
	for _, r := range reports {
		byCommit[r.Repo+"/"+r.Commit] = r
		reg, ok := s.registration("", r.Repo)
		if !ok || reg.Removed {
			continue
		}
		// Retries of what a passing cause left unscanned — not of a head the
		// branch has moved on from: that commit is nobody's concern now.
		if r.Kind == ScanHead {
			if hs := s.headState(ctx, r.Repo); hs.Commit != "" && hs.Commit != r.Commit {
				continue
			}
		}
		if r.Summary.Retryable > 0 && r.Attempts < s.cfg.Scan.MaxAttempts && !r.NextAttempt.IsZero() && !now.Before(r.NextAttempt) {
			s.pushScanIdle(scanJob{repo: r.Repo, commit: r.Commit, kind: r.Kind, ref: r.Ref, trigger: TriggerRetry})
		}
	}
	if s.releaseScans() {
		for _, m := range s.manifestHeads("") {
			if ctx.Err() != nil {
				return
			}
			if m.Status == ReleasePending {
				continue // scanned once pinned
			}
			reg, ok := s.registration("", m.Repo)
			if !ok || reg.Removed {
				continue
			}
			r, scanned := byCommit[m.Repo+"/"+m.Commit]
			switch {
			case !scanned:
				s.pushScanIdle(scanJob{repo: m.Repo, commit: m.Commit, kind: ScanRelease, trigger: TriggerRelease})
			case r.Kind == ScanRelease && (r.Gate.Model != st.Model || r.Gate.PromptVersion != st.PromptVersion):
				// A new model or prompt reads every package anew: so does
				// the release scan (the verdict cache keys on both).
				s.pushScanIdle(scanJob{repo: m.Repo, commit: m.Commit, kind: ScanRelease, trigger: TriggerModelChange})
			case m.UpdatedAt.After(r.StartedAt) && !m.UpdatedAt.After(now):
				// A pinning attempt finished after the scan read the
				// manifest: what it pinned has not been scanned.
				s.pushScanIdle(scanJob{repo: m.Repo, commit: m.Commit, kind: ScanRelease, trigger: TriggerRelease})
			case r.Kind != ScanRelease:
				// Scanned as a revision before it was a pinned release: its
				// pinned objects are scanned now.
				s.pushScanIdle(scanJob{repo: m.Repo, commit: m.Commit, kind: ScanRelease, trigger: TriggerRelease})
			}
		}
	}
	if s.headScans() && s.cfg.Scan.Interval > 0 {
		for _, r := range s.tracked() {
			hs := s.headState(ctx, r.Name)
			if hs.Commit == "" || !validCommit(hs.Commit) {
				continue
			}
			if hs.ScannedCommit != hs.Commit || now.Sub(hs.ScannedAt) >= s.cfg.Scan.Interval {
				s.pushScanIdle(scanJob{repo: r.Name, commit: hs.Commit, kind: ScanHead, ref: hs.Branch, trigger: TriggerSchedule})
			}
		}
	}
}

// --- the default branch -------------------------------------------------------

// headState returns the scanner's state of a repository's default branch.
func (s *Service) headState(ctx context.Context, repo string) HeadState {
	s.mu.RLock()
	hs := s.headStates[repo]
	s.mu.RUnlock()
	if hs != nil {
		return cloneHead(*hs)
	}
	out := HeadState{Repo: repo}
	if data, err := s.st.Get(ctx, headObject(repo)); err == nil {
		var stored HeadState
		if json.Unmarshal(data, &stored) == nil && stored.Repo == repo {
			out = stored
		}
	}
	s.mu.Lock()
	if s.headStates[repo] == nil {
		cp := cloneHead(out)
		s.headStates[repo] = &cp
	}
	s.mu.Unlock()
	return out
}

func cloneHead(h HeadState) HeadState {
	h.Notified = append([]string(nil), h.Notified...)
	return h
}

// updateHead changes a repository's head state under its lock and stores it.
func (s *Service) updateHead(ctx context.Context, repo string, fn func(*HeadState)) HeadState {
	unlock := s.locks.lock(headLock(repo))
	defer unlock()
	hs := s.headState(ctx, repo)
	fn(&hs)
	hs.Repo = repo
	if len(hs.Notified) > maxNotified {
		hs.Notified = hs.Notified[len(hs.Notified)-maxNotified:]
	}
	if data, err := json.Marshal(&hs); err == nil {
		if err := s.st.Put(ctx, headObject(repo), data); err != nil {
			s.log.Warn("storing the default branch's state failed", "repo", repo, "error", err)
		}
	}
	cp := cloneHead(hs)
	s.mu.Lock()
	s.headStates[repo] = &cp
	s.mu.Unlock()
	return hs
}

// maxNotified bounds the flagged dependencies remembered per default branch.
const maxNotified = 2048

// checkHead reads the default branch's head after a sync refreshed the mirror
// and queues its scan when it moved, when its scheduled rescan is due, or when
// it was never scanned. It runs under the repository's lock (sync).
func (s *Service) checkHead(ctx context.Context, repo Repo, cred Credential, syncTrigger string) {
	if !s.headScans() {
		// Not followed: the head is read only when a scan of it is asked
		// for (refreshHead), never at every poll.
		return
	}
	hs, err := s.refreshHead(ctx, repo, cred)
	if err != nil {
		return
	}
	trigger := TriggerSchedule
	switch syncTrigger {
	case "webhook", TriggerPush:
		trigger = TriggerPush
	case TriggerManual:
		trigger = TriggerManual
	}
	moved := hs.ScannedCommit != hs.Commit
	due := s.cfg.Scan.Interval > 0 && s.now().Sub(hs.ScannedAt) >= s.cfg.Scan.Interval
	if moved || due {
		s.enqueueScan(ctx, scanJob{repo: repo.Name, commit: hs.Commit, kind: ScanHead, ref: hs.Branch, trigger: trigger})
	}
}

// refreshHead reads the default branch's head from the mirror (as the last
// refresh left it) into the head state.
func (s *Service) refreshHead(ctx context.Context, repo Repo, cred Credential) (HeadState, error) {
	hsrc, ok := s.opts.Refs.(HeadSource)
	if !ok || !s.scansEnabled() {
		return HeadState{}, errors.New("repos: the default branch cannot be read")
	}
	head, err := hsrc.DefaultHead(ctx, repo, cred)
	now := s.now().UTC()
	hs := s.updateHead(ctx, repo.Name, func(h *HeadState) {
		h.CheckedAt = now
		if err != nil {
			h.LastError = err.Error()
			return
		}
		h.LastError = ""
		h.Branch, h.Commit = head.Branch, head.Commit
	})
	if err != nil {
		s.log.Warn("reading the default branch's head failed", "repo", repo.Name, "error", err)
		return hs, err
	}
	if !validCommit(hs.Commit) {
		return hs, errors.New("repos: the default branch's head is not a commit")
	}
	return hs, nil
}

// --- on request ---------------------------------------------------------------

// revRE is the shape of a revision a scan may be asked for: a tag, a branch, a
// commit ID or prefix — nothing git could read as an option or an expression.
var revRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/+-]{0,199}$`)

// ScanDisabledError is a scan request while the scans are off.
type ScanDisabledError struct{ Msg string }

func (e *ScanDisabledError) Error() string { return e.Msg }

// Scan queues a scan of a repository's revision on request: rev is a tag, a
// branch, a commit ID (or a prefix of one), or empty for the default branch's
// head, which is fetched first. A tagged release is scanned through its pinned
// objects; any other revision's dependencies are fetched through the proxy.
func (s *Service) Scan(ctx context.Context, tenant, name, rev, by string) (ScanTicket, error) {
	reg, ok := s.registration(tenant, name)
	if !ok || reg.Removed {
		return ScanTicket{}, ErrNotFound
	}
	if !s.scansEnabled() {
		return ScanTicket{}, &ScanDisabledError{Msg: "dependency scans are off: they need llmPackageScan.enabled and repositories.scan.enabled"}
	}
	rev = strings.TrimSpace(rev)
	if rev != "" && rev != "HEAD" && (!revRE.MatchString(rev) || strings.Contains(rev, "..")) {
		return ScanTicket{}, &ValidationError{Err: fmt.Errorf("%q is not a tag, branch or commit", rev)}
	}
	job := scanJob{repo: name, trigger: TriggerManual, by: by}
	if rev == "" || rev == "HEAD" {
		// The head as the remote has it now.
		if _, err := s.Sync(ctx, name, TriggerManual); err != nil {
			s.log.Warn("refreshing the repository before scanning its head failed; the head last seen is scanned", "repo", name, "error", err)
		}
		if !s.headScans() {
			// The sync does not read the head when it is not followed.
			if cred, err := s.credential(ctx, reg.Repo); err == nil {
				_, _ = s.refreshHead(ctx, reg.Repo, cred)
			}
		}
		hs := s.headState(ctx, name)
		if !validCommit(hs.Commit) {
			msg := "the default branch's head is not known yet"
			if hs.LastError != "" {
				msg += ": " + hs.LastError
			}
			return ScanTicket{}, &ConflictError{Msg: msg}
		}
		job.commit, job.kind, job.ref = hs.Commit, ScanHead, hs.Branch
	} else {
		commit, err := s.resolveRev(ctx, reg.Repo, rev)
		if err != nil {
			return ScanTicket{}, err
		}
		job.commit, job.kind, job.ref = commit, ScanRevision, rev
		if hs := s.headState(ctx, name); hs.Commit == commit && (rev == hs.Branch || rev == commit) {
			job.kind, job.ref = ScanHead, hs.Branch
		}
	}
	ticket := ScanTicket{Repo: name, Commit: job.commit, Ref: job.ref, Status: "queued"}
	if m, err := s.readManifest(ctx, name, job.commit); err == nil {
		job.kind = ScanRelease
		if m.Status == ReleasePending {
			// Recorded: the sweep queues it until the release is pinned.
			ticket.Kind, ticket.Status = ScanRelease, "deferred"
			s.enqueueScan(ctx, job)
			return ticket, nil
		}
	}
	ticket.Kind = job.kind
	if queued, running := s.scanQueuedOrRunning(name, job.commit); running {
		ticket.Status = "running"
	} else if queued {
		ticket.Status = "queued"
	}
	s.enqueueScan(ctx, job)
	return ticket, nil
}

// resolveRev returns the commit a revision names.
func (s *Service) resolveRev(ctx context.Context, repo Repo, rev string) (string, error) {
	if live, err := s.liveSnapshot(ctx, repo.Name); err == nil {
		if t, ok := live.Tags[rev]; ok && validCommit(t.Commit) {
			return t.Commit, nil
		}
	}
	if hsrc, ok := s.opts.Refs.(HeadSource); ok {
		commit, err := hsrc.ResolveRevision(ctx, repo, rev)
		if err == nil && validCommit(commit) {
			return commit, nil
		}
		if err != nil && !strings.Contains(err.Error(), "unknown revision") {
			return "", &ValidationError{Err: fmt.Errorf("revision %q: %v", rev, err)}
		}
	}
	lower := strings.ToLower(rev)
	if validCommit(lower) {
		if _, err := s.readManifest(ctx, repo.Name, lower); err == nil {
			return lower, nil
		}
	}
	return "", &ValidationError{Err: fmt.Errorf("revision %q is not a tag, branch or commit of %s", rev, repo.Name)}
}

// --- stored reports -----------------------------------------------------------

// loadScanReports indexes the stored reports.
func (s *Service) loadScanReports(ctx context.Context) error {
	names, err := s.st.List(ctx, "scans/")
	if err != nil {
		return err
	}
	for _, n := range names {
		data, err := s.st.Get(ctx, n)
		if err == nil {
			var rep *ScanReport
			if rep, err = parseScanReport(n, data); err == nil {
				s.indexScanReport(n, rep)
				continue
			}
		}
		// A report is a record, not state the registry needs to run: one
		// that cannot be read is rescanned (a release) or replaced (a head).
		s.log.Error("dependency scan report unreadable", "object", n, "error", err)
	}
	return nil
}

// refreshScanReports re-reads the reports another replica wrote.
func (s *Service) refreshScanReports(ctx context.Context) error {
	names, err := s.st.List(ctx, "scans/")
	if err != nil {
		return err
	}
	vs, _ := s.st.(versionedStore)
	for _, n := range names {
		stamp := ""
		if vs != nil {
			if v, err := vs.Version(ctx, n); err == nil {
				s.mu.RLock()
				seen := s.scanStamps[n]
				s.mu.RUnlock()
				if v == seen {
					continue
				}
				stamp = v
			}
		}
		data, err := s.st.Get(ctx, n)
		if err != nil {
			continue
		}
		if stamp != "" {
			// What was read is at least as new as the stamp.
			s.mu.Lock()
			s.scanStamps[n] = stamp
			s.mu.Unlock()
		}
		if rep, err := parseScanReport(n, data); err == nil {
			s.indexScanReport(n, rep)
		}
	}
	// Another replica's view of the default branches is re-read when next
	// needed.
	s.mu.Lock()
	s.headStates = map[string]*HeadState{}
	s.mu.Unlock()
	s.refreshScanMetrics()
	return nil
}

func parseScanReport(name string, data []byte) (*ScanReport, error) {
	var rep ScanReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, err
	}
	if !ValidName(rep.Repo) || !validCommit(rep.Commit) || scanObject(rep.Repo, rep.Commit) != name {
		return nil, fmt.Errorf("repos: %s does not hold the scan report its name says", name)
	}
	return &rep, nil
}

// maxFactsPerReport bounds the query facts one report contributes.
const maxFactsPerReport = 10000

// indexScanReport keeps a report's header for listings, and the dependencies
// it flags or could not examine for the query API (benign ones are not kept:
// the query model is rebuilt per query and must not read the reports).
func (s *Service) indexScanReport(name string, rep *ScanReport) {
	head := *rep
	head.Dependencies, head.LockFiles = nil, nil
	var facts []ScanFact
	for _, d := range rep.Dependencies {
		if rep.Kind == ScanRevision || d.Verdict == VerdictBenign || len(facts) >= maxFactsPerReport {
			continue // a revision scanned on request is nobody's current state
		}
		f := ScanFact{Tenant: rep.Tenant, Ecosystem: d.Type, Name: d.Name, Version: d.Version, Repo: rep.Repo,
			Commit: rep.Commit, Kind: rep.Kind, Verdict: d.Verdict, ScannedAt: rep.FinishedAt}
		if d.Detail != nil {
			f.Digest, f.Model = d.Detail.Digest, d.Detail.Model
			if !d.Detail.ScannedAt.IsZero() {
				f.ScannedAt = d.Detail.ScannedAt
			}
		}
		facts = append(facts, f)
	}
	s.mu.Lock()
	s.scanHeads[name] = head
	if len(facts) > 0 {
		s.scanFacts[name] = facts
	} else {
		delete(s.scanFacts, name)
	}
	s.mu.Unlock()
}

// scanHeaders returns the stored reports' headers (one repository's, or every
// one's), newest first.
func (s *Service) scanHeaders(repo string) []ScanReport {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []ScanReport
	for _, r := range s.scanHeads {
		if repo == "" || r.Repo == repo {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].FinishedAt.Equal(out[j].FinishedAt) {
			return out[i].FinishedAt.After(out[j].FinishedAt)
		}
		return out[i].Commit < out[j].Commit
	})
	return out
}

// readScanReport returns a stored report, or ErrNotFound.
func (s *Service) readScanReport(ctx context.Context, repo, commit string) (*ScanReport, error) {
	n := scanObject(repo, commit)
	data, err := s.st.Get(ctx, n)
	if err != nil {
		return nil, err
	}
	return parseScanReport(n, data)
}

// writeScanReport stores a report and indexes it.
func (s *Service) writeScanReport(ctx context.Context, rep *ScanReport) error {
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	n := scanObject(rep.Repo, rep.Commit)
	if err := s.st.Put(ctx, n, data); err != nil {
		return err
	}
	s.indexScanReport(n, rep)
	return nil
}

// --- metrics -----------------------------------------------------------------

// refreshScanMetrics publishes the malicious dependencies of each repository's
// current scans: the head's and every release's.
func (s *Service) refreshScanMetrics() {
	m := s.metrics()
	if m == nil {
		return
	}
	ctx := context.Background()
	heads := map[string]string{}
	malicious := map[string]int{}
	for _, r := range s.tracked() {
		heads[r.Name] = s.headReportCommit(ctx, r.Name)
		malicious[r.Name] = 0
	}
	for _, h := range s.scanHeaders("") {
		if h.Kind != ScanRelease && heads[h.Repo] != h.Commit {
			continue // an older head, or a revision scanned on request
		}
		malicious[h.Repo] += h.Summary.MaliciousUnreleased
	}
	m.setMaliciousDependencies(malicious)
}

// Lock order of a scan job: its scan-job lock, then a manifest lock
// (markRelease) or the head lock (updateHead) — one of them at a time. A scan
// job never takes a repository's lock; a sync, which holds that lock, takes the
// head lock after it (checkHead), never the reverse.

// maxKeptReports is how many reports of revisions that are not releases — old
// heads, revisions scanned on request — are kept per repository, besides the
// current head's. Release reports are kept as long as their releases.
const maxKeptReports = 20

// pruneScanReports deletes a repository's oldest reports of revisions that
// are neither a release nor the default branch's head.
func (s *Service) pruneScanReports(ctx context.Context, repo string) {
	hs := s.headState(ctx, repo)
	kept := 0
	for _, h := range s.scanHeaders(repo) { // newest first
		if h.Kind == ScanRelease || h.Commit == hs.Commit || h.Commit == hs.ScannedCommit {
			continue
		}
		if kept < maxKeptReports {
			kept++
			continue
		}
		n := scanObject(h.Repo, h.Commit)
		if err := s.st.Delete(ctx, n); err != nil {
			s.log.Warn("pruning an old dependency scan report failed", "object", n, "error", err)
			continue
		}
		s.mu.Lock()
		delete(s.scanHeads, n)
		delete(s.scanFacts, n)
		delete(s.scanStamps, n)
		s.mu.Unlock()
	}
}
