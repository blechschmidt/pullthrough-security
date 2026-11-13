package repos

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/repos/locate"
)

// runScan scans one revision of a repository and records the report.
func (s *Service) runScan(ctx context.Context, j scanJob) error {
	reg, ok := s.registration("", j.repo)
	if !ok {
		return ErrNotFound
	}
	if !s.scansEnabled() {
		return nil
	}
	unlock := s.locks.lock(scanJobLock(j.repo, j.commit))
	defer unlock()
	repo := reg.Repo
	gate := s.opts.Scans.Status()
	start := s.now().UTC()
	prev, _ := s.readScanReport(ctx, j.repo, j.commit)

	rep := &ScanReport{
		Repo: repo.Name, Tenant: repo.Tenant, Commit: j.commit, Kind: j.kind, Ref: j.ref,
		Trigger: j.trigger, RequestedBy: j.by, StartedAt: start, Gate: gate, URL: redactURL(repo.URL), Attempts: 1,
	}
	// A retry scans again only what a passing cause left unscanned; what has
	// a verdict (or an unscanned reason that will not pass) is kept.
	var prior map[string]DependencyScan
	if prev != nil && j.trigger == TriggerRetry && prev.Kind == j.kind {
		rep.Attempts = prev.Attempts + 1
		if prev.Gate.Model == gate.Model && prev.Gate.PromptVersion == gate.PromptVersion {
			prior = map[string]DependencyScan{}
			for _, d := range prev.Dependencies {
				if d.Unscanned == nil || !d.Unscanned.Retryable {
					prior[scanKey(d)] = d
				}
			}
		}
	}

	// A pinned release is scanned through its pins, whatever asked for the
	// scan: its bytes are in the cache, and they are what the release ships.
	m, merr := s.readManifest(ctx, repo.Name, j.commit)
	switch {
	case merr == nil && m.Status != ReleasePending:
		rep.Kind = ScanRelease
	case merr == nil && (j.kind == ScanRelease || s.releaseScans()):
		// Being pinned: scanned once pinned (the request stays recorded).
		return errScanDeferred
	case merr != nil && j.kind == ScanRelease:
		rep.Status, rep.Result = ScanFailed, ResultIncomplete
		rep.Reason = "there is no release manifest of " + short(j.commit) + ": " + merr.Error()
		s.finishScan(ctx, repo, rep, prev)
		return nil
	}
	hs := s.headState(ctx, repo.Name)
	if rep.Kind == ScanHead && hs.Commit != "" && hs.Commit != j.commit {
		// The branch has moved on since this scan was asked for: its new head
		// is scanned instead. Asked for by name, the commit is scanned as the
		// revision it now is.
		if j.trigger != TriggerManual {
			return nil
		}
		rep.Kind = ScanRevision
	}
	switch {
	case hs.Commit == j.commit && hs.Branch != "":
		rep.Branch = hs.Branch
	case rep.Kind == ScanHead && hs.Commit == "":
		rep.Branch = j.ref
	}
	if rep.Kind == ScanRelease && rep.Ref == "" {
		rep.Ref = rep.Branch
	}

	type work struct {
		dep     Dependency
		release bool
	}
	var items []work
	switch rep.Kind {
	case ScanRelease:
		rep.Tags = append([]string(nil), m.Tags...)
		rep.LockFiles, rep.Truncated, rep.Skipped = m.LockFiles, m.Truncated, m.Skipped
		for _, d := range m.Dependencies {
			items = append(items, work{dep: d, release: true})
		}
		if len(m.Dependencies) == 0 && m.Status == ReleaseFailed {
			rep.Status, rep.Result = ScanFailed, ResultIncomplete
			rep.Reason = "the release's lock files could not be read: " + m.Reason
			s.finishScan(ctx, repo, rep, prev)
			return nil
		}
	default:
		tmp := &Manifest{Repo: repo.Name, Commit: j.commit}
		if err := s.readLockfiles(ctx, repo, tmp); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			rep.Status, rep.Result = ScanFailed, ResultIncomplete
			rep.Reason = "reading the lock files at " + short(j.commit) + ": " + err.Error()
			s.finishScan(ctx, repo, rep, prev)
			return nil
		}
		rep.LockFiles, rep.Truncated, rep.Skipped = tmp.LockFiles, tmp.Truncated, tmp.Skipped
		if tm, _, err := s.tagsOf(ctx, repo.Name); err == nil {
			rep.Tags = tm.current[j.commit]
		}
		for _, d := range tmp.Dependencies {
			items = append(items, work{dep: d})
		}
	}

	results := make([]DependencyScan, len(items))
	env := s.scanLocateEnv(repo)
	sem := make(chan struct{}, s.cfg.Scan.Concurrency)
	var wg sync.WaitGroup
	lostLead := false
	for i, it := range items {
		if ctx.Err() != nil {
			break
		}
		if !s.isLeader() {
			lostLead = true
			break
		}
		if p, ok := prior[scanKey(fromDependency(it.dep))]; ok {
			p.Files = it.dep.Files
			results[i] = p
			continue
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(i int, it work) {
			defer wg.Done()
			defer func() { <-sem }()
			if it.release {
				results[i] = s.scanReleaseDependency(ctx, repo, it.dep)
			} else {
				results[i] = s.scanRevisionDependency(ctx, repo, env, it.dep)
			}
		}(i, it)
	}
	wg.Wait()
	if lostLead {
		return errNotLeader
	}
	if ctx.Err() != nil {
		// Shutting down: the request stays recorded and is run after the
		// restart.
		return ctx.Err()
	}
	rep.Dependencies = results
	settleScan(rep)
	s.finishScan(ctx, repo, rep, prev)
	return nil
}

// scanKey identifies a dependency within a report.
func scanKey(d DependencyScan) string {
	return strings.Join([]string{d.Type, d.Name, d.Version, d.ID, d.Source, d.Registry, d.Revision}, "\x00")
}

// fromDependency starts a dependency's result from its manifest record.
func fromDependency(d Dependency) DependencyScan {
	return DependencyScan{
		Type: d.Type, Name: d.Name, Version: d.Version, ID: d.ID, Source: d.Source, Registry: d.Registry,
		Revision: d.Revision, Dev: d.Dev, Files: append([]string(nil), d.Files...), Upstream: d.Upstream,
	}
}

// scanLocateEnv is the locating environment of a scan: documents are read as
// the scanner, and the LLM gate's refusals of them are the scan's to report.
func (s *Service) scanLocateEnv(repo Repo) locate.Env {
	env := s.locateEnv(repo)
	env.Fetch = documentFetcher{s: s, tenant: repo.Tenant, roles: s.rolesFor(repo), deferLLM: true, subject: s.cfg.Scan.Subject}
	return env
}

// --- one dependency -----------------------------------------------------------

// scanReleaseDependency scans a release dependency through its pinned objects.
// An object another gate refused is not pinned; what the LLM gate read in its
// bytes before that refusal, if it flagged them, is reported all the same.
func (s *Service) scanReleaseDependency(ctx context.Context, repo Repo, d Dependency) DependencyScan {
	ds := fromDependency(d)
	var arts []ArtifactScan
	pinned, read := 0, 0
	for _, o := range d.Objects {
		switch {
		case o.Status == StatusPinned && o.CacheKey != "":
			arts = append(arts, s.scanCachedObject(ctx, repo, d.Type, o))
			pinned++
		case o.LLM != nil && (o.LLM.Verdict == VerdictMalicious || o.LLM.Verdict == VerdictSuspicious):
			a := ArtifactScan{Role: o.Role, File: o.File, Upstream: o.Upstream, Path: o.Path, Digest: o.LLM.Digest}
			a.apply(o.LLM.scanOf(), false)
			arts = append(arts, a)
			read++
		}
	}
	if pinned+read == 0 {
		ds.Verdict = VerdictUnscanned
		ds.Unscanned = unscannedForStatus(d)
		ds.Reason = ds.Unscanned.Reason
		return ds
	}
	ds.Pinned = d.Status == StatusPinned
	// A dependency only partly pinned: what is not pinned was not scanned
	// (unless the reading of its bytes flagged it, above).
	for _, o := range d.Objects {
		if o.Status == StatusPinned || o.Optional || o.Status == StatusSkipped {
			continue
		}
		if o.LLM != nil && (o.LLM.Verdict == VerdictMalicious || o.LLM.Verdict == VerdictSuspicious) {
			continue
		}
		a := ArtifactScan{Role: o.Role, File: o.File, Upstream: o.Upstream, Path: o.Path, Digest: o.Digest}
		a.markUnscanned(unscannedForObject(o))
		arts = append(arts, a)
	}
	aggregate(&ds, arts)
	return ds
}

// scanCachedObject puts one cached object before the gate.
func (s *Service) scanCachedObject(ctx context.Context, repo Repo, eco string, o Object) ArtifactScan {
	a := ArtifactScan{Role: o.Role, File: o.File, Upstream: o.Upstream, Path: o.Path, CacheKey: o.CacheKey, Digest: o.Digest, Size: o.Size}
	if ok, reason := s.opts.Scans.Scope(eco, o.Upstream); !ok {
		a.NotApplicable, a.NotApplicableReason = UnscannedOutOfScope, reason
		return a
	}
	res, err := s.opts.Scans.ScanObject(ctx, ObjectScanRequest{
		Upstream: o.Upstream, Path: strings.TrimPrefix(o.Path, "/v1/"+o.Upstream), Accept: acceptFor(o.Role),
		CacheKey: o.CacheKey, Digest: o.Digest,
		Tenant: repo.Tenant, Subject: s.cfg.Scan.Subject, Roles: s.rolesFor(repo),
	})
	if err != nil {
		a.markUnscanned(&UnscannedInfo{Code: UnscannedScanFailed, Retryable: true,
			Reason: "the object could not be put before the scan", Detail: err.Error()})
		return a
	}
	a.apply(res, !res.Cached)
	return a
}

// acceptFor is the Accept header an object of a role was fetched with.
func acceptFor(role string) string {
	if role == "manifest" || role == "index" {
		return "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"
	}
	return ""
}

// scanRevisionDependency fetches a dependency's objects through the proxy (the
// gate judges them on the way) and reads the verdicts.
func (s *Service) scanRevisionDependency(ctx context.Context, repo Repo, env locate.Env, d Dependency) DependencyScan {
	ds := fromDependency(d)
	plan, err := locate.Locate(ctx, env, d.lock)
	if err != nil {
		var refused *locate.RefusedError
		u := &UnscannedInfo{Code: UnscannedFetchFailed, Reason: "it could not be located: " + err.Error(), Retryable: true}
		switch {
		case locate.IsUnsupported(err):
			u = &UnscannedInfo{Code: UnscannedUnsupported, Reason: "it cannot be fetched through the proxy: " + err.Error()}
		case errors.As(err, &refused):
			u = &UnscannedInfo{Code: UnscannedFetchRefused, Reason: "an admission gate refused it: " + err.Error()}
		}
		ds.Verdict, ds.Unscanned, ds.Reason = VerdictUnscanned, u, u.Reason
		return ds
	}
	ds.Upstream = plan.Upstream
	var arts []ArtifactScan
	for _, art := range plan.Artifacts {
		if ctx.Err() != nil {
			break
		}
		a := ArtifactScan{Role: art.Role, File: art.File, Upstream: art.Upstream, Path: "/v1/" + art.Upstream + art.Path}
		if ok, reason := s.opts.Scans.Scope(d.Type, art.Upstream); !ok {
			a.NotApplicable, a.NotApplicableReason = UnscannedOutOfScope, reason
			arts = append(arts, a)
			continue
		}
		fo := fetchOptions{subject: s.cfg.Scan.Subject, deferLLM: true}
		obj, llm := s.fetchArtifact(ctx, repo, art, fo)
		if obj.HTTPStatus == http.StatusNotFound && art.Fallback != "" {
			art.Path = art.Fallback
			a.Path = "/v1/" + art.Upstream + art.Path
			obj, llm = s.fetchArtifact(ctx, repo, art, fo)
		}
		if art.Optional && obj.Status != StatusPinned && llm == nil {
			continue // an optional object that is not there
		}
		a.CacheKey, a.Digest, a.Size = obj.CacheKey, obj.Digest, obj.Size
		switch {
		case llm != nil && llm.Applicable:
			// The gate examined the bytes on the way — whatever a later gate
			// then did with the fetch.
			a.apply(*llm, !llm.Cached)
		case llm != nil && obj.Status == StatusPinned:
			a.apply(*llm, false) // not package content, out of scope, covered by its image
		case obj.Status == StatusPinned:
			// Admitted and cached, but no reading came back with the fetch
			// (a serve path that reports none): ask the gate directly.
			a = s.scanCachedObject(ctx, repo, d.Type, obj)
		default:
			a.markUnscanned(unscannedForObject(obj))
		}
		if obj.Status != StatusPinned && a.Applicable && a.Verdict == VerdictBenign {
			// A clean reading counts only for bytes that were admitted,
			// recorded and matched against the lock file. A refused object, one
			// served without caching, bytes that are not the lock file's: a
			// clean reading of those says nothing about the dependency. (A
			// flag on them still stands: those are the bytes the registry
			// serves under its name.)
			a.markUnscanned(unscannedForObject(obj))
		}
		arts = append(arts, a)
	}
	aggregate(&ds, arts)
	return ds
}

// unscannedForStatus explains a release dependency with no pinned object.
func unscannedForStatus(d Dependency) *UnscannedInfo {
	reason := d.Reason
	switch d.Status {
	case StatusUnsupported:
		return &UnscannedInfo{Code: UnscannedUnsupported, Reason: "it cannot be fetched through the proxy: " + reason}
	case StatusRefused:
		return &UnscannedInfo{Code: UnscannedFetchRefused, Reason: "an admission gate refused it: " + reason}
	case StatusMismatch:
		return &UnscannedInfo{Code: UnscannedLockMismatch, Reason: "the bytes served are not the ones the lock file pins: " + reason}
	case StatusFailed:
		// The pinner retries it; once pinned, the release is scanned again.
		return &UnscannedInfo{Code: UnscannedNotPinned, Reason: "it is not pinned (the release pinner retries it): " + firstNonEmpty(reason, "it could not be fetched")}
	}
	return &UnscannedInfo{Code: UnscannedNotPinned, Reason: "none of its objects is pinned"}
}

// unscannedForObject explains an object a scan could not read.
func unscannedForObject(o Object) *UnscannedInfo {
	switch o.Status {
	case StatusRefused:
		return &UnscannedInfo{Code: UnscannedFetchRefused, Reason: "an admission gate refused it: " + o.Reason}
	case StatusMismatch:
		return &UnscannedInfo{Code: UnscannedLockMismatch, Reason: "the bytes served are not the ones the lock file pins: " + o.Reason}
	case StatusUncached:
		return &UnscannedInfo{Code: UnscannedNoDigest, Reason: "the proxy serves it without caching it, so there are no recorded bytes to bind a verdict to"}
	}
	return &UnscannedInfo{Code: UnscannedFetchFailed, Reason: "it could not be fetched: " + firstNonEmpty(o.Reason, o.Status), Retryable: o.HTTPStatus != http.StatusNotFound}
}

// markUnscanned records why an object has no verdict.
func (a *ArtifactScan) markUnscanned(u *UnscannedInfo) {
	a.Applicable = true
	a.Verdict, a.Unscanned, a.Reason = VerdictUnscanned, u, u.Reason
	a.Detail, a.Refused, a.Cached = nil, false, false
}

// apply records the gate's reading of an object.
func (a *ArtifactScan) apply(o ObjectScan, fresh bool) {
	a.ObjectScan = o
	a.fresh = fresh && o.Applicable && o.Unscanned == nil
	if o.Applicable && o.Verdict == "" {
		a.Verdict = VerdictUnscanned
	}
	if a.Digest == "" && o.Detail != nil {
		a.Digest = o.Detail.Digest
	}
}

// verdictRank orders verdicts worst last.
func verdictRank(v string) int {
	switch v {
	case VerdictMalicious:
		return 4
	case VerdictSuspicious:
		return 3
	case VerdictUnscanned:
		return 2
	case VerdictBenign:
		return 1
	}
	return 0
}

// aggregate derives a dependency's verdict from its objects: the worst reading
// of an object the gate examines. A dependency is benign only when every such
// object is; one the gate examines none of is unscanned, with the reason.
func aggregate(ds *DependencyScan, arts []ArtifactScan) {
	ds.Artifacts = arts
	var worst *ArtifactScan
	allCached, any := true, false
	for i := range arts {
		a := &arts[i]
		if !a.Applicable {
			continue
		}
		any = true
		if a.fresh || !a.Cached {
			allCached = false
		}
		if worst == nil || verdictRank(a.Verdict) > verdictRank(worst.Verdict) {
			worst = a
		}
	}
	if worst == nil {
		ds.Verdict = VerdictUnscanned
		ds.Unscanned = &UnscannedInfo{Code: UnscannedNoContent,
			Reason: "none of the objects fetched for it is package content the scan examines"}
		for _, a := range arts {
			if a.NotApplicable == UnscannedOutOfScope {
				ds.Unscanned = &UnscannedInfo{Code: UnscannedOutOfScope, Reason: a.NotApplicableReason}
				break
			}
		}
		if len(arts) == 0 {
			ds.Unscanned = &UnscannedInfo{Code: UnscannedNoContent, Reason: "the lock file pins no object of it that the proxy fetches"}
		}
		ds.Reason = ds.Unscanned.Reason
		return
	}
	ds.Verdict, ds.Reason, ds.Refused = worst.Verdict, worst.Reason, worst.Refused
	ds.Unscanned, ds.Detail = worst.Unscanned, worst.Detail
	ds.Cached = any && allCached && worst.Unscanned == nil
	// Released only when a break-glass grant releases every flagged object of
	// it: one released wheel does not release the sdist next to it.
	released := ""
	for _, a := range arts {
		if !a.Applicable || (a.Verdict != VerdictMalicious && a.Verdict != VerdictSuspicious) {
			continue
		}
		if a.BreakGlass == "" {
			released = ""
			break
		}
		if released == "" {
			released = a.BreakGlass
		}
	}
	if ds.Verdict == VerdictMalicious || ds.Verdict == VerdictSuspicious {
		ds.Released = released
	}
}

// settleScan counts a report's dependencies and derives its status and result.
func settleScan(rep *ScanReport) {
	var sum ScanSummary
	sum.UnscannedByCode = map[string]int{}
	var flaggedMal, flaggedSus, released []string
	for _, d := range rep.Dependencies {
		sum.Dependencies++
		switch d.Verdict {
		case VerdictMalicious:
			sum.Malicious++
			if d.Released == "" {
				flaggedMal = append(flaggedMal, d.Coordinate())
			} else {
				released = append(released, d.Coordinate())
			}
		case VerdictSuspicious:
			sum.Suspicious++
			if d.Released == "" {
				flaggedSus = append(flaggedSus, d.Coordinate())
			} else {
				released = append(released, d.Coordinate())
			}
		case VerdictBenign:
			sum.Benign++
		default:
			sum.Unscanned++
			code := "unknown"
			if d.Unscanned != nil {
				code = d.Unscanned.Code
				if d.Unscanned.Retryable {
					sum.Retryable++
				}
			}
			sum.UnscannedByCode[code]++
		}
		if d.Released != "" {
			sum.Released++
		}
		if d.Verdict != VerdictUnscanned {
			if d.Cached {
				sum.Cached++
			} else {
				sum.Scanned++
			}
		}
	}
	if len(sum.UnscannedByCode) == 0 {
		sum.UnscannedByCode = nil
	}
	sum.MaliciousUnreleased = len(flaggedMal)
	rep.Summary = sum
	rep.ContainsMaliciousDependency = len(flaggedMal) > 0

	// Lock files that were found and not read pin dependencies nobody
	// scanned: the scan is not complete, whatever the rest says.
	var reasons []string
	if rep.Truncated != "" {
		reasons = append(reasons, "the lock-file read stopped early: "+rep.Truncated)
	}
	var unread []string
	for _, lf := range rep.LockFiles {
		if lf.Error != "" {
			unread = append(unread, lf.Path+" ("+lf.Error+")")
		}
	}
	for _, sk := range rep.Skipped {
		if !strings.HasSuffix(sk.Path, "/") { // a directory passed over on purpose (vendored code, fixtures)
			unread = append(unread, sk.Path+" ("+sk.Reason+")")
		}
	}
	rep.Summary.UnreadLockFiles = len(unread)
	if len(unread) > 0 {
		reasons = append(reasons, fmt.Sprintf("%d lock file(s) could not be read, and what they pin is unscanned: %s", len(unread), strings.Join(firstN(unread, 5), "; ")))
	}
	incomplete := sum.Unscanned > 0 || len(unread) > 0 || rep.Truncated != ""
	switch {
	case sum.Malicious > 0:
		rep.Result = ResultMalicious
	case sum.Suspicious > 0:
		rep.Result = ResultSuspicious
	case incomplete:
		rep.Result = ResultIncomplete
	case sum.Dependencies == 0:
		rep.Result = ResultEmpty
		reasons = append(reasons, "no lock file pins a dependency")
	default:
		rep.Result = ResultClean
	}
	var lead []string
	if len(flaggedMal) > 0 {
		lead = append(lead, fmt.Sprintf("%d dependenc%s judged malicious: %s", len(flaggedMal), plural(len(flaggedMal), "y", "ies"), strings.Join(firstN(flaggedMal, 10), ", ")))
	}
	if len(flaggedSus) > 0 {
		lead = append(lead, fmt.Sprintf("%d dependenc%s judged suspicious: %s", len(flaggedSus), plural(len(flaggedSus), "y", "ies"), strings.Join(firstN(flaggedSus, 10), ", ")))
	}
	if len(released) > 0 {
		lead = append(lead, fmt.Sprintf("%d flagged dependenc%s released by break-glass: %s", len(released), plural(len(released), "y", "ies"), strings.Join(firstN(released, 10), ", ")))
	}
	reasons = append(lead, reasons...)
	if sum.Unscanned > 0 {
		codes := make([]string, 0, len(sum.UnscannedByCode))
		for c := range sum.UnscannedByCode {
			codes = append(codes, c)
		}
		sort.Strings(codes)
		parts := make([]string, 0, len(codes))
		for _, c := range codes {
			parts = append(parts, fmt.Sprintf("%d %s", sum.UnscannedByCode[c], c))
		}
		reasons = append(reasons, fmt.Sprintf("%d of %d dependencies are unscanned (%s)", sum.Unscanned, sum.Dependencies, strings.Join(parts, ", ")))
	}
	if incomplete {
		rep.Status = ScanIncomplete
	} else {
		rep.Status = ScanComplete
	}
	rep.Reason = strings.Join(reasons, "; ")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func firstN(list []string, n int) []string {
	if len(list) <= n {
		return list
	}
	return append(append([]string(nil), list[:n]...), fmt.Sprintf("and %d more", len(list)-n))
}

// --- recording ----------------------------------------------------------------

// finishScan acts on a report — the release manifest's mark, the default
// branch's state, the findings, the notifications, the audit record — and then
// stores it. The report is written last: whoever sees it (ptctl repos scan
// --wait, the admin console) finds everything it caused already recorded.
func (s *Service) finishScan(ctx context.Context, repo Repo, rep *ScanReport, prev *ScanReport) {
	if rep.Status == "" {
		settleScan(rep)
	}
	rep.FinishedAt = s.now().UTC()
	rep.NextAttempt = time.Time{}
	if rep.Summary.Retryable > 0 && rep.Attempts < s.cfg.Scan.MaxAttempts {
		rep.NextAttempt = rep.FinishedAt.Add(s.cfg.Scan.RetryInterval << uint(min(rep.Attempts-1, 10)))
	}
	if rep.Kind == ScanRelease {
		s.markRelease(ctx, rep)
		s.notifyRelease(ctx, rep.Repo, rep.Commit)
	}
	// The default branch's state only moves forward: a scan of a head the
	// branch has left meanwhile does not take "current head" back.
	isHead := false
	if rep.Kind == ScanHead || rep.Branch != "" {
		s.updateHead(ctx, rep.Repo, func(h *HeadState) {
			if h.Commit != "" && h.Commit != rep.Commit {
				return
			}
			isHead = true
			h.ScannedCommit, h.ScannedAt = rep.Commit, rep.FinishedAt
			if h.Branch == "" {
				h.Branch = firstNonEmpty(rep.Branch, rep.Ref)
			}
			if h.Commit == "" {
				h.Commit = rep.Commit
			}
		})
	}
	if s.opts.Findings != nil && rep.Status != ScanFailed {
		// A release's or a revision's document under its commit; the head's
		// under its branch, replaced by every head scan. A release that is
		// the head has both.
		if rep.Kind != ScanHead {
			s.opts.Findings.RecordScanFindings(ctx, rep.FindingsDocument())
		}
		if isHead {
			s.opts.Findings.RecordScanFindings(ctx, rep.headDocument())
		}
	}
	s.announceScan(ctx, rep, prev, isHead)

	decision := audit.DecisionAllow
	if rep.Result == ResultMalicious || rep.Result == ResultSuspicious {
		decision = audit.DecisionDeny
	}
	s.auditLog(ctx, audit.Event{
		Type:     audit.EventRepoScan,
		Subject:  s.cfg.Scan.Subject,
		Team:     rep.Tenant,
		Resource: "repo/" + rep.Repo + "@" + rep.Commit,
		Decision: decision,
		Reason:   "dependency scan " + rep.Status + ": " + rep.Result,
		Detail: map[string]any{
			"repo": rep.Repo, "commit": rep.Commit, "kind": rep.Kind, "ref": rep.Ref, "trigger": rep.Trigger,
			"status": rep.Status, "result": rep.Result, "dependencies": rep.Summary.Dependencies,
			"malicious": rep.Summary.Malicious, "suspicious": rep.Summary.Suspicious, "benign": rep.Summary.Benign,
			"unscanned": rep.Summary.Unscanned, "released": rep.Summary.Released, "cachedVerdicts": rep.Summary.Cached,
			"scanned": rep.Summary.Scanned, "model": rep.Gate.Model, "promptVersion": rep.Gate.PromptVersion,
			"action": rep.Gate.Action, "attempt": rep.Attempts,
		},
	})
	if err := s.writeScanReport(ctx, rep); err != nil {
		s.log.Error("storing a dependency scan report failed", "repo", rep.Repo, "commit", rep.Commit, "error", err)
		s.metrics().scan(rep.Kind, "store-failed", rep.FinishedAt.Sub(rep.StartedAt))
		return
	}
	if rep.Kind != ScanRelease {
		s.pruneScanReports(ctx, rep.Repo)
	}
	m := s.metrics()
	m.scan(rep.Kind, rep.Status, rep.FinishedAt.Sub(rep.StartedAt))
	for _, d := range rep.Dependencies {
		m.scannedDependency(d.Verdict)
	}
	s.refreshScanMetrics()
	s.log.Info("repository dependencies scanned", "repo", rep.Repo, "commit", short(rep.Commit), "kind", rep.Kind,
		"ref", rep.Ref, "trigger", rep.Trigger, "status", rep.Status, "result", rep.Result,
		"dependencies", rep.Summary.Dependencies, "malicious", rep.Summary.Malicious, "suspicious", rep.Summary.Suspicious,
		"unscanned", rep.Summary.Unscanned, "cachedVerdicts", rep.Summary.Cached, "attempt", rep.Attempts,
		"took", rep.FinishedAt.Sub(rep.StartedAt).Round(time.Millisecond))
}

// markRelease records a release's scan in its manifest: "contains malicious
// dependency" when the scan judged one of its dependencies malicious. The
// manifest's pins are untouched — the bytes stay, for forensics.
func (s *Service) markRelease(ctx context.Context, rep *ScanReport) {
	unlock := s.locks.lock(manifestLock(rep.Repo, rep.Commit))
	defer unlock()
	m, err := s.readManifest(ctx, rep.Repo, rep.Commit)
	if err != nil {
		return
	}
	rs := &ReleaseScan{
		Status: rep.Status, Result: rep.Result, ContainsMaliciousDependency: rep.ContainsMaliciousDependency,
		Malicious: rep.Summary.Malicious, Suspicious: rep.Summary.Suspicious, Unscanned: rep.Summary.Unscanned,
		Benign: rep.Summary.Benign, Model: rep.Gate.Model, PromptVersion: rep.Gate.PromptVersion,
		Action: rep.Gate.Action, ScannedAt: rep.FinishedAt,
	}
	for _, d := range rep.Dependencies {
		if d.Released != "" {
			continue
		}
		if d.Verdict == VerdictMalicious || (d.Verdict == VerdictSuspicious && rep.Gate.Action == "quarantine") {
			rs.Flagged = append(rs.Flagged, d.Coordinate())
		}
	}
	m.Scan = rs
	if err := s.writeManifest(ctx, m); err != nil {
		s.log.Error("recording the dependency scan in the release manifest failed", "repo", rep.Repo, "commit", rep.Commit, "error", err)
	}
}

// flagKey identifies a flagged dependency for announcements.
func flagKey(d DependencyScan) string {
	digest := ""
	if d.Detail != nil {
		digest = d.Detail.Digest
	}
	return d.Verdict + "|" + d.Coordinate() + "|" + digest
}

// announceScan notifies and audits each flagged dependency once: a dependency
// already announced for the same commit — or, for the default branch, for an
// earlier head — is not announced again.
func (s *Service) announceScan(ctx context.Context, rep *ScanReport, prev *ScanReport, head bool) {
	seen := map[string]bool{}
	if prev != nil {
		for _, d := range prev.Dependencies {
			if d.flagged() && d.Released == "" {
				seen[flagKey(d)] = true
			}
		}
	}
	if head {
		for _, k := range s.headState(ctx, rep.Repo).Notified {
			seen[k] = true
		}
	}
	quarantine := rep.Gate.Action == "quarantine"
	var announced []string
	for _, d := range rep.Dependencies {
		if !d.flagged() || d.Released != "" {
			continue
		}
		k := flagKey(d)
		if seen[k] {
			continue
		}
		seen[k] = true
		announced = append(announced, k)
		sev := notify.SeverityMedium
		switch {
		case d.Verdict == VerdictMalicious:
			sev = notify.SeverityCritical
		case quarantine:
			sev = notify.SeverityHigh
		}
		model, digest := "", ""
		if d.Detail != nil {
			model, digest = d.Detail.Model, d.Detail.Digest
		}
		summary := scanSentence(rep, d)
		s.emit(ctx, notify.RepositoryScanEvent(sev, rep.Repo, rep.Commit, scanWhere(rep), plainText(d.Coordinate()), d.Verdict, rep.Gate.Action, model, summary))
		s.auditLog(ctx, audit.Event{
			Type:      audit.EventRepoScan,
			Subject:   s.cfg.Scan.Subject,
			Team:      rep.Tenant,
			Ecosystem: d.Type,
			Resource:  "repo/" + rep.Repo + "@" + rep.Commit + "/" + d.Coordinate(),
			Decision:  audit.DecisionDeny,
			Reason:    "dependency judged " + d.Verdict,
			Detail: map[string]any{
				"repo": rep.Repo, "commit": rep.Commit, "kind": rep.Kind, "ref": rep.Ref, "event": "dependency-flagged",
				"coordinate": d.Coordinate(), "verdict": d.Verdict, "digest": digest, "model": model,
				"files": strings.Join(d.Files, ","), "pinned": d.Pinned, "refused": d.Refused, "action": rep.Gate.Action,
			},
		})
	}
	if head && len(announced) > 0 {
		s.updateHead(ctx, rep.Repo, func(h *HeadState) { h.Notified = append(h.Notified, announced...) })
	}
}

// plainText keeps a repository-controlled fragment — a tag name, a lock-file
// path — to characters that mean nothing to a renderer: Git allows "<", ">",
// "|" and "`" in both, and a notification's summary is rendered as Slack
// markup, where "<https://…|text>" is a link. Anything else becomes "_".
func plainText(s string) string {
	const max = 200
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= max {
			b.WriteString("…")
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case strings.ContainsRune("._/@+:=,-", r):
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func plainTexts(list []string) []string {
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = plainText(s)
	}
	return out
}

// scanWhere names what was scanned: a release's tags, a branch, a revision.
func scanWhere(rep *ScanReport) string {
	switch rep.Kind {
	case ScanRelease:
		if len(rep.Tags) > 0 {
			return "release " + strings.Join(plainTexts(rep.Tags), ", ")
		}
		return "release at " + short(rep.Commit)
	case ScanHead:
		return "branch " + plainText(rep.Ref)
	}
	if rep.Ref != "" {
		return "revision " + plainText(rep.Ref)
	}
	return "revision " + short(rep.Commit)
}

// scanSentence is the proxy's own sentence about a flagged dependency, for
// notifications and logs: what it is, where, and what the ladder does with it.
// The model's words are never part of it.
func scanSentence(rep *ScanReport, d DependencyScan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s of %s pins %s, which the LLM package-content scan judges %s", scanWhere(rep), rep.Repo, plainText(d.Coordinate()), d.Verdict)
	if len(d.Files) > 0 {
		fmt.Fprintf(&b, " (%s)", strings.Join(plainTexts(firstN(d.Files, 3)), ", "))
	}
	switch {
	case d.Refused && d.Pinned:
		b.WriteString(". Clients are refused it; the release keeps its pinned bytes for forensics")
	case d.Refused:
		b.WriteString(". Clients are refused it")
	case d.Pinned:
		b.WriteString(". It stays pinned in the release; under the gate's " + rep.Gate.Action + " action clients are served it")
	}
	b.WriteString(".")
	return capitalize(b.String())
}

// capitalize upper-cases a sentence's first letter.
func capitalize(s string) string {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return s
	}
	return string(s[0]-'a'+'A') + s[1:]
}
