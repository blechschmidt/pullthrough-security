package repos

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/repos/forge"
	"github.com/blechschmidt/pullthrough-security/internal/repos/update"
)

// maxUpdateAttempts bounds the starts over a default branch that keeps moving
// while a run computes.
const maxUpdateAttempts = 3

// errHeadMoved restarts a run: the default branch moved while it computed.
var errHeadMoved = errors.New("repos: the default branch moved")

// runUpdate runs one maintenance run under the repository's update lock and
// records it.
func (s *Service) runUpdate(ctx context.Context, repo Repo, run *UpdateRun) (*UpdateRun, error) {
	unlock := s.locks.lock(updateLock(repo.Name))
	defer unlock()
	defer s.upRunning.set(repo.Name, nil)
	// Every run is bounded, scheduled or asked for: one slow repository must
	// not hold up the others' scheduled runs.
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Update.RunTimeout)
	defer cancel()

	var err error
	for attempt := 1; attempt <= maxUpdateAttempts; attempt++ {
		run.Attempts = attempt
		run.Updates, run.Skipped, run.LockFiles = []AppliedUpdate{}, []SkippedCandidate{}, nil
		run.Commit, run.Tree, run.Previous, run.Pushed, run.Message = "", "", "", false, ""
		err = s.updateOnce(ctx, repo, run)
		if !errors.Is(err, errHeadMoved) {
			break
		}
		if syncErr := run.syncErr; syncErr != nil {
			// The mirror could not be refreshed: its head will not catch up
			// with the remote's however often the run starts over.
			err = fmt.Errorf("the repository could not be fetched, so its default branch's head is not known: %w", syncErr)
			break
		}
		s.log.Info("the default branch moved during a maintenance run; starting over on its new head",
			"repo", repo.Name, "branch", run.BaseBranch, "attempt", attempt)
	}
	switch {
	case errors.Is(err, errHeadMoved):
		run.Status, run.Reason = UpdateFailed, fmt.Sprintf("the default branch moved %d times while the run computed; it is tried again at the next run", maxUpdateAttempts)
		err = nil
	case err != nil:
		run.Status, run.Reason = UpdateFailed, err.Error()
	}
	run.FinishedAt = s.now().UTC()

	// What is recorded must be recorded even when the run's context ended.
	rctx := context.WithoutCancel(ctx)
	if !run.DryRun {
		st := s.readUpdateState(rctx, repo.Name)
		st.Repo, st.Branch = repo.Name, run.Branch
		st.LastRun, st.LastStatus, st.LastRunAt = run.ID, run.Status, run.StartedAt
		if run.Pushed {
			st.LastPushed, st.PushedAt, st.Conflict = run.Commit, run.FinishedAt, ""
		}
		switch run.Status {
		case UpdateConflict:
			st.Conflict = run.Reason
		case UpdateUnchanged, UpdatePushed:
			st.Conflict = ""
		case UpdateRetired:
			st.LastPushed, st.Conflict = "", ""
		}
		if werr := s.writeUpdateState(rctx, st); werr != nil {
			s.log.Error("storing the maintenance state failed", "repo", repo.Name, "error", werr)
		}
	}
	if werr := s.writeUpdateRun(rctx, run); werr != nil {
		s.log.Error("storing a maintenance run report failed", "repo", repo.Name, "error", werr)
	}
	m := s.metrics()
	m.updateRun(run.Status, run.FinishedAt.Sub(run.StartedAt))
	for _, u := range run.Updates {
		m.updateApplied(u.Method)
	}
	for _, sk := range run.Skipped {
		m.updateSkipped(sk.Code)
	}
	s.log.Info("maintenance run finished", "repo", repo.Name, "status", run.Status, "updates", len(run.Updates),
		"skipped", len(run.Skipped), "branch", run.Branch, "commit", short(run.Commit), "pushed", run.Pushed,
		"dryRun", run.DryRun, "took", run.FinishedAt.Sub(run.StartedAt).Round(time.Millisecond))
	return run, err
}

// updateOnce is one attempt of a run on the default branch's current head.
// When refreshing the mirror fails, run.syncErr says why.
func (s *Service) updateOnce(ctx context.Context, repo Repo, run *UpdateRun) error {
	run.syncErr = nil
	cred, err := s.credential(ctx, repo)
	if err != nil {
		return fmt.Errorf("resolving the repository's credentials: %w", err)
	}
	if _, err := s.Sync(ctx, repo.Name, "update"); err != nil {
		run.syncErr = err
		s.log.Warn("refreshing the repository before a maintenance run failed; the mirror as last fetched is used", "repo", repo.Name, "error", err)
	}
	hsrc, ok := s.opts.Refs.(HeadSource)
	if !ok {
		return errors.New("the repository's default branch cannot be read")
	}
	head, err := hsrc.DefaultHead(ctx, repo, cred)
	if err != nil {
		return fmt.Errorf("reading the default branch: %w", err)
	}
	if !validCommit(head.Commit) {
		return errors.New("the default branch's head is not a commit")
	}
	run.BaseBranch, run.Base = head.Branch, head.Commit
	if run.Branch == head.Branch {
		return fmt.Errorf("the maintenance branch %s is the repository's default branch; choose another (repositories.updates.branch, or the repository's updates.branch)", run.Branch)
	}
	if moved, err := s.headMoved(ctx, repo, cred, head); err != nil {
		return err
	} else if moved {
		return errHeadMoved
	}

	m := &Manifest{Repo: repo.Name, Tenant: repo.Tenant, Commit: head.Commit}
	if err := s.readLockfiles(ctx, repo, m); err != nil {
		return fmt.Errorf("reading the lock files at %s: %w", short(head.Commit), err)
	}
	plans, err := s.selectUpdates(ctx, repo, run, m)
	if err != nil {
		return err
	}
	files := s.writeUpdates(ctx, repo, run, m, plans)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	sortRun(run)
	if len(run.Updates) == 0 {
		run.Status = UpdateNone
		run.Reason = noUpdateReason(run)
		return s.retireBranch(ctx, repo, cred, run)
	}

	run.Message = commitMessage(run)
	commit, tree, err := s.opts.Branches.BuildCommit(ctx, repo, CommitSpec{
		Base: head.Commit, Files: files, Message: run.Message,
		Author: s.cfg.Update.AuthorName, Email: s.cfg.Update.AuthorEmail, When: s.now(), Signer: s.cfg.Update.Signer,
	})
	if err != nil {
		return fmt.Errorf("building the maintenance commit: %w", err)
	}
	run.Commit, run.Tree = commit, tree

	// The default branch must still be where the commit was built: a push
	// on top of a head it has left would propose stale lock files, and a
	// branch "unchanged" on that head is stale too.
	if moved, err := s.headMoved(ctx, repo, cred, head); err != nil {
		return err
	} else if moved {
		return errHeadMoved
	}
	remote, err := s.opts.Branches.RemoteBranch(ctx, repo, cred, run.Branch)
	if err != nil {
		return fmt.Errorf("reading the maintenance branch: %w", err)
	}
	run.Previous = remote
	if remote != "" {
		if rtree, parents, err := s.opts.Branches.CommitInfo(ctx, repo, remote); err == nil &&
			rtree == tree && len(parents) == 1 && parents[0] == head.Commit {
			// The branch already holds exactly these files on this head.
			run.Status, run.Commit = UpdateUnchanged, remote
			run.Reason = "the maintenance branch already holds these updates on " + short(head.Commit) + "; nothing was pushed"
			if !run.DryRun {
				// A pull request that could not be opened when the branch
				// was pushed is opened now; an open one is brought up to
				// date (the skipped candidates may have changed).
				s.openPullRequest(ctx, repo, run)
			}
			return nil
		}
	}
	if run.DryRun {
		run.Status = UpdateDryRun
		if remote == "" {
			run.Reason = "a run would create " + run.Branch + " at " + short(commit)
		} else {
			run.Reason = "a run would move " + run.Branch + " from " + short(remote) + " to " + short(commit)
		}
		return nil
	}

	// The lease: the branch must be where the updater left it — or gone (a
	// merged pull request's branch is often deleted). Commits someone else
	// pushed are never overwritten.
	st := s.readUpdateState(ctx, repo.Name)
	expect := ""
	switch {
	case remote == "":
	case remote == st.LastPushed:
		expect = remote
	case s.ownCommit(ctx, repo, remote):
		// A commit of this updater whose push the state does not record (the
		// state was restored from an older backup, or lost): the branch is
		// still the updater's.
		expect = remote
	default:
		run.Status = UpdateConflict
		run.Reason = fmt.Sprintf("%s is at %s, which the updater did not push (it last pushed %s); it is not overwritten. Delete the branch, or merge its changes, and the next run starts it over",
			run.Branch, short(remote), firstNonEmpty(short(st.LastPushed), "nothing"))
		s.auditUpdate(ctx, repo, run, audit.DecisionDeny, expect)
		s.emit(ctx, notify.RepositoryUpdateEvent(notify.SeverityMedium, repo.Name, run.Branch, short(remote), "conflict",
			plainText(repo.Name)+": "+plainText(run.Branch)+" is at "+short(remote)+", which the maintenance updater did not push; it is not overwritten"))
		return nil
	}
	if err := s.opts.Branches.PushBranch(ctx, repo, cred, run.Branch, commit, expect); err != nil {
		if errors.Is(err, ErrLeaseRejected) {
			run.Status = UpdateConflict
			run.Reason = run.Branch + " moved while the run pushed; it is not overwritten: " + err.Error()
			s.auditUpdate(ctx, repo, run, audit.DecisionDeny, expect)
			s.emit(ctx, notify.RepositoryUpdateEvent(notify.SeverityMedium, repo.Name, run.Branch, short(commit), "conflict",
				plainText(repo.Name)+": "+plainText(run.Branch)+" moved while the maintenance run pushed; it is not overwritten"))
			return nil
		}
		run.Status, run.Reason = UpdateFailed, "pushing "+run.Branch+": "+err.Error()
		s.auditUpdate(ctx, repo, run, audit.DecisionDeny, expect)
		s.metrics().updatePush("failed")
		s.emit(ctx, notify.RepositoryUpdateEvent(notify.SeverityMedium, repo.Name, run.Branch, short(commit), "push-failed",
			plainText(repo.Name)+": pushing the maintenance branch "+plainText(run.Branch)+" failed"))
		return fmt.Errorf("pushing %s: %w", run.Branch, err)
	}
	run.Pushed, run.Status = true, UpdatePushed
	if remote == "" {
		run.Reason = "created " + run.Branch + " at " + short(commit)
	} else {
		run.Reason = "moved " + run.Branch + " from " + short(remote) + " to " + short(commit)
	}
	s.metrics().updatePush("pushed")
	s.auditUpdate(ctx, repo, run, audit.DecisionAllow, expect)
	s.openPullRequest(ctx, repo, run)
	return nil
}

// ownCommit reports whether a commit is one this updater made: one parent,
// committed with the updater's identity, its message carrying a run's trailer.
// A branch whose tip is anything else holds someone's work.
func (s *Service) ownCommit(ctx context.Context, repo Repo, commit string) bool {
	raw, err := s.opts.Branches.CommitObject(ctx, repo, commit)
	if err != nil {
		return false
	}
	header, message, ok := strings.Cut(string(raw), "\n\n")
	if !ok {
		return false
	}
	parents, committer := 0, ""
	for _, line := range strings.Split(header, "\n") {
		switch {
		case strings.HasPrefix(line, "parent "):
			parents++
		case strings.HasPrefix(line, "committer "):
			committer = line
		}
	}
	if parents != 1 || !strings.Contains(committer, " <"+s.cfg.Update.AuthorEmail+"> ") {
		return false
	}
	for _, line := range strings.Split(message, "\n") {
		if id, ok := strings.CutPrefix(line, "Pullthrough-Run: "); ok && validRunID(strings.TrimSpace(id)) {
			return true
		}
	}
	return false
}

// retireBranch deletes the maintenance branch when a run finds no vetted
// update left and the branch is the updater's: what it proposes is no longer
// vetted (a verdict changed, the firewall or the cooldown now refuses it) or no
// longer needed, and a branch — and its pull request — must not go on
// proposing it. A branch someone else pushed to is left alone.
func (s *Service) retireBranch(ctx context.Context, repo Repo, cred Credential, run *UpdateRun) error {
	if why := passingSkip(run); why != "" {
		// A registry that could not be read, a scan the budget put off:
		// what the branch proposes may well still stand.
		return nil
	}
	remote, err := s.opts.Branches.RemoteBranch(ctx, repo, cred, run.Branch)
	if err != nil || remote == "" {
		return nil
	}
	st := s.readUpdateState(ctx, repo.Name)
	if remote != st.LastPushed && !s.ownCommit(ctx, repo, remote) {
		run.Reason += "; " + run.Branch + " holds commits the updater did not push and is left as it is"
		return nil
	}
	run.Previous = remote
	if run.DryRun {
		run.Reason += "; a run would delete " + run.Branch + ", which proposes nothing that is still vetted and needed"
		return nil
	}
	if err := s.opts.Branches.DeleteBranch(ctx, repo, cred, run.Branch, remote); err != nil {
		if errors.Is(err, ErrLeaseRejected) {
			run.Status = UpdateConflict
			run.Reason = run.Branch + " moved while the run deleted it; it is not touched: " + err.Error()
			s.auditUpdate(ctx, repo, run, audit.DecisionDeny, remote)
			return nil
		}
		s.auditUpdate(ctx, repo, run, audit.DecisionDeny, remote)
		return fmt.Errorf("deleting %s: %w", run.Branch, err)
	}
	run.Status = UpdateRetired
	run.Reason = noUpdateReason(run) + "; deleted " + run.Branch + " (was at " + short(remote) + "), which proposed nothing that is still vetted and needed"
	s.metrics().updatePush("deleted")
	s.auditUpdate(ctx, repo, run, audit.DecisionAllow, remote)
	return nil
}

// passingSkip returns the reason of a skipped candidate a later run may well
// not skip (a listing or a fetch that failed, a scan that did not happen, a
// requirement that could not be read), or "" when every skip is a decision.
func passingSkip(run *UpdateRun) string {
	for _, sk := range run.Skipped {
		switch sk.Code {
		case SkipListingFailed, SkipFetchFailed, SkipUnscanned, SkipUnknownConstr, SkipLimit:
			return sk.Code
		}
	}
	return ""
}

// headMoved reports whether the remote's default branch is no longer at the
// commit the run builds on.
func (s *Service) headMoved(ctx context.Context, repo Repo, cred Credential, head Head) (bool, error) {
	remote, err := s.opts.Branches.RemoteBranch(ctx, repo, cred, head.Branch)
	if err != nil {
		return false, fmt.Errorf("reading the default branch on the remote: %w", err)
	}
	return remote != "" && remote != head.Commit, nil
}

// noUpdateReason explains a run without updates.
func noUpdateReason(run *UpdateRun) string {
	if run.Dependencies == 0 {
		return "no lock file pins a dependency the updater can update"
	}
	if len(run.Skipped) == 0 {
		return fmt.Sprintf("all %d dependencies are at their newest compatible version", run.Dependencies)
	}
	return fmt.Sprintf("no newer compatible version of the %d dependencies passed vetting (%d candidates skipped)", run.Dependencies, len(run.Skipped))
}

func sortRun(run *UpdateRun) {
	sort.SliceStable(run.Updates, func(i, j int) bool {
		a, b := run.Updates[i], run.Updates[j]
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.Name < b.Name
	})
	sort.SliceStable(run.Skipped, func(i, j int) bool {
		a, b := run.Skipped[i], run.Skipped[j]
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.To > b.To
	})
}

// --- writing the lock files --------------------------------------------------------

// writeUpdates writes the planned updates into their lock files and returns
// the files to commit. Updates that cannot be written are skipped with the
// reason; those written become run.Updates.
func (s *Service) writeUpdates(ctx context.Context, repo Repo, run *UpdateRun, m *Manifest, plans []*plannedUpdate) map[string][]byte {
	// Each lock file and the updates of its entries.
	byFile := map[string][]*plannedUpdate{}
	for _, p := range plans {
		for _, loc := range p.dep.Files {
			lf, ok := lockFileOf(m, loc)
			if !ok {
				continue
			}
			byFile[lf.Path] = appendPlan(byFile[lf.Path], p)
		}
	}
	paths := make([]string, 0, len(byFile))
	for p := range byFile {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	out := map[string][]byte{}
	landed := map[*plannedUpdate]*AppliedUpdate{}
	for _, lp := range paths {
		if ctx.Err() != nil {
			return out
		}
		lf, _ := lockFileOf(m, lp+":0")
		res := s.writeLockFile(ctx, repo, run, m, lf, byFile[lp])
		run.LockFiles = append(run.LockFiles, res.report)
		for p, files := range res.landed {
			for name, data := range res.files {
				out[name] = data
			}
			a := landed[p]
			if a == nil {
				a = &AppliedUpdate{Type: p.dep.Type, Name: p.dep.Name, From: p.dep.Version, To: p.to,
					Bump: p.bump.String(), Constraint: p.constraint, Method: res.method[p], Verdict: VerdictBenign,
					ScanIDs: p.scanIDs, Digest: p.digest, Model: p.model, Upstream: p.upstream}
				landed[p] = a
			}
			for _, f := range files {
				a.Files = appendUniqueString(a.Files, f)
			}
		}
		for p, why := range res.failed {
			run.Skipped = append(run.Skipped, SkippedCandidate{Type: p.dep.Type, Name: p.dep.Name, From: p.dep.Version, To: p.to,
				Code: why.code, Reason: lp + ": " + why.reason, Verdict: VerdictBenign, Digest: p.digest})
		}
	}
	for _, p := range plans {
		if a := landed[p]; a != nil {
			sort.Strings(a.Files)
			run.Updates = append(run.Updates, *a)
		}
	}
	return out
}

func appendPlan(list []*plannedUpdate, p *plannedUpdate) []*plannedUpdate {
	for _, q := range list {
		if q == p {
			return list
		}
	}
	return append(list, p)
}

type skipWhy struct{ code, reason string }

// lockFileResult is the outcome for one lock file.
type lockFileResult struct {
	report LockFileUpdate
	// files are the new contents to commit; landed the updates written, with
	// the files each changed; failed the updates that could not be.
	files  map[string][]byte
	landed map[*plannedUpdate][]string
	failed map[*plannedUpdate]skipWhy
	// method says how each landed update was written (native, sandbox).
	method map[*plannedUpdate]string
}

// siblingsOf lists the files a format's rewrite reads besides the lock file.
func siblingsOf(key, lockPath string) []string {
	dir := path.Dir(lockPath)
	join := func(n string) string {
		if dir == "." {
			return n
		}
		return dir + "/" + n
	}
	switch key {
	case "go/go.mod", "go/go.sum":
		return []string{join("go.mod"), join("go.sum")}
	case "npm/package-lock.json", "npm/npm-shrinkwrap.json":
		return []string{lockPath, join("package.json")}
	}
	return []string{lockPath}
}

// writeLockFile writes the updates of one lock file: natively where the new
// versions declare the dependencies the old ones did, through the sandboxed
// package manager otherwise (or when the native rewrite fails), and checks the
// result against what was intended.
func (s *Service) writeLockFile(ctx context.Context, repo Repo, run *UpdateRun, m *Manifest, lf LockFile, plans []*plannedUpdate) lockFileResult {
	key := lockfileKey(lf)
	res := lockFileResult{
		report: LockFileUpdate{Path: lf.Path, Format: key},
		files:  map[string][]byte{}, landed: map[*plannedUpdate][]string{}, failed: map[*plannedUpdate]skipWhy{},
		method: map[*plannedUpdate]string{},
	}
	fail := func(ps []*plannedUpdate, code, why string) {
		for _, p := range ps {
			res.failed[p] = skipWhy{code, why}
		}
		if res.report.Error == "" {
			res.report.Error = why
		}
	}
	support, ok := update.Format(key)
	if !ok || support.Method == update.Unsupported {
		reason := "the updater does not write " + key
		if ok {
			reason = support.Reason
		}
		fail(plans, SkipNotWritable, reason)
		return res
	}
	before, err := s.opts.Branches.ReadFiles(ctx, repo, run.Base, siblingsOf(key, lf.Path), maxManifestBytes)
	if err != nil || before[lf.Path] == nil {
		fail(plans, SkipNotWritable, "the lock file could not be read")
		return res
	}
	// What the repository says besides the lock file may have a client
	// build something other than the vetted version: such updates are not
	// written, natively or in the sandbox.
	red := s.redirects(ctx, repo, run.Base, key, lf, before, plans)
	if red.all != "" {
		fail(plans, red.code, red.all)
		return res
	}
	if len(red.byName) > 0 {
		var keep, refused []*plannedUpdate
		for _, p := range plans {
			if why := red.byName[p.dep.Name]; why != "" {
				res.failed[p] = skipWhy{red.code, why}
				refused = append(refused, p)
			} else {
				keep = append(keep, p)
			}
		}
		if len(keep) == 0 {
			res.report.Error = refused[0].dep.Name + ": " + red.byName[refused[0].dep.Name]
			return res
		}
		plans = keep
	}
	current := map[string][]byte{}
	for k, v := range before {
		current[k] = v
	}

	var native, rest []*plannedUpdate
	for _, p := range plans {
		if support.Method == update.Native && p.sameDeps {
			native = append(native, p)
		} else {
			rest = append(rest, p)
		}
	}
	method := ""
	if len(native) > 0 {
		changes := changesOf(native)
		up := update.NativeUpdater(key)
		var after map[string][]byte
		if up == nil {
			err = errors.New("no native updater")
		} else {
			var changed map[string][]byte
			changed, err = up.Apply(lf.Path, current, changes)
			if err == nil {
				after = merged(current, changed)
				err = update.Verify(lf.Path, current, after, changes)
			}
		}
		if err != nil {
			// The native rewrite cannot be made safely: the package manager
			// re-resolves these too.
			s.log.Info("native lock-file rewrite not possible; trying the format's fallback", "repo", repo.Name, "file", lf.Path, "error", err)
			for _, p := range native {
				p.sameDepsWhy = "the native rewrite failed: " + err.Error()
			}
			rest = append(rest, native...)
		} else {
			current = after
			method = string(update.Native)
			for _, p := range native {
				res.landed[p] = nil
				res.method[p] = string(update.Native)
			}
		}
	}
	if len(rest) > 0 {
		if support.Fallback != update.Sandbox {
			why := "a native rewrite is not possible (" + firstWhy(rest) + "), and " + key + " has no sandboxed re-resolution: " + support.Reason
			fail(rest, SkipNotWritable, why)
		} else if ok, why := s.sandboxTool(support.Tool); !ok {
			fail(rest, SkipNotWritable, "re-resolving the lock file needs the sandboxed "+support.Tool+" ("+firstWhy(rest)+"), and "+why)
		} else {
			resolved := false
			after, code, why := s.resolveInSandbox(ctx, repo, run, m, lf, support, current, rest)
			switch {
			case code == "":
				current, resolved = after, true
				for _, p := range rest {
					res.landed[p] = nil
					res.method[p] = string(update.Sandbox)
				}
			case len(rest) == 1:
				fail(rest, code, why)
			default:
				// One at a time: an update whose resolution brings in something
				// that is not vetted must not hold back the others.
				for _, p := range rest {
					one := []*plannedUpdate{p}
					after, code, why := s.resolveInSandbox(ctx, repo, run, m, lf, support, current, one)
					if code != "" {
						fail(one, code, why)
						continue
					}
					current, resolved = after, true
					res.landed[p] = nil
					res.method[p] = string(update.Sandbox)
				}
			}
			if resolved {
				if method == "" {
					method = string(update.Sandbox)
				} else {
					method = string(update.Native) + "+" + string(update.Sandbox)
				}
				res.report.Tool = support.Tool
			}
		}
	}
	res.report.Method = method
	var changedFiles []string
	for name, data := range current {
		if string(before[name]) != string(data) {
			res.files[name] = data
			changedFiles = append(changedFiles, name)
		}
	}
	sort.Strings(changedFiles)
	res.report.Changed = changedFiles
	for p := range res.landed {
		res.landed[p] = changedFiles
		res.report.Updates++
	}
	if len(res.landed) > 0 && len(changedFiles) == 0 {
		// Nothing changed after all: nothing landed.
		for p := range res.landed {
			res.failed[p] = skipWhy{SkipVerify, "the rewrite changed nothing"}
		}
		res.landed = map[*plannedUpdate][]string{}
		res.report.Updates = 0
	}
	return res
}

func firstWhy(ps []*plannedUpdate) string {
	for _, p := range ps {
		if p.sameDepsWhy != "" {
			return p.dep.Name + ": " + p.sameDepsWhy
		}
	}
	return "the new versions declare other dependencies"
}

func changesOf(ps []*plannedUpdate) []update.Change {
	out := make([]update.Change, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.change)
	}
	return out
}

func merged(base, changed map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(base)+len(changed))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range changed {
		out[k] = v
	}
	return out
}

func (s *Service) sandboxTool(tool string) (bool, string) {
	if s.opts.Sandbox == nil {
		return false, "no sandbox is configured (repositories.updates.sandbox)"
	}
	return s.opts.Sandbox.Tool(tool)
}

// --- commit message --------------------------------------------------------------

// maxMessageSkips bounds the skipped candidates the commit message lists.
const maxMessageSkips = 100

// commitMessage lists each update (old → new, verdict, scan IDs) and each
// skipped candidate with its reason. Repository- and registry-controlled text
// (names, versions, reasons that quote them) goes through plainText-like
// sanitising: it ends up in a Git commit, a pull request body and a terminal.
func commitMessage(run *UpdateRun) string {
	var b strings.Builder
	n := len(run.Updates)
	if n == 1 {
		u := run.Updates[0]
		fmt.Fprintf(&b, "Update %s from %s to %s\n\n", oneLine(u.Name), oneLine(u.From), oneLine(u.To))
	} else {
		fmt.Fprintf(&b, "Update %d dependencies\n\n", n)
	}
	fmt.Fprintf(&b, "Vetted updates of the dependencies the lock files on %s (%s) pin:\n", oneLine(run.BaseBranch), short(run.Base))
	b.WriteString("every update below is within the declared constraint, passed every\nadmission gate, and the LLM package-content scan judged its exact bytes benign.\n\n")
	b.WriteString("Updates:\n")
	for _, u := range run.Updates {
		fmt.Fprintf(&b, "- %s/%s %s -> %s (%s, %s): verdict %s, scan %s\n",
			u.Type, oneLine(u.Name), oneLine(u.From), oneLine(u.To), u.Bump, u.Method, u.Verdict, strings.Join(u.ScanIDs, ", "))
	}
	if len(run.Skipped) > 0 {
		b.WriteString("\nSkipped:\n")
		for i, sk := range run.Skipped {
			if i == maxMessageSkips {
				fmt.Fprintf(&b, "- and %d more (see the run report %s)\n", len(run.Skipped)-maxMessageSkips, run.ID)
				break
			}
			target := oneLine(sk.From)
			if sk.To != "" {
				target += " -> " + oneLine(sk.To)
			}
			fmt.Fprintf(&b, "- %s/%s %s: %s: %s\n", sk.Type, oneLine(sk.Name), target, sk.Code, oneLine(sk.Reason))
		}
	}
	fmt.Fprintf(&b, "\nPullthrough-Run: %s\n", run.ID)
	return b.String()
}

// oneLine keeps text on one line and bounded, without control characters.
func oneLine(s string) string {
	const max = 300
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= max {
			b.WriteString("…")
			break
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			b.WriteByte(' ')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// --- pull requests, audit -----------------------------------------------------------

// openPullRequest opens or updates the repository's pull/merge request for the
// maintenance branch, when configured. A failure is reported in the run, not
// fatal: the branch is pushed.
func (s *Service) openPullRequest(ctx context.Context, repo Repo, run *UpdateRun) {
	if !s.cfg.Update.PullRequests.Enabled || repo.Update == nil || repo.Update.Forge == "" {
		return
	}
	if s.opts.Secrets == nil || repo.Update.ForgeTokenRef == "" {
		run.PullRequestError = "no forge token is configured (updates.forgeTokenRef)"
		return
	}
	apiURL := repo.Update.ForgeAPI
	if apiURL == "" {
		var err error
		if apiURL, err = forgeAPIFor(repo.Update.Forge, repo.URL); err != nil {
			run.PullRequestError = err.Error()
			return
		}
	}
	token, err := s.opts.Secrets.Resolve(ctx, repo.Update.ForgeTokenRef)
	if err != nil {
		run.PullRequestError = "resolving the forge token: " + err.Error()
		return
	}
	target := repo.Update.ForgeRepo
	if target == "" {
		var ok bool
		if target, ok = forge.InferRepo(repo.URL); !ok {
			run.PullRequestError = "the forge project cannot be told from the repository's URL; set updates.forgeRepo"
			return
		}
	}
	client, err := forge.New(forge.Config{Kind: forge.Kind(repo.Update.Forge), APIURL: apiURL, Repo: target, Token: token,
		UserAgent: "pullthrough-security-maintenance"})
	if err != nil {
		run.PullRequestError = err.Error()
		return
	}
	title := strings.SplitN(run.Message, "\n", 2)[0]
	pr, err := client.Ensure(ctx, forge.PullRequestSpec{Head: run.Branch, Base: run.BaseBranch, Title: title, Body: pullRequestBody(run),
		Labels: s.cfg.Update.PullRequests.Labels, Draft: s.cfg.Update.PullRequests.Draft})
	if err != nil {
		run.PullRequestError = err.Error()
		s.metrics().updatePullRequest("failed")
		return
	}
	run.PullRequest = &pr
	s.metrics().updatePullRequest("ok")
}

// pullRequestBody renders the run for a pull/merge request as Markdown; every
// repository- or registry-controlled value is in a code span.
func pullRequestBody(run *UpdateRun) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Vetted dependency updates of `%s` at `%s`, proposed by the pullthrough-security maintenance updater.\n\n", mdCode(run.BaseBranch), short(run.Base))
	b.WriteString("Each update is within the project's declared constraint, passed every admission gate of the proxy, and the LLM package-content scan judged its exact bytes benign.\n\n")
	b.WriteString("| Dependency | From | To | Update | Method | Verdict | Scan |\n|---|---|---|---|---|---|---|\n")
	for _, u := range run.Updates {
		fmt.Fprintf(&b, "| `%s/%s` | `%s` | `%s` | %s | %s | %s | `%s` |\n", u.Type, mdCode(u.Name), mdCode(u.From), mdCode(u.To), u.Bump, u.Method, u.Verdict, mdCode(strings.Join(u.ScanIDs, ", ")))
	}
	if len(run.Skipped) > 0 {
		b.WriteString("\n<details><summary>Skipped candidates</summary>\n\n| Dependency | Candidate | Reason |\n|---|---|---|\n")
		for i, sk := range run.Skipped {
			if i == maxMessageSkips {
				fmt.Fprintf(&b, "| … | | %d more in run `%s` |\n", len(run.Skipped)-maxMessageSkips, run.ID)
				break
			}
			fmt.Fprintf(&b, "| `%s/%s` | `%s` | %s: `%s` |\n", sk.Type, mdCode(sk.Name), mdCode(firstNonEmpty(sk.To, sk.From)), sk.Code, mdCode(sk.Reason))
		}
		b.WriteString("\n</details>\n")
	}
	fmt.Fprintf(&b, "\nRun `%s`.\n", run.ID)
	return b.String()
}

// mdCode keeps text inside a Markdown code span: no backticks, pipes or
// line breaks.
func mdCode(s string) string {
	return strings.NewReplacer("`", "'", "|", "/", "\n", " ", "\r", " ").Replace(oneLine(s))
}

// auditUpdate records a push, or a push refused or failed.
func (s *Service) auditUpdate(ctx context.Context, repo Repo, run *UpdateRun, decision audit.Decision, expect string) {
	coords := make([]string, 0, len(run.Updates))
	for _, u := range run.Updates {
		coords = append(coords, u.Type+"/"+u.Name+"@"+u.From+"->"+u.To)
	}
	s.auditLog(ctx, audit.Event{
		Type:     audit.EventRepoUpdate,
		Subject:  s.cfg.Update.Subject,
		Team:     repo.Tenant,
		Resource: "repo/" + repo.Name + "@" + run.Branch,
		Decision: decision,
		Reason:   "maintenance branch " + run.Status + ": " + oneLine(run.Reason),
		Detail: map[string]any{
			"repo": repo.Name, "branch": run.Branch, "commit": run.Commit, "base": run.Base, "baseBranch": run.BaseBranch,
			"lease": expect, "previous": run.Previous, "status": run.Status, "updates": strings.Join(coords, ","),
			"skipped": len(run.Skipped), "run": run.ID, "trigger": run.Trigger, "requestedBy": run.RequestedBy,
			"signed": s.cfg.Update.Signer != nil,
		},
	})
}

// --- re-reading a rewritten lock file --------------------------------------------

// lockDependencies parses a lock file (with its go.mod/go.sum sibling) out of
// a set of files, mapping URLs that point at the proxy back to its upstreams
// as the lock-file scans do.
func lockDependencies(files map[string][]byte, lockPath string, proxy *lockfiles.Proxy) (map[string]lockfiles.Dependency, error) {
	parsed := lockfiles.ParseFiles(nil, proxy, files)
	out := map[string]lockfiles.Dependency{}
	dir := path.Dir(lockPath)
	found := false
	for _, f := range parsed {
		if path.Dir(f.Path) != dir {
			continue
		}
		if f.Path == lockPath {
			found = true
			if f.Error != "" {
				return nil, fmt.Errorf("%s: %s", f.Path, f.Error)
			}
		}
		for _, d := range f.Dependencies {
			out[d.Key()] = d
		}
	}
	if !found {
		return nil, fmt.Errorf("%s is not a lock file the parsers read", lockPath)
	}
	return out, nil
}
