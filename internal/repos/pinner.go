package repos

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/repos/locate"
)

// pinJob pins one release.
type pinJob struct {
	repo   string
	commit string
}

func (j pinJob) key() string { return j.repo + "/" + j.commit }

// enqueue queues a release for pinning; it reports whether it was queued (a
// release already queued, or a full queue, is not — the pending manifest is
// picked up by the next sweep).
func (s *Service) enqueue(repo, commit string) bool {
	j := pinJob{repo: repo, commit: commit}
	s.qmu.Lock()
	defer s.qmu.Unlock()
	if s.queued[j.key()] {
		return false
	}
	select {
	case s.queue <- j:
		s.queued[j.key()] = true
		s.metrics().setQueue(len(s.queue))
		return true
	default:
		return false
	}
}

func (s *Service) dequeued(j pinJob) {
	s.qmu.Lock()
	delete(s.queued, j.key())
	s.qmu.Unlock()
	s.metrics().setQueue(len(s.queue))
}

func (s *Service) worker() {
	for {
		select {
		case <-s.runCtx.Done():
			return
		case j := <-s.queue:
			if !s.isLeader() {
				// Another replica pins. The release is pending in the shared
				// state, where the leader's sweep finds it.
				s.dequeued(j)
				continue
			}
			err := s.Pin(s.runCtx, j.repo, j.commit)
			switch {
			case errors.Is(err, errNotLeader):
				s.log.Info("stopped pinning a release: another replica leads now and resumes it", "repo", j.repo, "commit", j.commit)
			case err != nil && !errors.Is(err, context.Canceled):
				s.log.Error("pinning a release failed", "repo", j.repo, "commit", j.commit, "error", err)
			}
			s.dequeued(j)
		}
	}
}

// sweepPending queues releases that are pending, and partial or failed ones
// whose next attempt is due.
func (s *Service) sweepPending(ctx context.Context) {
	now := s.now()
	for _, m := range s.manifestHeads("") {
		if ctx.Err() != nil {
			return
		}
		reg, ok := s.registration("", m.Repo)
		if !ok || reg.Removed {
			continue
		}
		due := m.Status == ReleasePending ||
			(!m.FullyPinned && m.Attempts < s.cfg.MaxAttempts && !now.Before(m.NextAttempt))
		if due {
			s.enqueue(m.Repo, m.Commit)
		}
	}
}

// Repin queues a release for pinning now: a commit a tag pointed at that was
// not pinned at the first sync, or one whose pins are incomplete. The commit
// must have been seen in the repository's tag history.
func (s *Service) Repin(ctx context.Context, tenant, name, commit string) error {
	reg, ok := s.registration(tenant, name)
	if !ok || reg.Removed {
		return ErrNotFound
	}
	commit = strings.ToLower(strings.TrimSpace(commit))
	if !validCommit(commit) {
		return &ValidationError{Err: fmt.Errorf("%q is not a full commit ID", commit)}
	}
	records, err := loadHistory(ctx, s.st, name)
	if err != nil && !errors.Is(err, ErrHistoryTampered) {
		return err
	}
	var tags []string
	for _, r := range records {
		if r.Commit == commit {
			tags = append(tags, r.Tag)
		}
	}
	if len(tags) == 0 {
		return &ValidationError{Err: fmt.Errorf("no tag of %s has pointed at %s", name, commit)}
	}
	unlock := s.locks.lock(manifestLock(name, commit))
	m, err := s.readManifest(ctx, name, commit)
	switch {
	case errors.Is(err, ErrNotFound):
		now := s.now().UTC()
		m = &Manifest{Repo: name, Tenant: reg.Tenant, Commit: commit, Status: ReleasePending, CreatedAt: now, UpdatedAt: now}
	case err != nil:
		unlock()
		return err
	}
	for _, t := range tags {
		m.addTag(t)
	}
	m.NextAttempt = time.Time{}
	if m.Attempts >= s.cfg.MaxAttempts {
		m.Attempts = 0 // an operator asked: the attempt budget starts over
	}
	err = s.writeManifest(ctx, m)
	unlock()
	if err != nil {
		return err
	}
	s.enqueue(name, commit)
	return nil
}

// Pin pins one release: it reads the lock files at the commit, fetches every
// dependency through the proxy, and stores the manifest. Dependencies a
// previous attempt pinned are kept as they are; the others are tried again.
//
// One job per release runs at a time (the "pinjob" lock). The manifest's own
// lock is held only to read and to write the manifest, never across the
// fetches: a sync that records a new tag of the release (ensurePending) must
// not wait for a job that may run for hours, nor hold up the reads of every
// other release of the repository meanwhile.
func (s *Service) Pin(ctx context.Context, name, commit string) error {
	reg, ok := s.registration("", name)
	if !ok {
		return ErrNotFound
	}
	unlock := s.locks.lock(pinJobLock(name, commit))
	err := s.pinJob(ctx, reg.Repo, commit)
	unlock()
	if err == nil {
		s.notifyRelease(ctx, name, commit)
	}
	return err
}

func pinJobLock(repo, commit string) string { return "pinjob\x00" + repo + "\x00" + commit }

// errNotLeader stops a job whose replica lost the leadership: the new leader
// resumes the release, and two replicas must not write its manifest at once.
var errNotLeader = errors.New("repos: this replica no longer leads")

// checkpointInterval is how often a running job stores what it has pinned so
// far: a pin becomes durable — visible to other replicas, safe from eviction
// after a crash — within this long of its fetch, not at the end of the job.
const checkpointInterval = 30 * time.Second

// pinJob is Pin under the release's job lock.
func (s *Service) pinJob(ctx context.Context, repo Repo, commit string) error {
	name := repo.Name
	m, err := s.lockedRead(ctx, repo, commit)
	if err != nil {
		return err
	}
	job := pinJob{repo: name, commit: commit}.key()
	// The job's holds outlive its last write of the manifest: what it pins is
	// held from its fetch until the stored manifest pins it.
	defer s.idx.release(job)

	start := s.now()
	m.Attempts++
	m.Tenant = repo.Tenant
	prior := map[string]Dependency{}
	for _, d := range m.Dependencies {
		if d.Status == StatusPinned {
			prior[d.key()] = d
		}
	}

	if err := s.readLockfiles(ctx, repo, m); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		m.LockFiles = nil
		m.Dependencies = mergePrior(nil, prior)
		m.settle()
		m.Status, m.FullyPinned = ReleaseFailed, false
		m.Reason = "reading the lock files at " + short(commit) + ": " + err.Error()
		s.finish(ctx, repo, m, start)
		return nil
	}

	work := make([]int, 0, len(m.Dependencies))
	for i, d := range m.Dependencies {
		if p, ok := prior[d.key()]; ok {
			p.Files = d.Files
			m.Dependencies[i] = p
			continue
		}
		work = append(work, i)
	}

	// Workers pin dependencies; this goroutine alone writes the manifest,
	// applying their results and checkpointing as it goes.
	type result struct {
		i   int
		dep Dependency
	}
	results := make(chan result)
	env := s.locateEnv(repo)
	sem := make(chan struct{}, s.cfg.Concurrency)
	jobCtx, cancelJob := context.WithCancel(ctx)
	defer cancelJob()
	var wg sync.WaitGroup
	go func() {
		for _, i := range work {
			if jobCtx.Err() != nil {
				break
			}
			sem <- struct{}{}
			wg.Add(1)
			dep := m.Dependencies[i] // copied before any result is applied
			go func(i int, dep Dependency) {
				defer wg.Done()
				defer func() { <-sem }()
				s.pinDependency(jobCtx, repo, job, env, &dep)
				results <- result{i: i, dep: dep}
			}(i, dep)
		}
		wg.Wait()
		close(results)
	}()
	lastCheckpoint := s.now()
	lostLead := false
	for r := range results {
		m.Dependencies[r.i] = r.dep
		if !lostLead && !s.isLeader() {
			// Another replica leads, and pins, now: this one stops and
			// writes nothing more. What it checkpointed stays pinned.
			lostLead = true
			cancelJob()
		}
		if !lostLead && s.now().Sub(lastCheckpoint) >= checkpointInterval {
			lastCheckpoint = s.now()
			s.checkpoint(ctx, m)
		}
	}
	if lostLead {
		return errNotLeader
	}
	if ctx.Err() != nil {
		// Shutting down: what was checkpointed stays pinned, the release stays
		// pending and is resumed after the restart.
		return ctx.Err()
	}
	m.settle()
	s.finish(ctx, repo, m, start)
	return nil
}

// lockedRead reads a release's manifest under its lock (a new one when there
// is none).
func (s *Service) lockedRead(ctx context.Context, repo Repo, commit string) (*Manifest, error) {
	unlock := s.locks.lock(manifestLock(repo.Name, commit))
	defer unlock()
	m, err := s.readManifest(ctx, repo.Name, commit)
	if errors.Is(err, ErrNotFound) {
		now := s.now().UTC()
		return &Manifest{Repo: repo.Name, Tenant: repo.Tenant, Commit: commit, Status: ReleasePending, CreatedAt: now}, nil
	}
	return m, err
}

// lockedWrite stores a job's manifest under the manifest's lock, keeping the
// tags recorded meanwhile by a sync (ensurePending) — the job's copy predates
// them.
func (s *Service) lockedWrite(ctx context.Context, m *Manifest) error {
	unlock := s.locks.lock(manifestLock(m.Repo, m.Commit))
	defer unlock()
	if cur, err := s.readManifest(ctx, m.Repo, m.Commit); err == nil {
		for _, t := range cur.Tags {
			m.addTag(t)
		}
	}
	return s.writeManifest(ctx, m)
}

// checkpoint stores a running job's progress: the release stays pending, the
// objects pinned so far are pinned durably.
func (s *Service) checkpoint(ctx context.Context, m *Manifest) {
	cp := *m
	cp.Dependencies = append([]Dependency(nil), m.Dependencies...)
	cp.summarize()
	cp.Status, cp.FullyPinned, cp.Reason = ReleasePending, false, "being pinned"
	cp.UpdatedAt = s.now().UTC()
	if err := s.lockedWrite(ctx, &cp); err != nil {
		s.log.Warn("checkpointing a release failed", "repo", m.Repo, "commit", m.Commit, "error", err)
		return
	}
	for _, t := range cp.Tags {
		m.addTag(t)
	}
}

// readLockfiles scans the commit's lock files into the manifest.
func (s *Service) readLockfiles(ctx context.Context, repo Repo, m *Manifest) error {
	if s.opts.Scanner == nil {
		return errors.New("no lock-file scanner is configured")
	}
	opts := s.cfg.Lockfiles
	opts.Include = append([]string(nil), repo.Lockfiles...)
	rep, err := s.opts.Scanner.Scan(ctx, repo, m.Commit, opts)
	if err != nil {
		return err
	}
	m.LockFiles = m.LockFiles[:0]
	m.Skipped = rep.Skipped
	m.Truncated = rep.Truncated
	m.Submodule = rep.Submodules
	byKey := map[string]int{}
	var deps []Dependency
	for _, f := range rep.Files {
		lf := LockFile{Path: f.Path, Type: f.Type, Format: f.Format, FormatVersion: f.FormatVersion,
			Dependencies: len(f.Dependencies), Warnings: len(f.Warnings), Error: f.Error}
		m.LockFiles = append(m.LockFiles, lf)
		for _, d := range f.Dependencies {
			if d.Dev && !*s.cfg.IncludeDev {
				continue
			}
			dep := fromLockfile(d)
			k := dep.key()
			if i, ok := byKey[k]; ok {
				deps[i].Files = appendUniqueString(deps[i].Files, fmt.Sprintf("%s:%d", d.File, d.Line))
				deps[i].LockDigests = mergeDigests(deps[i].LockDigests, d.Digests)
				deps[i].Dev = deps[i].Dev && d.Dev
				continue
			}
			if len(deps) >= s.cfg.MaxDependencies {
				m.Truncated = fmt.Sprintf("the lock files pin more than %d dependencies", s.cfg.MaxDependencies)
				continue
			}
			byKey[k] = len(deps)
			deps = append(deps, dep)
		}
	}
	sort.SliceStable(deps, func(i, j int) bool { return deps[i].Coordinate() < deps[j].Coordinate() })
	m.Dependencies = deps
	return nil
}

func fromLockfile(d lockfiles.Dependency) Dependency {
	return Dependency{
		Type: lockfiles.CanonicalType(d.Type), Name: d.Name, Version: d.Version, ID: d.ID,
		Source: d.Source, Registry: d.Registry, Revision: d.Revision, Dev: d.Dev,
		Files:       []string{fmt.Sprintf("%s:%d", d.File, d.Line)},
		LockDigests: append([]lockfiles.Digest(nil), d.Digests...),
		Unverified:  d.Unverified, UnverifiedReason: d.UnverifiedReason,
		Status: StatusFailed,
		// The rest of the lock file's record is what locating needs.
		lock: d,
	}
}

// mergePrior keeps the pinned dependencies of an earlier attempt when the
// lock files could not be read this time.
func mergePrior(deps []Dependency, prior map[string]Dependency) []Dependency {
	keys := make([]string, 0, len(prior))
	for k := range prior {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		deps = append(deps, prior[k])
	}
	return deps
}

func mergeDigests(a, b []lockfiles.Digest) []lockfiles.Digest {
	seen := map[string]bool{}
	for _, d := range a {
		seen[d.String()] = true
	}
	for _, d := range b {
		if !seen[d.String()] {
			seen[d.String()] = true
			a = append(a, d)
		}
	}
	return a
}

func appendUniqueString(list []string, s string) []string {
	for _, e := range list {
		if e == s {
			return list
		}
	}
	return append(list, s)
}

// locateEnv is the locating environment of a repository's dependencies.
func (s *Service) locateEnv(repo Repo) locate.Env {
	prefer := map[string]string{}
	for t, up := range repo.Upstreams {
		prefer[lockfiles.CanonicalType(t)] = up
	}
	return locate.Env{
		Upstreams:    s.opts.Upstreams,
		Prefer:       prefer,
		Fetch:        documentFetcher{s: s, tenant: repo.Tenant, roles: s.rolesFor(repo)},
		Platforms:    s.cfg.Platforms,
		MaxArtifacts: s.cfg.MaxArtifactsPerDependency,
	}
}

// pinDependency fetches one dependency's objects and records the outcome.
func (s *Service) pinDependency(ctx context.Context, repo Repo, job string, env locate.Env, dep *Dependency) {
	dep.Objects, dep.Notes, dep.Reason, dep.Upstream = nil, nil, "", ""
	plan, err := locate.Locate(ctx, env, dep.lock)
	if err != nil {
		var refused *locate.RefusedError
		switch {
		case locate.IsUnsupported(err):
			dep.Status, dep.Reason = StatusUnsupported, err.Error()
			s.metrics().pinFailure("unsupported")
		case errors.As(err, &refused):
			// A gate refused the registry document the dependency is found
			// through (its POM, its image manifest): the dependency is refused.
			dep.Status, dep.Reason = StatusRefused, err.Error()
			s.metrics().pinFailure("refused")
		default:
			dep.Status, dep.Reason = StatusFailed, err.Error()
			s.metrics().pinFailure("locate")
		}
		return
	}
	dep.Upstream, dep.Notes = plan.Upstream, plan.Notes
	for _, a := range plan.Artifacts {
		if ctx.Err() != nil {
			return
		}
		obj := s.fetchObject(ctx, repo, job, a)
		if obj.HTTPStatus == http.StatusNotFound && a.Fallback != "" {
			a.Path = a.Fallback
			obj = s.fetchObject(ctx, repo, job, a)
		}
		dep.Objects = append(dep.Objects, obj)
	}
	dep.Status, dep.Reason = dependencyStatus(dep.Objects)
	switch dep.Status {
	case StatusPinned:
	case StatusRefused:
		s.metrics().pinFailure("refused")
	case StatusMismatch:
		s.metrics().pinFailure("digest")
	default:
		s.metrics().pinFailure("fetch")
	}
}

// dependencyStatus derives a dependency's status from its objects: pinned when
// every object it needs is; otherwise the worst outcome, with its reason.
func dependencyStatus(objs []Object) (string, string) {
	rank := map[string]int{StatusMismatch: 4, StatusRefused: 3, StatusFailed: 2, StatusUncached: 1}
	worst, reason := "", ""
	for _, o := range objs {
		if o.Optional || o.Status == StatusPinned || o.Status == StatusSkipped {
			continue
		}
		if rank[o.Status] > rank[worst] || worst == "" {
			worst = o.Status
			reason = o.Reason
			if o.File != "" {
				reason = o.File + ": " + reason
			}
		}
	}
	switch worst {
	case "":
		return StatusPinned, ""
	case StatusUncached:
		return StatusFailed, reason
	default:
		return worst, reason
	}
}

// fetchObject drives one object through the proxy and judges the result.
func (s *Service) fetchObject(ctx context.Context, repo Repo, job string, a locate.Artifact) Object {
	obj := Object{Role: a.Role, File: a.File, Upstream: a.Upstream, Path: "/v1/" + a.Upstream + a.Path, Optional: a.Optional, FetchedAt: s.now().UTC()}
	if a.Error != "" {
		obj.Status, obj.Reason = StatusFailed, a.Error
		return obj
	}
	if s.opts.Fetcher == nil {
		obj.Status, obj.Reason = StatusFailed, "no fetcher is configured"
		return obj
	}
	chk, err := locate.NewChecker(a, s.cfg.SpoolDir)
	if err != nil {
		obj.Status, obj.Reason = StatusFailed, err.Error()
		return obj
	}
	defer chk.Close()
	var held string
	res, err := s.opts.Fetcher.Fetch(ctx, FetchRequest{
		Upstream: a.Upstream, Path: a.Path, Accept: a.Accept,
		Tenant: repo.Tenant, Subject: s.cfg.Subject, Roles: s.rolesFor(repo),
		Hold: func(key string) {
			held = key
			s.idx.hold(job, key)
		},
	}, chk)
	obj.HTTPStatus, obj.Cache, obj.Verdicts = res.Status, res.Cache, res.Verdicts
	obj.CacheKey, obj.Digest, obj.Size = res.CacheKey, res.Digest, res.Size
	if held != "" && obj.CacheKey == "" {
		obj.CacheKey = held
	}
	switch {
	case err != nil:
		obj.Status, obj.Reason = StatusFailed, err.Error()
	case res.Gate != "":
		obj.Status, obj.Gate, obj.Code = StatusRefused, res.Gate, res.Code
		obj.Reason = refusalReason(res)
	case res.Status == http.StatusOK && obj.CacheKey != "":
		check := chk.Result()
		obj.Check = &check
		if obj.Digest == "" {
			obj.Digest = check.SHA256
		}
		if obj.Size == 0 {
			obj.Size = check.Size
		}
		switch {
		case obj.Digest != check.SHA256:
			obj.Status = StatusFailed
			obj.Reason = "the bytes served (" + check.SHA256 + ") are not those the cache recorded (" + obj.Digest + ")"
		case check.Status == locate.CheckMismatch:
			obj.Status, obj.Reason = StatusMismatch, check.Detail
			s.reportMismatch(ctx, repo, a, check)
		default:
			obj.Status = StatusPinned
		}
	case res.Status == http.StatusOK:
		if a.Optional {
			obj.Status, obj.Reason = StatusSkipped, "served without caching"
		} else {
			obj.Status, obj.Reason = StatusUncached, "the proxy serves this object without caching it, so there is nothing to pin"
		}
	case res.Status == http.StatusNotFound && a.Optional:
		obj.Status, obj.Reason = StatusSkipped, "not found upstream"
	case res.Status == http.StatusNotFound:
		obj.Status, obj.Reason = StatusFailed, "not found upstream"
	default:
		obj.Status = StatusFailed
		obj.Reason = fmt.Sprintf("the proxy answered %d", res.Status)
		if res.Reason != "" {
			obj.Reason += ": " + res.Reason
		}
	}
	return obj
}

func refusalReason(res FetchResult) string {
	var parts []string
	if res.Gate != "" {
		parts = append(parts, "refused by "+res.Gate)
	} else {
		parts = append(parts, "refused")
	}
	if res.Code != "" {
		parts = append(parts, "("+res.Code+")")
	}
	out := strings.Join(parts, " ")
	if res.Reason != "" {
		out += ": " + res.Reason
	}
	return out
}

// reportMismatch records bytes that do not match the lock file: the proxy
// served something other than what the release was built with.
func (s *Service) reportMismatch(ctx context.Context, repo Repo, a locate.Artifact, check locate.CheckResult) {
	s.auditLog(ctx, audit.Event{
		Type:     audit.EventReleasePin,
		Subject:  s.cfg.Subject,
		Team:     repo.Tenant,
		Backend:  a.Upstream,
		Resource: "/v1/" + a.Upstream + a.Path,
		Decision: audit.DecisionDeny,
		Reason:   "lock-file digest mismatch: " + check.Detail,
		Detail:   map[string]any{"repo": repo.Name, "event": "digest-mismatch", "file": a.File, "sha256": check.SHA256, "checked": check.Checked},
	})
	s.emit(ctx, notify.ReleasePinEvent(notify.SeverityHigh, repo.Name, "", "digest-mismatch",
		a.Upstream+a.Path, "the proxy served "+a.File+" with a digest other than the lock file records: "+check.Detail))
}

// finish stores a manifest after an attempt, having checked that the objects
// it pins are still in the cache (the job's holds keep them there until it is
// stored), schedules the next attempt, and reports.
func (s *Service) finish(ctx context.Context, repo Repo, m *Manifest, start time.Time) {
	now := s.now().UTC()
	m.UpdatedAt = now
	// An object evicted between its fetch and its hold is not pinned after
	// all: check before the manifest says it is.
	if s.opts.Cache != nil && s.verifyPresent(ctx, m) {
		m.settle()
	}
	m.NextAttempt = time.Time{}
	if !m.FullyPinned && m.Attempts < s.cfg.MaxAttempts {
		backoff := s.cfg.RetryInterval << uint(min(m.Attempts-1, 10))
		m.NextAttempt = now.Add(backoff)
	}
	if err := s.lockedWrite(ctx, m); err != nil {
		s.log.Error("storing a release manifest failed; its pins are held only until the job ends", "repo", m.Repo, "commit", m.Commit, "error", err)
		s.metrics().pinFailure("store")
		return
	}
	s.metrics().release(m.Status, s.now().Sub(start))
	s.refreshPinMetrics()

	decision := audit.DecisionAllow
	if !m.FullyPinned {
		decision = audit.DecisionDeny
	}
	s.auditLog(ctx, audit.Event{
		Type:     audit.EventReleasePin,
		Subject:  s.cfg.Subject,
		Team:     m.Tenant,
		Resource: "repo/" + m.Repo + "@" + m.Commit,
		Decision: decision,
		Reason:   "release " + m.Status + firstNonEmpty(": "+m.Reason, ""),
		Detail: map[string]any{
			"repo": m.Repo, "commit": m.Commit, "tags": strings.Join(m.Tags, ","), "status": m.Status,
			"dependencies": m.Summary.Dependencies, "pinned": m.Summary.Pinned, "refused": m.Summary.Refused,
			"failed": m.Summary.Failed, "unsupported": m.Summary.Unsupported, "mismatched": m.Summary.Mismatched,
			"pinnedObjects": m.Summary.PinnedObjects, "pinnedBytes": m.Summary.PinnedBytes, "attempt": m.Attempts,
		},
	})
	if !m.FullyPinned && (m.Attempts == 1 || m.Attempts >= s.cfg.MaxAttempts) {
		sev := notify.SeverityMedium
		if m.Summary.Refused > 0 || m.Summary.Mismatched > 0 {
			sev = notify.SeverityHigh
		}
		s.emit(ctx, notify.ReleasePinEvent(sev, m.Repo, m.Commit, m.Status, "", "release "+strings.Join(m.Tags, ", ")+" is not fully pinned: "+m.Reason))
	}
	s.log.Info("release pinned", "repo", m.Repo, "commit", short(m.Commit), "tags", m.Tags, "status", m.Status,
		"dependencies", m.Summary.Dependencies, "pinned", m.Summary.Pinned, "objects", m.Summary.PinnedObjects,
		"attempt", m.Attempts, "took", s.now().Sub(start).Round(time.Millisecond))
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(strings.TrimPrefix(a, ":")) != "" {
		return a
	}
	return b
}

// verifyPresent marks pinned objects that are no longer in the cache; it
// reports whether it changed anything.
func (s *Service) verifyPresent(ctx context.Context, m *Manifest) bool {
	changed := false
	for i := range m.Dependencies {
		d := &m.Dependencies[i]
		for j := range d.Objects {
			o := &d.Objects[j]
			if o.Status != StatusPinned || o.CacheKey == "" {
				continue
			}
			ok, err := s.opts.Cache.Exists(ctx, o.CacheKey)
			if err != nil || ok {
				continue
			}
			o.Status, o.Reason = StatusFailed, "the object left the cache before its pin was stored"
			changed = true
		}
		if changed {
			d.Status, d.Reason = dependencyStatus(d.Objects)
		}
	}
	return changed
}

// refreshPinMetrics publishes the pin set's size.
func (s *Service) refreshPinMetrics() {
	objects, bytes := s.idx.stats()
	s.metrics().setPins(objects, bytes)
}

// documentFetcher reads index documents through the proxy for locating.
type documentFetcher struct {
	s      *Service
	tenant string
	roles  []string
}

// rolesFor returns the access-control roles a repository's dependencies are
// fetched with: its own, or the service default.
func (s *Service) rolesFor(repo Repo) []string {
	if len(repo.Roles) > 0 {
		return append([]string(nil), repo.Roles...)
	}
	return append([]string(nil), s.cfg.Roles...)
}

// maxDocumentBytes bounds an index document read for locating.
const maxDocumentBytes = 64 << 20

func (f documentFetcher) FetchDocument(ctx context.Context, upstream, path, accept string) (locate.Document, error) {
	if f.s.opts.Fetcher == nil {
		return locate.Document{}, errors.New("no fetcher is configured")
	}
	buf := &boundedBuffer{max: maxDocumentBytes}
	res, err := f.s.opts.Fetcher.Fetch(ctx, FetchRequest{Upstream: upstream, Path: path, Accept: accept,
		Tenant: f.tenant, Subject: f.s.cfg.Subject, Roles: f.roles}, buf)
	if err != nil {
		return locate.Document{}, err
	}
	if buf.overflow {
		return locate.Document{}, fmt.Errorf("the document is larger than %d bytes", maxDocumentBytes)
	}
	if res.Gate != "" {
		return locate.Document{Status: res.Status}, &locate.RefusedError{Gate: res.Gate, Code: res.Code, Reason: res.Reason}
	}
	return locate.Document{Status: res.Status, ContentType: res.ContentType, Body: buf.Bytes()}, nil
}

// boundedBuffer collects up to max bytes and remembers an overflow.
type boundedBuffer struct {
	bytes.Buffer
	max      int
	overflow bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.max {
		b.overflow = true
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

// --- integrity repair -------------------------------------------------------

// RepairPinned is called when the cache found a pinned object's bytes corrupted
// and removed them: it fetches the object again through the proxy and checks
// that the fresh bytes are the ones the release pinned. When they cannot be
// fetched, or are different, it raises an alert. It runs in the background and
// reports whether a repair was started.
func (s *Service) RepairPinned(key string) bool {
	ids := s.idx.pinnedBy(key)
	if len(ids) == 0 {
		return false
	}
	s.repairMu.Lock()
	if s.repairing[key] {
		s.repairMu.Unlock()
		return true
	}
	s.repairing[key] = true
	s.repairMu.Unlock()
	done := func() {
		s.repairMu.Lock()
		delete(s.repairing, key)
		s.repairMu.Unlock()
	}
	started := s.spawn(func() {
		defer done()
		ctx, cancel := context.WithTimeout(s.runCtx, 30*time.Minute)
		defer cancel()
		s.repair(ctx, key, ids)
	})
	if !started {
		done() // shutting down: the next start's integrity check finds it again
	}
	return true
}

func (s *Service) repair(ctx context.Context, key string, ids []string) {
	// Find a record of the object: where it was fetched from, what it was.
	var (
		repo  Repo
		found *Object
		owner *Manifest
	)
	for _, id := range ids {
		name, commit := splitManifestID(id)
		m, err := s.readManifest(ctx, name, commit)
		if err != nil {
			continue
		}
		for i := range m.Dependencies {
			for j := range m.Dependencies[i].Objects {
				o := &m.Dependencies[i].Objects[j]
				if o.CacheKey == key && o.Status == StatusPinned {
					found, owner = o, m
					break
				}
			}
			if found != nil {
				break
			}
		}
		if found != nil {
			if reg, ok := s.registration("", name); ok {
				repo = reg.Repo
			} else {
				repo = Repo{Name: name, Tenant: m.Tenant}
			}
			break
		}
	}
	if found == nil {
		return
	}
	want := found.Digest
	upstream := found.Upstream
	backendPath := strings.TrimPrefix(found.Path, "/v1/"+upstream)
	art := locate.Artifact{Upstream: upstream, Path: backendPath, Role: found.Role, File: found.File}
	if found.Role == "manifest" || found.Role == "index" {
		art.Accept = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"
	}
	obj := s.fetchObject(ctx, repo, "repair:"+key, art)
	s.idx.release("repair:" + key)
	ok := obj.Status == StatusPinned && obj.CacheKey == key && obj.Digest == want
	s.metrics().repair(ok)
	detail := map[string]any{"key": key, "releases": strings.Join(ids, ","), "expected": want, "got": obj.Digest, "status": obj.Status}
	if ok {
		s.auditLog(ctx, audit.Event{Type: audit.EventReleasePin, Subject: s.cfg.Subject, Team: repo.Tenant, Backend: upstream,
			Resource: found.Path, Decision: audit.DecisionAllow, Reason: "pinned object restored after an integrity failure", Detail: detail})
		s.log.Warn("pinned object restored after an integrity failure", "key", key, "releases", ids)
		s.recordRepair(ctx, ids, key, "")
		return
	}
	reason := "the pinned object could not be fetched again: " + firstNonEmpty(obj.Reason, obj.Status)
	if obj.Status == StatusPinned && obj.Digest != want {
		reason = "the object fetched again is not the one the release pinned (" + obj.Digest + " instead of " + want + ")"
	}
	// The releases no longer have their object. Their manifests say so, and
	// the key is no longer pinned for them: whatever the cache now holds under
	// it — the bytes the upstream serves today, if it serves any — is an
	// ordinary cache entry, not one the pin would keep forever and an
	// administrator could not purge.
	s.recordRepair(ctx, ids, key, "lost to an integrity failure: "+reason)
	s.auditLog(ctx, audit.Event{Type: audit.EventReleasePin, Subject: s.cfg.Subject, Team: repo.Tenant, Backend: upstream,
		Resource: found.Path, Decision: audit.DecisionDeny, Reason: reason, Detail: detail})
	s.emit(ctx, notify.ReleasePinEvent(notify.SeverityCritical, owner.Repo, owner.Commit, "pin-lost", found.Path, reason))
	s.log.Error("a pinned object was lost to an integrity failure", "key", key, "releases", ids, "reason", reason)
}

// recordRepair updates the manifests that pin key after a repair: a restored
// object counts a repair; a lost one (lost != "") is marked failed with the
// reason, and its key stops being pinned by those releases.
func (s *Service) recordRepair(ctx context.Context, ids []string, key, lost string) {
	for _, id := range ids {
		name, commit := splitManifestID(id)
		// The job lock first, as Pin takes it: a running job's final write
		// must not undo this record.
		unlockJob := s.locks.lock(pinJobLock(name, commit))
		unlock := s.locks.lock(manifestLock(name, commit))
		if m, err := s.readManifest(ctx, name, commit); err == nil {
			for i := range m.Dependencies {
				d := &m.Dependencies[i]
				touched := false
				for j := range d.Objects {
					o := &d.Objects[j]
					if o.CacheKey != key || o.Status != StatusPinned {
						continue
					}
					touched = true
					if lost == "" {
						o.Repairs++
					} else {
						o.Status, o.Reason = StatusFailed, lost
					}
				}
				if touched && lost != "" {
					d.Status, d.Reason = dependencyStatus(d.Objects)
				}
			}
			if lost != "" {
				m.settle()
				if m.Attempts >= s.cfg.MaxAttempts {
					m.Attempts = s.cfg.MaxAttempts - 1 // one more attempt to fetch it again
				}
				m.NextAttempt = s.now().Add(s.cfg.RetryInterval)
			}
			var drop []string
			if lost != "" {
				drop = []string{key}
			}
			if err := s.writeManifest(ctx, m, drop...); err != nil {
				s.log.Warn("recording an integrity repair in the release manifest failed", "repo", name, "commit", commit, "error", err)
			}
		}
		unlock()
		unlockJob()
	}
	s.refreshPinMetrics()
}
