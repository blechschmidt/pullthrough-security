package repos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/scan/watch"
)

// SyncResult summarizes one sync of a repository.
type SyncResult struct {
	Repo    string `json:"repo"`
	Tags    int    `json:"tags"`
	Created int    `json:"created"`
	Moved   int    `json:"moved"`
	Deleted int    `json:"deleted"`
	// Queued is how many releases were queued for pinning.
	Queued int `json:"queued"`
	// Initial reports the repository's first sync.
	Initial bool `json:"initial,omitempty"`
}

// liveFor returns the cached live state of a repository, loading it from the
// store on first use. Only a sync (under the repository's lock) writes it;
// everyone else reads a snapshot (liveSnapshot).
func (s *Service) liveFor(ctx context.Context, name string) (*liveState, error) {
	s.mu.RLock()
	live := s.live[name]
	s.mu.RUnlock()
	if live != nil {
		return live, nil
	}
	loaded, _, err := loadLive(ctx, s.st, name)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing := s.live[name]; existing != nil {
		// Another caller loaded it meanwhile; a sync may already have
		// written to that one.
		return existing, nil
	}
	s.live[name] = loaded
	return loaded, nil
}

// liveSnapshot returns a copy of a repository's live state for a reader. It
// takes no repository lock: a reader never waits for a sync's fetch.
func (s *Service) liveSnapshot(ctx context.Context, name string) (*liveState, error) {
	live, err := s.liveFor(ctx, name)
	if err != nil {
		return nil, err
	}
	return live.snapshot(), nil
}

// saveLive persists a live state (best effort: it is rebuilt from the history
// when lost). The caller is the sync holding the repository's lock, the only
// writer, so reading the state here races with nothing but readers.
func (s *Service) saveLive(ctx context.Context, live *liveState) {
	live.mu.RLock()
	data, err := json.Marshal(live)
	live.mu.RUnlock()
	if err == nil {
		err = s.st.Put(ctx, liveObject(live.Repo), data)
	}
	if err != nil {
		s.log.Warn("saving repository tracking state failed", "repo", live.Repo, "error", err)
	}
}

// Sync fetches a repository's tags and records what changed: a created,
// moved or deleted tag appends a history record and an audit event, and the
// commit a created or moved tag names is queued for pinning.
func (s *Service) Sync(ctx context.Context, name, trigger string) (SyncResult, error) {
	res, changed, err := s.sync(ctx, name, trigger)
	// The releases whose tags changed are announced once the repository's
	// lock is released (announcing reads the tags under it).
	for _, commit := range changed {
		s.notifyRelease(ctx, name, commit)
	}
	return res, err
}

// sync is Sync under the repository's lock; it returns the commits whose tags
// changed.
func (s *Service) sync(ctx context.Context, name, trigger string) (SyncResult, []string, error) {
	res := SyncResult{Repo: name}
	reg, ok := s.registration("", name)
	if !ok || reg.Removed {
		return res, nil, ErrNotFound
	}
	if s.opts.Refs == nil {
		return res, nil, errors.New("repos: no Git mirror is configured")
	}
	repo := reg.Repo
	unlock := s.locks.lock(name)
	defer unlock()

	live, err := s.liveFor(ctx, name)
	if err != nil {
		return res, nil, err
	}
	// Another replica may have appended to the history since this one read
	// it (a sync through its API): catch up first, or the diff would record
	// its changes a second time.
	if _, err := s.st.Get(ctx, historyObject(name, live.head()+1)); err == nil {
		s.mu.Lock()
		if s.live[name] == live {
			delete(s.live, name)
		}
		s.mu.Unlock()
		if live, err = s.liveFor(ctx, name); err != nil {
			return res, nil, err
		}
	} else if !errors.Is(err, ErrNotFound) {
		return res, nil, err
	}
	if live.HistoryError != "" {
		// A history that does not verify is not appended to: an appended
		// record would chain onto records that cannot be trusted.
		s.metrics().syncError(name)
		return res, nil, fmt.Errorf("repos: %s: %s", name, live.HistoryError)
	}
	start := s.now().UTC()
	live.update(func(l *liveState) { l.LastSync = start })

	cred, err := s.credential(ctx, repo)
	if err != nil {
		live.update(func(l *liveState) { l.LastError = "resolving credentials: " + err.Error() })
		s.saveLive(ctx, live)
		s.metrics().syncError(name)
		return res, nil, fmt.Errorf("repos: %s: resolving credentials: %w", name, err)
	}
	tips, err := s.opts.Refs.Tags(ctx, repo, cred)
	if err != nil {
		// A mirror that could not be refreshed tells nothing new; above all it
		// must not be read as every tag having been deleted.
		live.update(func(l *liveState) { l.LastError = err.Error() })
		s.saveLive(ctx, live)
		s.metrics().syncError(name)
		return res, nil, fmt.Errorf("repos: %s: %w", name, err)
	}
	for tag := range tips {
		if !repo.tagSelected(tag) || !validCommit(tips[tag].Commit) {
			delete(tips, tag)
		}
	}
	res.Tags = len(tips)

	initial := !live.Synced
	res.Initial = initial
	tags := make([]string, 0, len(tips))
	for t := range tips {
		tags = append(tags, t)
	}
	sort.Strings(tags)

	var recs []TagRecord
	for _, tag := range tags {
		tip := tips[tag]
		cur, known := live.Tags[tag]
		switch {
		case !known:
			recs = append(recs, TagRecord{Tag: tag, Kind: TagCreated, Commit: tip.Commit, Object: tip.Object, At: start, Initial: initial, Trigger: trigger})
		case cur.Commit != tip.Commit:
			recs = append(recs, TagRecord{Tag: tag, Kind: TagMoved, Commit: tip.Commit, Object: tip.Object, At: start, Trigger: trigger,
				Supersedes: cur.Seq, PreviousCommit: cur.Commit, PreviousLastSeen: cur.LastSeen})
		default:
			cur.LastSeen = start
			if tip.Object != "" {
				cur.Object = tip.Object
			}
			live.update(func(l *liveState) { l.Tags[tag] = cur })
		}
	}
	gone := make([]string, 0)
	for tag := range live.Tags {
		if _, ok := tips[tag]; !ok {
			gone = append(gone, tag)
		}
	}
	sort.Strings(gone)
	for _, tag := range gone {
		cur := live.Tags[tag]
		recs = append(recs, TagRecord{Tag: tag, Kind: TagDeleted, At: start, Trigger: trigger,
			Supersedes: cur.Seq, PreviousCommit: cur.Commit, PreviousLastSeen: cur.LastSeen})
	}

	written, err := appendRecords(ctx, s.st, live, recs)
	for _, r := range written {
		live.update(func(l *liveState) {
			switch r.Kind {
			case TagCreated, TagMoved:
				l.Tags[r.Tag] = liveTag{Commit: r.Commit, Object: r.Object, Seq: r.Seq, FirstSeen: r.At, LastSeen: r.At}
			case TagDeleted:
				delete(l.Tags, r.Tag)
			}
		})
		s.recordTagEvent(ctx, repo, r)
		switch r.Kind {
		case TagCreated:
			res.Created++
		case TagMoved:
			res.Moved++
		case TagDeleted:
			res.Deleted++
		}
	}
	appendErr := err
	if appendErr != nil {
		// The live state is reloaded from the history next time. What was
		// written is acted on below all the same: a recorded tag whose
		// release were not queued now would never be pinned, as the next
		// sync finds it already known.
		s.mu.Lock()
		delete(s.live, name)
		s.mu.Unlock()
		s.metrics().syncError(name)
	} else {
		done := s.now().UTC()
		live.update(func(l *liveState) {
			l.Synced = true
			l.LastSuccess = done
			l.LastError = ""
		})
		s.saveLive(ctx, live)
		s.metrics().setTags(name, len(live.Tags))
	}

	// Keep every commit a tag names reachable in the mirror, so that the
	// release can still be read after its tag moves.
	for _, r := range written {
		if r.Commit != "" {
			if err := s.opts.Refs.Keep(ctx, repo, r.Commit); err != nil {
				s.log.Warn("keeping a tagged commit in the mirror failed", "repo", name, "commit", r.Commit, "error", err)
			}
		}
	}

	res.Queued = s.queueReleases(ctx, repo, written, initial)
	if len(written) > 0 {
		s.log.Info("repository tags changed", "repo", name, "created", res.Created, "moved", res.Moved,
			"deleted", res.Deleted, "queued", res.Queued, "trigger", trigger)
	}
	var changed []string
	seen := map[string]bool{}
	for _, r := range written {
		for _, c := range []string{r.Commit, r.PreviousCommit} {
			if c != "" && !seen[c] {
				seen[c] = true
				changed = append(changed, c)
			}
		}
	}
	return res, changed, appendErr
}

// recordTagEvent writes a tag record to the audit log, counts it, and alerts
// on a tag that moved or disappeared — a release tag that is force-moved after
// publication is the classic sign of a tampered release.
func (s *Service) recordTagEvent(ctx context.Context, repo Repo, r TagRecord) {
	s.metrics().tagEvent(r.Kind)
	detail := map[string]any{
		"repo":    repo.Name,
		"tag":     r.Tag,
		"event":   r.Kind,
		"seq":     r.Seq,
		"trigger": r.Trigger,
		"hash":    r.Hash,
	}
	if r.Commit != "" {
		detail["commit"] = r.Commit
	}
	if r.PreviousCommit != "" {
		detail["previousCommit"] = r.PreviousCommit
	}
	if r.Initial {
		detail["initial"] = true
	}
	reason := fmt.Sprintf("tag %s %s", r.Tag, r.Kind)
	switch r.Kind {
	case TagCreated:
		reason += " at " + short(r.Commit)
	case TagMoved:
		reason += " from " + short(r.PreviousCommit) + " to " + short(r.Commit)
	case TagDeleted:
		reason += " (was " + short(r.PreviousCommit) + ")"
	}
	s.auditLog(ctx, audit.Event{
		Type:      audit.EventReleaseTag,
		Subject:   "system:repository-tracker",
		Team:      repo.Tenant,
		Ecosystem: "git",
		Resource:  "repo/" + repo.Name + "@" + r.Tag,
		Decision:  audit.DecisionAllow,
		Reason:    reason,
		Detail:    detail,
	})
	switch r.Kind {
	case TagMoved:
		s.emit(ctx, notify.ReleaseTagEvent(notify.SeverityHigh, repo.Name, r.Tag, r.Kind, r.PreviousCommit, r.Commit,
			"release tag "+r.Tag+" of "+repo.Name+" was moved to another commit; the release it named stays pinned"))
	case TagDeleted:
		s.emit(ctx, notify.ReleaseTagEvent(notify.SeverityMedium, repo.Name, r.Tag, r.Kind, r.PreviousCommit, "",
			"release tag "+r.Tag+" of "+repo.Name+" was deleted; the release it named stays pinned"))
	}
}

func short(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	return c
}

// queueReleases queues the commits of created and moved tags for pinning. At
// a repository's first sync only the BackfillTags most recently committed
// releases are pinned; the others are recorded and can be pinned on request.
func (s *Service) queueReleases(ctx context.Context, repo Repo, written []TagRecord, initial bool) int {
	type candidate struct {
		commit string
		tags   []string
		when   time.Time
	}
	byCommit := map[string]*candidate{}
	var order []string
	for _, r := range written {
		if r.Kind == TagDeleted || r.Commit == "" {
			continue
		}
		c := byCommit[r.Commit]
		if c == nil {
			c = &candidate{commit: r.Commit}
			byCommit[r.Commit] = c
			order = append(order, r.Commit)
		}
		c.tags = append(c.tags, r.Tag)
	}
	limit := len(order)
	if initial {
		backfill := *s.cfg.BackfillTags
		if repo.BackfillTags != nil {
			backfill = *repo.BackfillTags
		}
		if backfill >= 0 && backfill < limit {
			for _, commit := range order {
				t, err := s.opts.Refs.CommitTime(ctx, repo, commit)
				if err == nil {
					byCommit[commit].when = t
				}
			}
			sort.SliceStable(order, func(i, j int) bool { return byCommit[order[i]].when.After(byCommit[order[j]].when) })
			limit = backfill
		}
	}
	queued := 0
	for i, commit := range order {
		c := byCommit[commit]
		if i >= limit {
			// Recorded, not pinned: a manifest is created on request (Repin).
			continue
		}
		if err := s.ensurePending(ctx, repo, commit, c.tags); err != nil {
			s.log.Error("recording a release for pinning failed", "repo", repo.Name, "commit", commit, "error", err)
			continue
		}
		if s.enqueue(repo.Name, commit) {
			queued++
		}
	}
	return queued
}

// ensurePending makes sure a release has a manifest: a new one is created
// pending (so a restart resumes it), an existing one records the new tags.
func (s *Service) ensurePending(ctx context.Context, repo Repo, commit string, tags []string) error {
	unlock := s.locks.lock(manifestLock(repo.Name, commit))
	defer unlock()
	m, err := s.readManifest(ctx, repo.Name, commit)
	switch {
	case errors.Is(err, ErrNotFound):
		now := s.now().UTC()
		m = &Manifest{Repo: repo.Name, Tenant: repo.Tenant, Commit: commit, Status: ReleasePending, CreatedAt: now, UpdatedAt: now}
	case err != nil:
		return err
	}
	for _, t := range tags {
		m.addTag(t)
	}
	if m.Status != ReleasePending && m.FullyPinned {
		// Already pinned: the new tag only names the same release.
		return s.writeManifest(ctx, m)
	}
	if m.Status != ReleasePending {
		// A partial or failed release is retried now rather than at its
		// next scheduled attempt: a tag pointing at it again is a reason.
		m.NextAttempt = time.Time{}
	}
	return s.writeManifest(ctx, m)
}

func manifestLock(repo, commit string) string { return "manifest\x00" + repo + "\x00" + commit }

// --- webhook -----------------------------------------------------------------

// WebhookHandler receives push webhooks (GitHub/Gitea format, signed like the
// commit scanner's). A push of a tag of a registered repository syncs it;
// branch pushes are acknowledged and ignored. Without a webhook secret there
// is no receiver (nil): a delivery anyone can send would have the proxy fetch
// from the Git host on their say-so.
func (s *Service) WebhookHandler() http.Handler {
	if s.cfg.WebhookSecret == "" {
		return nil
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, watch.MaxWebhookBody+1))
		if err != nil || len(body) > watch.MaxWebhookBody {
			s.metrics().webhook("rejected")
			http.Error(w, "reading request body", http.StatusBadRequest)
			return
		}
		// The signature is checked before anything in the payload is read.
		if !watch.VerifySignature(s.cfg.WebhookSecret, r.Header, body) {
			s.metrics().webhook("rejected")
			s.log.Warn("repository webhook rejected: invalid or missing signature", "remote", r.RemoteAddr)
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
		switch ev := watch.WebhookEvent(r.Header); ev {
		case "ping":
			s.metrics().webhook("accepted")
			writeJSON(w, http.StatusOK, map[string]string{"status": "pong"})
			return
		case "", "push":
			// A push event covers tags too: created, force-updated and
			// deleted tags arrive as pushes of refs/tags/<name>.
		default:
			s.metrics().webhook("ignored")
			writeJSON(w, http.StatusAccepted, map[string]string{"status": "ignored", "event": ev})
			return
		}
		push, err := watch.ParsePush(body)
		if err != nil {
			s.metrics().webhook("rejected")
			http.Error(w, "malformed push payload", http.StatusBadRequest)
			return
		}
		var matched []string
		for _, repo := range s.tracked() {
			if push.Names(repo.URL, repo.FullName) {
				matched = append(matched, repo.Name)
			}
		}
		if len(matched) == 0 {
			s.metrics().webhook("rejected")
			http.Error(w, "repository not registered", http.StatusNotFound)
			return
		}
		ref := push.Ref
		if !strings.HasPrefix(ref, "refs/tags/") {
			s.metrics().webhook("ignored")
			writeJSON(w, http.StatusAccepted, map[string]any{"status": "ignored", "reason": "not a tag", "repos": matched})
			return
		}
		if !s.isLeader() {
			s.metrics().webhook("deferred")
			writeJSON(w, http.StatusAccepted, map[string]any{"status": "deferred", "reason": "another replica tracks repositories; its next poll picks the change up", "repos": matched})
			return
		}
		s.metrics().webhook("accepted")
		for _, name := range matched {
			s.goSync(name, "webhook")
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"status": "accepted", "repos": matched, "ref": ref})
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
