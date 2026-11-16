package fullmirror

import (
	"regexp"
	"strings"
	"time"
)

// Status is the engine's state, for GET /api/fullmirror/status, `ptctl
// fullmirror status` and the metrics.
type Status struct {
	// Enabled reports that at least one upstream is mirrored.
	Enabled bool `json:"enabled"`
	// Running reports that the followers have been started; Attached that the
	// engine has the gateway to fetch through; Leader that this replica leads
	// the full mirror (only the leader polls and fetches).
	Running  bool `json:"running"`
	Attached bool `json:"attached"`
	Leader   bool `json:"leader"`
	// StateDir is where the state is kept; Tenant and Subject who the mirror
	// fetches as.
	StateDir string `json:"stateDir,omitempty"`
	Tenant   string `json:"tenant,omitempty"`
	Subject  string `json:"subject,omitempty"`
	// Paused reports the operators' global pause.
	Paused      bool      `json:"paused"`
	PausedBy    string    `json:"pausedBy,omitempty"`
	PausedAt    time.Time `json:"pausedAt,omitzero"`
	PauseReason string    `json:"pauseReason,omitempty"`
	// Lockdown is the mode of an engaged emergency lockdown, which holds the
	// mirror.
	Lockdown string `json:"lockdown,omitempty"`
	// Totals sum the upstreams.
	Totals Totals `json:"totals"`
	// Upstreams are the mirrored upstreams, by name.
	Upstreams []UpstreamStatus `json:"upstreams"`
}

// Totals are the sums over every mirrored upstream.
type Totals struct {
	Upstreams     int    `json:"upstreams"`
	Queued        int    `json:"queued"`
	Packages      uint64 `json:"packages"`
	PackageErrors uint64 `json:"packageErrors"`
	Fetched       uint64 `json:"fetched"`
	FetchedBytes  uint64 `json:"fetchedBytes"`
	Refused       uint64 `json:"refused"`
	Failed        uint64 `json:"failed"`
	Skipped       uint64 `json:"skipped"`
	Deferred      int    `json:"deferred"`
	BudgetBytes   int64  `json:"budgetBytes"`
	BudgetUsed    int64  `json:"budgetUsedBytes"`
}

// UpstreamStatus is one mirrored upstream's state.
type UpstreamStatus struct {
	Upstream string `json:"upstream"`
	Type     string `json:"type"`
	// Tier is the registry's tier in the full-mirroring catalog.
	Tier string `json:"tier,omitempty"`
	// State is what the follower is doing or waiting for (StateFollowing,
	// StatePaused, …); Detail says more.
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
	// Phase is "bootstrap" until the registry has been enumerated once,
	// "follow" after; Cursor is where the next poll continues.
	Phase  string `json:"phase,omitempty"`
	Cursor string `json:"cursor,omitempty"`
	DryRun bool   `json:"dryRun"`
	// Paused reports this upstream's own pause (see Status.Paused for the
	// global one).
	Paused        bool      `json:"paused"`
	PausedBy      string    `json:"pausedBy,omitempty"`
	PausedAt      time.Time `json:"pausedAt,omitzero"`
	PauseReason   string    `json:"pauseReason,omitempty"`
	ResyncPending bool      `json:"resyncPending,omitempty"`
	Policy        Policy    `json:"policy"`
	// The feed as of the last poll.
	LastPoll          time.Time `json:"lastPoll,omitzero"`
	LastChange        time.Time `json:"lastChange,omitzero"`
	LastCommit        time.Time `json:"lastCommit,omitzero"`
	NextPoll          time.Time `json:"nextPoll,omitzero"`
	BackoffUntil      time.Time `json:"backoffUntil,omitzero"`
	BootstrapStarted  time.Time `json:"bootstrapStarted,omitzero"`
	BootstrapFinished time.Time `json:"bootstrapFinished,omitzero"`
	FeedHead          string    `json:"feedHead,omitempty"`
	// Lag is how many changes the mirror is behind the feed's head, and
	// LagSeconds how far behind in time, when the feed says.
	Lag        *int64   `json:"lag,omitempty"`
	LagSeconds *float64 `json:"lagSeconds,omitempty"`
	// Queued is how many changes of the current batch are still to do;
	// InFlight how many files are being fetched.
	Queued   int `json:"queued"`
	InFlight int `json:"inFlight"`
	// Deferred is how many files wait in the deferred queue — refused for
	// now by a gate (a maturity cooldown, a scanner that could not judge
	// them) — and NextDeferred when the first of them is asked for again.
	Deferred     int       `json:"deferred"`
	NextDeferred time.Time `json:"nextDeferred,omitzero"`
	// Batch is the current batch's number.
	Batch        uint64        `json:"batch,omitempty"`
	Budget       Budget        `json:"budget"`
	Counters     Counters      `json:"counters"`
	RecentErrors []ErrorRecord `json:"recentErrors,omitempty"`
}

// Policy is an upstream's configured policy, for display.
type Policy struct {
	Versions          string   `json:"versions"`
	Include           []string `json:"include,omitempty"`
	Exclude           []string `json:"exclude,omitempty"`
	MaxArtifactBytes  int64    `json:"maxArtifactBytes,omitempty"`
	Concurrency       int      `json:"concurrency"`
	RequestsPerSecond float64  `json:"requestsPerSecond"`
	PollInterval      string   `json:"pollInterval"`
	Window            string   `json:"window"`
}

// Budget is an upstream's byte budget.
type Budget struct {
	Limit     int64 `json:"limit"`
	Used      int64 `json:"used"`
	Exhausted bool  `json:"exhausted"`
}

// peekInterval is how long a non-leading replica reuses the state it read.
const peekInterval = 2 * time.Second

// Status returns the engine's state. Safe on nil.
func (e *Engine) Status() Status {
	if e == nil || len(e.followers) == 0 {
		return Status{Enabled: false, Upstreams: []UpstreamStatus{}}
	}
	e.mu.Lock()
	st := Status{
		Enabled:  true,
		Running:  e.started && !e.stopped,
		Attached: e.fetcher != nil,
		StateDir: e.opts.Dir,
		Tenant:   e.opts.Tenant,
		Subject:  Subject,
	}
	e.mu.Unlock()
	st.Leader = e.isLeader()
	if active, mode := e.killSwitch(); active {
		st.Lockdown = firstNonEmpty(mode, "active")
	}
	g := e.globalControl(false)
	st.Paused, st.PausedBy, st.PausedAt, st.PauseReason = g.Paused, g.PausedBy, g.PausedAt, g.Reason
	st.Upstreams = make([]UpstreamStatus, 0, len(e.followers))
	for _, f := range e.followers {
		us := f.status()
		st.Upstreams = append(st.Upstreams, us)
		t := &st.Totals
		t.Upstreams++
		t.Queued += us.Queued
		t.Packages += us.Counters.Packages
		t.PackageErrors += us.Counters.PackageErrors
		t.Fetched += us.Counters.Fetched
		t.FetchedBytes += us.Counters.FetchedBytes
		t.Refused += us.Counters.Refused
		t.Failed += us.Counters.Failed
		t.Skipped += us.Counters.SkippedTotal()
		t.Deferred += us.Deferred
		t.BudgetBytes += us.Budget.Limit
		t.BudgetUsed += us.Budget.Used
	}
	return st
}

// UpstreamStatus returns one upstream's state.
func (e *Engine) UpstreamStatus(upstream string) (UpstreamStatus, error) {
	if !e.Enabled() {
		return UpstreamStatus{}, ErrUnknownUpstream
	}
	f, ok := e.byName[upstream]
	if !ok {
		return UpstreamStatus{}, ErrUnknownUpstream
	}
	return f.status(), nil
}

// status renders the follower's state. A replica that does not lead reads the
// leader's from the shared state directory.
func (f *follower) status() UpstreamStatus {
	now := f.e.now()
	f.mu.Lock()
	var st upstreamState
	if f.loaded {
		st = f.st
		st.Counters = st.Counters.clone()
		st.RecentErrors = append([]ErrorRecord(nil), st.RecentErrors...)
		if st.Batch != nil {
			b := *st.Batch
			b.Ahead = append([]int(nil), b.Ahead...)
			st.Batch = &b
		}
	} else {
		st = f.peekLocked(now)
	}
	us := UpstreamStatus{
		Upstream: f.s.Upstream,
		Type:     f.s.Type,
		Tier:     string(f.tier),
		State:    f.activity,
		Detail:   f.detail,
		Phase:    st.Phase,
		Cursor:   st.Cursor,
		DryRun:   f.s.DryRun,
		Policy: Policy{
			Versions:          f.s.VersionPolicy(),
			Include:           patternStrings(f.s.Include),
			Exclude:           patternStrings(f.s.Exclude),
			MaxArtifactBytes:  f.s.MaxArtifactBytes,
			Concurrency:       f.s.Concurrency,
			RequestsPerSecond: f.s.RequestsPerSecond,
			PollInterval:      f.s.PollInterval.String(),
			Window:            f.s.Window.String(),
		},
		Paused:            f.control.Paused,
		PausedBy:          f.control.PausedBy,
		PausedAt:          f.control.PausedAt,
		PauseReason:       f.control.Reason,
		ResyncPending:     f.control.ResyncSeq > st.ResyncHandled,
		LastPoll:          st.LastPoll,
		LastChange:        st.LastChange,
		LastCommit:        st.LastCommit,
		BootstrapStarted:  st.BootstrapStarted,
		BootstrapFinished: st.BootstrapFinished,
		FeedHead:          st.Head,
		InFlight:          f.inFlight,
		Budget: Budget{
			Limit:     f.s.ByteBudget,
			Used:      st.BudgetUsed,
			Exhausted: st.BudgetUsed >= f.s.ByteBudget || (st.BudgetExhaustedAt > 0 && f.s.ByteBudget <= st.BudgetExhaustedAt),
		},
		Counters:     st.Counters,
		RecentErrors: st.RecentErrors,
	}
	if b := st.Batch; b != nil {
		us.Batch = b.Seq
		us.Queued = b.queued()
	}
	if f.loaded {
		if f.nextPoll.After(now) {
			us.NextPoll = f.nextPoll.UTC()
		}
		if f.backoffUntil.After(now) {
			us.BackoffUntil = f.backoffUntil.UTC()
		}
		if b := st.Batch; b != nil && f.ahead != nil {
			// The live progress: the items done ahead are counted here,
			// and only persisted with the next write.
			if q := b.Total - b.Done - len(f.ahead); q >= 0 {
				us.Queued = q
			}
		}
		us.Deferred = len(f.deferred)
		if due := f.nextDueLocked(); !due.IsZero() {
			us.NextDeferred = due.UTC()
		}
	} else {
		us.Deferred, us.NextDeferred = f.peekedDeferred, f.peekedNextDue
	}
	if us.State == "" {
		us.State = StateStarting
	}
	f.mu.Unlock()
	if st.LagKnown {
		lag := st.Lag
		us.Lag = &lag
	}
	if !st.CursorTime.IsZero() {
		ref := st.HeadTime
		if ref.IsZero() {
			ref = now
		}
		if secs := ref.Sub(st.CursorTime).Seconds(); secs >= 0 {
			us.LagSeconds = &secs
		}
	}
	if us.RecentErrors == nil {
		us.RecentErrors = []ErrorRecord{}
	}
	return us
}

// peekLocked returns the state on disk (cached for peekInterval), and reads
// the deferred queue's size with it.
func (f *follower) peekLocked(now time.Time) upstreamState {
	if f.peeked != nil && now.Sub(f.peekedAt) < peekInterval {
		return *f.peeked
	}
	st, err := f.e.store.loadState(f.s.Upstream)
	if err != nil {
		st = f.freshState()
	}
	f.peekedDeferred, f.peekedNextDue = 0, time.Time{}
	if def, err := f.e.store.loadDeferred(f.s.Upstream); err == nil {
		f.peekedDeferred = len(def.Items)
		for _, it := range def.Items {
			if f.peekedNextDue.IsZero() || it.NotBefore.Before(f.peekedNextDue) {
				f.peekedNextDue = it.NotBefore.UTC()
			}
		}
	}
	f.peeked, f.peekedAt = &st, now
	return st
}

// patternStrings renders compiled name patterns as they were configured
// (CompilePatterns anchors each one).
func patternStrings(res []*regexp.Regexp) []string {
	if len(res) == 0 {
		return nil
	}
	out := make([]string, 0, len(res))
	for _, re := range res {
		out = append(out, strings.TrimSuffix(strings.TrimPrefix(re.String(), "^(?:"), ")$"))
	}
	return out
}
