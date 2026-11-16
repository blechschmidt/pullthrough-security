package fullscan

import (
	"time"
)

// Status is the full scan's state, for GET /api/fullscan/status, `ptctl
// fullscan status` and the metrics.
type Status struct {
	// Enabled reports that at least one upstream is in scope; All that the
	// global fullScan.enabled set the scope.
	Enabled bool `json:"enabled"`
	All     bool `json:"all,omitempty"`
	// Running reports that the loop runs; Attached that it has the gateway;
	// Leader that this replica leads (only the leader scans).
	Running  bool `json:"running"`
	Attached bool `json:"attached"`
	Leader   bool `json:"leader"`
	// State is what the full scan is doing or waiting for; Detail says more.
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
	// AsOf is when the figures were taken (a replica that does not lead shows
	// the leader's last published ones).
	AsOf     time.Time `json:"asOf,omitzero"`
	StateDir string    `json:"stateDir,omitempty"`
	Tenant   string    `json:"tenant,omitempty"`
	Subject  string    `json:"subject"`
	// Signature is the scan signature verdicts are current under (model,
	// prompt version, verdict schema version).
	Signature   string `json:"signature,omitempty"`
	Concurrency int    `json:"concurrency"`
	// The operators' global pause.
	Paused      bool      `json:"paused"`
	PausedBy    string    `json:"pausedBy,omitempty"`
	PausedAt    time.Time `json:"pausedAt,omitzero"`
	PauseReason string    `json:"pauseReason,omitempty"`
	Lockdown    string    `json:"lockdown,omitempty"`
	// Queue is the scan queue; Budget the cost budget.
	Queue  QueueStatus  `json:"queue"`
	Budget BudgetStatus `json:"budget"`
	// The backfill sweep.
	Sweep SweepStatus `json:"sweep"`
	// Totals sum the upstreams; Untracked counts the cached objects the last
	// sweep could attribute to no upstream.
	Totals    Figures `json:"totals"`
	Untracked int     `json:"untracked"`
	// Dropped counts the notes dropped because the loop could not keep up
	// (their artifacts are found by the next sweep); Overflow the artifacts
	// not tracked because the inventory is full.
	Dropped   uint64           `json:"dropped,omitempty"`
	Overflow  uint64           `json:"overflow,omitempty"`
	Upstreams []UpstreamStatus `json:"upstreams"`
}

// Figures count an upstream's tracked artifacts by their last reading.
type Figures struct {
	// Cached counts the tracked artifacts the cache holds.
	Cached int `json:"cached"`
	// Scanned counts those with a current verdict, by the gate's reading:
	// Benign, Suspicious, Malicious.
	Scanned    int `json:"scanned"`
	Benign     int `json:"benign"`
	Suspicious int `json:"suspicious"`
	Malicious  int `json:"malicious"`
	// Pending counts those waiting in the queue; Errors those given up on
	// after their attempts (the next sweep queues them again).
	Pending int `json:"pending"`
	Errors  int `json:"errors"`
	// Refused counts those the model refused to judge; Unscannable those the
	// gate cannot examine for another reason of their own (too large, a
	// format it cannot unpack, an answer it could not read). Neither is
	// benign.
	Refused     int `json:"refused"`
	Unscannable int `json:"unscannable"`
	// NotApplicable counts those holding nothing the gate examines (a
	// metadata document, an index, a blob its image's verdict covers).
	NotApplicable int `json:"notApplicable"`
	// Quarantined counts the artifacts the ladder removed from the cache;
	// their verdicts are counted above (Malicious, Suspicious).
	Quarantined int `json:"quarantined"`
	// RefusedByAction counts the cached artifacts the configured action
	// refuses to clients (a pin kept them, or the action does not evict).
	RefusedByAction int `json:"refusedByAction"`
	// GatesPassed counts the artifacts every admission gate admitted (the
	// full mirror's fetch, or the full scan's gate pass); GateRefused those
	// another gate refused in a gate pass. The rest were judged only on a
	// client's pull.
	GatesPassed int `json:"gatesPassed"`
	GateRefused int `json:"gateRefused"`
}

// Oldest names the artifact that has waited longest for a verdict.
type Oldest struct {
	Path   string    `json:"path,omitempty"`
	Key    string    `json:"key,omitempty"`
	Cached time.Time `json:"cached"`
	// Since is when it was queued; State pending or error.
	Since time.Time `json:"since,omitzero"`
	State string    `json:"state"`
	// AgeSeconds is how long it has been cached without a verdict.
	AgeSeconds float64 `json:"ageSeconds"`
}

// UpstreamStatus is one upstream's full scan.
type UpstreamStatus struct {
	Upstream    string    `json:"upstream"`
	Paused      bool      `json:"paused"`
	PausedBy    string    `json:"pausedBy,omitempty"`
	PausedAt    time.Time `json:"pausedAt,omitzero"`
	PauseReason string    `json:"pauseReason,omitempty"`
	Figures
	// OldestUnscanned is the cached artifact without a verdict that has been
	// cached longest.
	OldestUnscanned *Oldest `json:"oldestUnscanned,omitempty"`
	// Untracked counts the cached objects of the upstream the last sweep could
	// not track (cached before fill metadata existed).
	Untracked int `json:"untracked"`
	// SpentUSD is what the full scan's model calls for this upstream cost.
	SpentUSD float64  `json:"spentUsd"`
	Counters Counters `json:"counters"`
}

// QueueStatus is the scan queue.
type QueueStatus struct {
	// Client, Mirror and Backfill count the artifacts queued per class (those
	// waiting out a retry included); Delayed those waiting out a retry;
	// Parked those of paused upstreams; InFlight the scans running.
	Client   int `json:"client"`
	Mirror   int `json:"mirror"`
	Backfill int `json:"backfill"`
	Delayed  int `json:"delayed"`
	Parked   int `json:"parked"`
	InFlight int `json:"inFlight"`
}

// BudgetStatus is the cost budget.
type BudgetStatus struct {
	Daily   WindowStatus `json:"daily"`
	Monthly WindowStatus `json:"monthly"`
	// TotalSpentUSD is everything spent since the state was created.
	TotalSpentUSD float64 `json:"totalSpentUsd"`
	Exhausted     bool    `json:"exhausted"`
}

// WindowStatus is one window of the budget.
type WindowStatus struct {
	Window     string    `json:"window"`
	SpentUSD   float64   `json:"spentUsd"`
	CeilingUSD float64   `json:"ceilingUsd"`
	Exhausted  bool      `json:"exhausted"`
	ResetsAt   time.Time `json:"resetsAt"`
}

// SweepStatus is the backfill sweep.
type SweepStatus struct {
	Interval     string    `json:"interval"`
	Running      bool      `json:"running"`
	LastStarted  time.Time `json:"lastStarted,omitzero"`
	LastFinished time.Time `json:"lastFinished,omitzero"`
	LastError    string    `json:"lastError,omitempty"`
	Next         time.Time `json:"next,omitzero"`
	// Inventory says whether the cache can be listed at all.
	Inventory bool `json:"inventory"`
}

// peekInterval is how long a replica that does not lead reuses what it read.
const peekInterval = 2 * time.Second

// statusTTL is how long the leader reuses a status it computed.
const statusTTL = time.Second

// Status returns the full scan's state. Safe on nil.
func (s *Service) Status() Status {
	if !s.Enabled() {
		return Status{Subject: Subject, Upstreams: []UpstreamStatus{}}
	}
	ctl := s.refreshControl(false)
	now := s.now()
	leader := s.isLeader()
	s.mu.Lock()
	var st Status
	switch {
	case s.loaded:
		if s.statusCache != nil && now.Sub(s.statusAt) < statusTTL {
			st = *s.statusCache
		} else {
			st = s.statusLocked(now)
			cp := st
			s.statusCache, s.statusAt = &cp, now
		}
	default:
		st = s.peekLocked(now)
	}
	st.Running = s.started && !s.stopped
	st.Attached = s.scanner != nil
	st.State, st.Detail = s.activity, s.detail
	s.mu.Unlock()
	st.Leader = leader
	if st.State == "" {
		st.State = StateStarting
	}
	if active, mode := s.killSwitch(); active {
		st.Lockdown = firstNonEmpty(mode, "active")
	}
	st.Paused, st.PausedBy, st.PausedAt, st.PauseReason = ctl.Paused, ctl.PausedBy, ctl.PausedAt, ctl.Reason
	st.Dropped = s.dropped.Load()
	ups := make([]UpstreamStatus, len(st.Upstreams))
	for i, u := range st.Upstreams {
		pc := ctl.Upstreams[u.Upstream]
		u.Paused, u.PausedBy, u.PausedAt, u.PauseReason = pc.Paused, pc.PausedBy, pc.PausedAt, pc.Reason
		ups[i] = u
	}
	st.Upstreams = ups
	return st
}

// peekLocked returns the figures the leader last published, for a replica
// that does not lead.
func (s *Service) peekLocked(now time.Time) Status {
	if s.peeked == nil || now.Sub(s.peekedAt) >= peekInterval {
		st, err := s.store.loadState()
		if err != nil {
			st = stateFile{}
		}
		s.peeked, s.peekedAt = &st, now
	}
	if p := s.peeked.Published; p != nil {
		out := *p
		out.Upstreams = append([]UpstreamStatus(nil), p.Upstreams...)
		out.Queue.InFlight = 0
		return out
	}
	return s.baseStatusLocked(now, stateFile{})
}

// baseStatusLocked is the part of the status the configuration and the
// persisted state give.
func (s *Service) baseStatusLocked(now time.Time, st stateFile) Status {
	out := Status{
		Enabled:     true,
		All:         s.opts.All,
		StateDir:    s.opts.Dir,
		Tenant:      s.opts.Tenant,
		Subject:     Subject,
		Concurrency: s.opts.Concurrency,
		AsOf:        now.UTC(),
		Signature:   s.signatureLocked(),
		Overflow:    s.overflow,
	}
	l := st.Ledger
	dayEx, _ := l.exhausted(now, s.opts.DailyUSD, 0)
	monEx, _ := l.exhausted(now, 0, s.opts.MonthlyUSD)
	out.Budget = BudgetStatus{
		Daily:         WindowStatus{Window: WindowDay, SpentUSD: l.DaySpentUSD, CeilingUSD: s.opts.DailyUSD, Exhausted: dayEx, ResetsAt: resetsAt(now, WindowDay)},
		Monthly:       WindowStatus{Window: WindowMonth, SpentUSD: l.MonthSpentUSD, CeilingUSD: s.opts.MonthlyUSD, Exhausted: monEx, ResetsAt: resetsAt(now, WindowMonth)},
		TotalSpentUSD: l.TotalSpentUSD,
		Exhausted:     dayEx || monEx,
	}
	out.Sweep = SweepStatus{
		Interval:     s.opts.SweepInterval.String(),
		Running:      s.sweeping,
		LastStarted:  st.LastSweep,
		LastFinished: st.LastSweepFinished,
		LastError:    st.LastSweepError,
		Inventory:    s.inventory != nil,
	}
	if s.loaded && !s.nextSweep.IsZero() {
		out.Sweep.Next = s.nextSweep.UTC()
	}
	out.Untracked = st.Untracked[""]
	out.Upstreams = make([]UpstreamStatus, 0, len(s.names))
	for _, name := range s.names {
		u := UpstreamStatus{Upstream: name, Untracked: st.Untracked[name]}
		if c := st.Counters[name]; c != nil {
			u.Counters = c.clone()
			u.SpentUSD = c.SpentUSD
		}
		out.Upstreams = append(out.Upstreams, u)
	}
	return out
}

// statusLocked computes the leader's status from the inventory.
func (s *Service) statusLocked(now time.Time) Status {
	// The ledger's windows roll on read; the copy keeps the state untouched.
	out := s.baseStatusLocked(now, s.st)
	byName := make(map[string]int, len(out.Upstreams))
	for i, u := range out.Upstreams {
		byName[u.Upstream] = i
	}
	oldest := make(map[string]*Item, len(out.Upstreams))
	for _, it := range s.items {
		i, ok := byName[it.Upstream]
		if !ok {
			continue
		}
		f := &out.Upstreams[i].Figures
		if it.Evicted {
			f.Quarantined++
		} else {
			f.Cached++
		}
		switch it.State {
		case StateScanned:
			if !it.Evicted {
				f.Scanned++
			}
			switch it.Verdict {
			case "malicious":
				f.Malicious++
			case "suspicious":
				f.Suspicious++
			case "benign":
				if !it.Evicted {
					f.Benign++
				}
			}
			if it.Action != "" && !it.Evicted {
				f.RefusedByAction++
			}
		case StatePending:
			f.Pending++
		case StateError:
			f.Errors++
		case StateUnscannable:
			if it.Code == CodeProviderRefusal {
				f.Refused++
			} else {
				f.Unscannable++
			}
			if it.Action != "" && !it.Evicted {
				f.RefusedByAction++
			}
		case StateNotApplicable:
			f.NotApplicable++
		}
		switch {
		case it.Gates == GatesPassed && !it.Evicted:
			f.GatesPassed++
		case it.Gates == GatesRefused:
			f.GateRefused++
		}
		if it.unscanned() && !it.Evicted {
			if o := oldest[it.Upstream]; o == nil || olderFirst(it, o) {
				oldest[it.Upstream] = it
			}
		}
		if it.State == StatePending {
			switch it.Priority {
			case PriorityClient:
				out.Queue.Client++
			case PriorityMirror:
				out.Queue.Mirror++
			default:
				out.Queue.Backfill++
			}
		}
	}
	for i := range out.Upstreams {
		u := &out.Upstreams[i]
		if it := oldest[u.Upstream]; it != nil {
			u.OldestUnscanned = &Oldest{
				Path: it.Path, Key: it.Key, Cached: it.Cached, Since: it.Enqueued, State: it.State,
				AgeSeconds: now.Sub(it.Cached).Seconds(),
			}
		}
		addFigures(&out.Totals, u.Figures)
	}
	if s.q != nil {
		_, delayed, parked := s.q.sizes()
		out.Queue.Delayed, out.Queue.Parked = delayed, parked
	}
	out.Queue.InFlight = s.running
	return out
}

func addFigures(t *Figures, f Figures) {
	t.Cached += f.Cached
	t.Scanned += f.Scanned
	t.Benign += f.Benign
	t.Suspicious += f.Suspicious
	t.Malicious += f.Malicious
	t.Pending += f.Pending
	t.Errors += f.Errors
	t.Refused += f.Refused
	t.Unscannable += f.Unscannable
	t.NotApplicable += f.NotApplicable
	t.Quarantined += f.Quarantined
	t.RefusedByAction += f.RefusedByAction
	t.GatesPassed += f.GatesPassed
	t.GateRefused += f.GateRefused
}

// UpstreamStatus returns one upstream's full scan.
func (s *Service) UpstreamStatus(upstream string) (UpstreamStatus, error) {
	if !s.Enabled() {
		return UpstreamStatus{}, ErrDisabled
	}
	if !s.inScope(upstream) {
		return UpstreamStatus{}, ErrUnknownUpstream
	}
	for _, u := range s.Status().Upstreams {
		if u.Upstream == upstream {
			return u, nil
		}
	}
	return UpstreamStatus{}, ErrUnknownUpstream
}

// Redacted returns the status a tenant-bound identity is shown: the figures,
// without what names a single artifact (the path and cache key of the oldest
// unscanned one), the state directory, the full mirror's tenant, the
// operators' names and reasons, and error texts — none of it the tenant's
// business, and some of it about other tenants' caches.
func (st Status) Redacted() Status {
	out := st
	out.StateDir, out.Tenant, out.Detail = "", "", ""
	out.PausedBy, out.PauseReason = "", ""
	out.Sweep.LastError = ""
	out.Upstreams = make([]UpstreamStatus, len(st.Upstreams))
	for i, u := range st.Upstreams {
		if u.OldestUnscanned != nil {
			o := *u.OldestUnscanned
			o.Path, o.Key = "", ""
			u.OldestUnscanned = &o
		}
		u.PausedBy, u.PauseReason = "", ""
		out.Upstreams[i] = u
	}
	return out
}
