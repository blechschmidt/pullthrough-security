package adminauth

import "sync"

// Metrics accumulates authentication/authorization counters for the admin
// surface. The proxy bridges these into the Prometheus registry as scrape-time
// callbacks, so this struct is the single source of truth.
type Metrics struct {
	mu sync.Mutex

	authSuccessByRole   map[string]uint64
	authSuccessByMethod map[string]uint64
	authFailureByReason map[string]uint64
	authzAllowByCap     map[string]uint64
	authzDenyByCap      map[string]uint64
	logins              uint64
	loginFailures       uint64
	logouts             uint64
}

func newMetrics() *Metrics {
	return &Metrics{
		authSuccessByRole:   make(map[string]uint64),
		authSuccessByMethod: make(map[string]uint64),
		authFailureByReason: make(map[string]uint64),
		authzAllowByCap:     make(map[string]uint64),
		authzDenyByCap:      make(map[string]uint64),
	}
}

func (m *Metrics) recordAuthSuccess(method string, roles []Role) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authSuccessByMethod[method]++
	if len(roles) == 0 {
		m.authSuccessByRole["none"]++
		return
	}
	for _, r := range roles {
		m.authSuccessByRole[string(r)]++
	}
}

func (m *Metrics) recordAuthFailure(reason string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authFailureByReason[reason]++
}

func (m *Metrics) recordAuthz(cap Capability, allowed bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if allowed {
		m.authzAllowByCap[cap.String()]++
	} else {
		m.authzDenyByCap[cap.String()]++
	}
}

func (m *Metrics) recordLogin(ok bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if ok {
		m.logins++
	} else {
		m.loginFailures++
	}
}

func (m *Metrics) recordLogout() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logouts++
}

// Snapshot is an immutable copy of the metrics for export.
type Snapshot struct {
	AuthSuccessByRole   map[string]uint64
	AuthSuccessByMethod map[string]uint64
	AuthFailureByReason map[string]uint64
	AuthzAllowByCap     map[string]uint64
	AuthzDenyByCap      map[string]uint64
	Logins              uint64
	LoginFailures       uint64
	Logouts             uint64
}

// Snapshot returns a deep copy of the current counters.
func (m *Metrics) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := func(in map[string]uint64) map[string]uint64 {
		out := make(map[string]uint64, len(in))
		for k, v := range in {
			out[k] = v
		}
		return out
	}
	return Snapshot{
		AuthSuccessByRole:   cp(m.authSuccessByRole),
		AuthSuccessByMethod: cp(m.authSuccessByMethod),
		AuthFailureByReason: cp(m.authFailureByReason),
		AuthzAllowByCap:     cp(m.authzAllowByCap),
		AuthzDenyByCap:      cp(m.authzDenyByCap),
		Logins:              m.logins,
		LoginFailures:       m.loginFailures,
		Logouts:             m.logouts,
	}
}
