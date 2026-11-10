package admin

import (
	"net/http"
	httppprof "net/http/pprof"
	"runtime"
)

// ProfilingOptions configures the runtime profiling surface. When Enabled, the
// admin server exposes the standard net/http/pprof endpoints — plus the
// runtime/trace execution-trace capture — under <prefix>/api/debug/pprof/,
// guarded by exactly the same authentication and RBAC as the rest of the admin
// API (see requiredCapability: the profiling endpoints demand the "operate"
// capability, since capturing a CPU profile or execution trace consumes runtime
// resources for its duration).
//
// Profiling is off by default: the endpoints expose detailed runtime internals
// (stack traces, allocation sites, command line) and a CPU/trace capture holds
// the profiler for its requested duration, so an operator opts in explicitly.
type ProfilingOptions struct {
	// Enabled turns the profiling surface on.
	Enabled bool
	// BlockProfileRate is passed to runtime.SetBlockProfileRate when profiling is
	// enabled. It is the approximate number of nanoseconds of blocking between
	// sampled events; a value of 0 leaves block profiling disabled (the Go
	// default, so /debug/pprof/block reports nothing). A small positive value
	// (e.g. 10000) enables low-overhead sampling.
	BlockProfileRate int
	// MutexProfileFraction is passed to runtime.SetMutexProfileFraction when
	// profiling is enabled. On average 1/rate of mutex contention events are
	// reported; 0 leaves mutex profiling disabled (so /debug/pprof/mutex reports
	// nothing). A value such as 100 enables low-overhead sampling.
	MutexProfileFraction int
}

// applyProfilingRates configures the process-wide block and mutex profilers so
// the corresponding pprof endpoints return data. It is a no-op when profiling is
// disabled. Both settings default to "off" (0), matching the Go runtime, so an
// operator who only wants CPU/heap/goroutine profiles pays no sampling overhead.
func (o ProfilingOptions) applyProfilingRates() {
	if !o.Enabled {
		return
	}
	if o.BlockProfileRate > 0 {
		runtime.SetBlockProfileRate(o.BlockProfileRate)
	}
	if o.MutexProfileFraction > 0 {
		runtime.SetMutexProfileFraction(o.MutexProfileFraction)
	}
}

// registerProfiling mounts the net/http/pprof handlers (index, cmdline, CPU
// profile, symbol, and the runtime/trace execution trace, plus the named runtime
// profiles — heap, goroutine, allocs, block, mutex, threadcreate — served by the
// index handler) under <prefix>/api/debug/pprof/.
//
// The handlers are built into a private sub-mux keyed on the paths pprof expects
// ("/debug/pprof/..."), then mounted under the admin API prefix via
// http.StripPrefix so pprof's own path handling (and the relative links its
// index page emits) resolve correctly regardless of the configured admin prefix.
// Because the mount point sits under the "/api/" subtree, it inherits the admin
// authentication + RBAC middleware wrapping the whole mux — there is no separate
// listener and no unauthenticated access.
func (s *Server) registerProfiling(mux *http.ServeMux) {
	pm := http.NewServeMux()
	pm.HandleFunc("/debug/pprof/", httppprof.Index)
	pm.HandleFunc("/debug/pprof/cmdline", httppprof.Cmdline)
	pm.HandleFunc("/debug/pprof/profile", httppprof.Profile)
	pm.HandleFunc("/debug/pprof/symbol", httppprof.Symbol)
	pm.HandleFunc("/debug/pprof/trace", httppprof.Trace)

	stripped := http.StripPrefix(s.prefix+"/api", pm)
	mux.Handle(s.prefix+"/api/debug/pprof/", stripped)
}
