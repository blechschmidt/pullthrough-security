package loadbench

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Result is the aggregated outcome of a load run.
type Result struct {
	// Started is when the measured run began; Elapsed is its wall-clock duration.
	Started time.Time     `json:"started"`
	Elapsed time.Duration `json:"elapsedNanos"`

	// Total is every request issued during measurement (including failures).
	Total int64 `json:"total"`
	// Success counts 2xx responses; NotFound counts 404s (tracked separately so
	// the negative-cache workload's expected misses are not read as errors);
	// ClientErrors counts other 4xx; ServerErrors counts 5xx; Failures counts
	// transport-level errors (no HTTP response).
	Success      int64 `json:"success"`
	NotFound     int64 `json:"notFound"`
	ClientErrors int64 `json:"clientErrors"`
	ServerErrors int64 `json:"serverErrors"`
	Failures     int64 `json:"failures"`

	// Bytes is the total response-body bytes read from the proxy.
	Bytes int64 `json:"bytes"`

	// Cache classification by the proxy's X-Cache response header.
	CacheHits   int64 `json:"cacheHits"`   // X-Cache: HIT
	CacheMisses int64 `json:"cacheMisses"` // X-Cache: MISS
	Coalesced   int64 `json:"coalesced"`   // X-Cache: COALESCED-HIT
	Bypass      int64 `json:"bypass"`      // X-Cache: BYPASS
	OtherCache  int64 `json:"otherCache"`  // any other X-Cache value (e.g. BLOCKED)

	// StatusCodes is the full HTTP status-code histogram.
	StatusCodes map[int]int64 `json:"statusCodes"`

	// Latency is the client-observed per-request latency distribution.
	Latency LatencyStats `json:"latency"`

	// Server is the proxy's authoritative counter delta over the run, present
	// only when a ServerMetrics sampler was configured and both samples
	// succeeded. ServerMetricsError records why it is absent otherwise.
	Server             *ServerDelta `json:"server,omitempty"`
	ServerMetricsError string       `json:"serverMetricsError,omitempty"`
}

// LatencyStats is a latency distribution. Durations are nanoseconds in JSON.
type LatencyStats struct {
	Count int64         `json:"count"`
	Min   time.Duration `json:"minNanos"`
	Mean  time.Duration `json:"meanNanos"`
	P50   time.Duration `json:"p50Nanos"`
	P90   time.Duration `json:"p90Nanos"`
	P95   time.Duration `json:"p95Nanos"`
	P99   time.Duration `json:"p99Nanos"`
	P999  time.Duration `json:"p999Nanos"`
	Max   time.Duration `json:"maxNanos"`
}

// ServerDelta is the change in the proxy's cumulative cache/coalescer counters
// across the run (gauges carry the post-run value).
type ServerDelta struct {
	CacheHits         int64 `json:"cacheHits"`
	CacheMisses       int64 `json:"cacheMisses"`
	CoalesceLookups   int64 `json:"coalesceLookups"`
	Coalesced         int64 `json:"coalesced"`
	Leads             int64 `json:"leads"`
	NegativeHits      int64 `json:"negativeHits"`
	NegativeStored    int64 `json:"negativeStored"`
	NegativeEvictions int64 `json:"negativeEvictions"`
	NegativeEntries   int   `json:"negativeEntries"`
	InFlight          int   `json:"inFlight"`

	// Outbound connection-pool deltas (Task 130): connection acquisitions handed
	// to upstream requests over the run, how many reused a pooled keep-alive
	// connection, and how many new connections were dialed.
	ConnAcquired int64 `json:"connAcquired"`
	ConnReused   int64 `json:"connReused"`
	ConnDials    int64 `json:"connDials"`
}

// ConnReuseRatio is the fraction of connection acquisitions over the run that
// reused a pooled connection rather than dialing a new one, in [0,1]. It is the
// headline connection-churn metric: a well-tuned transport under steady load
// reuses nearly every connection. It returns 0 (not measured) when no
// acquisitions were observed.
func (d *ServerDelta) ConnReuseRatio() float64 {
	if d == nil || d.ConnAcquired <= 0 {
		return 0
	}
	return float64(d.ConnReused) / float64(d.ConnAcquired)
}

// computeLatency sorts the samples and extracts the distribution.
func computeLatency(samples []time.Duration) LatencyStats {
	n := len(samples)
	if n == 0 {
		return LatencyStats{}
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	var sum time.Duration
	for _, s := range samples {
		sum += s
	}
	return LatencyStats{
		Count: int64(n),
		Min:   samples[0],
		Mean:  sum / time.Duration(n),
		P50:   percentile(samples, 0.50),
		P90:   percentile(samples, 0.90),
		P95:   percentile(samples, 0.95),
		P99:   percentile(samples, 0.99),
		P999:  percentile(samples, 0.999),
		Max:   samples[n-1],
	}
}

// percentile returns the nearest-rank percentile of a sorted slice. p is in
// [0,1].
func percentile(sorted []time.Duration, p float64) time.Duration {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 1 {
		return sorted[n-1]
	}
	// Nearest-rank: rank = ceil(p*n), 1-indexed.
	rank := int(p*float64(n) + 0.9999999)
	if rank < 1 {
		rank = 1
	}
	if rank > n {
		rank = n
	}
	return sorted[rank-1]
}

// Throughput returns the achieved request rate in requests/second.
func (r Result) Throughput() float64 {
	if r.Elapsed <= 0 {
		return 0
	}
	return float64(r.Total) / r.Elapsed.Seconds()
}

// ByteThroughput returns the achieved body throughput in bytes/second.
func (r Result) ByteThroughput() float64 {
	if r.Elapsed <= 0 {
		return 0
	}
	return float64(r.Bytes) / r.Elapsed.Seconds()
}

// cacheDecided is the number of responses the proxy served from or filled into
// the cache (hits + coalesced hits + misses). It excludes bypasses, blocks, and
// errors, which are not cache decisions.
func (r Result) cacheDecided() int64 {
	return r.CacheHits + r.Coalesced + r.CacheMisses
}

// CacheHitRatio is the client-observed fraction of cache decisions served from
// the cache (a plain hit or a coalesced hit), in [0,1]. It is 0 when no
// cacheable responses were seen.
func (r Result) CacheHitRatio() float64 {
	d := r.cacheDecided()
	if d == 0 {
		return 0
	}
	return float64(r.CacheHits+r.Coalesced) / float64(d)
}

// CoalesceRatio is the client-observed fraction of cache decisions satisfied by
// joining an in-flight upstream fetch rather than issuing their own — the
// singleflight-coalescing efficacy. It is 0 when no cacheable responses were
// seen.
func (r Result) CoalesceRatio() float64 {
	d := r.cacheDecided()
	if d == 0 {
		return 0
	}
	return float64(r.Coalesced) / float64(d)
}

// Format renders a human-readable report. It is the text the CLI prints.
func (r Result) Format() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Load test results\n")
	fmt.Fprintf(&b, "  duration:        %s\n", r.Elapsed.Round(time.Millisecond))
	fmt.Fprintf(&b, "  requests:        %d total  (%d ok, %d 404, %d 4xx, %d 5xx, %d failed)\n",
		r.Total, r.Success, r.NotFound, r.ClientErrors, r.ServerErrors, r.Failures)
	fmt.Fprintf(&b, "  throughput:      %.1f req/s  |  %s/s\n", r.Throughput(), humanBytes(r.ByteThroughput()))
	fmt.Fprintf(&b, "  bytes served:    %s\n", humanBytes(float64(r.Bytes)))
	fmt.Fprintf(&b, "\nLatency (client-observed)\n")
	fmt.Fprintf(&b, "  min / mean:      %s / %s\n", dur(r.Latency.Min), dur(r.Latency.Mean))
	fmt.Fprintf(&b, "  p50 / p90:       %s / %s\n", dur(r.Latency.P50), dur(r.Latency.P90))
	fmt.Fprintf(&b, "  p95 / p99:       %s / %s\n", dur(r.Latency.P95), dur(r.Latency.P99))
	fmt.Fprintf(&b, "  p99.9:           %s\n", dur(r.Latency.P999))
	fmt.Fprintf(&b, "  max:             %s\n", dur(r.Latency.Max))
	fmt.Fprintf(&b, "\nCache behavior (from X-Cache)\n")
	fmt.Fprintf(&b, "  hit ratio:       %.1f%%  (%d hit, %d coalesced, %d miss)\n",
		100*r.CacheHitRatio(), r.CacheHits, r.Coalesced, r.CacheMisses)
	fmt.Fprintf(&b, "  coalescing:      %.1f%%  (%d of %d cache decisions joined an in-flight fetch)\n",
		100*r.CoalesceRatio(), r.Coalesced, r.cacheDecided())
	if r.Bypass > 0 || r.OtherCache > 0 {
		fmt.Fprintf(&b, "  other:           %d bypass, %d other (e.g. blocked)\n", r.Bypass, r.OtherCache)
	}
	if r.Server != nil {
		s := r.Server
		fmt.Fprintf(&b, "\nServer-side delta (admin metrics)\n")
		fmt.Fprintf(&b, "  cache:           %d hits, %d misses", s.CacheHits, s.CacheMisses)
		if dn := s.CacheHits + s.CacheMisses; dn > 0 {
			fmt.Fprintf(&b, "  (%.1f%% hit ratio)", 100*float64(s.CacheHits)/float64(dn))
		}
		fmt.Fprintf(&b, "\n")
		fmt.Fprintf(&b, "  coalescer:       %d coalesced, %d leads", s.Coalesced, s.Leads)
		if dd := s.Coalesced + s.Leads; dd > 0 {
			fmt.Fprintf(&b, "  (%.1f%% dedup)", 100*float64(s.Coalesced)/float64(dd))
		}
		fmt.Fprintf(&b, "\n")
		fmt.Fprintf(&b, "  negative cache:  %d hits, %d stored, %d evicted  (now %d entries)\n",
			s.NegativeHits, s.NegativeStored, s.NegativeEvictions, s.NegativeEntries)
		if s.ConnAcquired > 0 {
			fmt.Fprintf(&b, "  upstream conns:  %d acquired, %d reused, %d dialed  (%.1f%% reuse)\n",
				s.ConnAcquired, s.ConnReused, s.ConnDials, 100*s.ConnReuseRatio())
		}
	} else if r.ServerMetricsError != "" {
		fmt.Fprintf(&b, "\nServer-side metrics unavailable: %s\n", r.ServerMetricsError)
	}
	return b.String()
}

func dur(d time.Duration) string {
	switch {
	case d == 0:
		return "0"
	case d < time.Microsecond:
		return fmt.Sprintf("%dns", d.Nanoseconds())
	case d < time.Millisecond:
		return fmt.Sprintf("%.1fµs", float64(d.Nanoseconds())/1e3)
	case d < time.Second:
		return fmt.Sprintf("%.2fms", float64(d.Nanoseconds())/1e6)
	default:
		return fmt.Sprintf("%.3fs", d.Seconds())
	}
}

func humanBytes(n float64) string {
	const unit = 1024.0
	if n < unit {
		return fmt.Sprintf("%.0f B", n)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	v := n / unit
	for _, u := range units {
		if v < unit {
			return fmt.Sprintf("%.1f %s", v, u)
		}
		v /= unit
	}
	return fmt.Sprintf("%.1f PiB", v)
}
