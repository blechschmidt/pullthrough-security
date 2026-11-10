package proxy

import (
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/auth"
)

// MeteringRecorder is the narrow per-tenant usage-accounting surface the gateway
// records into (Task 84). It is satisfied structurally by *metering.Meter, so
// the proxy package does not depend on the concrete metering implementation
// (mirroring MetricsRecorder). When no recorder is supplied, the gateway records
// into a no-op.
type MeteringRecorder interface {
	// RecordRequest accounts one served backend request to a tenant, by backend
	// and ecosystem.
	RecordRequest(tenant, backend, ecosystem string)
	// RecordTraffic accounts served bytes to a tenant, categorized by whether the
	// bytes were a cache hit or required an upstream fetch.
	RecordTraffic(tenant string, bytes int64, cacheHit bool)
	// RecordStorage accounts the storage footprint a tenant caused by filling the
	// cache with a newly-fetched artifact.
	RecordStorage(tenant string, bytes int64)
	// RecordScan accounts one admission-scan invocation (and its estimated cost)
	// against a tenant, attributed to the owning gate.
	RecordScan(tenant, gate string)
	// RecordBlock accounts one admission-gate refusal against a tenant.
	RecordBlock(tenant, gate string)
}

// nopMetering is the recorder used when metering is disabled.
type nopMetering struct{}

func (nopMetering) RecordRequest(string, string, string) {}
func (nopMetering) RecordTraffic(string, int64, bool)    {}
func (nopMetering) RecordStorage(string, int64)          {}
func (nopMetering) RecordScan(string, string)            {}
func (nopMetering) RecordBlock(string, string)           {}

// metering returns the configured recorder, or a no-op when disabled, so call
// sites never need a nil check.
func (g *Gateway) metering() MeteringRecorder {
	if g.deps.Metering != nil {
		return g.deps.Metering
	}
	return nopMetering{}
}

// meteringTenant resolves the tenant a request is billed to from the
// authenticated principal, or "" (the meter buckets that as unscoped).
func meteringTenant(r *http.Request) string {
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		return p.Team
	}
	return ""
}

// meterRequest accounts a served request to its tenant.
func (g *Gateway) meterRequest(r *http.Request, backend string) {
	g.metering().RecordRequest(meteringTenant(r), backend, g.ecosystemFor(backend))
}

// meterTraffic accounts served bytes to a tenant, categorized by cache outcome.
func (g *Gateway) meterTraffic(r *http.Request, bytes int64, cacheHit bool) {
	g.metering().RecordTraffic(meteringTenant(r), bytes, cacheHit)
}

// meterStorage accounts the cache-fill footprint a tenant caused.
func (g *Gateway) meterStorage(r *http.Request, bytes int64) {
	g.metering().RecordStorage(meteringTenant(r), bytes)
}

// meterScan accounts one admission-scan invocation against a tenant.
func (g *Gateway) meterScan(r *http.Request, gate string) {
	g.metering().RecordScan(meteringTenant(r), gate)
}

// meterBlock accounts one admission-gate refusal against a tenant.
func (g *Gateway) meterBlock(r *http.Request, gate string) {
	g.metering().RecordBlock(meteringTenant(r), gate)
}
