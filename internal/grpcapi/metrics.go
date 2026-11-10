package grpcapi

import "sync"

// metrics accumulates per-RPC gRPC/Connect telemetry. It is guarded by a mutex
// because the per-RPC maps grow lazily and many requests may run concurrently.
type metrics struct {
	mu        sync.Mutex
	requests  int64
	errors    int64
	streams   int64
	streamMsg int64
	rpcCalls  map[string]int64
	rpcErrors map[string]int64
}

// Snapshot is the service's cumulative telemetry, surfaced to Prometheus via the
// metrics bridge and to the admin info endpoint.
type Snapshot struct {
	// Requests is the total number of RPCs dispatched (unary and streaming).
	Requests int64 `json:"requests"`
	// Errors is the total number of RPCs that returned a Connect error.
	Errors int64 `json:"errors"`
	// Streams is the total number of server-streaming RPCs dispatched.
	Streams int64 `json:"streams"`
	// StreamMessages is the total number of messages sent across all streaming
	// RPCs.
	StreamMessages int64 `json:"streamMessages"`
	// RPCCalls counts invocations per RPC method name.
	RPCCalls map[string]int64 `json:"rpcCalls"`
	// RPCErrors counts invocations per RPC method name that returned an error.
	RPCErrors map[string]int64 `json:"rpcErrors"`
}

// recordRPC records one completed RPC (unary or streaming) by method name,
// noting whether it ended in an error.
func (m *metrics) recordRPC(method string, isErr bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests++
	if isErr {
		m.errors++
	}
	if m.rpcCalls == nil {
		m.rpcCalls = map[string]int64{}
		m.rpcErrors = map[string]int64{}
	}
	m.rpcCalls[method]++
	if isErr {
		m.rpcErrors[method]++
	}
}

// recordStream notes a server-streaming RPC and the number of messages it sent.
func (m *metrics) recordStream(messages int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.streams++
	m.streamMsg += int64(messages)
}

func (m *metrics) snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	calls := make(map[string]int64, len(m.rpcCalls))
	for k, v := range m.rpcCalls {
		calls[k] = v
	}
	errs := make(map[string]int64, len(m.rpcErrors))
	for k, v := range m.rpcErrors {
		errs[k] = v
	}
	return Snapshot{
		Requests:       m.requests,
		Errors:         m.errors,
		Streams:        m.streams,
		StreamMessages: m.streamMsg,
		RPCCalls:       calls,
		RPCErrors:      errs,
	}
}
